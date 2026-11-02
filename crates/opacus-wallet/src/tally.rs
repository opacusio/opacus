//! GIP-2 WP-2: the deterministic Stage A tally engine.
//!
//! Additive module: nothing in the existing wallet files changes.
//!
//! GIP-2 section 3.2 step 4 / P-5: the tally engine checks every ballot
//! of the published archive, rejects duplicate `VS` serials, and
//! publishes the aggregate result with per-ballot traceability. The
//! engine here is ORDINARY SOFTWARE (no new trust root, no consensus
//! change): every input is public, every step is deterministic, and the
//! whole tally can be replayed by anyone - "a wrong tally is detectable
//! by replay" (GIP-2 section 7).
//!
//! - [`DeclaredProposal`] is the voting proposal's fixed parameter set
//!   (GIP-2 R-5: snapshot height, anchor, window and class are declared
//!   BEFORE voting starts; P-3: `H_snap = H_open`).
//! - [`tally`] processes the ballot archive in a canonical order
//!   (sorted by ballot bytes), verifies every ballot standalone
//!   ([`crate::gov::verify_ballot`], the milliseconds-per-ballot budget
//!   of P-5), pins each ballot to the DECLARED anchor and proposal
//!   (the node-side freshness gate of [`crate::gov::verify_ballot_against_tree`]
//!   generalised to the public replay: the archived frontier root of
//!   P-3 stands, fail-closed), enforces one vote per serial with the
//!   [`SeenSet`] (R-3), and accumulates the public weight per choice.
//! - [`decide`] applies P-6 verbatim: quorum 5% of the emission
//!   denominator for fund decisions and 2% for process transitions;
//!   approval 60% of YES+NO weight for fund decisions, simple majority
//!   for process votes; ABSTAIN counts toward participation only;
//!   quorum not met = status quo persists (fail-closed).
//! - [`emission_upto`] is the public quorum denominator of P-5,
//!   `sum(block_reward(0..H_snap))` - a deterministic function of
//!   consensus, so no balance is revealed. It mirrors
//!   `opacus_consensus::block::block_reward` (the wallet cannot depend
//!   on the consensus crate without a dependency cycle: consensus
//!   already depends on the wallet). The two implementations are pinned
//!   together by the consensus-side sync test
//!   `crates/opacus-consensus/tests/gov_emission_sync.rs`; a schedule
//!   change is a Standards Track GIP (GIP-2 R-7) and MUST touch both.
//! - The result ([`TallyRecord`], with a canonical wire format) commits
//!   to the declared parameters, the totals, and the sorted sighashes
//!   of the ACCEPTED ballots via `result_hash`. Proof bytes do NOT
//!   enter the hash (halo2 blinding is random): two independent runs
//!   over the same archive produce the SAME `result_hash`, which is
//!   what makes the record a golden vector. Rejected ballots are trace
//!   metadata, not hash inputs: the hash identifies the DECISION.
//!
//! Measured per-ballot budget (P-5): verification is the mock/real
//! halo2 verify path of `opacus-zk::vote`, milliseconds per ballot;
//! the `~10 s` envelope in P-2 is the PROVER budget and does not apply
//! here.

use opacus_zk::prelude::{Fp, PrimeField};
use opacus_zk::vote::{proposal_id, SeenSet};

use crate::gov::{register, verify_ballot, Choice, GovBallot, GovError};

// ---------------------------------------------------------------------------
// Proposal class (GIP-2 P-6)
// ---------------------------------------------------------------------------

/// The two decision classes of P-6 with their thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteClass {
    /// Fund decisions (the GIP-1 C-4 class): quorum 5%, approval 60%
    /// of YES+NO weight.
    Fund,
    /// Process transitions (GIP status changes): quorum 2%, simple
    /// majority of YES+NO weight.
    Process,
}

impl VoteClass {
    /// Wire / hash byte of the class.
    pub fn to_u8(self) -> u8 {
        match self {
            VoteClass::Fund => 0,
            VoteClass::Process => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(VoteClass::Fund),
            1 => Some(VoteClass::Process),
            _ => None,
        }
    }

    /// Quorum as a fraction of the emission denominator (P-6).
    pub fn quorum(self) -> (u64, u64) {
        match self {
            VoteClass::Fund => (5, 100),
            VoteClass::Process => (2, 100),
        }
    }
}

/// The declared voting proposal (GIP-2 R-5, P-3): the parameter set that
/// MUST be public before the window opens. `anchor` is the frontier root
/// at `h_open` (P-3: `H_snap = H_open`; re-snapshotting on dispute is NOT
/// planned - the declared anchor stands).
#[derive(Clone, Debug)]
pub struct DeclaredProposal {
    /// The GIP being voted on (R-4).
    pub gip: u32,
    /// The status transition tag (GIP-0 numbering).
    pub transition: u8,
    /// Vote-open height = snapshot height (P-3).
    pub h_open: u64,
    /// The declared snapshot anchor (frontier root at `h_open`).
    pub anchor: Fp,
    /// Fund or process decision (P-6).
    pub class: VoteClass,
}

impl DeclaredProposal {
    /// The public proposal identity every ballot must carry.
    pub fn proposal_id(&self) -> Fp {
        proposal_id(self.gip, self.transition, self.h_open, self.anchor)
    }
}

// ---------------------------------------------------------------------------
// Quorum denominator (GIP-2 P-5)
// ---------------------------------------------------------------------------

/// Emission schedule constants - MUST stay in sync with
/// `opacus_consensus::block::block_reward` (see the sync test cited in
/// the module docs).
pub const HALVING_INTERVAL: u64 = 210_000;
pub const INITIAL_REWARD: u64 = 10_000_000_000;

/// The public quorum denominator (P-5): `sum(block_reward(0..h))`, the
/// exclusive upper bound matching the GIP notation. Closed form over the
/// halving eras; mirrors the consensus schedule exactly.
pub fn emission_upto(h: u64) -> u64 {
    if h == 0 {
        return 0;
    }
    let last_era = (h - 1) / HALVING_INTERVAL;
    let mut total = 0u64;
    for era in 0..=last_era {
        let reward = INITIAL_REWARD >> era.min(60);
        if reward == 0 {
            break; // every later era contributes nothing either
        }
        let era_start = era * HALVING_INTERVAL;
        let era_end = era_start + HALVING_INTERVAL;
        let upto = h.min(era_end);
        total = total.saturating_add((upto - era_start) * reward);
    }
    total
}

// ---------------------------------------------------------------------------
// Per-ballot verdicts and the record
// ---------------------------------------------------------------------------

/// Why the engine rejected a ballot. Per-ballot rejection is
/// traceability, not a fatal error (GIP-2 3.2 step 4: rejects duplicates,
/// publishes the aggregate result WITH the trace).
#[derive(Clone, Debug)]
pub enum Rejection {
    /// The bytes did not parse as a canonical ballot, or the standalone
    /// verification failed (shape, dust floor, ZK proof, binding
    /// signature - the [`GovError`] carries the specific reason).
    Malformed(GovError),
    /// The ballot's gip/transition/h_open/proposal identity does not
    /// match the declared proposal.
    ProposalMismatch,
    /// The ballot anchors at a root other than the declared anchor
    /// (stale or foreign snapshot; P-3 fail-closed).
    AnchorMismatch,
    /// A vote serial of the ballot was already registered (R-3).
    DuplicateSerial,
}

/// The trace line of one archive entry (P-5 per-ballot traceability).
#[derive(Clone, Debug)]
pub struct BallotTrace {
    /// Position of the entry in the SUBMITTED archive (0-based).
    pub index: usize,
    /// The ballot sighash when the bytes parsed; `None` otherwise.
    pub sighash: Option<[u8; 32]>,
    /// Whether the ballot was counted.
    pub accepted: bool,
    /// The rejection reason when not accepted.
    pub rejection: Option<Rejection>,
}

/// The outcome of a recorded decision (P-6, fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Quorum met and approval threshold reached: the proposal carries.
    Accepted,
    /// Quorum met, approval threshold NOT reached: status quo persists.
    Rejected,
    /// Quorum not met: status quo persists (fail-closed governance).
    NoQuorum,
}

impl Outcome {
    pub fn to_u8(self) -> u8 {
        match self {
            Outcome::Accepted => 0,
            Outcome::Rejected => 1,
            Outcome::NoQuorum => 2,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Outcome::Accepted),
            1 => Some(Outcome::Rejected),
            2 => Some(Outcome::NoQuorum),
            _ => None,
        }
    }
}

/// The published aggregate result (the "minutes" artifact of GIP-2 3.2
/// step 5). `result_hash` commits to the declared parameters, the weight
/// totals, and the sorted sighashes of the accepted ballots; the trace
/// is published alongside but is NOT part of the hash.
#[derive(Clone, Debug)]
pub struct TallyRecord {
    pub gip: u32,
    pub transition: u8,
    pub h_open: u64,
    pub class: VoteClass,
    pub anchor: Fp,
    pub proposal: Fp,
    /// The P-5 denominator `emission_upto(h_open)`.
    pub denominator: u64,
    /// YES / NO / ABSTAIN weight sums over the accepted ballots.
    pub yes: u64,
    pub no: u64,
    pub abstain: u64,
    /// Accepted / rejected ballot counts.
    pub accepted: u64,
    pub rejected: u64,
    pub quorum_met: bool,
    pub outcome: Outcome,
    /// blake3 over the canonical decision inputs (see [`Self::hash_inputs`]).
    pub result_hash: [u8; 32],
    /// Per-ballot trace over the submitted archive, in submission order.
    pub trace: Vec<BallotTrace>,
}

/// Wire version of the record artifact.
pub const TALLY_RECORD_VERSION: u8 = 1;

/// The single fatal error of the engine: weight accumulation overflow.
/// Ballot weights are u64 and the emission denominator is ~4.2e15, so a
/// real archive cannot trigger this; hitting it means the archive (or
/// the schedule) is corrupt - fail-closed, no result is produced.
#[derive(Debug)]
pub enum TallyError {
    WeightOverflow,
}

impl std::fmt::Display for TallyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TallyError::WeightOverflow => write!(f, "ballot weight accumulation overflow"),
        }
    }
}

impl std::error::Error for TallyError {}

impl TallyRecord {
    /// The bytes `result_hash` commits to: the domain tag, the record
    /// version, the declared parameters, the totals, and the sorted
    /// sighashes of the accepted ballots.
    fn hash_inputs(&self, accepted_sighashes: &[[u8; 32]]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160 + 32 * accepted_sighashes.len());
        buf.extend_from_slice(b"OPACUS_GOV_TALLY_V1");
        buf.push(TALLY_RECORD_VERSION);
        buf.push(self.class.to_u8());
        buf.push(self.outcome.to_u8());
        buf.extend_from_slice(&self.gip.to_le_bytes());
        buf.push(self.transition);
        buf.extend_from_slice(&self.h_open.to_le_bytes());
        buf.extend_from_slice(self.anchor.to_repr().as_ref());
        buf.extend_from_slice(self.proposal.to_repr().as_ref());
        buf.extend_from_slice(&self.denominator.to_le_bytes());
        buf.extend_from_slice(&self.yes.to_le_bytes());
        buf.extend_from_slice(&self.no.to_le_bytes());
        buf.extend_from_slice(&self.abstain.to_le_bytes());
        buf.extend_from_slice(&(accepted_sighashes.len() as u64).to_le_bytes());
        for s in accepted_sighashes {
            buf.extend_from_slice(s);
        }
        buf
    }

    /// Canonical wire encoding (the publication format):
    /// `version u8 | class u8 | outcome u8 | gip le32 | transition u8 |
    /// h_open le64 | anchor 32 | proposal 32 | denominator le64 |
    /// yes le64 | no le64 | abstain le64 | accepted le64 | rejected le64 |
    /// quorum u8 | result_hash 32`. The trace is published separately.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 64 + 32);
        out.push(TALLY_RECORD_VERSION);
        out.push(self.class.to_u8());
        out.push(self.outcome.to_u8());
        out.extend_from_slice(&self.gip.to_le_bytes());
        out.push(self.transition);
        out.extend_from_slice(&self.h_open.to_le_bytes());
        out.extend_from_slice(self.anchor.to_repr().as_ref());
        out.extend_from_slice(self.proposal.to_repr().as_ref());
        out.extend_from_slice(&self.denominator.to_le_bytes());
        out.extend_from_slice(&self.yes.to_le_bytes());
        out.extend_from_slice(&self.no.to_le_bytes());
        out.extend_from_slice(&self.abstain.to_le_bytes());
        out.extend_from_slice(&self.accepted.to_le_bytes());
        out.extend_from_slice(&self.rejected.to_le_bytes());
        out.push(self.quorum_met as u8);
        out.extend_from_slice(&self.result_hash);
        out
    }

    /// Strict canonical parse: exact length, known class and outcome
    /// bytes. Verification of a PUBLISHED record is replay (P-5): the
    /// archive is re-tallied and the `result_hash` compared.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GovError> {
        // version u8 | class u8 | outcome u8 | gip le32 | transition u8
        // | h_open le64 | anchor 32 | proposal 32 | 6 x le64 | quorum u8
        // | result_hash 32.
        const LEN: usize = 3 + 4 + 1 + 8 + 64 + 48 + 1 + 32;
        if bytes.len() != LEN {
            return if bytes.len() < LEN {
                Err(GovError::Truncated)
            } else {
                Err(GovError::TrailingBytes)
            };
        }
        let mut cur = 0usize;
        let version = take(&mut cur, 1, bytes)?[0];
        if version != TALLY_RECORD_VERSION {
            return Err(GovError::Version(version));
        }
        let class = VoteClass::from_u8(take(&mut cur, 1, bytes)?[0]).ok_or(GovError::Canonical)?;
        let outcome = Outcome::from_u8(take(&mut cur, 1, bytes)?[0]).ok_or(GovError::Canonical)?;
        let gip = u32::from_le_bytes(take(&mut cur, 4, bytes)?.try_into().expect("4 bytes"));
        let transition = take(&mut cur, 1, bytes)?[0];
        let h_open = u64::from_le_bytes(take(&mut cur, 8, bytes)?.try_into().expect("8 bytes"));
        let anchor = Fp::from_repr(take(&mut cur, 32, bytes)?.try_into().expect("32 bytes"))
            .into_option()
            .ok_or(GovError::Canonical)?;
        let proposal = Fp::from_repr(take(&mut cur, 32, bytes)?.try_into().expect("32 bytes"))
            .into_option()
            .ok_or(GovError::Canonical)?;
        let denominator =
            u64::from_le_bytes(take(&mut cur, 8, bytes)?.try_into().expect("8 bytes"));
        let yes = u64::from_le_bytes(take(&mut cur, 8, bytes)?.try_into().expect("8 bytes"));
        let no = u64::from_le_bytes(take(&mut cur, 8, bytes)?.try_into().expect("8 bytes"));
        let abstain = u64::from_le_bytes(take(&mut cur, 8, bytes)?.try_into().expect("8 bytes"));
        let accepted = u64::from_le_bytes(take(&mut cur, 8, bytes)?.try_into().expect("8 bytes"));
        let rejected = u64::from_le_bytes(take(&mut cur, 8, bytes)?.try_into().expect("8 bytes"));
        let quorum_met = take(&mut cur, 1, bytes)?[0];
        if quorum_met > 1 {
            return Err(GovError::Canonical);
        }
        let mut result_hash = [0u8; 32];
        result_hash.copy_from_slice(take(&mut cur, 32, bytes)?);
        Ok(TallyRecord {
            gip,
            transition,
            h_open,
            class,
            anchor,
            proposal,
            denominator,
            yes,
            no,
            abstain,
            accepted,
            rejected,
            quorum_met: quorum_met == 1,
            outcome,
            result_hash,
            trace: Vec::new(),
        })
    }
}

/// Read the next `n` bytes at `*cur` (the gov.rs `rd` pattern).
fn take<'a>(cur: &mut usize, n: usize, bytes: &'a [u8]) -> Result<&'a [u8], GovError> {
    if *cur + n > bytes.len() {
        return Err(GovError::Truncated);
    }
    let s = &bytes[*cur..*cur + n];
    *cur += n;
    Ok(s)
}

// ---------------------------------------------------------------------------
// The decision rule (GIP-2 P-6, verbatim)
// ---------------------------------------------------------------------------

/// Pure decision function: `(quorum_met, outcome)` for the given totals.
/// Comparisons run in u128 so no intermediate can overflow. ABSTAIN
/// counts toward participation only.
pub fn decide(
    class: VoteClass,
    denominator: u64,
    yes: u64,
    no: u64,
    abstain: u64,
) -> (bool, Outcome) {
    let participation = yes as u128 + no as u128 + abstain as u128;
    // Degenerate denominator (h_open = 0): no supply exists to vote on -
    // fail-closed, no quorum.
    if denominator == 0 {
        return (false, Outcome::NoQuorum);
    }
    let (qn, qd) = class.quorum();
    let quorum_met = participation * qd as u128 >= denominator as u128 * qn as u128;
    if !quorum_met {
        return (false, Outcome::NoQuorum);
    }
    let yes_no = yes as u128 + no as u128;
    let approved = match class {
        // 60% of YES+NO weight; a zero YES+NO sum (all-ABSTAIN quorum)
        // approves nothing.
        VoteClass::Fund => yes_no > 0 && yes as u128 * 100 >= yes_no * 60,
        // Simple majority; a tie is rejected (fail-closed).
        VoteClass::Process => yes as u128 * 2 > yes_no,
    };
    (
        true,
        if approved {
            Outcome::Accepted
        } else {
            Outcome::Rejected
        },
    )
}

// ---------------------------------------------------------------------------
// The engine (GIP-2 3.2 step 4, P-5)
// ---------------------------------------------------------------------------

/// Deterministically tally the published ballot archive against the
/// declared proposal.
///
/// Processing order is canonical: entries are sorted by ballot bytes
/// (stable, so byte-equal copies keep submission order), which makes the
/// accepted set, the totals and the `result_hash` independent of the
/// archive arrival order - the replay guarantee of P-5. `DEPTH` is the
/// frontier depth the ballots were proven against (the circuit is
/// compiled per depth, exactly like the spend path).
pub fn tally<const DEPTH: usize, A: AsRef<[u8]>>(
    declared: &DeclaredProposal,
    archive: &[A],
) -> Result<TallyRecord, TallyError> {
    // Canonical processing order over (bytes, submission index).
    let mut order: Vec<(Vec<u8>, usize)> = archive
        .iter()
        .enumerate()
        .map(|(i, entry)| (entry.as_ref().to_vec(), i))
        .collect();
    order.sort_by(|a, b| a.0.cmp(&b.0));

    let mut seen = SeenSet::new();
    let mut trace = vec![
        BallotTrace {
            index: 0,
            sighash: None,
            accepted: false,
            rejection: None,
        };
        archive.len()
    ];
    let (mut yes, mut no, mut abstain) = (0u64, 0u64, 0u64);
    let mut accepted_sighashes: Vec<[u8; 32]> = Vec::new();
    let mut accepted_count = 0u64;
    let mut rejected_count = 0u64;

    for (bytes, orig_idx) in order {
        let verdict = process_ballot::<DEPTH>(declared, &bytes, &mut seen);
        match &verdict {
            Ok(sighash) => {
                // Parse again to read the public weight and choice; the
                // bytes just verified, so this cannot fail.
                let b = GovBallot::from_bytes(&bytes).expect("verified ballot reparse");
                let slot = match b.choice {
                    Choice::For => &mut yes,
                    Choice::Against => &mut no,
                    Choice::Abstain => &mut abstain,
                };
                *slot = slot.checked_add(b.v).ok_or(TallyError::WeightOverflow)?;
                accepted_sighashes.push(*sighash);
                accepted_count += 1;
                trace[orig_idx] = BallotTrace {
                    index: orig_idx,
                    sighash: Some(*sighash),
                    accepted: true,
                    rejection: None,
                };
            }
            Err(rejection) => {
                let sighash = GovBallot::from_bytes(&bytes).ok().map(|b| b.sighash());
                rejected_count += 1;
                trace[orig_idx] = BallotTrace {
                    index: orig_idx,
                    sighash,
                    accepted: false,
                    rejection: Some(rejection.clone()),
                };
            }
        }
    }

    let denominator = emission_upto(declared.h_open);
    let (quorum_met, outcome) = decide(declared.class, denominator, yes, no, abstain);
    let mut record = TallyRecord {
        gip: declared.gip,
        transition: declared.transition,
        h_open: declared.h_open,
        class: declared.class,
        anchor: declared.anchor,
        proposal: declared.proposal_id(),
        denominator,
        yes,
        no,
        abstain,
        accepted: accepted_count,
        rejected: rejected_count,
        quorum_met,
        outcome,
        result_hash: [0u8; 32],
        trace,
    };
    let hash = blake3::hash(&record.hash_inputs(&accepted_sighashes));
    record.result_hash = hash.into();
    Ok(record)
}

/// Verify one archive entry against the declared proposal and the
/// seen-set; `Ok(sighash)` when the ballot counts.
fn process_ballot<const DEPTH: usize>(
    declared: &DeclaredProposal,
    bytes: &[u8],
    seen: &mut SeenSet,
) -> Result<[u8; 32], Rejection> {
    // 1. Canonical parse.
    let b = GovBallot::from_bytes(bytes).map_err(Rejection::Malformed)?;
    // 2. The anchor gate FIRST (P-3 fail-closed - the declared anchor of
    //    the archived H_snap frontier stands): a stale or foreign
    //    snapshot is reported as such, before the proposal identity.
    if b.anchor != declared.anchor {
        return Err(Rejection::AnchorMismatch);
    }
    // 3. The ballot must vote on the DECLARED proposal.
    if b.gip != declared.gip
        || b.transition != declared.transition
        || b.h_open != declared.h_open
        || b.proposal != declared.proposal_id()
    {
        return Err(Rejection::ProposalMismatch);
    }
    // 4. Full standalone verification: shape, T_min dust floor, the ZK
    //    proof-of-balance over instances reconstructed from the fields,
    //    the binding signature. Milliseconds per ballot (P-5).
    verify_ballot::<DEPTH>(&b).map_err(Rejection::Malformed)?;
    // 5. One vote per serial (R-3, Stage A: the tally enforces it
    //    publicly, the same-note-same-proposal VS determinism makes a
    //    plain seen-set sufficient).
    register(seen, &b).map_err(|_| Rejection::DuplicateSerial)?;
    Ok(b.sighash())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gov::{build_ballot, T_MIN};
    use crate::tx_v4::WalletNoteV4;
    use crate::zk_spend::TreeState;
    use opacus_zk::prelude::PrimeField;

    /// Small test depth (the wallet test convention).
    const DEPTH: usize = 4;

    // -- Deterministic fixture -------------------------------------------

    fn fixed_bytes(x: u64) -> [u8; 32] {
        let repr: [u8; 32] = Fp::from(x).to_repr().as_ref().try_into().unwrap();
        repr
    }

    /// A note with fully deterministic field elements (unlike
    /// `WalletNoteV4::random`): same seed -> same note -> same VS ->
    /// same sighash. Proof blinding still differs run-to-run, which the
    /// golden-vector test exploits.
    fn fixed_note(seed: u64, value: u64) -> WalletNoteV4 {
        WalletNoteV4 {
            d: fixed_bytes(seed * 4 + 1),
            a: fixed_bytes(seed * 4 + 2),
            b: fixed_bytes(seed * 4 + 3),
            rho: fixed_bytes(seed * 4 + 4),
            value,
        }
    }

    struct Scenario {
        tree: TreeState,
        notes: Vec<WalletNoteV4>,
    }

    /// A frontier of 16 deterministic notes (DEPTH = 4 is full).
    fn scenario(values: &[u64; 16]) -> Scenario {
        let mut tree = TreeState::new(DEPTH);
        let notes: Vec<WalletNoteV4> = values
            .iter()
            .enumerate()
            .map(|(i, &v)| fixed_note(i as u64 + 1, v))
            .collect();
        for n in &notes {
            tree.append(n.tree_entry().unwrap());
        }
        Scenario { tree, notes }
    }

    fn build(sc: &Scenario, idx: usize, gip: u32, h_open: u64, choice: Choice) -> GovBallot {
        let note = &sc.notes[idx];
        build_ballot::<DEPTH>(&sc.tree, &[idx], &[note], gip, 0, h_open, choice)
            .expect("fixture ballot must build")
    }

    fn declared(anchor: Fp, h_open: u64, class: VoteClass) -> DeclaredProposal {
        DeclaredProposal {
            gip: 2,
            transition: 0,
            h_open,
            anchor,
            class,
        }
    }

    // -- Emission denominator golden values ------------------------------

    #[test]
    fn emission_upto_golden_values() {
        let era = HALVING_INTERVAL;
        let r = INITIAL_REWARD;
        assert_eq!(emission_upto(0), 0);
        assert_eq!(emission_upto(1), r);
        // First era sum: 210,000 blocks x 10 G atoms.
        assert_eq!(emission_upto(era), 2_100_000_000_000_000);
        assert_eq!(emission_upto(era - 1), 2_100_000_000_000_000 - r);
        // Two / three eras (the GIP-1 §9 window is 3 epochs = 630,000).
        assert_eq!(emission_upto(2 * era), 3_150_000_000_000_000);
        assert_eq!(emission_upto(3 * era), 3_675_000_000_000_000);
        // Monotone with the exact per-height step inside an era.
        for h in [1u64, 2, 999, 210_000, 210_001, 630_000] {
            assert!(emission_upto(h) > emission_upto(h - 1));
        }
        assert_eq!(
            emission_upto(630_001) - emission_upto(630_000),
            r >> 3,
            "era 3 reward is the 8x-halved step"
        );
        // Convergence: once the shifted reward hits zero, the sum stops
        // growing (era 34+ adds nothing).
        assert_eq!(emission_upto(34 * era), emission_upto(100 * era));
        // The step across a whole era e is exactly HALVING_INTERVAL
        // blocks at INITIAL_REWARD >> e.
        assert_eq!(emission_upto(2 * era) - emission_upto(era), era * (r >> 1));
    }

    // -- Decision matrix golden values (P-6, hand-computed) ---------------

    #[test]
    fn decision_matrix_golden() {
        const D: u64 = 4_200_000_000_000_000; // 4.2e15, the 34-era emission
        let q5 = D / 20; // 2.1e14, the 5% fund quorum
        let q2 = D / 50; // 8.4e13, the 2% process quorum

        // Fund, exact-boundary cases.
        assert_eq!(
            decide(VoteClass::Fund, D, q5, 0, 0),
            (true, Outcome::Accepted),
            "quorum exactly 5%, 100% YES"
        );
        assert_eq!(
            decide(VoteClass::Fund, D, q5 * 3 / 5, q5 * 2 / 5, 0),
            (true, Outcome::Accepted),
            "exactly 60% of YES+NO approves"
        );
        assert_eq!(
            decide(VoteClass::Fund, D, q5 * 3 / 5 - 1, q5 * 2 / 5 + 1, 0),
            (true, Outcome::Rejected),
            "just under 60% rejects"
        );
        assert_eq!(
            decide(VoteClass::Fund, D, q5 - 1, 0, 0),
            (false, Outcome::NoQuorum),
            "just under 5% participation: status quo"
        );
        assert_eq!(
            decide(VoteClass::Fund, D, 0, 0, q5),
            (true, Outcome::Rejected),
            "all-ABSTAIN quorum approves nothing"
        );

        // Process, exact-boundary cases.
        assert_eq!(
            decide(VoteClass::Process, D, q2, 0, 0),
            (true, Outcome::Accepted),
            "process quorum 2%, all YES"
        );
        assert_eq!(
            decide(VoteClass::Process, D, q2 / 2, q2 / 2, 0),
            (true, Outcome::Rejected),
            "an exact tie is rejected (fail-closed)"
        );
        assert_eq!(
            decide(VoteClass::Process, D, q2 / 2 + 1, q2 / 2 - 1, 0),
            (true, Outcome::Accepted),
            "one atom of YES surplus is a majority"
        );
        assert_eq!(
            decide(VoteClass::Process, D, 0, 0, q2 - 1),
            (false, Outcome::NoQuorum),
            "process quorum not met"
        );

        // Degenerate / fail-closed denominator.
        assert_eq!(
            decide(VoteClass::Fund, 0, u64::MAX, u64::MAX, 0),
            (false, Outcome::NoQuorum)
        );
        assert_eq!(
            decide(VoteClass::Process, 0, u64::MAX, 0, 0),
            (false, Outcome::NoQuorum)
        );
    }

    // -- Record wire ------------------------------------------------------

    #[test]
    fn record_wire_roundtrip() {
        // A minimal honest tally (one ballot) to obtain a real record.
        let mut values = [0u64; 16];
        values[0] = 600_000_000;
        let sc = scenario(&values);
        let d = declared(sc.tree.root(), 4, VoteClass::Process);
        let ballot = build(&sc, 0, 2, 4, Choice::For);
        let archive = vec![ballot.to_bytes()];
        let rec = tally::<DEPTH, _>(&d, &archive).expect("tally");

        let bytes = rec.to_bytes();
        let parsed = TallyRecord::from_bytes(&bytes).expect("canonical parse");
        assert_eq!(parsed.class, VoteClass::Process);
        assert_eq!(parsed.outcome, rec.outcome);
        assert_eq!(parsed.result_hash, rec.result_hash);
        assert_eq!(parsed.to_bytes(), bytes, "re-encode is identical");
        assert!(parsed.trace.is_empty(), "the wire carries no trace");

        // Strict framing: truncation and trailing bytes are rejected.
        assert!(matches!(
            TallyRecord::from_bytes(&bytes[..bytes.len() - 1]),
            Err(GovError::Truncated)
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            TallyRecord::from_bytes(&trailing),
            Err(GovError::TrailingBytes)
        ));
    }

    // -- Fund vote end-to-end with the full rejection trace ----------------

    #[test]
    fn fund_vote_accepted_with_full_trace() {
        let mut values = [0u64; 16];
        values[0] = 3_000_000_000; // FOR
        values[1] = 1_500_000_000; // AGAINST
        values[2] = 600_000_000; // ABSTAIN
        values[3] = 1_000_000_000; // cross-GIP ballot
        let sc = scenario(&values);

        let h_open = 2;
        let d = declared(sc.tree.root(), h_open, VoteClass::Fund);

        let for_ballot = build(&sc, 0, 2, h_open, Choice::For);
        let against_ballot = build(&sc, 1, 2, h_open, Choice::Against);
        let abstain_ballot = build(&sc, 2, 2, h_open, Choice::Abstain);
        let cross_gip = build(&sc, 3, 4, h_open, Choice::For); // wrong GIP
                                                               // A foreign-anchor ballot: a DIFFERENT frontier, same declared
                                                               // heights - the artifact is self-consistent, the declared anchor
                                                               // gate must reject it (P-3 fail-closed).
        let mut foreign_values = [0u64; 16];
        foreign_values[0] = 2_000_000;
        let foreign_sc = scenario(&foreign_values);
        let foreign_ballot = build(&foreign_sc, 0, 2, h_open, Choice::For);
        assert_ne!(foreign_ballot.anchor, d.anchor);
        // A dust ballot: hand-built below T_MIN - the dust check fires
        // before the proof check (verify_ballot order), so no proof is
        // needed to exercise the reason.
        let dust = GovBallot {
            version: crate::gov::BALLOT_VERSION,
            gip: 2,
            transition: 0,
            h_open,
            choice: Choice::For,
            anchor: d.anchor,
            proposal: d.proposal_id(),
            v: T_MIN - 1,
            vs: vec![Fp::from(1u64)],
            bvk: [0u8; 32],
            sig: [0u8; 64],
            proof: Vec::new(),
        };

        let for_bytes = for_ballot.to_bytes();
        let archive = vec![
            for_bytes.clone(),
            against_ballot.to_bytes(),
            abstain_ballot.to_bytes(),
            for_bytes.clone(), // byte-equal duplicate: DuplicateSerial
            cross_gip.to_bytes(),
            foreign_ballot.to_bytes(),
            dust.to_bytes(),
        ];
        let rec = tally::<DEPTH, _>(&d, &archive).expect("tally");

        // Totals (P-6: ABSTAIN counts toward participation only).
        assert_eq!(rec.yes, 3_000_000_000);
        assert_eq!(rec.no, 1_500_000_000);
        assert_eq!(rec.abstain, 600_000_000);
        assert_eq!(rec.accepted, 3);
        assert_eq!(rec.rejected, 4);
        // Denominator: 2 blocks x 10 G atoms; quorum 5% = 1e9.
        assert_eq!(rec.denominator, 20_000_000_000);
        assert!(rec.quorum_met);
        // 3e9 / (3e9 + 1.5e9) = 66.7% >= 60%.
        assert_eq!(rec.outcome, Outcome::Accepted);

        // Trace: every archive entry has its verdict, in submission
        // order (trace is indexed by SUBMISSION position).
        assert_eq!(rec.trace.len(), 7);
        assert!(rec.trace[0].accepted);
        assert!(rec.trace[1].accepted);
        assert!(rec.trace[2].accepted);
        assert!(matches!(
            rec.trace[3].rejection,
            Some(Rejection::DuplicateSerial)
        ));
        assert!(matches!(
            rec.trace[4].rejection,
            Some(Rejection::ProposalMismatch)
        ));
        assert!(matches!(
            rec.trace[5].rejection,
            Some(Rejection::AnchorMismatch)
        ));
        assert!(matches!(
            rec.trace[6].rejection,
            Some(Rejection::Malformed(GovError::Dust { .. }))
        ));

        // Replay determinism: SHUFFLE the archive - the record is
        // identical except the trace indices (which follow submission
        // order by design).
        let mut shuffled = archive.clone();
        shuffled.reverse();
        let replay = tally::<DEPTH, _>(&d, &shuffled).expect("replay");
        assert_eq!(replay.result_hash, rec.result_hash);
        assert_eq!(replay.yes, rec.yes);
        assert_eq!(replay.no, rec.no);
        assert_eq!(replay.abstain, rec.abstain);
        assert_eq!(replay.accepted, rec.accepted);
        assert_eq!(replay.rejected, rec.rejected);
        assert_eq!(replay.outcome, rec.outcome);
        assert_ne!(
            format!("{:?}", replay.trace),
            format!("{:?}", rec.trace),
            "trace follows submission order"
        );
        // ...and the shuffled trace carries the same verdict multiset.
        let mut a: Vec<(bool, Option<Rejection>)> = rec
            .trace
            .iter()
            .map(|t| (t.accepted, t.rejection.clone()))
            .collect();
        let mut b: Vec<(bool, Option<Rejection>)> = replay
            .trace
            .iter()
            .map(|t| (t.accepted, t.rejection.clone()))
            .collect();
        a.sort_by_key(|x| format!("{x:?}"));
        b.sort_by_key(|x| format!("{x:?}"));
        assert_eq!(
            format!("{a:?}"),
            format!("{b:?}"),
            "verdict multisets must match"
        );
    }

    // -- Fund vote rejected on approval, despite quorum --------------------

    #[test]
    fn fund_vote_rejected_below_approval() {
        let mut values = [0u64; 16];
        values[4] = 1_500_000_000; // FOR
        values[5] = 3_000_000_000; // AGAINST
        let sc = scenario(&values);
        let h_open = 3;
        let d = declared(sc.tree.root(), h_open, VoteClass::Fund);
        let archive = vec![
            build(&sc, 4, 2, h_open, Choice::For).to_bytes(),
            build(&sc, 5, 2, h_open, Choice::Against).to_bytes(),
        ];
        let rec = tally::<DEPTH, _>(&d, &archive).expect("tally");
        assert_eq!(rec.denominator, 30_000_000_000);
        assert!(rec.quorum_met, "4.5e9 >= 5% of 3e10 = 1.5e9");
        assert_eq!(rec.yes, 1_500_000_000);
        assert_eq!(rec.no, 3_000_000_000);
        assert_eq!(rec.outcome, Outcome::Rejected, "33% of YES+NO < 60%");
        assert_ne!(rec.result_hash, [0u8; 32]);
    }

    // -- Fund vote without quorum: status quo ------------------------------

    #[test]
    fn fund_vote_no_quorum() {
        let mut values = [0u64; 16];
        values[6] = 600_000_000; // ABSTAIN only
        let sc = scenario(&values);
        let h_open = 4;
        let d = declared(sc.tree.root(), h_open, VoteClass::Fund);
        let archive = vec![build(&sc, 6, 2, h_open, Choice::Abstain).to_bytes()];
        let rec = tally::<DEPTH, _>(&d, &archive).expect("tally");
        assert_eq!(rec.denominator, 40_000_000_000);
        // 600e6 < 5% of 4e10 = 2e9.
        assert!(!rec.quorum_met);
        assert_eq!(rec.outcome, Outcome::NoQuorum);
        assert_eq!(
            rec.accepted, 1,
            "the ballot counted, the proposal did not carry"
        );
    }

    // -- Process votes: simple majority ------------------------------------

    #[test]
    fn process_majority_rules() {
        let mut values = [0u64; 16];
        values[7] = 1_000_000_000; // FOR (D)
        values[8] = 1_900_000_000; // AGAINST (D)
        values[9] = 3_000_000_000; // FOR (E)
        values[10] = 1_000_000_000; // AGAINST (E)
        let sc = scenario(&values);

        // D: quorum met (2.9e9 >= 2% of 5e10 = 1e9), but the majority is
        // AGAINST -> Rejected.
        let d = declared(sc.tree.root(), 5, VoteClass::Process);
        let rec_d = tally::<DEPTH, _>(
            &d,
            &[
                build(&sc, 7, 2, 5, Choice::For).to_bytes(),
                build(&sc, 8, 2, 5, Choice::Against).to_bytes(),
            ],
        )
        .expect("tally D");
        assert!(rec_d.quorum_met);
        assert_eq!(rec_d.outcome, Outcome::Rejected);

        // E: a plain majority of YES+NO carries the process vote.
        let e = declared(sc.tree.root(), 6, VoteClass::Process);
        let rec_e = tally::<DEPTH, _>(
            &e,
            &[
                build(&sc, 9, 2, 6, Choice::For).to_bytes(),
                build(&sc, 10, 2, 6, Choice::Against).to_bytes(),
            ],
        )
        .expect("tally E");
        assert!(rec_e.quorum_met);
        assert_eq!(rec_e.outcome, Outcome::Accepted);

        // The SAME archive under the FUND class: quorum 5% of 6e10 = 3e9
        // is met (4e9 participation) and 75% of YES+NO >= 60%, so it
        // carries too - but the class byte is a hash input, so the
        // records are distinct.
        let e_fund = DeclaredProposal {
            class: VoteClass::Fund,
            ..declared(sc.tree.root(), 6, VoteClass::Process)
        };
        let rec_fund = tally::<DEPTH, _>(
            &e_fund,
            &[
                build(&sc, 9, 2, 6, Choice::For).to_bytes(),
                build(&sc, 10, 2, 6, Choice::Against).to_bytes(),
            ],
        )
        .expect("tally E as fund");
        assert!(rec_fund.quorum_met);
        assert_eq!(rec_fund.outcome, Outcome::Accepted);
        assert_ne!(
            rec_fund.result_hash, rec_e.result_hash,
            "class is a hash input"
        );
    }

    // -- Golden-vector property: blinding and order independence -----------

    #[test]
    fn golden_vector_result_hash_is_replay_stable() {
        // Two INDEPENDENT builds of the same logical archive: the halo2
        // blinding is fresh each time, so the proof bytes differ - but
        // the sighashes and therefore the result hash MUST be identical
        // (this is what makes the record a golden vector).
        let run = || {
            let mut values = [0u64; 16];
            values[11] = 2_000_000_000; // FOR
            values[12] = 1_000_000_000; // AGAINST
            let sc = scenario(&values);
            let h_open = 7;
            let d = declared(sc.tree.root(), h_open, VoteClass::Fund);
            let archive = vec![
                build(&sc, 11, 2, h_open, Choice::For).to_bytes(),
                build(&sc, 12, 2, h_open, Choice::Against).to_bytes(),
            ];
            tally::<DEPTH, _>(&d, &archive).expect("tally").result_hash
        };
        let h1 = run();
        let h2 = run();
        assert_ne!(h1, [0u8; 32]);
        assert_eq!(h1, h2, "proof blinding must not affect the result hash");

        // Interleaving with a foreign entry does not move the accepted
        // set: the same two ballots plus a same-proposal dust entry
        // produce the same accepted sighashes.
        let mut values = [0u64; 16];
        values[11] = 2_000_000_000;
        values[12] = 1_000_000_000;
        let sc = scenario(&values);
        let h_open = 7;
        let d = declared(sc.tree.root(), h_open, VoteClass::Fund);
        let dust = GovBallot {
            version: crate::gov::BALLOT_VERSION,
            gip: 2,
            transition: 0,
            h_open,
            choice: Choice::For,
            anchor: d.anchor,
            proposal: d.proposal_id(),
            v: 0,
            vs: vec![Fp::from(9u64)],
            bvk: [0u8; 32],
            sig: [0u8; 64],
            proof: Vec::new(),
        };
        let rec = tally::<DEPTH, _>(
            &d,
            &[
                dust.to_bytes(),
                build(&sc, 11, 2, h_open, Choice::For).to_bytes(),
                build(&sc, 12, 2, h_open, Choice::Against).to_bytes(),
            ],
        )
        .expect("tally");
        assert_eq!(rec.accepted, 2);
        assert_eq!(rec.rejected, 1);
        assert_eq!(rec.result_hash, h1, "rejected entries are not hash inputs");
    }
}
