//! GIP-2 WP-1: the Stage A governance ballot builder in opacus-wallet.
//!
//! Additive module: nothing in the existing wallet files changes.
//!
//! - [`GovBallot`] is the off-chain ballot artifact of GIP-2 Stage A: one
//!   ZK proof-of-balance ([`opacus_zk::vote::BallotCircuit`]) plus the
//!   binding signature over the ballot bytes (GIP-N, transition, choice,
//!   H_open, anchor, proposal, V, VS list).
//! - [`build_ballot`] is the build pipeline: every note must already be a
//!   leaf of the local frontier, every path must recompute to the anchor
//!   BEFORE any proving work (the wallet is the first validator of its own
//!   ballots, the [`crate::tx_v4`] pattern), the dust floor `T_MIN`
//!   applies to the whole ballot (GIP-2 P-2), and the proof is verified
//!   before the ballot is returned.
//! - [`verify_ballot`] reconstructs the normative proof instances from the
//!   ballot fields alone; [`verify_ballot_against_tree`] additionally
//!   pins the ballot's anchor to a local frontier (the node-side
//!   freshness gate; the full H_snap replay is WP-2).
//! - [`SeenSet`] (re-exported) is the tally-side duplicate-VS primitive:
//!   the same note voting twice on the same proposal derives the SAME
//!   vote serial (R-3), so a plain seen-set rejects the duplicate.
//!
//! Ballot weight `V` is public in Stage A (GIP-2 P-1, exact weighted
//! voting); the privacy claim covers note identities, owners and
//! cross-proposal linkage - the derived ballot verification key enters
//! the proposal, so ballots of the same voter on different proposals do
//! not link.

use opacus_zk::merkle;
use opacus_zk::prelude::{Fp, PrimeField};
use opacus_zk::spend::{sign_bind, verify_bind};
use opacus_zk::vote::{
    ballot_instances_sized, ballot_key, ballot_vk, ballot_vk_bytes, ballot_vk_from_bytes,
    proposal_id, vote_serial, BallotHeader, BallotNote, BallotWitness, MAX_BALLOT_NOTES,
};
use opacus_zk::vote::{prove_ballot_sized, verify_ballot_sized, SeenSet};

use crate::tx_v4::WalletNoteV4;
use crate::zk_spend::TreeState;

/// Dust floor per ballot (GIP-2 P-2): `T_min = 10^6` atomic units. The
/// real spam barrier is the proving cost; this only keeps zero-value
/// fragment noise out of the archive.
pub const T_MIN: u64 = 1_000_000;

/// Wire version of the ballot artifact.
pub const BALLOT_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Choice
// ---------------------------------------------------------------------------

/// A vote on a GIP status transition (GIP-2 R-4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    For,
    Against,
    Abstain,
}

impl Choice {
    pub fn to_u8(self) -> u8 {
        match self {
            Choice::For => 0,
            Choice::Against => 1,
            Choice::Abstain => 2,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Choice::For),
            1 => Some(Choice::Against),
            2 => Some(Choice::Abstain),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the ballot pipeline.
#[derive(Clone, Debug)]
pub enum GovError {
    /// Ballot shape violation (note count, index/notes mismatch).
    Topology(String),
    /// Ballot weight below the dust floor (GIP-2 P-2).
    Dust { v: u64, t_min: u64 },
    /// Stored note bytes are not valid field elements.
    CorruptNote,
    /// The note's tree entry is not the leaf at the given index.
    UnknownLeaf,
    /// A path does not recompute to the anchor (stale or foreign tree).
    RootMismatch,
    /// The proposal identity does not match the ballot fields.
    ProposalMismatch,
    /// Wire version is not [`BALLOT_VERSION`].
    Version(u8),
    /// Unknown choice byte.
    Choice(u8),
    /// A field encoding is not canonical.
    Canonical,
    /// The byte stream ended mid-field.
    Truncated,
    /// Extra bytes after the complete ballot.
    TrailingBytes,
    /// Halo2 prove/verify failure.
    Proof(String),
    /// Binding signature failed under the published bvk.
    Balance,
    /// The serials of this ballot were already registered (R-3).
    DuplicateVote,
}

impl std::fmt::Display for GovError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GovError::Topology(m) => write!(f, "ballot topology violation: {m}"),
            GovError::Dust { v, t_min } => write!(f, "ballot weight {v} below T_min {t_min}"),
            GovError::CorruptNote => write!(f, "stored note bytes are corrupt"),
            GovError::UnknownLeaf => write!(f, "note entry not found at the given leaf index"),
            GovError::RootMismatch => write!(f, "ballot anchor does not match the frontier"),
            GovError::ProposalMismatch => write!(f, "proposal identity mismatch"),
            GovError::Version(v) => write!(f, "unsupported ballot version: {v}"),
            GovError::Choice(c) => write!(f, "unknown choice byte: {c}"),
            GovError::Canonical => write!(f, "non-canonical field encoding"),
            GovError::Truncated => write!(f, "ballot bytes truncated mid-field"),
            GovError::TrailingBytes => write!(f, "trailing bytes after ballot"),
            GovError::Proof(e) => write!(f, "zk proof failure: {e}"),
            GovError::Balance => write!(f, "binding signature check failed"),
            GovError::DuplicateVote => write!(f, "duplicate vote serial (R-3)"),
        }
    }
}

impl std::error::Error for GovError {}

// ---------------------------------------------------------------------------
// GovBallot
// ---------------------------------------------------------------------------

/// The Stage A ballot artifact (GIP-2 3.2): the fields every verifier
/// needs, the derived proposal identity, the published verification key
/// of the binding signature, and the single stacked ZK proof.
#[derive(Clone, Debug)]
pub struct GovBallot {
    /// Wire version ([`BALLOT_VERSION`]).
    pub version: u8,
    /// The GIP being voted on (GIP-2 R-4).
    pub gip: u32,
    /// The status transition tag (GIP-0 numbering; proposal-level detail).
    pub transition: u8,
    /// Vote-open height: the anchor is the frontier root AT `h_open`
    /// (GIP-2 P-3: H_snap = H_open).
    pub h_open: u64,
    /// FOR / AGAINST / ABSTAIN.
    pub choice: Choice,
    /// The snapshot anchor root.
    pub anchor: Fp,
    /// The public proposal identity ([`opacus_zk::vote::proposal_id`]).
    pub proposal: Fp,
    /// Ballot weight V = sum of the voted note values (public in Stage A).
    pub v: u64,
    /// One vote serial per voted note, in ballot order.
    pub vs: Vec<Fp>,
    /// Compressed verification key of the binding signature.
    pub bvk: [u8; 32],
    /// Binding signature over the ballot sighash.
    pub sig: [u8; 64],
    /// The halo2 ballot proof (opaque bytes).
    pub proof: Vec<u8>,
}

impl GovBallot {
    /// The voted decision fields (the sighash binding set).
    pub fn header(&self) -> BallotHeader {
        BallotHeader {
            gip: self.gip,
            transition: self.transition,
            choice: self.choice.to_u8(),
            h_open: self.h_open,
            anchor: self.anchor,
            proposal: self.proposal,
            v: self.v,
        }
    }

    /// The ballot sighash (what [`Self::sig`] commits to).
    pub fn sighash(&self) -> [u8; 32] {
        opacus_zk::vote::ballot_sighash(&self.header(), &self.vs)
    }
}

// ---------------------------------------------------------------------------
// Build pipeline [GIP-2 3.2 step 2, P-2]
// ---------------------------------------------------------------------------

/// Build and prove one ballot from `notes` (with their leaf positions in
/// the local frontier `tree`).
///
/// The ballot anchors at the tree's CURRENT root (GIP-2 P-3: the proposal
/// fixes `H_snap = H_open` before the window opens; the caller is
/// responsible for calling this at the open height). Every note must sit
/// at the given leaf index, every path must recompute to the anchor
/// before proving, and the dust floor applies to the whole ballot.
pub fn build_ballot<const DEPTH: usize>(
    tree: &TreeState,
    indices: &[usize],
    notes: &[&WalletNoteV4],
    gip: u32,
    transition: u8,
    h_open: u64,
    choice: Choice,
) -> Result<GovBallot, GovError> {
    if notes.is_empty() || notes.len() > MAX_BALLOT_NOTES {
        return Err(GovError::Topology(format!(
            "a ballot carries 1..={MAX_BALLOT_NOTES} notes, got {}",
            notes.len()
        )));
    }
    if indices.len() != notes.len() {
        return Err(GovError::Topology(
            "indices and notes must have the same length".to_string(),
        ));
    }

    let anchor = tree.root();
    let proposal = proposal_id(gip, transition, h_open, anchor);

    let mut wnotes = Vec::with_capacity(notes.len());
    let mut vs = Vec::with_capacity(notes.len());
    let mut shares: Vec<(Fp, Fp)> = Vec::with_capacity(notes.len());
    let mut v_total: u64 = 0;

    for (note, &idx) in notes.iter().zip(indices.iter()) {
        let (d, a, b, rho) = note.parts().ok_or(GovError::CorruptNote)?;
        let entry = note.tree_entry().ok_or(GovError::CorruptNote)?;
        if tree.leaf(idx) != Some(entry) {
            return Err(GovError::UnknownLeaf);
        }
        let path = tree.auth_path(idx).ok_or(GovError::UnknownLeaf)?;
        if merkle::recompute_root(entry, &path) != anchor {
            return Err(GovError::RootMismatch);
        }
        wnotes.push(BallotNote {
            d,
            a,
            b,
            rho,
            v: note.value,
            path,
        });
        vs.push(vote_serial(a, b, rho, proposal));
        shares.push((a, b));
        v_total = v_total
            .checked_add(note.value)
            .ok_or_else(|| GovError::Topology("ballot weight overflow".to_string()))?;
    }
    if v_total < T_MIN {
        return Err(GovError::Dust {
            v: v_total,
            t_min: T_MIN,
        });
    }

    let bsk = ballot_key(&shares, proposal);
    let bvk_point = ballot_vk(&shares, proposal);
    let bvk = ballot_vk_bytes(&shares, proposal);

    let mut ballot = GovBallot {
        version: BALLOT_VERSION,
        gip,
        transition,
        h_open,
        choice,
        anchor,
        proposal,
        v: v_total,
        vs,
        bvk,
        sig: [0u8; 64],
        proof: Vec::new(),
    };
    let sighash = ballot.sighash();
    ballot.sig = sign_bind(&sighash, bsk, &bvk_point);

    let k = wnotes.len();
    let instances = instances_k(anchor, proposal, v_total, &ballot.vs, k);
    let witness = BallotWitness { notes: wnotes };
    ballot.proof = prove_k::<DEPTH>(&witness, &instances, k)?;

    // The wallet is the first validator of its own ballots [S4 10
    // pattern]: the fresh ballot must pass the full verification loop
    // before any state can be considered committed.
    verify_ballot::<DEPTH>(&ballot)?;
    Ok(ballot)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Full standalone verification of a ballot artifact: shape checks, the
/// proposal identity, the ZK proof against instances reconstructed from
/// the fields alone, and the binding signature.
pub fn verify_ballot<const DEPTH: usize>(b: &GovBallot) -> Result<(), GovError> {
    if b.version != BALLOT_VERSION {
        return Err(GovError::Version(b.version));
    }
    let k = b.vs.len();
    if k == 0 || k > MAX_BALLOT_NOTES {
        return Err(GovError::Topology(format!(
            "a ballot carries 1..={MAX_BALLOT_NOTES} notes, got {k}"
        )));
    }
    if b.v < T_MIN {
        return Err(GovError::Dust {
            v: b.v,
            t_min: T_MIN,
        });
    }
    if b.proposal != proposal_id(b.gip, b.transition, b.h_open, b.anchor) {
        return Err(GovError::ProposalMismatch);
    }
    let instances = instances_k(b.anchor, b.proposal, b.v, &b.vs, k);
    zk_verify_k::<DEPTH>(&b.proof, &instances, k)?;

    let bvk = ballot_vk_from_bytes(&b.bvk).ok_or(GovError::Canonical)?;
    if !verify_bind(&b.sighash(), &bvk, &b.sig) {
        return Err(GovError::Balance);
    }
    Ok(())
}

/// Node-side freshness gate: full [`verify_ballot`] plus the requirement
/// that the ballot's anchor IS the current local frontier root. A ballot
/// minted against an older (stale) or unrelated (foreign) tree state
/// fails here. Stage A note: the declared proposal anchor is pinned at
/// H_open; the authoritative replay against the archived H_snap frontier
/// is the tally engine's job (WP-2).
pub fn verify_ballot_against_tree<const DEPTH: usize>(
    b: &GovBallot,
    tree: &TreeState,
) -> Result<(), GovError> {
    if b.anchor != tree.root() {
        return Err(GovError::RootMismatch);
    }
    verify_ballot::<DEPTH>(b)
}

/// Tally-side duplicate-VS registration (GIP-2 R-3, Stage A): every
/// serial of the ballot must be fresh.
pub fn register(seen: &mut SeenSet, b: &GovBallot) -> Result<(), GovError> {
    for vs in &b.vs {
        if !seen.insert(*vs) {
            return Err(GovError::DuplicateVote);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-K dispatch (the circuit is compiled per ballot size)
// ---------------------------------------------------------------------------

fn instances_k(anchor: Fp, proposal: Fp, v: u64, vs: &[Fp], _k: usize) -> Vec<Fp> {
    ballot_instances_sized(anchor, proposal, v, vs)
}

fn prove_k<const DEPTH: usize>(
    witness: &BallotWitness,
    instances: &[Fp],
    _k: usize,
) -> Result<Vec<u8>, GovError> {
    prove_ballot_sized::<DEPTH>(witness, instances).map_err(|e| GovError::Proof(e.to_string()))
}

fn zk_verify_k<const DEPTH: usize>(
    proof: &[u8],
    instances: &[Fp],
    _k: usize,
) -> Result<(), GovError> {
    verify_ballot_sized::<DEPTH>(proof, instances).map_err(|e| GovError::Proof(e.to_string()))
}

// ---------------------------------------------------------------------------
// Wire format (canonical, strict)
// ---------------------------------------------------------------------------

fn rd<'a>(cur: &mut usize, n: usize, bytes: &'a [u8]) -> Result<&'a [u8], GovError> {
    if *cur + n > bytes.len() {
        return Err(GovError::Truncated);
    }
    let s = &bytes[*cur..*cur + n];
    *cur += n;
    Ok(s)
}

fn rd32(cur: &mut usize, bytes: &[u8]) -> Result<Fp, GovError> {
    let b = rd(cur, 32, bytes)?;
    let mut f = [0u8; 32];
    f.copy_from_slice(b);
    Fp::from_repr(f).into_option().ok_or(GovError::Canonical)
}

impl GovBallot {
    /// Canonical wire encoding:
    /// `version u8 | gip le32 | transition u8 | h_open le64 | choice u8 |
    /// anchor 32 | proposal 32 | v le64 | k u8 | VS_k x 32 | bvk 32 |
    /// sig 64 | le32(len) | proof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 32 * self.vs.len() + 96 + self.proof.len());
        out.push(self.version);
        out.extend_from_slice(&self.gip.to_le_bytes());
        out.push(self.transition);
        out.extend_from_slice(&self.h_open.to_le_bytes());
        out.push(self.choice.to_u8());
        out.extend_from_slice(self.anchor.to_repr().as_ref());
        out.extend_from_slice(self.proposal.to_repr().as_ref());
        out.extend_from_slice(&self.v.to_le_bytes());
        out.push(self.vs.len() as u8);
        for vs in &self.vs {
            out.extend_from_slice(vs.to_repr().as_ref());
        }
        out.extend_from_slice(&self.bvk);
        out.extend_from_slice(&self.sig);
        out.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof);
        out
    }

    /// Strict canonical parse: bounds, canonical field encodings, no
    /// trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GovError> {
        let mut cur = 0usize;
        let version = *rd(&mut cur, 1, bytes)?.first().ok_or(GovError::Truncated)?;
        if version != BALLOT_VERSION {
            return Err(GovError::Version(version));
        }
        let gip = u32::from_le_bytes(rd(&mut cur, 4, bytes)?.try_into().unwrap());
        let transition = *rd(&mut cur, 1, bytes)?.first().unwrap();
        let h_open = u64::from_le_bytes(rd(&mut cur, 8, bytes)?.try_into().unwrap());
        let choice = Choice::from_u8(*rd(&mut cur, 1, bytes)?.first().unwrap())
            .ok_or(GovError::Choice(bytes[cur - 1]))?;
        let anchor = rd32(&mut cur, bytes)?;
        let proposal = rd32(&mut cur, bytes)?;
        let v = u64::from_le_bytes(rd(&mut cur, 8, bytes)?.try_into().unwrap());
        let k = *rd(&mut cur, 1, bytes)?.first().unwrap() as usize;
        if k == 0 || k > MAX_BALLOT_NOTES {
            return Err(GovError::Topology(format!(
                "a ballot carries 1..={MAX_BALLOT_NOTES} notes, got {k}"
            )));
        }
        let mut vs = Vec::with_capacity(k);
        for _ in 0..k {
            vs.push(rd32(&mut cur, bytes)?);
        }
        let mut bvk = [0u8; 32];
        bvk.copy_from_slice(rd(&mut cur, 32, bytes)?);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(rd(&mut cur, 64, bytes)?);
        let plen = u32::from_le_bytes(rd(&mut cur, 4, bytes)?.try_into().unwrap()) as usize;
        let proof = rd(&mut cur, plen, bytes)?.to_vec();
        if cur != bytes.len() {
            return Err(GovError::TrailingBytes);
        }
        Ok(GovBallot {
            version,
            gip,
            transition,
            h_open,
            choice,
            anchor,
            proposal,
            v,
            vs,
            bvk,
            sig,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_v4::WalletNoteV4;
    use opacus_zk::vote::SeenSet;

    /// Small test depth (the wallet test convention; the circuit is
    /// generic over DEPTH exactly like the spend circuit).
    const DEPTH: usize = 4;

    struct BallotFixture {
        tree: TreeState,
        indices: Vec<usize>,
        notes: Vec<WalletNoteV4>,
        gip: u32,
        h_open: u64,
    }

    /// A frontier of `count` notes; the ballot votes GIP-2 acceptance.
    fn fixture(count: usize, values: &[u64]) -> BallotFixture {
        let mut tree = TreeState::new(DEPTH);
        let mut notes = Vec::with_capacity(count);
        for i in 0..count {
            let v = values.get(i).copied().unwrap_or(1_000_000);
            let n = WalletNoteV4::random(v);
            let entry = n.tree_entry().expect("test note entry");
            tree.append(entry);
            notes.push(n);
        }
        BallotFixture {
            tree,
            indices: (0..count).collect(),
            notes,
            gip: 2,
            h_open: 100,
        }
    }

    #[test]
    fn honest_ballot_loop() {
        let f = fixture(3, &[2_500_000, 1_500_000, 1_000_000]);
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        let ballot =
            build_ballot::<DEPTH>(&f.tree, &f.indices, &refs, f.gip, 0, f.h_open, Choice::For)
                .expect("honest ballot must build");

        // Field sanity: the anchor is the frontier root, the proposal
        // identity derives from the ballot fields, V is the exact sum.
        assert_eq!(ballot.anchor, f.tree.root());
        assert_eq!(
            ballot.proposal,
            proposal_id(ballot.gip, ballot.transition, ballot.h_open, ballot.anchor)
        );
        assert_eq!(ballot.v, 5_000_000);
        assert_eq!(ballot.vs.len(), 3);

        // The full standalone verification loop.
        verify_ballot::<DEPTH>(&ballot).expect("honest ballot must verify");

        // The node-side freshness gate against the same tree.
        verify_ballot_against_tree::<DEPTH>(&ballot, &f.tree)
            .expect("fresh ballot must pass the local gate");

        // Tally registration accepts a fresh ballot.
        let mut seen = SeenSet::new();
        register(&mut seen, &ballot).expect("fresh ballot registers");
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn duplicate_vs_rejected() {
        let f = fixture(2, &[2_000_000, 1_500_000]);
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        let for_ballot =
            build_ballot::<DEPTH>(&f.tree, &f.indices, &refs, f.gip, 0, f.h_open, Choice::For)
                .expect("first ballot");
        // The SAME notes voting AGAINST on the SAME proposal derive the
        // SAME serials (R-3 determinism) - flipping the choice does not
        // create a second vote.
        let against_ballot = build_ballot::<DEPTH>(
            &f.tree,
            &f.indices,
            &refs,
            f.gip,
            0,
            f.h_open,
            Choice::Against,
        )
        .expect("second ballot builds (the proof is valid)");
        assert_eq!(
            for_ballot.vs, against_ballot.vs,
            "VS must be proposal-bound"
        );

        let mut seen = SeenSet::new();
        register(&mut seen, &for_ballot).expect("first registration");
        let err = register(&mut seen, &against_ballot).unwrap_err();
        assert!(matches!(err, GovError::DuplicateVote));
    }

    #[test]
    fn foreign_anchor_rejected() {
        let f = fixture(3, &[2_000_000, 1_500_000, 1_000_000]);
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        let ballot =
            build_ballot::<DEPTH>(&f.tree, &f.indices, &refs, f.gip, 0, f.h_open, Choice::For)
                .expect("ballot");

        // A DIFFERENT tree (an unrelated frontier state): the ballot's
        // anchor is not this tree's root.
        let foreign = fixture(2, &[3_000_000, 2_000_000]);
        let err = verify_ballot_against_tree::<DEPTH>(&ballot, &foreign.tree).unwrap_err();
        assert!(matches!(err, GovError::RootMismatch));
        // The standalone verification still passes (the artifact is
        // self-consistent) - the anchor pinning is the tree gate's job.
        verify_ballot::<DEPTH>(&ballot).expect("self-consistent artifact");
    }

    #[test]
    fn stale_snapshot_rejected() {
        let f = fixture(3, &[2_000_000, 1_500_000, 1_000_000]);
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        let ballot =
            build_ballot::<DEPTH>(&f.tree, &f.indices, &refs, f.gip, 0, f.h_open, Choice::For)
                .expect("ballot at the open height");

        // The frontier GROWS after H_open (R-2: notes moved after the
        // snapshot carry no weight). The old ballot's anchor is now stale.
        let grown = fixture(5, &[2_000_000, 1_500_000, 1_000_000, 700_000, 900_000]);
        assert_ne!(ballot.anchor, grown.tree.root());
        let err = verify_ballot_against_tree::<DEPTH>(&ballot, &grown.tree).unwrap_err();
        assert!(matches!(err, GovError::RootMismatch));
    }

    #[test]
    fn dust_below_t_min_rejected() {
        let f = fixture(2, &[500_000, 400_000]);
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        let err =
            build_ballot::<DEPTH>(&f.tree, &f.indices, &refs, f.gip, 0, f.h_open, Choice::For)
                .unwrap_err();
        assert!(matches!(
            err,
            GovError::Dust {
                v: 900_000,
                t_min: T_MIN
            }
        ));

        // Topology: a ninth note is out of shape.
        let big = fixture(9, &[1_000_000; 9]);
        let refs9: Vec<&WalletNoteV4> = big.notes.iter().collect();
        let err = build_ballot::<DEPTH>(
            &big.tree,
            &big.indices,
            &refs9,
            big.gip,
            0,
            big.h_open,
            Choice::For,
        )
        .unwrap_err();
        assert!(matches!(err, GovError::Topology(_)));
    }

    #[test]
    fn wire_roundtrip_and_tamper_detection() {
        let f = fixture(2, &[2_500_000, 1_500_000]);
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        let ballot = build_ballot::<DEPTH>(
            &f.tree,
            &f.indices,
            &refs,
            f.gip,
            0,
            f.h_open,
            Choice::Abstain,
        )
        .expect("ballot");

        // Roundtrip: parse(to_bytes(b)) == b.
        let bytes = ballot.to_bytes();
        let parsed = GovBallot::from_bytes(&bytes).expect("canonical parse");
        assert_eq!(parsed.gip, ballot.gip);
        assert_eq!(parsed.choice, Choice::Abstain);
        assert_eq!(parsed.v, ballot.v);
        assert_eq!(parsed.vs, ballot.vs);
        assert_eq!(parsed.sig, ballot.sig);
        assert_eq!(parsed.proof, ballot.proof);
        verify_ballot::<DEPTH>(&parsed).expect("parsed ballot verifies");

        // A flipped choice byte breaks the binding signature (the choice
        // is inside the sighash). Layout: 0 version, 1..5 gip, 5
        // transition, 6..14 h_open, 14 choice.
        let mut tampered = bytes.clone();
        assert_eq!(tampered[14], 2, "fixture choice is Abstain");
        tampered[14] = 0; // Abstain(2) -> For(0)
        let t = GovBallot::from_bytes(&tampered).expect("still canonical");
        assert!(matches!(
            verify_ballot::<DEPTH>(&t).unwrap_err(),
            GovError::Balance
        ));

        // Truncated and trailing-byte streams are rejected.
        assert!(matches!(
            GovBallot::from_bytes(&bytes[..bytes.len() - 1]),
            Err(GovError::Truncated) | Err(GovError::TrailingBytes)
        ));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            GovBallot::from_bytes(&trailing),
            Err(GovError::TrailingBytes)
        ));
    }

    #[test]
    fn cross_proposal_ballots_do_not_link() {
        let f = fixture(2, &[2_000_000, 1_500_000]);
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        let b1 = build_ballot::<DEPTH>(&f.tree, &f.indices, &refs, f.gip, 0, 100, Choice::For)
            .expect("proposal A ballot");
        // A different proposal: new h_open (and therefore a new anchor in
        // a live chain) - here the same tree, different h_open, so the
        // proposal identity differs while the notes are the same.
        let mut tree2 = TreeState::new(DEPTH);
        for n in &f.notes {
            tree2.append(n.tree_entry().unwrap());
        }
        let indices2 = f.indices.clone();
        let b2 = build_ballot::<DEPTH>(&tree2, &indices2, &refs, 4, 0, 200, Choice::For)
            .expect("proposal B ballot");
        assert_ne!(b1.proposal, b2.proposal);
        assert_ne!(b1.vs, b2.vs, "fresh serials per proposal");
        assert_ne!(b1.bvk, b2.bvk, "no cross-proposal key linkage");
        // Both register in one seen-set: the serial sets are disjoint.
        let mut seen = SeenSet::new();
        register(&mut seen, &b1).expect("A registers");
        register(&mut seen, &b2).expect("B registers");
        assert_eq!(seen.len(), 4);
    }
}
