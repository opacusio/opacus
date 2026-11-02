//! Shared code of the GIP-2 WP-D1 rehearsal bins (runbook stage R1).
//!
//! Three small bins - `dress_collector`, `dress_voter`, `dress_auditor` -
//! rehearse the whole GIP-2 vote over REAL serialization boundaries
//! (files in a drop directory stand in for the network; zero node
//! work). This module carries everything the three processes must agree
//! on:
//!
//! * the deterministic rehearsal shape (the synthetic frontier is a
//!   pure function of the declared seed - the same derivation the R0
//!   example pins, see `examples/dress_rehearsal.rs`);
//! * the published declaration (`declared.json`: the proposal, the
//!   collector key and the rehearsal block that lets any voter process
//!   rebuild the anchored frontier);
//! * the verdict/label vocabulary of the transport and the tally (the
//!   minutes and the auditor speak exactly the R0 labels);
//! * the minutes integrity contract: the collector publishes
//!   `{minutes_body, minutes_digest}` where the digest is blake3 over
//!   the canonical pretty serialization of the body - the auditor
//!   recomputes it, so a tampered minutes file (one flipped byte) is
//!   rejected before any replay work.
//!
//! The R0 example keeps its own frozen copy of the derivation helpers:
//! it is the delivered WP-D0 artifact and its golden vectors are
//! committed; this module is the two-process shape of the same contract.

// The module is compiled into THREE separate bin crates (voter,
// collector, auditor); each uses the vocabulary it needs. Items unused
// by one bin are live in another - do not warn per bin.
#![allow(dead_code)]

use opacus_crypto::CompressedRistretto;
use opacus_wallet::gov::{Choice, GovError, T_MIN};
use opacus_wallet::gov_transport::{ballot_keypair_from_seed, Ingest, TransportError};
use opacus_wallet::tally::{DeclaredProposal, Outcome, Rejection, VoteClass};
use opacus_wallet::tx_v4::WalletNoteV4;
use opacus_wallet::zk_spend::{fp_from_bytes, fp_to_bytes, TreeState};
use opacus_zk::prelude::Fp;

// ---------------------------------------------------------------------------
// The rehearsal shape (runbook R0/R1: gip 2, transition 0, h_open 100)
// ---------------------------------------------------------------------------

/// Mainnet-shaped frontier depth (the runbook pins `TreeState::<32>`).
pub const DEPTH: usize = 32;
/// The declared proposal shape of the rehearsal (the `declare` defaults).
pub const DEFAULT_GIP: u32 = 2;
pub const DEFAULT_TRANSITION: u8 = 0;
pub const DEFAULT_H_OPEN: u64 = 100;
/// The deterministic seed and frontier size of the rehearsal (runbook
/// example: seed 42, 7 voters).
pub const DEFAULT_SEED: u64 = 42;
pub const DEFAULT_VOTERS: usize = 7;

/// Counter-based domain-separated derivation: one blake3 call per value,
/// nothing shared, nothing mutable - the whole rehearsal is a pure
/// function of the seed.
pub fn domain_bytes(seed: u64, domain: &str, idx: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"opacus-dress-rehearsal-v1");
    h.update(&seed.to_le_bytes());
    h.update(domain.as_bytes());
    h.update(&(idx as u64).to_le_bytes());
    *h.finalize().as_bytes()
}

fn domain_fp(seed: u64, domain: &str, idx: usize) -> Fp {
    Fp::from(u64::from_le_bytes(
        domain_bytes(seed, domain, idx)[..8]
            .try_into()
            .expect("u64 slice"),
    ))
}

/// A note whose every field is derived from the seed: canonical field
/// encodings by construction (`Fp::from(u64)`), so `parts()` never
/// fails and the tree entry is a pure function of `(seed, leaf)`.
pub fn deterministic_note(seed: u64, leaf: usize, value: u64) -> WalletNoteV4 {
    WalletNoteV4 {
        d: fp_to_bytes(domain_fp(seed, "diversifier", leaf)),
        a: fp_to_bytes(domain_fp(seed, "share-a", leaf)),
        b: fp_to_bytes(domain_fp(seed, "share-b", leaf)),
        rho: fp_to_bytes(domain_fp(seed, "rho", leaf)),
        value,
    }
}

// Values in atoms. The Fund quorum of `emission_upto(100)` is 5% of
// 1e12 = 5e10, so the synthetic voters deliberately hold whale-sized
// notes to clear it - a synthetic frontier, not a supply model.
const VOTER_VALUES: [u64; 7] = [
    12_000_000_000,
    11_000_000_000,
    13_000_000_000,
    10_500_000_000,
    10_800_000_000,
    12_500_000_000,
    11_500_000_000,
];
const VOTER_CHOICES: [Choice; 7] = [
    Choice::For,
    Choice::For,
    Choice::For,
    Choice::Against,
    Choice::For,
    Choice::Abstain,
    Choice::For,
];
/// The 8th leaf: a dust note whose owner can never vote (P-2 gate).
pub const DUST_LEAF_VALUE: u64 = 500_000;

pub fn voter_value(i: usize) -> u64 {
    if i < VOTER_VALUES.len() {
        VOTER_VALUES[i]
    } else {
        // Deterministic extension beyond the canonical shape.
        10_500_000_000 + ((i as u64 * 1_250_000_007) % 3_000_000_000)
    }
}

pub fn voter_choice(i: usize) -> Choice {
    if i < VOTER_CHOICES.len() {
        VOTER_CHOICES[i]
    } else {
        match i % 3 {
            0 => Choice::For,
            1 => Choice::Against,
            _ => Choice::Abstain,
        }
    }
}

/// The synthetic frontier every process rebuilds from the declaration:
/// one note per voter (values deliberately straddling `T_MIN`) plus the
/// trailing dust leaf. Returns the tree and the voting notes (leaf i is
/// notes[i]; the dust leaf is the last tree leaf, owned by nobody).
pub fn rehearsal_tree(seed: u64, voters: usize) -> (TreeState, Vec<WalletNoteV4>) {
    let mut tree = TreeState::new(DEPTH);
    let mut notes = Vec::with_capacity(voters + 1);
    for i in 0..voters {
        let note = deterministic_note(seed, i, voter_value(i));
        tree.append(note.tree_entry().expect("seeded note is well-formed"));
        notes.push(note);
    }
    let dust = deterministic_note(seed, voters, DUST_LEAF_VALUE);
    tree.append(dust.tree_entry().expect("seeded note is well-formed"));
    (tree, notes)
}

/// The collector key (a seed derivation - no new trust root): the
/// secret half opens the envelopes at close, the public half is
/// declared with the proposal.
pub fn collector_keys(seed: u64) -> (opacus_crypto::ecies::NoteSecret, CompressedRistretto) {
    let mut seed64 = [0u8; 64];
    seed64[..32].copy_from_slice(&domain_bytes(seed, "collector", 0));
    seed64[32..].copy_from_slice(&domain_bytes(seed, "collector", 1));
    let sk = ballot_keypair_from_seed(&seed64);
    let pk = sk.public();
    (sk, pk)
}

// ---------------------------------------------------------------------------
// The published declaration (declared.json)
// ---------------------------------------------------------------------------

/// The published declaration: the proposal of P-3, the collector key of
/// P-4 and the rehearsal block that lets every voter process rebuild
/// the anchored frontier deterministically.
pub struct Declaration {
    pub gip: u32,
    pub transition: u8,
    pub h_open: u64,
    pub anchor: Fp,
    pub collector_pk: CompressedRistretto,
    pub seed: u64,
    pub voters: usize,
}

impl Declaration {
    /// The full declaration file: the R0-shaped proposal fields plus the
    /// rehearsal block.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "gip": self.gip,
            "transition": self.transition,
            "h_open": self.h_open,
            "anchor": hex_encode(&fp_to_bytes(self.anchor)),
            "class": "fund",
            "collector_pk": hex_encode(self.collector_pk.as_bytes()),
            "rehearsal": {
                "seed": self.seed,
                "voters": self.voters,
                "depth": DEPTH,
            },
        })
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Declaration, String> {
        let field = |name: &str| {
            v.get(name)
                .ok_or_else(|| format!("declared.{name} missing"))
                .cloned()
        };
        let class = field("class")?
            .as_str()
            .ok_or("declared.class not a string")?
            .to_string();
        if class != "fund" {
            return Err(format!(
                "declared.class {class:?} is not a rehearsal class (fund)"
            ));
        }
        let anchor_hex = field("anchor")?
            .as_str()
            .ok_or("declared.anchor not a string")?
            .to_string();
        let pk_hex = field("collector_pk")?
            .as_str()
            .ok_or("declared.collector_pk not a string")?
            .to_string();
        let anchor_bytes: [u8; 32] = hex_decode(&anchor_hex, "declared.anchor")?
            .try_into()
            .map_err(|_| "declared.anchor must be 32 bytes".to_string())?;
        let pk_bytes: [u8; 32] = hex_decode(&pk_hex, "declared.collector_pk")?
            .try_into()
            .map_err(|_| "declared.collector_pk must be 32 bytes".to_string())?;
        let anchor = fp_from_bytes(&anchor_bytes).ok_or("declared.anchor non-canonical")?;
        let rehearsal = v
            .get("rehearsal")
            .ok_or("declared.rehearsal missing (the voters cannot rebuild the frontier)")?;
        let seed = rehearsal
            .get("seed")
            .and_then(|s| s.as_u64())
            .ok_or("declared.rehearsal.seed missing")?;
        let voters = rehearsal
            .get("voters")
            .and_then(|s| s.as_u64())
            .ok_or("declared.rehearsal.voters missing")? as usize;
        let depth = rehearsal
            .get("depth")
            .and_then(|s| s.as_u64())
            .ok_or("declared.rehearsal.depth missing")? as usize;
        if depth != DEPTH {
            return Err(format!("declared.rehearsal.depth {depth} != {DEPTH}"));
        }
        Ok(Declaration {
            gip: field("gip")?.as_u64().ok_or("declared.gip not a number")? as u32,
            transition: field("transition")?
                .as_u64()
                .ok_or("declared.transition not a number")? as u8,
            h_open: field("h_open")?
                .as_u64()
                .ok_or("declared.h_open not a number")?,
            anchor,
            collector_pk: CompressedRistretto(pk_bytes),
            seed,
            voters,
        })
    }

    /// The R0-shaped proposal (what the tally consumes and the minutes
    /// publish - cross-stage comparable with the R0 golden vectors).
    pub fn declared_proposal(&self) -> DeclaredProposal {
        DeclaredProposal {
            gip: self.gip,
            transition: self.transition,
            h_open: self.h_open,
            anchor: self.anchor,
            class: VoteClass::Fund,
        }
    }

    /// The R0-shaped declaration object (as published in the minutes).
    pub fn declared_json(&self) -> serde_json::Value {
        serde_json::json!({
            "gip": self.gip,
            "transition": self.transition,
            "h_open": self.h_open,
            "anchor": hex_encode(&fp_to_bytes(self.anchor)),
            "class": "fund",
            "collector_pk": hex_encode(self.collector_pk.as_bytes()),
        })
    }
}

/// The light proposal parse for REPLAY-side consumers (the auditor):
/// the minutes publish the R0-shaped declaration WITHOUT the rehearsal
/// block (no frontier rebuild is needed to replay a tally).
pub fn declared_proposal_from_json(v: &serde_json::Value) -> Result<DeclaredProposal, String> {
    let field = |name: &str| {
        v.get(name)
            .ok_or_else(|| format!("declared.{name} missing"))
            .cloned()
    };
    let class = field("class")?
        .as_str()
        .ok_or("declared.class not a string")?
        .to_string();
    if class != "fund" {
        return Err(format!(
            "declared.class {class:?} is not a rehearsal class (fund)"
        ));
    }
    let anchor_hex = field("anchor")?
        .as_str()
        .ok_or("declared.anchor not a string")?
        .to_string();
    let anchor_bytes: [u8; 32] = hex_decode(&anchor_hex, "declared.anchor")?
        .try_into()
        .map_err(|_| "declared.anchor must be 32 bytes".to_string())?;
    let anchor = fp_from_bytes(&anchor_bytes).ok_or("declared.anchor non-canonical")?;
    Ok(DeclaredProposal {
        gip: field("gip")?.as_u64().ok_or("declared.gip not a number")? as u32,
        transition: field("transition")?
            .as_u64()
            .ok_or("declared.transition not a number")? as u8,
        h_open: field("h_open")?
            .as_u64()
            .ok_or("declared.h_open not a number")?,
        anchor,
        class: VoteClass::Fund,
    })
}

/// Parse a `for|against|abstain` choice.
pub fn parse_choice(s: &str) -> Result<Choice, String> {
    match s {
        "for" => Ok(Choice::For),
        "against" => Ok(Choice::Against),
        "abstain" => Ok(Choice::Abstain),
        other => Err(format!("unknown choice {other:?} (for|against|abstain)")),
    }
}

// ---------------------------------------------------------------------------
// Minutes integrity: blake3 over the canonical body serialization
// ---------------------------------------------------------------------------

/// The exact bytes the digest covers: serde_json's canonical pretty
/// serialization of the body (deterministic for the same Value).
pub fn canonical_json_bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec_pretty(v).expect("a serde_json::Value always serializes")
}

/// blake3 over [`canonical_json_bytes`] - the tamper-evidence of the
/// published minutes.
pub fn minutes_digest(body: &serde_json::Value) -> String {
    hex_encode(blake3::hash(&canonical_json_bytes(body)).as_bytes())
}

// ---------------------------------------------------------------------------
// Verdict/label vocabulary (the minutes and the auditor speak the R0 labels)
// ---------------------------------------------------------------------------

pub fn gov_err_kind(e: &GovError) -> String {
    match e {
        GovError::Topology(_) => "topology".into(),
        GovError::Dust { .. } => "dust".into(),
        GovError::CorruptNote => "corrupt_note".into(),
        GovError::UnknownLeaf => "unknown_leaf".into(),
        GovError::RootMismatch => "root_mismatch".into(),
        GovError::ProposalMismatch => "proposal_mismatch".into(),
        GovError::Version(_) => "version".into(),
        GovError::Choice(_) => "choice".into(),
        GovError::Canonical => "canonical".into(),
        GovError::Truncated => "truncated".into(),
        GovError::TrailingBytes => "trailing_bytes".into(),
        GovError::Proof(_) => "proof".into(),
        GovError::Balance => "balance".into(),
        GovError::DuplicateVote => "duplicate_vote".into(),
    }
}

pub fn rejection_label(r: &Rejection) -> String {
    match r {
        Rejection::Malformed(e) => format!("malformed:{}", gov_err_kind(e)),
        Rejection::ProposalMismatch => "proposal_mismatch".into(),
        Rejection::AnchorMismatch => "anchor_mismatch".into(),
        Rejection::DuplicateSerial => "duplicate_serial".into(),
    }
}

pub fn transport_label(e: &TransportError) -> String {
    use opacus_crypto::ecies::EnoteError;
    match e {
        TransportError::Enote(inner) => match inner {
            EnoteError::BadLength { .. } => "enote:bad_length".into(),
            EnoteError::BadVersion(_) => "enote:bad_version".into(),
            EnoteError::BadEphemeralKey => "enote:bad_ephemeral_key".into(),
            EnoteError::BadRecipientKey => "enote:bad_recipient_key".into(),
            EnoteError::MacMismatch => "enote:mac_mismatch".into(),
        },
        TransportError::Ballot(e) => format!("ballot:{}", gov_err_kind(e)),
        TransportError::Magic => "magic".into(),
        TransportError::Version(_) => "version".into(),
        TransportError::Oversize { .. } => "oversize".into(),
        TransportError::Truncated => "truncated".into(),
        TransportError::HeaderMismatch => "header_mismatch".into(),
        TransportError::ProposalMismatch => "proposal_mismatch".into(),
    }
}

pub fn ingest_label(r: &Result<Ingest, TransportError>) -> String {
    match r {
        Ok(Ingest::Accepted { index }) => format!("accepted@{index}"),
        Ok(Ingest::Retransmission) => "retransmission".into(),
        Err(e) => format!("rejected:{}", transport_label(e)),
    }
}

pub fn outcome_label(o: Outcome) -> &'static str {
    match o {
        Outcome::Accepted => "accepted",
        Outcome::Rejected => "rejected",
        Outcome::NoQuorum => "no_quorum",
    }
}

// ---------------------------------------------------------------------------
// Wire helpers (the byte-exact injection points are part of the record)
// ---------------------------------------------------------------------------

/// Offset of the `v` field in the canonical ballot wire: version 1 +
/// gip 4 + transition 1 + h_open 8 + choice 1 + anchor 32 + proposal 32.
pub const WIRE_V_OFFSET: usize = 79;
/// Offset of the cleartext `h_open` in the envelope wire: magic 4 +
/// version 1 + gip 4 + transition 1.
pub const ENVELOPE_H_OPEN_OFFSET: usize = 10;

pub fn patch_u64_le(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode(s: &str, what: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("{what}: odd hex length {}", s.len()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("{what}: bad hex at byte {i}: {e}"))
        })
        .collect()
}

/// The `T_MIN` gate value, re-exported for the fault documentation.
pub const T_MIN_GATE: u64 = T_MIN;
