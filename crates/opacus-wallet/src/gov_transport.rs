//! GIP-2 WP-3: the WG-29 ballot transport profile plus the raw fallback
//! (P-4).
//!
//! Additive module: nothing in the existing wallet files changes.
//!
//! GIP-2 P-4 answers open question 8.3 (ballot transport) in two tiers:
//!
//! * **Primary - the WG-29 sealed envelope** ([`BallotEnvelope`]): the
//!   canonical ballot bytes ([`GovBallot::to_bytes`]) are sealed with
//!   the WG-29 ECIES algebra ([`opacus_crypto::ecies`], the
//!   [`opacus_crypto::ecies::BALLOT_TAGS`] instantiation) to the
//!   per-proposal ballot collector key. Before close the ballot is
//!   hidden from everyone except the collector - network-layer
//!   anonymity equal to transaction broadcast: the envelope is the
//!   payload the v5 wire gossip carries, and it adds no sender
//!   information of its own. Zero consensus impact: no byte of this
//!   module is consensus input.
//! * **Fallback - raw publication**: the canonical ballot bytes are
//!   published as-is (documented WEAKER: the choice, the weight and the
//!   vote serials are public before close). Copying a raw ballot is
//!   useless for double-voting - the serials are one-time tokens and
//!   the tally rejects duplicates (R-3) - but the ballot is linkable to
//!   where it surfaced. [`BallotArchive::ingest_raw`] accepts exactly
//!   this form.
//!
//! The collector key is a DERIVATION of the collector's BIP-39 seed
//! ([`ballot_keypair_from_seed`], the D3 pattern with its own tag) - no
//! new keys or trust roots (GIP-2 section 7); the public half is
//! declared alongside the voting proposal, out of band. The envelope
//! carries the proposal tag `(gip, transition, h_open)` in CLEARTEXT:
//! the proposal is public by construction (declared 14 days before
//! H_open, P-3), and the tag lets the collector bucket and pre-route
//! envelopes without opening them. A relabelled envelope fails closed
//! on the ballot-header match ([`TransportError::HeaderMismatch`]).
//!
//! [`BallotArchive`] is the collector-side "auditable minutes" of P-4:
//! it ingests from BOTH transports, dedupes only byte-equal
//! retransmissions, and deliberately performs NO cryptographic
//! verification - every verdict (shape, dust, anchor, proposal, ZK
//! proof, binding signature, duplicate serials) belongs to the tally
//! engine ([`crate::tally::tally`]) and its published trace. Filtering
//! at ingest would HIDE attempts from the minutes; keeping them makes
//! the archive complete and the trace the single source of verdicts.
//! [`BallotArchive::publish`] emits the entries (each the canonical
//! ballot bytes, ready for [`crate::tally::tally`]) plus the
//! [`BallotArchive::archive_id`] fingerprint: blake3 over the per-entry
//! digests in ARRIVAL order. The arrival-ordered `archive_id` and the
//! decision `result_hash` (sorted accepted sighashes, order-invariant)
//! are two different artifacts - the minutes fingerprint their exact
//! submission history, the decision fingerprints its outcome; shuffling
//! arrival order changes the former and not the latter (tested).

use std::collections::HashSet;

use opacus_crypto::ecies::{
    id_digest, keypair_from_seed_tagged, open_with_tags, seal_with_tags, EnoteError, NoteSecret,
    BALLOT_DERIVE_TAG, BALLOT_TAGS,
};
use opacus_crypto::CompressedRistretto;

use crate::gov::{GovBallot, GovError};

// ---------------------------------------------------------------------------
// Envelope wire (P-4 primary transport)
// ---------------------------------------------------------------------------

/// Wire version of the ballot envelope.
pub const ENVELOPE_VERSION: u8 = 1;

/// Envelope magic: "Ghost Ballot Envelope v1".
pub const ENVELOPE_MAGIC: [u8; 4] = *b"GBE1";

/// Cleartext header: magic 4 || version 1 || gip 4 || transition 1 ||
/// h_open 8.
pub const ENVELOPE_HEADER_LEN: usize = 4 + 1 + 4 + 1 + 8;

/// Minimum sealed blob: epk 32 || nonce 16 || mac 32 (ct may be empty at
/// the primitive level; the envelope parse still requires a payload
/// because a ballot is never empty).
pub const ENVELOPE_MIN_SEALED_LEN: usize = 32 + 16 + 1 + 32;

/// Profile cap of one envelope (a DoS bound for the parse path, not a
/// semantic limit: a K = 8 ballot at DEPTH = 32 is well under it).
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;

/// Errors of the ballot transport profile.
#[derive(Clone, Debug)]
pub enum TransportError {
    /// The WG-29 ECIES layer rejected the blob (wrong key, tampering,
    /// bad length).
    Enote(EnoteError),
    /// The ballot inside did not parse canonically ([`GovError`]).
    Ballot(GovError),
    /// The envelope magic is not [`ENVELOPE_MAGIC`].
    Magic,
    /// The envelope version is not [`ENVELOPE_VERSION`].
    Version(u8),
    /// The envelope (or its sealed blob) exceeds the profile cap.
    Oversize { got: usize },
    /// The byte stream ended mid-field.
    Truncated,
    /// The ballot header does not match the envelope's cleartext tag.
    HeaderMismatch,
    /// The envelope (or ballot) belongs to a different proposal than
    /// the archive scope.
    ProposalMismatch,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Enote(e) => write!(f, "ballot envelope ecies: {e}"),
            TransportError::Ballot(e) => write!(f, "ballot envelope payload: {e}"),
            TransportError::Magic => write!(f, "ballot envelope magic mismatch"),
            TransportError::Version(v) => write!(f, "unsupported envelope version: {v}"),
            TransportError::Oversize { got } => {
                write!(f, "ballot envelope exceeds the profile cap: {got}")
            }
            TransportError::Truncated => write!(f, "ballot envelope truncated mid-field"),
            TransportError::HeaderMismatch => {
                write!(f, "ballot header does not match the envelope tag")
            }
            TransportError::ProposalMismatch => {
                write!(f, "envelope belongs to a different proposal")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// Derive the ballot collector keypair from the collector's BIP-39 seed
/// (the D3 pattern with [`opacus_crypto::ecies::BALLOT_DERIVE_TAG`]). A
/// derivation of the existing wallet seed - no new trust root.
pub fn ballot_keypair_from_seed(seed: &[u8; 64]) -> NoteSecret {
    keypair_from_seed_tagged(BALLOT_DERIVE_TAG, seed)
}

/// The P-4 primary transport artifact: the proposal tag in cleartext
/// plus the WG-29 sealed ballot.
#[derive(Clone, Debug)]
pub struct BallotEnvelope {
    /// The GIP being voted on (public, P-3).
    pub gip: u32,
    /// The status transition tag (public, P-3).
    pub transition: u8,
    /// Vote-open height = snapshot height (public, P-3).
    pub h_open: u64,
    /// The WG-29 sealed blob: `epk 32 || nonce 16 || ct || mac 32`.
    pub sealed: Vec<u8>,
}

/// The parsed fields of one sealed blob: (epk, nonce, ciphertext).
type SealedParts<'a> = ([u8; 32], [u8; 16], &'a [u8]);

impl BallotEnvelope {
    /// Seal one ballot to the collector key (primary transport). The
    /// plaintext is the canonical ballot wire; the cleartext tag is the
    /// ballot's own proposal header, so a mislabelled envelope fails
    /// the match at open.
    pub fn seal(
        b: &GovBallot,
        collector_pk: &CompressedRistretto,
    ) -> Result<BallotEnvelope, TransportError> {
        let sealed = seal_with_tags(
            &BALLOT_TAGS,
            u32::from(ENVELOPE_VERSION),
            &b.to_bytes(),
            collector_pk,
        )
        .map_err(TransportError::Enote)?;
        Ok(BallotEnvelope {
            gip: b.gip,
            transition: b.transition,
            h_open: b.h_open,
            sealed,
        })
    }

    /// Canonical envelope wire:
    /// `magic 4 | version u8 | gip le32 | transition u8 | h_open le64 |
    /// epk 32 | nonce 16 | le32(ct_len) | ct | mac 32`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + 4 + self.sealed.len());
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.extend_from_slice(&self.gip.to_le_bytes());
        out.push(self.transition);
        out.extend_from_slice(&self.h_open.to_le_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    /// Strict canonical parse: magic, version, header layout, minimum
    /// sealed length, the profile cap, no trailing bytes (the sealed
    /// blob is self-delimiting: ct is everything before the final 32
    /// MAC bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<BallotEnvelope, TransportError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(TransportError::Oversize { got: bytes.len() });
        }
        if bytes.len() < ENVELOPE_HEADER_LEN + ENVELOPE_MIN_SEALED_LEN {
            return Err(TransportError::Truncated);
        }
        if bytes[0..4] != ENVELOPE_MAGIC {
            return Err(TransportError::Magic);
        }
        if bytes[4] != ENVELOPE_VERSION {
            return Err(TransportError::Version(bytes[4]));
        }
        let gip = u32::from_le_bytes(bytes[5..9].try_into().expect("fixed slice"));
        let transition = bytes[9];
        let h_open = u64::from_le_bytes(bytes[10..18].try_into().expect("fixed slice"));
        Ok(BallotEnvelope {
            gip,
            transition,
            h_open,
            sealed: bytes[ENVELOPE_HEADER_LEN..].to_vec(),
        })
    }

    /// The public relay id of the envelope (the WG-29 id digest under
    /// the ballot tags, hops = 0): what the v5 gossip uses to dedupe.
    /// Randomized per seal (fresh epk/nonce), stable per byte-string.
    pub fn envelope_id(&self) -> Result<[u8; 32], TransportError> {
        let (epk, nonce, ct) = Self::parse_sealed(&self.sealed)?;
        Ok(id_digest(
            &BALLOT_TAGS,
            u32::from(ENVELOPE_VERSION),
            0,
            &epk,
            &nonce,
            ct,
        ))
    }

    /// Open with the collector key: MAC over the sealed blob, decrypt,
    /// strict ballot parse, then the envelope-tag match (fail-closed
    /// against relabelling).
    pub fn open(&self, collector_sk: &NoteSecret) -> Result<GovBallot, TransportError> {
        let plain = open_with_tags(
            &BALLOT_TAGS,
            u32::from(ENVELOPE_VERSION),
            &self.sealed,
            collector_sk,
        )
        .map_err(TransportError::Enote)?;
        let b = GovBallot::from_bytes(&plain).map_err(TransportError::Ballot)?;
        if b.gip != self.gip || b.transition != self.transition || b.h_open != self.h_open {
            return Err(TransportError::HeaderMismatch);
        }
        Ok(b)
    }

    fn parse_sealed(sealed: &[u8]) -> Result<SealedParts<'_>, TransportError> {
        if sealed.len() < ENVELOPE_MIN_SEALED_LEN {
            return Err(TransportError::Truncated);
        }
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&sealed[0..32]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&sealed[32..48]);
        let ct = &sealed[48..sealed.len() - 32];
        Ok((epk, nonce, ct))
    }
}

// ---------------------------------------------------------------------------
// The collector-side archive (the "auditable minutes" of P-4)
// ---------------------------------------------------------------------------

/// Domain tag of the minutes fingerprint.
pub const ARCHIVE_TAG: &[u8] = b"ghost-ballot-archive-v1";

/// The verdict of one archive ingest. Cryptographic verdicts are NOT
/// taken here - the tally owns them; the archive only dedupes byte-equal
/// retransmissions so the minutes stay noise-free but complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingest {
    /// Appended at the given index (arrival order, 0-based).
    Accepted { index: usize },
    /// A byte-equal copy of an already-archived ballot.
    Retransmission,
}

/// The per-proposal ballot archive of P-4: the collector ingests
/// envelopes (primary) and raw ballot bytes (fallback) all window long
/// and publishes the minutes at close.
#[derive(Clone, Debug)]
pub struct BallotArchive {
    gip: u32,
    transition: u8,
    h_open: u64,
    entries: Vec<Vec<u8>>,
    seen: HashSet<Vec<u8>>,
}

impl BallotArchive {
    /// One archive collects exactly one proposal's ballots (the scope
    /// is the declared `(gip, transition, h_open)` of P-3).
    pub fn new(gip: u32, transition: u8, h_open: u64) -> BallotArchive {
        BallotArchive {
            gip,
            transition,
            h_open,
            entries: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// The declared scope.
    pub fn scope(&self) -> (u32, u8, u64) {
        (self.gip, self.transition, self.h_open)
    }

    /// Archived ballots in arrival order (each the canonical ballot
    /// wire, ready for [`crate::tally::tally`]).
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }

    /// Number of archived ballots.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing was archived yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Fallback ingest (P-4, documented weaker): the raw canonical
    /// ballot bytes, public before close. Strict canonical parse +
    /// scope check; no other verification (the tally owns the
    /// verdicts).
    pub fn ingest_raw(&mut self, bytes: &[u8]) -> Result<Ingest, TransportError> {
        let b = GovBallot::from_bytes(bytes).map_err(TransportError::Ballot)?;
        self.scope_check(b.gip, b.transition, b.h_open)?;
        self.insert(b.to_bytes())
    }

    /// Primary ingest: open the WG-29 envelope with the collector key,
    /// then the same gates as the raw path. The envelope's cleartext
    /// tag is checked against the archive scope BEFORE opening (cheap
    /// bucket routing), the ballot header against the envelope tag
    /// AFTER opening (relabeling guard).
    pub fn ingest_sealed(
        &mut self,
        env: &BallotEnvelope,
        collector_sk: &NoteSecret,
    ) -> Result<Ingest, TransportError> {
        self.scope_check(env.gip, env.transition, env.h_open)?;
        let b = env.open(collector_sk)?;
        self.insert(b.to_bytes())
    }

    /// The minutes fingerprint: blake3 over
    /// [`ARCHIVE_TAG`] `|| le64(count) || blake3(entry) ...` in ARRIVAL
    /// order. Two archives with the same submissions in different
    /// arrival order have DIFFERENT ids and produce the SAME tally
    /// `result_hash` - the minutes fingerprint their submission
    /// history, the decision is order-invariant (P-5 replay).
    pub fn archive_id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(ARCHIVE_TAG);
        h.update(&(self.entries.len() as u64).to_le_bytes());
        for e in &self.entries {
            h.update(blake3::hash(e).as_bytes());
        }
        *h.finalize().as_bytes()
    }

    /// Publish the minutes at close (P-4: "the tally engine MUST
    /// publish the full ballot archive at close; the archive is the
    /// auditable minutes"): the entries in arrival order plus the
    /// fingerprint. `entries` feeds [`crate::tally::tally`] directly.
    pub fn publish(&self) -> PublishedArchive {
        PublishedArchive {
            entries: self.entries.clone(),
            archive_id: self.archive_id(),
        }
    }

    fn scope_check(&self, gip: u32, transition: u8, h_open: u64) -> Result<(), TransportError> {
        if gip != self.gip || transition != self.transition || h_open != self.h_open {
            return Err(TransportError::ProposalMismatch);
        }
        Ok(())
    }

    fn insert(&mut self, canonical: Vec<u8>) -> Result<Ingest, TransportError> {
        if self.seen.contains(&canonical) {
            return Ok(Ingest::Retransmission);
        }
        self.seen.insert(canonical.clone());
        self.entries.push(canonical);
        Ok(Ingest::Accepted {
            index: self.entries.len() - 1,
        })
    }
}

/// The published minutes of P-4 (the close artifact).
#[derive(Clone, Debug)]
pub struct PublishedArchive {
    /// The ballots in arrival order (canonical wire bytes).
    pub entries: Vec<Vec<u8>>,
    /// The arrival-order fingerprint ([`BallotArchive::archive_id`]).
    pub archive_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// Tests (the WP-1 fixture pattern: mock-prover ballots at DEPTH = 4)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gov::{build_ballot, Choice, T_MIN};
    use crate::tx_v4::WalletNoteV4;
    use crate::zk_spend::TreeState;
    use opacus_crypto::ecies::{note_keypair_from_seed, ENOTE_TAGS};
    use opacus_zk::vote::proposal_id;

    /// Small test depth (the wallet test convention).
    const DEPTH: usize = 4;

    struct BallotFixture {
        tree: TreeState,
        indices: Vec<usize>,
        notes: Vec<WalletNoteV4>,
        gip: u32,
        h_open: u64,
    }

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

    fn ballot_of(f: &BallotFixture, choice: Choice) -> GovBallot {
        let refs: Vec<&WalletNoteV4> = f.notes.iter().collect();
        build_ballot::<DEPTH>(&f.tree, &f.indices, &refs, f.gip, 0, f.h_open, choice)
            .expect("test ballot must build")
    }

    /// One voter = one note: a single-note ballot of the fixture.
    fn single_note_ballot(f: &BallotFixture, i: usize, choice: Choice) -> GovBallot {
        let refs = [&f.notes[i]];
        build_ballot::<DEPTH>(&f.tree, &[i], &refs, f.gip, 0, f.h_open, choice)
            .expect("single-note ballot must build")
    }

    fn seed(b: u8) -> [u8; 64] {
        [b; 64]
    }

    #[test]
    fn ballot_key_derivation_is_tag_separated() {
        let note = note_keypair_from_seed(&seed(1));
        let ballot = ballot_keypair_from_seed(&seed(1));
        // The derivation tags are domain-separated: same seed, two
        // different keys; deterministic in the seed.
        assert_ne!(note.public(), ballot.public());
        assert_eq!(ballot.public(), ballot_keypair_from_seed(&seed(1)).public());
        assert_ne!(ballot.public(), ballot_keypair_from_seed(&seed(2)).public());
    }

    #[test]
    fn envelope_seal_open_roundtrip() {
        let f = fixture(3, &[2_500_000, 1_500_000, 1_000_000]);
        let ballot = ballot_of(&f, Choice::For);
        let sk = ballot_keypair_from_seed(&seed(7));

        let env = BallotEnvelope::seal(&ballot, &sk.public()).expect("seal");
        // Wire roundtrip + caps sanity.
        let wire = env.to_bytes();
        assert!(wire.len() <= MAX_ENVELOPE_BYTES);
        let parsed = BallotEnvelope::from_bytes(&wire).expect("canonical envelope parse");
        assert_eq!(
            (parsed.gip, parsed.transition, parsed.h_open),
            (f.gip, 0, f.h_open)
        );

        // Open: the ballot comes back byte-exact and the proposal
        // identity matches the ballot fields.
        let opened = parsed.open(&sk).expect("collector opens");
        assert_eq!(opened.to_bytes(), ballot.to_bytes());
        assert_eq!(
            opened.proposal,
            proposal_id(ballot.gip, ballot.transition, ballot.h_open, ballot.anchor)
        );

        // The envelope id is stable per byte-string and randomized per
        // seal (fresh epk/nonce).
        assert_eq!(parsed.envelope_id().unwrap(), env.envelope_id().unwrap());
        let env2 = BallotEnvelope::seal(&ballot, &sk.public()).expect("seal again");
        assert_ne!(env2.envelope_id().unwrap(), env.envelope_id().unwrap());
    }

    #[test]
    fn envelope_rejects_wrong_key_and_tampering() {
        let f = fixture(2, &[2_500_000, 1_500_000]);
        let ballot = ballot_of(&f, Choice::Against);
        let sk = ballot_keypair_from_seed(&seed(11));
        let stranger = ballot_keypair_from_seed(&seed(12));

        let env = BallotEnvelope::seal(&ballot, &sk.public()).expect("seal");
        // Wrong collector key: MAC mismatch, never a valid open.
        assert!(matches!(
            env.open(&stranger),
            Err(TransportError::Enote(EnoteError::MacMismatch))
        ));

        // Tampering with any byte of the sealed blob fails closed.
        for flip in [0usize, 40, 60, env.sealed.len() - 1] {
            let mut t = env.clone();
            t.sealed[flip] ^= 1;
            assert!(t.open(&sk).is_err(), "flip {flip}");
        }

        // Wire-level gates: magic, version, truncation, oversize.
        let wire = env.to_bytes();
        let mut bad_magic = wire.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            BallotEnvelope::from_bytes(&bad_magic),
            Err(TransportError::Magic)
        ));
        let mut bad_version = wire.clone();
        bad_version[4] = 2;
        assert!(matches!(
            BallotEnvelope::from_bytes(&bad_version),
            Err(TransportError::Version(2))
        ));
        assert!(matches!(
            BallotEnvelope::from_bytes(&wire[..ENVELOPE_HEADER_LEN + ENVELOPE_MIN_SEALED_LEN - 1]),
            Err(TransportError::Truncated)
        ));
        let big = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        match BallotEnvelope::from_bytes(&big) {
            Err(TransportError::Oversize { got }) => {
                assert_eq!(got, MAX_ENVELOPE_BYTES + 1)
            }
            other => panic!("expected oversize, got {other:?}"),
        }
    }

    #[test]
    fn relabelled_envelope_and_cross_tags_fail_closed() {
        let f = fixture(2, &[2_500_000, 1_500_000]);
        let ballot = ballot_of(&f, Choice::For);
        let sk = ballot_keypair_from_seed(&seed(21));
        let env = BallotEnvelope::seal(&ballot, &sk.public()).expect("seal");

        // Relabel the cleartext tag (same proposal family, other GIP):
        // the MAC is untouched, the ballot opens, and the header match
        // rejects the mismatch.
        let mut relabelled = env.clone();
        relabelled.gip = 9;
        assert!(matches!(
            relabelled.open(&sk),
            Err(TransportError::HeaderMismatch)
        ));

        // Cross-tag isolation: the ballot blob under the ENOTE tags (or
        // with the enote version input) fails closed on the MAC.
        assert_eq!(
            open_with_tags(&ENOTE_TAGS, u32::from(ENVELOPE_VERSION), &env.sealed, &sk),
            Err(EnoteError::MacMismatch)
        );
        assert_eq!(
            open_with_tags(&BALLOT_TAGS, 2, &env.sealed, &sk),
            Err(EnoteError::MacMismatch)
        );
    }

    #[test]
    fn raw_fallback_roundtrip() {
        // The fallback transport IS the canonical ballot wire: parse
        // and re-encode are byte-stable.
        let f = fixture(2, &[2_500_000, 1_500_000]);
        let ballot = ballot_of(&f, Choice::Abstain);
        let raw = ballot.to_bytes();
        let parsed = GovBallot::from_bytes(&raw).expect("raw fallback parse");
        assert_eq!(parsed.to_bytes(), raw);
    }

    #[test]
    fn sealed_and_raw_paths_feed_the_same_tally() {
        use crate::tally::{tally, DeclaredProposal, VoteClass};

        // Three SEPARATE voters (R-3: the same notes on the same
        // proposal derive the same serials, so one fixture cannot cast
        // three countable ballots): voter 0 votes FOR, voter 1 AGAINST,
        // voter 2 ABSTAINs.
        let f = fixture(3, &[3_000_000, 2_000_000, 1_500_000]);
        let for_ballot = single_note_ballot(&f, 0, Choice::For);
        let against_ballot = single_note_ballot(&f, 1, Choice::Against);
        let abstain_ballot = single_note_ballot(&f, 2, Choice::Abstain);
        let sk = ballot_keypair_from_seed(&seed(31));

        let declared = DeclaredProposal {
            gip: f.gip,
            transition: 0,
            h_open: f.h_open,
            anchor: f.tree.root(),
            class: VoteClass::Process,
        };

        // Archive A: everything arrives SEALED. Archive B: the same
        // ballots arrive RAW, in a different order.
        let mut a = BallotArchive::new(f.gip, 0, f.h_open);
        for b in [&for_ballot, &against_ballot, &abstain_ballot] {
            let env = BallotEnvelope::seal(b, &sk.public()).expect("seal");
            assert!(matches!(
                a.ingest_sealed(&env, &sk),
                Ok(Ingest::Accepted { index: _ })
            ));
        }
        let mut c = BallotArchive::new(f.gip, 0, f.h_open);
        for b in [&abstain_ballot, &for_ballot, &against_ballot] {
            assert!(matches!(
                c.ingest_raw(&b.to_bytes()),
                Ok(Ingest::Accepted { index: _ })
            ));
        }

        let published_a = a.publish();
        let published_c = c.publish();
        assert_ne!(
            published_a.archive_id, published_c.archive_id,
            "arrival order is part of the minutes fingerprint"
        );
        assert_eq!(
            a.archive_id(),
            published_a.archive_id,
            "fingerprint is stable"
        );

        // The decision is transport- and order-invariant (P-5), and
        // all three voters' weights are counted: YES 3M + NO 2M +
        // ABSTAIN 1.5M.
        let rec_a = tally::<DEPTH, _>(&declared, &published_a.entries).expect("tally A");
        let rec_c = tally::<DEPTH, _>(&declared, &published_c.entries).expect("tally C");
        assert_eq!(rec_a.result_hash, rec_c.result_hash);
        assert_eq!(rec_a.outcome, rec_c.outcome);
        assert_eq!(rec_a.accepted, 3);
        assert_eq!(
            (rec_a.yes, rec_a.no, rec_a.abstain),
            (3_000_000, 2_000_000, 1_500_000)
        );
        // Envelope headers and raw bytes both scoped to the archive:
        // nothing leaked across proposals.
        assert_eq!(published_a.entries.len(), 3);
    }

    #[test]
    fn archive_records_retransmission_and_double_vote() {
        use crate::tally::{tally, DeclaredProposal, VoteClass};

        let f = fixture(2, &[2_000_000, 1_500_000]);
        let sk = ballot_keypair_from_seed(&seed(41));

        // Retransmission: a byte-equal copy is deduped, not archived.
        let mut arch = BallotArchive::new(f.gip, 0, f.h_open);
        let env = BallotEnvelope::seal(&ballot_of(&f, Choice::For), &sk.public()).expect("seal");
        assert!(matches!(
            arch.ingest_sealed(&env, &sk),
            Ok(Ingest::Accepted { index: 0 })
        ));
        assert!(matches!(
            arch.ingest_sealed(&env, &sk),
            Ok(Ingest::Retransmission)
        ));
        assert_eq!(arch.len(), 1);

        // Double-vote attempt: the SAME notes vote AGAINST on the SAME
        // proposal - the serials are proposal-bound (R-3), so the two
        // ballots share their VS set. Byte-different, so the minutes
        // KEEP the attempt and the tally trace carries the verdict.
        let against = ballot_of(&f, Choice::Against);
        assert!(matches!(
            arch.ingest_raw(&against.to_bytes()),
            Ok(Ingest::Accepted { index: 1 })
        ));

        let declared = DeclaredProposal {
            gip: f.gip,
            transition: 0,
            h_open: f.h_open,
            anchor: f.tree.root(),
            class: VoteClass::Process,
        };
        let published = arch.publish();
        let rec = tally::<DEPTH, _>(&declared, &published.entries).expect("tally");
        assert_eq!(rec.accepted + rec.rejected, 2);
        let dup = rec
            .trace
            .iter()
            .find(|t| !t.accepted)
            .expect("the double-vote attempt is in the trace");
        assert!(matches!(
            dup.rejection,
            Some(crate::tally::Rejection::DuplicateSerial)
        ));
    }

    #[test]
    fn archive_scope_and_proposal_mismatch_rejected() {
        let f = fixture(2, &[2_500_000, 1_500_000]);
        let ballot = ballot_of(&f, Choice::For);
        let sk = ballot_keypair_from_seed(&seed(51));

        let mut arch = BallotArchive::new(f.gip, 0, f.h_open);
        // A raw ballot for another proposal is out of scope.
        let other = fixture(2, &[2_500_000, 1_500_000]);
        let other_ballot = {
            let refs: Vec<&WalletNoteV4> = other.notes.iter().collect();
            build_ballot::<DEPTH>(
                &other.tree,
                &other.indices,
                &refs,
                other.gip,
                0,
                other.h_open + 1,
                Choice::For,
            )
            .expect("other-proposal ballot")
        };
        assert!(matches!(
            arch.ingest_raw(&other_ballot.to_bytes()),
            Err(TransportError::ProposalMismatch)
        ));
        // An envelope tagged for another proposal is rejected before
        // opening.
        let env = BallotEnvelope::seal(&ballot, &sk.public()).expect("seal");
        let mut foreign_env = env.clone();
        foreign_env.h_open += 1;
        assert!(matches!(
            arch.ingest_sealed(&foreign_env, &sk),
            Err(TransportError::ProposalMismatch)
        ));
        // The well-tagged envelope of a foreign-SCOPE ballot still
        // fails closed: the ballot inside does not match the declared
        // proposal (the tally would reject it as ProposalMismatch too).
        assert_eq!(arch.len(), 0);
        // And the honest path still works after all the rejects.
        assert!(matches!(
            arch.ingest_sealed(&env, &sk),
            Ok(Ingest::Accepted { index: 0 })
        ));
        assert_eq!(
            arch.entries()[0],
            ballot.to_bytes(),
            "the minutes store the canonical ballot bytes"
        );
    }

    #[test]
    fn the_archive_blindly_keeps_what_the_tally_rejects() {
        // The transport is verdict-agnostic: a ballot whose weight was
        // flipped below T_min still parses canonically, so the archive
        // KEEPS it (the minutes stay complete) and the TALLY rejects it
        // as Dust - the attempt stays visible and auditable.
        use crate::gov::GovError;
        use crate::tally::{tally, DeclaredProposal, Rejection, VoteClass};

        let f = fixture(1, &[T_MIN]);
        let ballot = ballot_of(&f, Choice::For);
        let sk = ballot_keypair_from_seed(&seed(61));

        // Flip the public weight v (wire offset: version 0, gip 1..5,
        // transition 5, h_open 6..14, choice 14, anchor 15..47,
        // proposal 47..79, v 79..87) from T_MIN to T_MIN - 1.
        let mut dusty = ballot.to_bytes();
        assert_eq!(u64::from_le_bytes(dusty[79..87].try_into().unwrap()), T_MIN);
        dusty[79..87].copy_from_slice(&(T_MIN - 1).to_le_bytes());
        let dusty = GovBallot::from_bytes(&dusty).expect("still canonical");

        let mut arch = BallotArchive::new(f.gip, 0, f.h_open);
        let env = BallotEnvelope::seal(&dusty, &sk.public()).expect("seal (no verdicts here)");
        assert!(matches!(
            arch.ingest_sealed(&env, &sk),
            Ok(Ingest::Accepted { index: 0 })
        ));

        let declared = DeclaredProposal {
            gip: f.gip,
            transition: 0,
            h_open: f.h_open,
            anchor: f.tree.root(),
            class: VoteClass::Process,
        };
        let rec = tally::<DEPTH, _>(&declared, &arch.publish().entries).expect("tally");
        assert_eq!(rec.accepted, 0);
        assert_eq!(rec.rejected, 1);
        match &rec.trace[0].rejection {
            Some(Rejection::Malformed(GovError::Dust { v, t_min })) => {
                assert_eq!(*v, T_MIN - 1);
                assert_eq!(*t_min, T_MIN);
            }
            other => panic!("expected dust rejection, got {other:?}"),
        }
    }
}
