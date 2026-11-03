//! GIP-2 WP-D2d: the ballot collector service (runbook stage R3, third
//! work item) - the ingest endpoint + archive + close + publish.
//!
//! This is the node-side counterpart of the R1 `dress_collector` bin:
//! the same [`BallotArchive`] mechanics (reused VERBATIM, no new
//! crypto - the runbook pins that), but the ingest endpoint now speaks
//! the WP-D2c gossip channel instead of a drop directory:
//!
//! * senders ship GBE1 envelopes through
//!   [`opacus_network::gov_channel::seal_stream`] - the envelope wire
//!   chunked into opaque sealed note blobs keyed by the public
//!   `envelope_id` - and drop the blobs into the collector's SPOOL
//!   directory, the file-per-blob stand-in for the v5 note path (the
//!   chunk header lives inside the sealed payload, so the spool, like
//!   the network, never interprets anything);
//! * [`GovCollectorService::drain_spool`] consumes the spool in a
//!   deterministic (sorted) scan, opens every blob with the collector
//!   NODE identity and feeds [`GovAssembler`]: a completed stream
//!   emits the envelope wire byte-exactly, a byte-equal retransmission
//!   (even re-sealed, fresh ECIES blobs) is dropped by the assembler,
//!   and anything that opens but violates the channel is a hard
//!   channel verdict - logged, never fatal;
//! * a completed wire is routed blind (the R1 discipline): GBE1 magic
//!   goes to `BallotArchive::ingest_sealed` (scope check, open with
//!   the collector BALLOT key, byte-equal dedupe), everything else to
//!   `ingest_raw` (the documented weaker fallback). Every verdict -
//!   accepted, retransmission, rejected, chunk pending - lands in the
//!   event log; nothing is silently dropped;
//! * [`GovCollectorService::close`] tallies (`tally::<DEPTH>`), runs
//!   the pure P-6 decision rule and publishes `{minutes_body,
//!   minutes_digest}` - the EXACT R1 minutes schema, so the R1
//!   `dress_auditor` replays a service close unchanged.
//!
//! State is one JSON file (`state.json`): the archived ballots in
//! arrival order plus the full event log plus the completed stream
//! ids. Reopening rebuilds the archive by the canonical raw parse
//! (the auditor path, zero proving), so ingest/close can run as
//! separate processes and the archive survives restarts.
//!
//! Layering: `opacus-node` already depends on `opacus-network`; the
//! wallet dependency enters here because the collector owns ballot
//! mechanics. The wallet's own production graph stays node-free (the
//! WP-D2c property is untouched).

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use opacus_crypto::ecies::NoteSecret;
use opacus_crypto::CompressedRistretto;
use opacus_network::gov_channel::{feed_note, GovAssembler, GovChannelError};
use opacus_network::identity::NodeIdentity;
use opacus_network::NoteBlob;
use opacus_wallet::gov::GovError;
use opacus_wallet::gov_transport::{
    BallotArchive, BallotEnvelope, Ingest, TransportError, ENVELOPE_MAGIC,
};
use opacus_wallet::tally::{decide, tally, DeclaredProposal, Outcome, Rejection};
use opacus_wallet::zk_spend::fp_to_bytes;
use serde_json::json;

/// Mainnet-shaped frontier depth (the runbook pins the rehearsal to 32).
pub const DEPTH: usize = 32;

/// The state file name inside the collector state directory.
pub const STATE_FILE: &str = "state.json";
/// The node identity file name inside the collector state directory
/// (the routing trust root; the ballot key is a separate trust root).
pub const IDENTITY_FILE: &str = "collector-identity.json";
/// The spool file extension (one sealed channel blob per file).
pub const CHUNK_EXT: &str = "gchunk";

/// The rehearsal collector key policy (the same `domain_bytes`
/// derivation the R1 `dress/common.rs` pins: no new trust root - the
/// secret half opens the envelopes at close, the public half is
/// declared with the proposal). Production operator keys enter later
/// with the wallet CLI integration; the service itself takes the
/// [`NoteSecret`] from the caller.
pub fn collector_keys_from_seed(seed: u64) -> (NoteSecret, CompressedRistretto) {
    let mut seed64 = [0u8; 64];
    seed64[..32].copy_from_slice(&domain_bytes(seed, "collector", 0));
    seed64[32..].copy_from_slice(&domain_bytes(seed, "collector", 1));
    let sk = opacus_wallet::gov_transport::ballot_keypair_from_seed(&seed64);
    let pk = sk.public();
    (sk, pk)
}

/// The shared rehearsal derivation (byte-identical to
/// `dress/common.rs::domain_bytes` - one blake3 call per value).
fn domain_bytes(seed: u64, domain: &str, idx: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"opacus-dress-rehearsal-v1");
    h.update(&seed.to_le_bytes());
    h.update(domain.as_bytes());
    h.update(&(idx as u64).to_le_bytes());
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// The verdict/label vocabulary (the exact R1 strings, so the minutes of
// a service close and a dress close are indistinguishable to the auditor)
// ---------------------------------------------------------------------------

fn gov_err_kind(e: &GovError) -> String {
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

fn rejection_label(r: &Rejection) -> String {
    match r {
        Rejection::Malformed(e) => format!("malformed:{}", gov_err_kind(e)),
        Rejection::ProposalMismatch => "proposal_mismatch".into(),
        Rejection::AnchorMismatch => "anchor_mismatch".into(),
        Rejection::DuplicateSerial => "duplicate_serial".into(),
    }
}

fn transport_label(e: &TransportError) -> String {
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

fn ingest_label(r: &Result<Ingest, TransportError>) -> String {
    match r {
        Ok(Ingest::Accepted { index }) => format!("accepted@{index}"),
        Ok(Ingest::Retransmission) => "retransmission".into(),
        Err(e) => format!("rejected:{}", transport_label(e)),
    }
}

fn outcome_label(o: Outcome) -> &'static str {
    match o {
        Outcome::Accepted => "accepted",
        Outcome::Rejected => "rejected",
        Outcome::NoQuorum => "no_quorum",
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/// The ballot collector service: gossip-channel ingest endpoint +
/// [`BallotArchive`] + close/publish, with one-file JSON persistence.
pub struct GovCollectorService {
    proposal: DeclaredProposal,
    collector_pk: CompressedRistretto,
    collector_sk: NoteSecret,
    archive: BallotArchive,
    asm: GovAssembler,
    identity: NodeIdentity,
    events: Vec<serde_json::Value>,
    completed: BTreeSet<String>,
    state_path: PathBuf,
}

impl GovCollectorService {
    /// Open (or reopen) the collector over `state_dir`: the node
    /// identity is loaded or generated there, the archive is rebuilt
    /// from the persisted ballot entries (the canonical raw parse, the
    /// auditor path - zero proving). The collector BALLOT key comes
    /// from the CALLER (the operator surface - the bin derives it from
    /// the declared rehearsal seed and pins it against the declared
    /// collector_pk; a production deployment would load the operator
    /// key file): the service never guesses a trust root.
    pub fn open(
        state_dir: &Path,
        proposal: DeclaredProposal,
        collector_sk: NoteSecret,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let identity_path = state_dir.join(IDENTITY_FILE);
        let (identity, _) = NodeIdentity::load_or_generate(&identity_path)
            .map_err(|e| io::Error::other(format!("collector identity: {e}")))?;
        let collector_pk = collector_sk.public();
        let mut archive = BallotArchive::new(proposal.gip, proposal.transition, proposal.h_open);
        let state_path = state_dir.join(STATE_FILE);
        let mut events = Vec::new();
        let mut completed = BTreeSet::new();
        if state_path.exists() {
            let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&state_path)?)
                .map_err(|e| io::Error::other(format!("{}: {e}", state_path.display())))?;
            for e in doc["entries"]
                .as_array()
                .ok_or_else(|| io::Error::other("state.entries missing"))?
            {
                let wire = hex::decode(
                    e["wire"]
                        .as_str()
                        .ok_or_else(|| io::Error::other("entry wire"))?,
                )
                .map_err(|e| io::Error::other(format!("entry wire hex: {e}")))?;
                archive.ingest_raw(&wire).map_err(|e| {
                    io::Error::other(format!("persisted entry is not canonical: {e}"))
                })?;
            }
            if let Some(list) = doc["events"].as_array() {
                events = list.clone();
            }
            if let Some(list) = doc["completed"].as_array() {
                for s in list.iter().filter_map(|s| s.as_str()) {
                    completed.insert(s.to_string());
                }
            }
        }
        Ok(Self {
            proposal,
            collector_pk,
            collector_sk,
            archive,
            // Bounded like the channel: 256 concurrent streams, an
            // 8192-id dedupe window (one rehearsal vote is ~16).
            asm: GovAssembler::new(256, 8192),
            identity,
            events,
            completed,
            state_path,
        })
    }

    /// The collector NODE routing key to publish with the declaration
    /// (the senders chunk + seal to this point; the node identity
    /// routes, the ballot key opens).
    pub fn routing_pk(&self) -> CompressedRistretto {
        self.identity.pr
    }

    /// The hex routing key (the `collector-node.json` payload).
    pub fn routing_pk_hex(&self) -> String {
        hex::encode(self.identity.pr.as_bytes())
    }

    /// The 16-hex node id (log shorthand).
    pub fn node_id_short(&self) -> String {
        hex::encode(opacus_network::identity::node_id_of(
            &self.identity.pe,
            &self.identity.pr,
        ))[..16]
            .to_string()
    }

    /// The archived ballot count so far.
    pub fn archived(&self) -> usize {
        self.archive.len()
    }

    /// The event log so far.
    pub fn events(&self) -> &[serde_json::Value] {
        &self.events
    }

    /// Completed stream ids (hex), the envelope-level arrival record.
    pub fn completed_streams(&self) -> Vec<String> {
        self.completed.iter().cloned().collect()
    }

    /// Ingest one serialized channel blob (one spool file payload).
    /// The blind router: whatever happens, the verdict lands in the
    /// event log and `Err` is reserved for LOCAL failures (state io),
    /// never for peer bytes.
    pub fn ingest_blob(&mut self, label: &str, bytes: &[u8]) -> Result<String, io::Error> {
        let verdict = match serde_json::from_slice::<NoteBlob>(bytes) {
            Ok(blob) => match feed_note(&blob, &self.identity, &mut self.asm) {
                Ok(None) => "chunk:pending-or-duplicate".to_string(),
                Ok(Some(wire)) => self.completed_wire(label, &wire),
                Err(e) => format!("rejected:channel:{}", channel_label(&e)),
            },
            Err(e) => format!("rejected:blob_parse:{e}"),
        };
        self.events.push(json!({
            "file": label,
            "bytes": bytes.len(),
            "result": verdict,
        }));
        Ok(verdict)
    }

    /// A reassembled wire: GBE1 magic -> the sealed path (open with the
    /// collector BALLOT key, byte-equal dedupe), anything else -> the
    /// raw fallback. The stream id is recorded at completion.
    fn completed_wire(&mut self, label: &str, wire: &[u8]) -> String {
        let sid = if let Ok(env) = BallotEnvelope::from_bytes(wire) {
            match env.envelope_id() {
                Ok(id) => hex::encode(id),
                Err(_) => "opaque".to_string(),
            }
        } else {
            // The raw-fallback profile: stream id = blake3 over the wire.
            hex::encode(blake3::hash(wire).as_bytes())
        };
        self.completed.insert(sid.clone());
        let verdict = if wire.starts_with(&ENVELOPE_MAGIC) {
            match BallotEnvelope::from_bytes(wire) {
                Ok(env) => ingest_label(&self.archive.ingest_sealed(&env, &self.collector_sk)),
                Err(e) => format!("rejected:{}", transport_label(&e)),
            }
        } else {
            ingest_label(&self.archive.ingest_raw(wire))
        };
        self.events.push(json!({
            "file": format!("stream-complete:{sid}"),
            "bytes": wire.len(),
            "result": verdict,
            "via": label,
        }));
        verdict
    }

    /// Drain the spool directory (the ingest endpoint): every
    /// `*.gchunk` file in sorted order is ingested and REMOVED - the
    /// spool is an endpoint, the event log and the archive are the
    /// record. Returns the number of blobs consumed.
    pub fn drain_spool(&mut self, spool: &Path) -> Result<usize, io::Error> {
        std::fs::create_dir_all(spool)?;
        let mut files: Vec<PathBuf> = std::fs::read_dir(spool)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(CHUNK_EXT))
            .collect();
        files.sort();
        let mut count = 0usize;
        for path in files {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let bytes = std::fs::read(&path)?;
            self.ingest_blob(&name, &bytes)?;
            std::fs::remove_file(&path)?;
            count += 1;
        }
        Ok(count)
    }

    /// Persist the archive + event log (`state.json`).
    pub fn save(&self) -> io::Result<()> {
        let doc = json!({
            "scope": {
                "gip": self.proposal.gip,
                "transition": self.proposal.transition,
                "h_open": self.proposal.h_open,
            },
            "archived": self.archive.len(),
            "completed": self.completed_streams(),
            "entries": self
                .archive
                .entries()
                .iter()
                .enumerate()
                .map(|(i, e)| json!({ "index": i, "wire": hex::encode(e) }))
                .collect::<Vec<_>>(),
            "events": self.events,
        });
        let tmp = self.state_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&doc)?)?;
        std::fs::rename(&tmp, &self.state_path)
    }

    /// Close: tally + the pure P-6 decision rule + publish the minutes
    /// (the EXACT R1 schema - `{minutes_body, minutes_digest}`,
    /// blake3-pinned over the canonical body - so the R1
    /// `dress_auditor` replays a service close unchanged). Returns the
    /// close statement values (also printed to stdout by the bin).
    pub fn close(&self, minutes_out: &Path) -> Result<CloseStatement, io::Error> {
        let record = tally::<DEPTH, _>(&self.proposal, self.archive.entries())
            .map_err(|e| io::Error::other(format!("tally: {e}")))?;
        let (quorum, outcome) = decide(
            record.class,
            record.denominator,
            record.yes,
            record.no,
            record.abstain,
        );
        assert_eq!(quorum, record.quorum_met, "decide/tally quorum agree");
        assert_eq!(outcome, record.outcome, "decide/tally outcome agree");

        let body = json!({
            "declared": {
                "gip": self.proposal.gip,
                "transition": self.proposal.transition,
                "h_open": self.proposal.h_open,
                "anchor": hex::encode(fp_to_bytes(self.proposal.anchor)),
                "class": "fund",
                "collector_pk": hex::encode(self.collector_pk.as_bytes()),
            },
            "archive_id": hex::encode(self.archive.archive_id()),
            "entries": self
                .archive
                .entries()
                .iter()
                .enumerate()
                .map(|(i, e)| json!({ "index": i, "wire": hex::encode(e) }))
                .collect::<Vec<_>>(),
            "ingest_events": self.events,
            "tally": {
                "gip": record.gip,
                "transition": record.transition,
                "h_open": record.h_open,
                "class": "fund",
                "denominator": record.denominator,
                "yes": record.yes,
                "no": record.no,
                "abstain": record.abstain,
                "accepted": record.accepted,
                "rejected": record.rejected,
                "quorum_met": record.quorum_met,
                "outcome": outcome_label(record.outcome),
                "result_hash": hex::encode(record.result_hash),
            },
            "trace": record
                .trace
                .iter()
                .map(|t| {
                    json!({
                        "index": t.index,
                        "sighash": t.sighash.map(hex::encode),
                        "accepted": t.accepted,
                        "rejection": t.rejection.as_ref().map(rejection_label),
                    })
                })
                .collect::<Vec<_>>(),
            "record_wire_hex": hex::encode(record.to_bytes()),
        });
        let document = json!({
            "minutes_body": body,
            "minutes_digest": hex::encode(blake3::hash(
                &serde_json::to_vec_pretty(&body).expect("body serializes")
            ).as_bytes()),
        });
        if let Some(parent) = minutes_out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(minutes_out, serde_json::to_vec_pretty(&document)?)?;
        Ok(CloseStatement {
            outcome: outcome_label(record.outcome).to_string(),
            yes: record.yes,
            no: record.no,
            abstain: record.abstain,
            accepted: record.accepted,
            rejected: record.rejected,
            result_hash: hex::encode(record.result_hash),
            archive_id: hex::encode(self.archive.archive_id()),
        })
    }
}

/// The close statement (printed and logged by the bin/scenario).
#[derive(Debug, Clone)]
pub struct CloseStatement {
    pub outcome: String,
    pub yes: u64,
    pub no: u64,
    pub abstain: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub result_hash: String,
    pub archive_id: String,
}

/// The channel error vocabulary for the blind event log.
fn channel_label(e: &GovChannelError) -> String {
    match e {
        GovChannelError::EmptyStream => "empty_stream".into(),
        GovChannelError::StreamTooLarge(_) => "stream_too_large".into(),
        GovChannelError::ChunkTooLarge(_) => "chunk_too_large".into(),
        GovChannelError::TooManyChunks { .. } => "too_many_chunks".into(),
        GovChannelError::IndexOutOfRange { .. } => "index_out_of_range".into(),
        GovChannelError::BadChunkVersion(_) => "bad_chunk_version".into(),
        GovChannelError::ChunkNotCanonical { .. } => "chunk_not_canonical".into(),
        GovChannelError::StreamConflict => "stream_conflict".into(),
        GovChannelError::TooManyStreams(_) => "too_many_streams".into(),
        GovChannelError::HashMismatch => "hash_mismatch".into(),
        GovChannelError::Note(_) => "enote".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opacus_wallet::gov::{build_ballot, verify_ballot, Choice};
    use opacus_wallet::gov_transport::ballot_keypair_from_seed;
    use opacus_wallet::tx_v4::WalletNoteV4;
    use opacus_wallet::zk_spend::{fp_to_bytes, TreeState};
    use opacus_zk::prelude::Fp;

    const GIP: u32 = 2;
    const TRANSITION: u8 = 0;
    const H_OPEN: u64 = 100;

    fn domain_fp(domain: &str, idx: usize) -> Fp {
        Fp::from(u64::from_le_bytes(
            blake3::Hasher::new()
                .update(b"opacus-gov-collector-test-v1")
                .update(domain.as_bytes())
                .update(&(idx as u64).to_le_bytes())
                .finalize()
                .as_bytes()[..8]
                .try_into()
                .expect("u64 slice"),
        ))
    }

    fn deterministic_note(leaf: usize, value: u64) -> WalletNoteV4 {
        WalletNoteV4 {
            d: fp_to_bytes(domain_fp("diversifier", leaf)),
            a: fp_to_bytes(domain_fp("share-a", leaf)),
            b: fp_to_bytes(domain_fp("share-b", leaf)),
            rho: fp_to_bytes(domain_fp("rho", leaf)),
            value,
        }
    }

    /// Two real DEPTH=32 ballots on one declared frontier (the only
    /// proves in this module): voter 0 votes For (ships SEALED), voter
    /// 1 votes Against (ships RAW - the documented weaker fallback).
    fn honest_ballots() -> (DeclaredProposal, Vec<u8>, [u8; 32], Vec<u8>) {
        let mut tree = TreeState::new(DEPTH);
        let voter0 = deterministic_note(0, 12_000_000_000);
        tree.append(voter0.tree_entry().expect("seeded note"));
        let voter1 = deterministic_note(1, 9_000_000_000);
        tree.append(voter1.tree_entry().expect("seeded note"));
        for leaf in 2..4 {
            tree.append(
                deterministic_note(leaf, 9_500_000_000 + leaf as u64)
                    .tree_entry()
                    .expect("seeded note"),
            );
        }
        let b0 = build_ballot::<DEPTH>(
            &tree,
            &[0],
            &[&voter0],
            GIP,
            TRANSITION,
            H_OPEN,
            Choice::For,
        )
        .expect("ballot 0 builds");
        let b1 = build_ballot::<DEPTH>(
            &tree,
            &[1],
            &[&voter1],
            GIP,
            TRANSITION,
            H_OPEN,
            Choice::Against,
        )
        .expect("ballot 1 builds");
        verify_ballot::<DEPTH>(&b0).expect("ballot 0 verifies");
        verify_ballot::<DEPTH>(&b1).expect("ballot 1 verifies");
        let proposal = DeclaredProposal {
            gip: GIP,
            transition: TRANSITION,
            h_open: H_OPEN,
            anchor: tree.root(),
            class: opacus_wallet::tally::VoteClass::Fund,
        };
        let collector_pk = collector_keys_from_seed(GIP as u64).1;
        let env = BallotEnvelope::seal(&b0, &collector_pk).expect("seal");
        let sid = env.envelope_id().expect("envelope id");
        (proposal, env.to_bytes(), sid, b1.to_bytes())
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gov-collector-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// Ship one envelope wire through the spool endpoint: chunk + seal
    /// to the collector routing key, one file per blob (exactly what
    /// the sender example does).
    fn ship(spool: &Path, wire: &[u8], sid: [u8; 32], routing: &CompressedRistretto) -> usize {
        std::fs::create_dir_all(spool).expect("spool dir");
        let blobs =
            opacus_network::gov_channel::seal_stream(wire, sid, routing).expect("chunk + seal");
        for b in &blobs {
            let digest = blake3::hash(&serde_json::to_vec(b).expect("blob json"));
            let name = format!("{}.{}", hex::encode(&digest.as_bytes()[..12]), CHUNK_EXT);
            std::fs::write(spool.join(name), serde_json::to_vec(b).expect("blob json"))
                .expect("spool write");
        }
        blobs.len()
    }

    #[test]
    fn spool_endpoint_archive_close_and_persistence() {
        let dir = temp_dir("e2e");
        let spool = dir.join("spool");
        let state = dir.join("collector");
        let (proposal, wire, sid, raw) = honest_ballots();

        let mut svc = GovCollectorService::open(
            &state,
            proposal.clone(),
            collector_keys_from_seed(GIP as u64).0,
        )
        .expect("open");
        let routing = svc.routing_pk();

        // 1. The sealed envelope rides the channel endpoint: 52 blobs,
        //    the last one completes the stream into the archive.
        let n = ship(&spool, &wire, sid, &routing);
        assert_eq!(n, 52, "the GBE1 shape chunks exactly like the D2c e2e");
        let drained = svc.drain_spool(&spool).expect("drain");
        assert_eq!(drained, n);
        assert_eq!(svc.archived(), 1, "one honest ballot archived");
        let log = format!("{:?}", svc.events());
        assert!(log.contains("accepted@0"), "the accept is logged: {log}");
        assert!(
            log.contains("chunk:pending-or-duplicate"),
            "the 51 lead chunks are logged"
        );

        // 2. The raw fallback over the same endpoint (the documented
        //    weaker profile): a DIFFERENT ballot's canonical wire - the
        //    completed stream carries no GBE1 magic and lands in the
        //    archive through ingest_raw. (A raw copy of the SAME ballot
        //    would be the R1 retransmission case instead.)
        let raw_sid: [u8; 32] = *blake3::hash(&raw).as_bytes();
        ship(&spool, &raw, raw_sid, &routing);
        svc.drain_spool(&spool).expect("drain raw");
        assert_eq!(svc.archived(), 2, "the raw fallback is archived");

        // 3. A byte-equal retransmission, RE-SEALED (fresh ECIES blobs,
        //    same chunk plaintexts, same envelope id): the assembler
        //    drops every chunk, nothing new is archived, no new stream
        //    completes.
        let completes_before = svc.completed_streams().len();
        let n2 = ship(&spool, &wire, sid, &routing);
        svc.drain_spool(&spool).expect("drain retransmit");
        assert_eq!(svc.archived(), 2, "retransmission changes nothing");
        assert_eq!(
            svc.completed_streams().len(),
            completes_before,
            "no second stream may complete"
        );
        assert_eq!(n2, 52);

        // 4. Blind-minutes discipline: garbage files are logged, never
        //    fatal, and never silently dropped.
        std::fs::write(spool.join("broken.gchunk"), b"{not json").expect("garbage");
        std::fs::write(spool.join("ignored.txt"), b"wrong extension").expect("wrong ext");
        let drained = svc.drain_spool(&spool).expect("drain garbage");
        assert_eq!(drained, 1, "only the channel extension is consumed");
        assert!(spool.join("ignored.txt").exists(), "foreign files stay");
        let log = format!("{:?}", svc.events());
        assert!(
            log.contains("rejected:blob_parse"),
            "garbage is logged: {log}"
        );

        // 5. Persistence: reopen rebuilds the archive (the auditor
        //    path) and the completed-stream record.
        svc.save().expect("save");
        let completed_before = svc.completed_streams();
        let events_before = svc.events().len();
        drop(svc);
        let svc2 = GovCollectorService::open(
            &state,
            proposal.clone(),
            collector_keys_from_seed(GIP as u64).0,
        )
        .expect("reopen");
        assert_eq!(svc2.archived(), 2, "the archive survives the restart");
        assert_eq!(svc2.completed_streams(), completed_before);
        assert_eq!(svc2.events().len(), events_before);

        // 6. Close: the tally + decision rule + the R1 minutes schema.
        let minutes = dir.join("minutes.json");
        let stmt = svc2.close(&minutes).expect("close");
        assert_eq!(stmt.accepted, 2, "both ballots accepted");
        assert_eq!(stmt.rejected, 0);
        assert_eq!(
            stmt.outcome, "no_quorum",
            "12e9 of 1e12 misses the 5% Fund quorum"
        );
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&minutes).expect("minutes")).expect("json");
        assert_eq!(
            doc["minutes_body"]["entries"]
                .as_array()
                .expect("entries")
                .len(),
            2
        );
        assert_eq!(
            doc["minutes_body"]["tally"]["result_hash"]
                .as_str()
                .expect("hash"),
            stmt.result_hash
        );
        assert_eq!(
            doc["minutes_body"]["archive_id"].as_str().expect("id"),
            stmt.archive_id
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collector_key_policy_matches_the_rehearsal_derivation() {
        // The service key policy and the R1 dress derivation agree (the
        // declared collector_pk opens what the rehearsal voters sealed).
        let (sk, pk) = collector_keys_from_seed(42);
        let mut seed64 = [0u8; 64];
        seed64[..32].copy_from_slice(&domain_bytes(42, "collector", 0));
        seed64[32..].copy_from_slice(&domain_bytes(42, "collector", 1));
        let sk2 = ballot_keypair_from_seed(&seed64);
        assert_eq!(
            hex::encode(sk.public().as_bytes()),
            hex::encode(pk.as_bytes())
        );
        assert_eq!(
            hex::encode(sk.public().as_bytes()),
            hex::encode(sk2.public().as_bytes())
        );
    }
}
