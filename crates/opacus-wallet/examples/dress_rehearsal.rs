//! GIP-2 WP-D0 (runbook stage R0): the deterministic in-process dress
//! rehearsal.
//!
//! One command runs the WHOLE GIP-2 protocol against a synthetic frontier
//! with the real prover and records the close artifacts:
//!
//! ```sh
//! cargo run -p opacus-wallet --release --example dress_rehearsal -- \
//!     --voters 7 --seed 42 --out artifacts/
//! ```
//!
//! Determinism contract (`docs/gips/GIP-2-dress-rehearsal-runbook.md`,
//! stage R0): every decision artifact is a pure function of `--seed` -
//! the note fields, the tree frontier, the serials, the sighashes, the
//! weight totals, the outcome, the `result_hash` and the `archive_id`
//! over the produced minutes. The ONLY run-to-run variance is the halo2
//! proof blinding (OsRng inside `create_proof`): the ballot wire bytes
//! and therefore the literal entry hex differ between runs while every
//! decision artifact stays identical, and the golden replay test
//! (`tests/dress_rehearsal_golden.rs`) pins exactly the stable part.
//!
//! Script (runbook R0, step by step):
//! 1. A `TreeState` at mainnet depth; one note per voter, values mixed
//!    around `T_MIN` on purpose (the 8th leaf is a dust note that can
//!    never vote).
//! 2. The proposal declaration: gip 2, transition 0, h_open 100,
//!    `anchor = tree.root()`, class Fund.
//! 3. The collector key: `ballot_keypair_from_seed` (a derivation - no
//!    new trust root); the declaration is written BEFORE any ballot.
//! 4. Per voter: `build_ballot` -> `verify_ballot` -> seal to the
//!    collector key -> `ingest_sealed`. Voter 0 re-publishes the same
//!    ballot over the raw fallback (a byte-equal RETRANSMISSION);
//!    voter 1 publishes ONLY raw (the two transports must feed the
//!    tally identically).
//! 5. The adversarial matrix - every case must surface, none is fatal:
//!    a build-time dust rejection (the T_MIN gate BEFORE the proving
//!    work), a dust ballot smuggled over the raw fallback
//!    (Malformed(Dust) in the trace), a double vote on the same notes
//!    (DuplicateSerial), a foreign-scope envelope (wrong h_open ->
//!    ProposalMismatch), a relabelled envelope (HeaderMismatch), a
//!    corrupted envelope byte (MacMismatch), a truncated blob
//!    (Truncated) and an oversized blob (Oversize).
//! 6. `tally` + `decide`; the trace must cover the injected faults;
//!    the shuffled archive re-tally yields the SAME `result_hash` and
//!    a DIFFERENT `archive_id` (P-5: the decision is order-invariant,
//!    the minutes fingerprint their submission history).
//! 7. `declared.json`, `minutes.json` and `golden-vectors.json` are
//!    written to `--out` (the committed golden set lives under
//!    `crates/opacus-wallet/tests/vectors/`).

use std::fs;
use std::path::PathBuf;

use opacus_crypto::CompressedRistretto;
use opacus_wallet::gov::{build_ballot, verify_ballot, Choice, GovError, T_MIN};
use opacus_wallet::gov_transport::{
    ballot_keypair_from_seed, BallotArchive, BallotEnvelope, Ingest, TransportError,
    ENVELOPE_HEADER_LEN, ENVELOPE_MIN_SEALED_LEN, MAX_ENVELOPE_BYTES,
};
use opacus_wallet::tally::{
    decide, emission_upto, tally, DeclaredProposal, Outcome, Rejection, VoteClass,
};
use opacus_wallet::tx_v4::WalletNoteV4;
use opacus_wallet::zk_spend::{fp_to_bytes, TreeState};
use opacus_zk::prelude::Fp;

/// Mainnet-shaped frontier depth (the runbook pins `TreeState::<32>`).
const DEPTH: usize = 32;
/// The declared proposal shape of the rehearsal (runbook R0 step 2).
const GIP: u32 = 2;
const TRANSITION: u8 = 0;
const H_OPEN: u64 = 100;

// ---------------------------------------------------------------------------
// Deterministic derivation
// ---------------------------------------------------------------------------

/// Counter-based domain-separated derivation: one blake3 call per value,
/// nothing shared, nothing mutable - the whole rehearsal is a pure
/// function of the seed.
fn domain_bytes(seed: u64, domain: &str, idx: usize) -> [u8; 32] {
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
fn deterministic_note(seed: u64, leaf: usize, value: u64) -> WalletNoteV4 {
    WalletNoteV4 {
        d: fp_to_bytes(domain_fp(seed, "diversifier", leaf)),
        a: fp_to_bytes(domain_fp(seed, "share-a", leaf)),
        b: fp_to_bytes(domain_fp(seed, "share-b", leaf)),
        rho: fp_to_bytes(domain_fp(seed, "rho", leaf)),
        value,
    }
}

// ---------------------------------------------------------------------------
// The rehearsal shape
// ---------------------------------------------------------------------------

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
const DUST_LEAF_VALUE: u64 = 500_000;

fn voter_value(i: usize) -> u64 {
    if i < VOTER_VALUES.len() {
        VOTER_VALUES[i]
    } else {
        // Deterministic extension beyond the canonical shape.
        10_500_000_000 + ((i as u64 * 1_250_000_007) % 3_000_000_000)
    }
}

fn voter_choice(i: usize) -> Choice {
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

// ---------------------------------------------------------------------------
// Ingest event log (the minutes' transport-side trace: blind, complete)
// ---------------------------------------------------------------------------

struct Event {
    step: &'static str,
    subject: String,
    result: String,
}

impl Event {
    fn new(step: &'static str, subject: impl Into<String>, result: impl Into<String>) -> Self {
        Event {
            step,
            subject: subject.into(),
            result: result.into(),
        }
    }
}

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

// ---------------------------------------------------------------------------
// Wire helpers (the byte-exact injection points are part of the record)
// ---------------------------------------------------------------------------

/// Offset of the `v` field in the canonical ballot wire: version 1 +
/// gip 4 + transition 1 + h_open 8 + choice 1 + anchor 32 + proposal 32.
const WIRE_V_OFFSET: usize = 79;
/// Offset of the cleartext `h_open` in the envelope wire: magic 4 +
/// version 1 + gip 4 + transition 1.
const ENVELOPE_H_OPEN_OFFSET: usize = 10;

fn patch_u64_le(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// The rehearsal
// ---------------------------------------------------------------------------

struct Args {
    voters: usize,
    seed: u64,
    out: PathBuf,
}

fn parse_args() -> Args {
    let mut args = Args {
        voters: 7,
        seed: 42,
        out: PathBuf::from("artifacts"),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--voters" => {
                args.voters = it
                    .next()
                    .expect("--voters needs a value")
                    .parse()
                    .expect("--voters must be a number");
            }
            "--seed" => {
                args.seed = it
                    .next()
                    .expect("--seed needs a value")
                    .parse()
                    .expect("--seed must be a number");
            }
            "--out" => {
                args.out = PathBuf::from(it.next().expect("--out needs a value"));
            }
            other => panic!("unknown argument: {other} (supported: --voters --seed --out)"),
        }
    }
    args
}

fn main() {
    let args = parse_args();
    let seed = args.seed;
    let voters = args.voters.max(1);
    println!(
        "dress rehearsal: voters={voters} seed={seed} depth={DEPTH} out={}",
        args.out.display()
    );

    // R0 step 1: the synthetic frontier. Every field is a pure function
    // of the seed; the values deliberately straddle T_MIN.
    let mut tree = TreeState::new(DEPTH);
    let mut notes = Vec::with_capacity(voters + 1);
    for i in 0..voters {
        let note = deterministic_note(seed, i, voter_value(i));
        tree.append(note.tree_entry().expect("seeded note is well-formed"));
        notes.push(note);
    }
    let dust_note = deterministic_note(seed, voters, DUST_LEAF_VALUE);
    tree.append(dust_note.tree_entry().expect("seeded note is well-formed"));
    println!(
        "frontier: {} leaves ({} voting notes + 1 dust leaf), root anchored",
        tree.len(),
        voters
    );

    // R0 step 2: the declaration (P-3: anchor = root at H_open).
    let anchor = tree.root();
    let declared = DeclaredProposal {
        gip: GIP,
        transition: TRANSITION,
        h_open: H_OPEN,
        anchor,
        class: VoteClass::Fund,
    };

    // R0 step 3: the collector key (a seed derivation - no new trust
    // root) is published WITH the declaration, before any ballot.
    let mut collector_seed = [0u8; 64];
    collector_seed[..32].copy_from_slice(&domain_bytes(seed, "collector", 0));
    collector_seed[32..].copy_from_slice(&domain_bytes(seed, "collector", 1));
    let collector_sk = ballot_keypair_from_seed(&collector_seed);
    let collector_pk = collector_sk.public();
    println!(
        "collector key published: {}",
        hex_encode(collector_pk.as_bytes())
    );

    // R0 step 4: the honest vote window.
    let mut archive = BallotArchive::new(GIP, TRANSITION, H_OPEN);
    let mut events: Vec<Event> = Vec::new();
    let mut sealed_bytes: Vec<Vec<u8>> = vec![Vec::new(); voters];
    let mut raw_bytes: Vec<Vec<u8>> = vec![Vec::new(); voters];
    for i in 0..voters {
        let choice = voter_choice(i);
        let ballot =
            build_ballot::<DEPTH>(&tree, &[i], &[&notes[i]], GIP, TRANSITION, H_OPEN, choice)
                .expect("honest voter ballot must build");
        verify_ballot::<DEPTH>(&ballot).expect("honest voter ballot must verify standalone");
        let raw = ballot.to_bytes();
        let outcome = if i == 1 {
            // Voter 1 publishes ONLY the raw fallback (documented
            // weaker, P-4): same canonical bytes, no envelope.
            archive.ingest_raw(&raw)
        } else {
            let env = BallotEnvelope::seal(&ballot, &collector_pk).expect("sealing must not fail");
            let wire = env.to_bytes();
            sealed_bytes[i] = wire;
            archive.ingest_sealed(&env, &collector_sk)
        };
        raw_bytes[i] = raw;
        println!(
            "voter {i} ({choice:?}, v={}): {}",
            notes[i].value,
            ingest_label(&outcome)
        );
        events.push(Event::new(
            "honest-vote",
            format!("voter{i}/{choice:?}"),
            ingest_label(&outcome),
        ));
        if i == 0 {
            // Voter 0 re-publishes the SAME ballot over the fallback:
            // a byte-equal retransmission must dedupe, never double
            // count (P-4).
            let dup = archive.ingest_raw(&raw_bytes[0]);
            println!("voter 0 raw retransmission: {}", ingest_label(&dup));
            events.push(Event::new(
                "retransmission",
                "voter0/raw-copy",
                ingest_label(&dup),
            ));
            assert!(
                matches!(dup, Ok(Ingest::Retransmission)),
                "byte-equal retransmission must dedupe"
            );
        }
    }

    // R0 step 5: the adversarial matrix. None of these may crash the
    // collector; every one must surface in the event log or the trace.
    inject_adversaries(&mut AdversaryCtx {
        seed,
        tree: &tree,
        notes: &notes,
        collector_pk: &collector_pk,
        collector_sk: &collector_sk,
        archive: &mut archive,
        events: &mut events,
        raw_bytes: &raw_bytes,
        sealed_bytes: &sealed_bytes,
    });

    // R0 step 6: the tally and the decision.
    let record = tally::<DEPTH, _>(&declared, archive.entries()).expect("tally must not overflow");
    let denominator = emission_upto(H_OPEN);
    let (quorum_met, outcome) = decide(
        declared.class,
        denominator,
        record.yes,
        record.no,
        record.abstain,
    );
    assert_eq!(quorum_met, record.quorum_met, "decide/tally quorum agree");
    assert_eq!(outcome, record.outcome, "decide/tally outcome agree");

    // The trace must cover the injected faults (P-5 traceability).
    let dust_hits = record
        .trace
        .iter()
        .filter(|t| {
            matches!(
                &t.rejection,
                Some(Rejection::Malformed(GovError::Dust { .. }))
            )
        })
        .count();
    let dup_hits = record
        .trace
        .iter()
        .filter(|t| matches!(&t.rejection, Some(Rejection::DuplicateSerial)))
        .count();
    let accepted = record.trace.iter().filter(|t| t.accepted).count();
    assert_eq!(dust_hits, 1, "the smuggled dust ballot must surface once");
    assert_eq!(dup_hits, 1, "the double vote must surface once");
    assert_eq!(accepted, voters, "every honest ballot must be accepted");
    assert_eq!(
        accepted as u64, record.accepted,
        "trace/record accepted counts agree"
    );

    // P-5 replay: shuffle the archive, re-tally, SAME result_hash.
    let mut shuffled: Vec<Vec<u8>> = archive.entries().to_vec();
    shuffled.reverse();
    let replay = tally::<DEPTH, _>(&declared, &shuffled).expect("replay tally must not overflow");
    assert_eq!(
        record.result_hash, replay.result_hash,
        "result_hash is order-invariant (P-5)"
    );
    // ...while the minutes fingerprint their submission history.
    let mut replay_archive = BallotArchive::new(GIP, TRANSITION, H_OPEN);
    for e in &shuffled {
        replay_archive
            .ingest_raw(e)
            .expect("replayed archive entries are canonical");
    }
    assert_ne!(
        archive.archive_id(),
        replay_archive.archive_id(),
        "different arrival order -> different archive_id"
    );
    println!("replay: same result_hash, different archive_id (P-5) - ok");

    // R0 step 7: the close artifacts.
    let golden = serde_json::json!({
        "voters": voters,
        "seed": seed,
        "depth": DEPTH,
        "gip": GIP,
        "transition": TRANSITION,
        "h_open": H_OPEN,
        "class": "fund",
        "result_hash": hex_encode(&record.result_hash),
        "archive_id": hex_encode(&archive.archive_id()),
        "denominator": denominator,
        "yes": record.yes,
        "no": record.no,
        "abstain": record.abstain,
        "accepted": record.accepted,
        "rejected": record.rejected,
        "quorum_met": record.quorum_met,
        "outcome": outcome_label(record.outcome),
        "trace_rejections": {
            "duplicate_serial": dup_hits,
            "dust": dust_hits,
        },
    });
    let minutes = serde_json::json!({
        "declared": declared_json(&declared, &collector_pk),
        "archive_id": hex_encode(&archive.archive_id()),
        "entries": archive
            .entries()
            .iter()
            .enumerate()
            .map(|(i, e)| serde_json::json!({ "index": i, "wire": hex_encode(e) }))
            .collect::<Vec<_>>(),
        "ingest_events": events
            .iter()
            .map(|e| serde_json::json!({
                "step": e.step,
                "subject": e.subject,
                "result": e.result,
            }))
            .collect::<Vec<_>>(),
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
            "result_hash": hex_encode(&record.result_hash),
        },
        "trace": record
            .trace
            .iter()
            .map(|t| serde_json::json!({
                "index": t.index,
                "sighash": t.sighash.map(|s| hex_encode(&s)),
                "accepted": t.accepted,
                "rejection": t.rejection.as_ref().map(rejection_label),
            }))
            .collect::<Vec<_>>(),
        "record_wire_hex": hex_encode(&record.to_bytes()),
    });

    fs::create_dir_all(&args.out).expect("output directory must be creatable");
    let declared_path = args.out.join("declared.json");
    let minutes_path = args.out.join("minutes.json");
    let golden_path = args.out.join("golden-vectors.json");
    fs::write(
        &declared_path,
        serde_json::to_vec_pretty(&declared_json(&declared, &collector_pk)).unwrap(),
    )
    .expect("declared.json must write");
    fs::write(&minutes_path, serde_json::to_vec_pretty(&minutes).unwrap())
        .expect("minutes.json must write");
    fs::write(&golden_path, serde_json::to_vec_pretty(&golden).unwrap())
        .expect("golden-vectors.json must write");

    println!("----------------------------------------------");
    println!(
        "outcome={} yes={} no={} abstain={} accepted={} rejected={}",
        outcome_label(record.outcome),
        record.yes,
        record.no,
        record.abstain,
        record.accepted,
        record.rejected
    );
    println!("result_hash={}", hex_encode(&record.result_hash));
    println!("archive_id={}", hex_encode(&archive.archive_id()));
    println!(
        "artifacts: {} {} {}",
        declared_path.display(),
        minutes_path.display(),
        golden_path.display()
    );
    println!("VERDICT: rehearsal complete, all injected faults surfaced, none fatal");
}

// ---------------------------------------------------------------------------
// The adversarial matrix (runbook R0 step 5)
// ---------------------------------------------------------------------------

/// Everything the injections need, bundled so the injector stays
/// readable (clippy's argument budget is spent on the protocol calls).
struct AdversaryCtx<'a> {
    seed: u64,
    tree: &'a TreeState,
    notes: &'a [WalletNoteV4],
    collector_pk: &'a CompressedRistretto,
    collector_sk: &'a opacus_crypto::ecies::NoteSecret,
    archive: &'a mut BallotArchive,
    events: &'a mut Vec<Event>,
    raw_bytes: &'a [Vec<u8>],
    sealed_bytes: &'a [Vec<u8>],
}

fn inject_adversaries(a: &mut AdversaryCtx<'_>) {
    let seed = a.seed;
    let tree = a.tree;
    let notes = a.notes;
    let collector_pk = a.collector_pk;
    let collector_sk = a.collector_sk;
    let raw_bytes = a.raw_bytes;
    let sealed_bytes = a.sealed_bytes;
    let archive = &mut *a.archive;
    let events = &mut *a.events;
    // 5a. Build-time dust: the owner of the 8th leaf cannot even MINT a
    //     ballot - the T_MIN gate fires before any proving work (P-2).
    let dust_note = deterministic_note(seed, notes.len(), DUST_LEAF_VALUE);
    let build_err = build_ballot::<DEPTH>(
        tree,
        &[notes.len()],
        &[&dust_note],
        GIP,
        TRANSITION,
        H_OPEN,
        Choice::For,
    )
    .expect_err("a dust note must never build a ballot");
    assert!(matches!(build_err, GovError::Dust { .. }));
    println!("build-time dust rejection: {build_err}");
    events.push(Event::new(
        "build-dust",
        format!("leaf{}/dust-owner", notes.len()),
        format!("rejected:{build_err}"),
    ));

    // 5b. Trace-level dust: voter 3's canonical ballot wire patched to
    //     v = T_MIN - 1 smuggles over the blind raw fallback; the
    //     transport accepts (it verifies nothing by design), the tally
    //     surfaces Malformed(Dust) BEFORE the ZK work (P-2 gate order).
    let mut dust_wire = raw_bytes[3].clone();
    patch_u64_le(&mut dust_wire, WIRE_V_OFFSET, T_MIN - 1);
    let dust_ingest = archive.ingest_raw(&dust_wire);
    println!(
        "dust smuggle over raw fallback: {}",
        ingest_label(&dust_ingest)
    );
    events.push(Event::new(
        "trace-dust",
        "smuggled/v=T_MIN-1",
        ingest_label(&dust_ingest),
    ));
    assert!(
        matches!(dust_ingest, Ok(Ingest::Accepted { .. })),
        "the blind archive must accept and let the tally judge"
    );

    // 5c. Double vote: voter 2 votes AGAINST with the SAME notes - the
    //     serials are choice-independent (R-3 determinism), the
    //     distinct wire enters the archive, the tally reports
    //     DuplicateSerial.
    let double = build_ballot::<DEPTH>(
        tree,
        &[2],
        &[&notes[2]],
        GIP,
        TRANSITION,
        H_OPEN,
        Choice::Against,
    )
    .expect("the double-vote ballot builds (the proof is valid)");
    let double_env = BallotEnvelope::seal(&double, collector_pk).expect("sealing must not fail");
    let double_ingest = archive.ingest_sealed(&double_env, collector_sk);
    println!(
        "double vote (voter 2, Against): {}",
        ingest_label(&double_ingest)
    );
    events.push(Event::new(
        "double-vote",
        "voter2/against-same-notes",
        ingest_label(&double_ingest),
    ));

    // 5d. Foreign scope: a VALID ballot minted at h_open = 101, sealed
    //     to the right collector key - the archive scope gate rejects
    //     it before opening (cheap bucket routing, P-4).
    let foreign = build_ballot::<DEPTH>(
        tree,
        &[6],
        &[&notes[6]],
        GIP,
        TRANSITION,
        H_OPEN + 1,
        Choice::For,
    )
    .expect("the foreign-scope ballot builds");
    let foreign_env = BallotEnvelope::seal(&foreign, collector_pk).expect("sealing must not fail");
    let foreign_ingest = archive.ingest_sealed(&foreign_env, collector_sk);
    println!(
        "foreign scope (h_open={}): {}",
        H_OPEN + 1,
        ingest_label(&foreign_ingest)
    );
    events.push(Event::new(
        "foreign-scope",
        format!("voter6/h_open={}", H_OPEN + 1),
        ingest_label(&foreign_ingest),
    ));
    assert!(
        matches!(&foreign_ingest, Err(TransportError::ProposalMismatch)),
        "foreign scope must fail the archive scope gate"
    );

    // 5e. Relabelled envelope: the SAME foreign envelope with its
    //     cleartext h_open patched back to the archive scope - the
    //     scope gate passes, the ballot-header match AFTER opening
    //     fails closed (the WP-3 relabelling guard). The cleartext tag
    //     is outside the MAC, so the seal stays intact.
    let mut relabelled = foreign_env.to_bytes();
    patch_u64_le(&mut relabelled, ENVELOPE_H_OPEN_OFFSET, H_OPEN);
    let relabelled = BallotEnvelope::from_bytes(&relabelled).expect("the relabelled header parses");
    let relabel_ingest = archive.ingest_sealed(&relabelled, collector_sk);
    println!("relabelled envelope: {}", ingest_label(&relabel_ingest));
    events.push(Event::new(
        "relabelled-envelope",
        "voter6/tag-h_open-rewritten",
        ingest_label(&relabel_ingest),
    ));
    assert!(
        matches!(&relabel_ingest, Err(TransportError::HeaderMismatch)),
        "a relabelled envelope must fail closed on the header match"
    );

    // 5f. Corrupted envelope: one flipped MAC byte on voter 5's wire.
    let victim5 = &sealed_bytes[5];
    let mut corrupt = victim5.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0x01;
    let corrupt_env = BallotEnvelope::from_bytes(&corrupt).expect("one flipped byte still parses");
    let corrupt_ingest = archive.ingest_sealed(&corrupt_env, collector_sk);
    println!(
        "corrupted envelope (MAC byte): {}",
        ingest_label(&corrupt_ingest)
    );
    events.push(Event::new(
        "corrupted-envelope",
        "voter5/mac-byte-flip",
        ingest_label(&corrupt_ingest),
    ));
    assert!(matches!(
        &corrupt_ingest,
        Err(TransportError::Enote(
            opacus_crypto::ecies::EnoteError::MacMismatch
        ))
    ));

    // 5g. Truncated blob: one byte below the minimum envelope length.
    let short = &victim5[..ENVELOPE_HEADER_LEN + ENVELOPE_MIN_SEALED_LEN - 1];
    let truncated = BallotEnvelope::from_bytes(short);
    println!(
        "truncated envelope ({} bytes): {}",
        short.len(),
        match &truncated {
            Ok(_) => "accepted".to_string(),
            Err(e) => format!("rejected:{}", transport_label(e)),
        }
    );
    events.push(Event::new(
        "truncated-envelope",
        "blob/below-min-length",
        match &truncated {
            Ok(_) => "accepted".into(),
            Err(e) => format!("rejected:{}", transport_label(e)),
        },
    ));
    assert!(
        matches!(&truncated, Err(TransportError::Truncated)),
        "a below-minimum blob must fail as truncated"
    );

    // 5h. Oversize: one byte over the profile cap.
    let big = vec![0u8; MAX_ENVELOPE_BYTES + 1];
    let oversize = BallotEnvelope::from_bytes(&big);
    println!(
        "oversize blob ({} bytes): {}",
        big.len(),
        match &oversize {
            Ok(_) => "accepted".to_string(),
            Err(e) => format!("rejected:{}", transport_label(e)),
        }
    );
    events.push(Event::new(
        "oversize-envelope",
        format!("blob/{}-bytes", big.len()),
        match &oversize {
            Ok(_) => "accepted".into(),
            Err(e) => format!("rejected:{}", transport_label(e)),
        },
    ));
    assert!(matches!(
        &oversize,
        Err(TransportError::Oversize { got }) if *got == MAX_ENVELOPE_BYTES + 1
    ));
}

fn outcome_label(o: Outcome) -> &'static str {
    match o {
        Outcome::Accepted => "accepted",
        Outcome::Rejected => "rejected",
        Outcome::NoQuorum => "no_quorum",
    }
}

fn declared_json(
    declared: &DeclaredProposal,
    collector_pk: &CompressedRistretto,
) -> serde_json::Value {
    serde_json::json!({
        "gip": declared.gip,
        "transition": declared.transition,
        "h_open": declared.h_open,
        "anchor": hex_encode(&fp_to_bytes(declared.anchor)),
        "class": "fund",
        "collector_pk": hex_encode(collector_pk.as_bytes()),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
