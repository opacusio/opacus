//! GIP-2 WP-D0 golden replay test (runbook stage R0 definition of done).
//!
//! Replays the COMMITTED rehearsal artifacts
//! (`tests/vectors/{declared,minutes,golden-vectors}.json`) through the
//! real engine and re-derives every stable close artifact:
//!
//! 1. `tally::<32>` over the committed archive entries - each accepted
//!    ballot's ZK proof is re-verified at mainnet depth; the totals,
//!    the outcome, the counts and the `result_hash` must match the
//!    golden vector.
//! 2. The published record wire (`record_wire_hex`) must re-serialize
//!    from the replayed record byte-for-byte (the record wire carries
//!    no proof blinding - it is fully deterministic).
//! 3. The minutes fingerprint (`archive_id`) must recompute over the
//!    committed arrival order.
//! 4. P-5: the SHUFFLED archive re-tally yields the SAME `result_hash`
//!    and a DIFFERENT `archive_id`.
//! 5. The trace must carry the injected faults: exactly one
//!    DuplicateSerial and exactly one Malformed(Dust), and every honest
//!    ballot accepted.

use opacus_wallet::gov::GovError;
use opacus_wallet::gov_transport::BallotArchive;
use opacus_wallet::tally::{
    decide, emission_upto, tally, DeclaredProposal, Outcome, Rejection, TallyRecord, VoteClass,
};
use opacus_wallet::zk_spend::fp_from_bytes;
use opacus_zk::prelude::Fp;

/// Mainnet-shaped frontier depth (the runbook pins the rehearsal to 32).
const DEPTH: usize = 32;
/// The committed GIP-2 rehearsal shape.
const GIP: u32 = 2;
const TRANSITION: u8 = 0;
const H_OPEN: u64 = 100;

fn read_json(name: &str) -> serde_json::Value {
    let path = format!(
        "{}",
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("vectors")
            .join(name)
            .display()
    );
    let raw = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("committed golden artifact {path} is missing: {e}"));
    serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("{path} is not valid JSON: {e}"))
}

fn hex_decode(s: &str, what: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|e| panic!("{what}: bad hex at byte {i}: {e}"))
        })
        .collect()
}

fn fp_from_hex(s: &str, what: &str) -> Fp {
    let bytes: [u8; 32] = hex_decode(s, what)
        .try_into()
        .unwrap_or_else(|_| panic!("{what}: anchor must be 32 bytes"));
    fp_from_bytes(&bytes).unwrap_or_else(|| panic!("{what}: non-canonical field encoding"))
}

fn outcome_of(label: &str) -> Outcome {
    match label {
        "accepted" => Outcome::Accepted,
        "rejected" => Outcome::Rejected,
        "no_quorum" => Outcome::NoQuorum,
        other => panic!("unknown outcome label: {other}"),
    }
}

#[test]
fn golden_vector_result_hash_is_replay_stable() {
    let declared_json = read_json("declared.json");
    let minutes = read_json("minutes.json");
    let golden = read_json("golden-vectors.json");

    // The declared proposal, rebuilt from the published declaration.
    assert_eq!(declared_json["gip"], GIP);
    assert_eq!(declared_json["transition"], TRANSITION);
    assert_eq!(declared_json["h_open"], H_OPEN);
    let declared = DeclaredProposal {
        gip: GIP,
        transition: TRANSITION,
        h_open: H_OPEN,
        anchor: fp_from_hex(
            declared_json["anchor"].as_str().expect("anchor hex"),
            "anchor",
        ),
        class: VoteClass::Fund,
    };

    // The committed archive, in arrival order.
    let entries_json = minutes["entries"].as_array().expect("entries array");
    let entries: Vec<Vec<u8>> = entries_json
        .iter()
        .enumerate()
        .map(|(i, e)| {
            assert_eq!(e["index"], i, "minutes entries are arrival-ordered");
            hex_decode(
                e["wire"]
                    .as_str()
                    .unwrap_or_else(|| panic!("entry {i} wire")),
                "entry",
            )
        })
        .collect();
    assert_eq!(
        entries.len(),
        golden["voters"].as_u64().unwrap() as usize + 2,
        "the archive carries the honest ballots plus the dust smuggle and the double vote"
    );

    // 1. The engine replay: every accepted proof re-verifies here.
    let record = tally::<DEPTH, _>(&declared, &entries).expect("replay tally must not overflow");

    assert_eq!(record.gip, GIP);
    assert_eq!(record.transition, TRANSITION);
    assert_eq!(record.h_open, H_OPEN);
    assert_eq!(record.class, VoteClass::Fund);
    assert_eq!(record.anchor, declared.anchor);
    assert_eq!(record.denominator, golden["denominator"].as_u64().unwrap());
    assert_eq!(record.denominator, emission_upto(H_OPEN));
    assert_eq!(record.yes, golden["yes"].as_u64().unwrap());
    assert_eq!(record.no, golden["no"].as_u64().unwrap());
    assert_eq!(record.abstain, golden["abstain"].as_u64().unwrap());
    assert_eq!(record.accepted, golden["accepted"].as_u64().unwrap());
    assert_eq!(record.rejected, golden["rejected"].as_u64().unwrap());
    assert_eq!(record.quorum_met, golden["quorum_met"].as_bool().unwrap());
    assert_eq!(
        record.outcome,
        outcome_of(golden["outcome"].as_str().unwrap())
    );
    let expected_hash: [u8; 32] =
        hex_decode(golden["result_hash"].as_str().unwrap(), "result_hash")
            .try_into()
            .expect("result_hash is 32 bytes");
    assert_eq!(
        record.result_hash, expected_hash,
        "result_hash must reproduce byte-for-byte"
    );

    // 2. The published record wire re-serializes identically.
    let record_wire = hex_decode(minutes["record_wire_hex"].as_str().unwrap(), "record_wire");
    assert_eq!(
        record.to_bytes(),
        record_wire,
        "the replayed record wire must match the published minutes byte-for-byte"
    );
    TallyRecord::from_bytes(&record_wire).expect("the published record parses canonically");

    // 3. The minutes fingerprint recomputes over the arrival order.
    let mut archive = BallotArchive::new(GIP, TRANSITION, H_OPEN);
    for e in &entries {
        archive
            .ingest_raw(e)
            .expect("committed entries are canonical in-scope ballots");
    }
    let expected_id: [u8; 32] = hex_decode(golden["archive_id"].as_str().unwrap(), "archive_id")
        .try_into()
        .expect("archive_id is 32 bytes");
    assert_eq!(
        archive.archive_id(),
        expected_id,
        "archive_id must reproduce over the committed arrival order"
    );

    // 4. P-5: shuffled re-tally - same decision, different minutes id.
    let mut shuffled = entries.clone();
    shuffled.reverse();
    let replay = tally::<DEPTH, _>(&declared, &shuffled).expect("shuffled tally must not overflow");
    assert_eq!(
        record.result_hash, replay.result_hash,
        "the decision is order-invariant (P-5)"
    );
    let mut shuffled_archive = BallotArchive::new(GIP, TRANSITION, H_OPEN);
    for e in &shuffled {
        shuffled_archive
            .ingest_raw(e)
            .expect("replayed entries are canonical");
    }
    assert_ne!(
        archive.archive_id(),
        shuffled_archive.archive_id(),
        "the minutes fingerprint their submission history"
    );

    // 5. The trace carries every injected fault.
    let dust_hits = record
        .trace
        .iter()
        .filter(|t| {
            matches!(
                &t.rejection,
                Some(Rejection::Malformed(GovError::Dust { .. }))
            )
        })
        .count() as u64;
    let dup_hits = record
        .trace
        .iter()
        .filter(|t| matches!(&t.rejection, Some(Rejection::DuplicateSerial)))
        .count() as u64;
    let accepted_count = record.trace.iter().filter(|t| t.accepted).count() as u64;
    assert_eq!(
        dust_hits,
        golden["trace_rejections"]["dust"].as_u64().unwrap()
    );
    assert_eq!(
        dup_hits,
        golden["trace_rejections"]["duplicate_serial"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(accepted_count, record.accepted);

    // The engine's own decision rule agrees with the published outcome.
    let (quorum, outcome) = decide(
        record.class,
        record.denominator,
        record.yes,
        record.no,
        record.abstain,
    );
    assert_eq!(quorum, record.quorum_met);
    assert_eq!(outcome, record.outcome);
}
