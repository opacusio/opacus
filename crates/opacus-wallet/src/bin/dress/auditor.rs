//! GIP-2 WP-D1 (runbook stage R1): the `dress_auditor` bin.
//!
//! The independent third party of the rehearsal (and, by stage R4, the
//! standing acceptance tool for any real vote): given the published
//! minutes it
//!
//! 1. verifies the minutes integrity - the blake3 digest over the
//!    canonical body; a tampered file (one flipped byte) is REJECTED
//!    before any replay work;
//! 2. replays every published entry through the strict canonical parse
//!    into a fresh [`BallotArchive`] and re-derives the `archive_id`;
//! 3. re-runs the tally (every accepted ballot's ZK proof re-verifies
//!    at mainnet depth) and the pure P-6 decision rule, and matches
//!    totals, outcome, `result_hash` AND the published record wire
//!    byte-for-byte;
//! 4. replays the full per-ballot trace (verdict labels included).
//!
//! Exit code 0 + `VERDICT: replay ok` on success; exit code 2 +
//! `REJECTED: <reason>` on any mismatch.
//!
//! ```sh
//! cargo run -p opacus-wallet --bin dress_auditor -- \
//!     --minutes ./net/minutes.json
//! ```

use std::fs;

use opacus_wallet::gov_transport::BallotArchive;
use opacus_wallet::tally::{tally, TallyRecord};

#[path = "common.rs"]
mod common;
use common::{
    hex_decode, hex_encode, minutes_digest, outcome_label, rejection_label, transport_label, DEPTH,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut minutes: Option<String> = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--minutes" => {
                minutes = Some(
                    it.next()
                        .unwrap_or_else(|| panic!("--minutes needs a value"))
                        .clone(),
                )
            }
            other => {
                eprintln!("unknown flag {other} (supported: --minutes)");
                std::process::exit(2);
            }
        }
    }
    let minutes = minutes.unwrap_or_else(|| {
        eprintln!("usage: dress_auditor --minutes <minutes.json>");
        std::process::exit(2);
    });

    let raw = fs::read(&minutes).unwrap_or_else(|e| panic!("{} must be readable: {e}", minutes));
    match audit(&raw) {
        Ok(report) => {
            println!("{report}");
            println!("VERDICT: replay ok");
        }
        Err(reason) => {
            eprintln!("REJECTED: {reason}");
            std::process::exit(2);
        }
    }
}

/// The full independent replay. Every failure is a `String` reason.
fn audit(raw: &[u8]) -> Result<String, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| format!("the minutes are not valid JSON: {e}"))?;
    let body = doc
        .get("minutes_body")
        .ok_or("minutes_body field missing")?;
    let published_digest = doc
        .get("minutes_digest")
        .and_then(|d| d.as_str())
        .ok_or("minutes_digest field missing")?;

    // 1. Integrity: the digest must reproduce over the canonical body.
    let recomputed = minutes_digest(body);
    if recomputed != published_digest {
        return Err(format!(
            "minutes digest mismatch: published {published_digest}, recomputed {recomputed} \
             (the file was tampered with)"
        ));
    }

    // The declared proposal, rebuilt from the published minutes (the
    // replay-side light parse: no rehearsal block in the minutes).
    let declared_json = body.get("declared").ok_or("declared field missing")?;
    let proposal = common::declared_proposal_from_json(declared_json)
        .map_err(|e| format!("the published declaration is malformed: {e}"))?;

    // 2. The entries replay as canonical in-scope ballots, in the
    //    published arrival order, and the archive_id re-derives.
    let entries_json = body
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or("entries field missing")?;
    let mut entries: Vec<Vec<u8>> = Vec::with_capacity(entries_json.len());
    for (i, e) in entries_json.iter().enumerate() {
        let index = e
            .get("index")
            .and_then(|x| x.as_u64())
            .ok_or("entry index missing")?;
        if index != i as u64 {
            return Err(format!(
                "entry {i} carries index {index} (arrival order broken)"
            ));
        }
        let wire = e
            .get("wire")
            .and_then(|x| x.as_str())
            .ok_or("entry wire missing")?;
        entries.push(hex_decode(wire, "entry wire")?);
    }
    let mut archive = BallotArchive::new(proposal.gip, proposal.transition, proposal.h_open);
    for (i, e) in entries.iter().enumerate() {
        archive.ingest_raw(e).map_err(|err| {
            format!(
                "entry {i} does not replay as a canonical in-scope ballot: {}",
                transport_label(&err)
            )
        })?;
    }
    let published_archive_id = body
        .get("archive_id")
        .and_then(|x| x.as_str())
        .ok_or("archive_id field missing")?;
    let archive_id = hex_encode(&archive.archive_id());
    if archive_id != published_archive_id {
        return Err(format!(
            "archive_id mismatch: published {published_archive_id}, replayed {archive_id}"
        ));
    }

    // 3. The engine replay: proofs re-verify, totals and the decision
    //    rule must reproduce, the record wire must be byte-stable.
    let record = tally::<DEPTH, _>(&proposal, archive.entries())
        .map_err(|e| format!("the replay tally failed: {e}"))?;
    let tally_json = body.get("tally").ok_or("tally field missing")?;
    let field_u64 = |name: &str| {
        tally_json
            .get(name)
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("tally.{name} missing"))
    };
    for (name, got) in [
        ("denominator", record.denominator),
        ("yes", record.yes),
        ("no", record.no),
        ("abstain", record.abstain),
        ("accepted", record.accepted),
        ("rejected", record.rejected),
    ] {
        let published = field_u64(name)?;
        if published != got {
            return Err(format!(
                "tally.{name} mismatch: published {published}, replayed {got}"
            ));
        }
    }
    let published_quorum = tally_json
        .get("quorum_met")
        .and_then(|x| x.as_bool())
        .ok_or("tally.quorum_met missing")?;
    if published_quorum != record.quorum_met {
        return Err(format!(
            "tally.quorum_met mismatch: published {published_quorum}, replayed {}",
            record.quorum_met
        ));
    }
    let published_outcome = tally_json
        .get("outcome")
        .and_then(|x| x.as_str())
        .ok_or("tally.outcome missing")?;
    if published_outcome != outcome_label(record.outcome) {
        return Err(format!(
            "tally.outcome mismatch: published {published_outcome}, replayed {}",
            outcome_label(record.outcome)
        ));
    }
    let published_hash = tally_json
        .get("result_hash")
        .and_then(|x| x.as_str())
        .ok_or("tally.result_hash missing")?;
    let result_hash = hex_encode(&record.result_hash);
    if result_hash != published_hash {
        return Err(format!(
            "result_hash mismatch: published {published_hash}, replayed {result_hash}"
        ));
    }
    let published_wire = body
        .get("record_wire_hex")
        .and_then(|x| x.as_str())
        .ok_or("record_wire_hex field missing")?;
    if hex_encode(&record.to_bytes()) != published_wire {
        return Err("the replayed record wire differs from the published record_wire_hex".into());
    }
    TallyRecord::from_bytes(&record.to_bytes())
        .map_err(|e| format!("the replayed record does not parse canonically: {e}"))?;

    // 4. The trace replays verdict by verdict.
    let trace_json = body
        .get("trace")
        .and_then(|x| x.as_array())
        .ok_or("trace field missing")?;
    if trace_json.len() != record.trace.len() {
        return Err(format!(
            "trace length mismatch: published {}, replayed {}",
            trace_json.len(),
            record.trace.len()
        ));
    }
    for (pub_t, rec_t) in trace_json.iter().zip(record.trace.iter()) {
        let idx = pub_t
            .get("index")
            .and_then(|x| x.as_u64())
            .ok_or("trace index missing")?;
        if idx != rec_t.index as u64 {
            return Err(format!("trace entry {} carries index {idx}", rec_t.index));
        }
        let pub_accepted = pub_t
            .get("accepted")
            .and_then(|x| x.as_bool())
            .ok_or("trace accepted missing")?;
        if pub_accepted != rec_t.accepted {
            return Err(format!("trace entry {} accepted mismatch", rec_t.index));
        }
        let pub_rejection = pub_t
            .get("rejection")
            .map(|x| x.as_str().unwrap_or_default().to_string())
            .unwrap_or_default();
        let rec_rejection = rec_t
            .rejection
            .as_ref()
            .map(rejection_label)
            .unwrap_or_default();
        if pub_rejection != rec_rejection {
            return Err(format!(
                "trace entry {} rejection mismatch: published {:?}, replayed {:?}",
                rec_t.index, pub_rejection, rec_rejection
            ));
        }
        let pub_sighash = pub_t
            .get("sighash")
            .map(|x| x.as_str().unwrap_or_default().to_string())
            .unwrap_or_default();
        let rec_sighash = rec_t.sighash.map(|s| hex_encode(&s)).unwrap_or_default();
        if pub_sighash != rec_sighash {
            return Err(format!("trace entry {} sighash mismatch", rec_t.index));
        }
    }

    Ok(format!(
        "audited: {} entry(ies), declared gip={} transition={} h_open={} class=fund, \
         outcome={} yes={} no={} abstain={} accepted={} rejected={}",
        entries.len(),
        record.gip,
        record.transition,
        record.h_open,
        outcome_label(record.outcome),
        record.yes,
        record.no,
        record.abstain,
        record.accepted,
        record.rejected
    ))
}
