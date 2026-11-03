//! GIP-2 R3 scripted-scenario close artifacts (runbook stage R3 DoD).
//!
//! The committed close of the collector service
//! (`tests/vectors/dress-r3/minutes.json` - the maintainer declaration,
//! the collector state with the full ingest event log, and the
//! blake3-pinned minutes) replays clean through the R1 `dress_auditor`
//! and rejects tampering - the R3 definition of done ("every
//! participant, and one offline auditor, replays") pinned in CI.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The committed R3 close artifacts (the collector service run).
const R3_VECTORS: &str = "tests/vectors/dress-r3";

fn manifest_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn auditor(minutes: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_dress_auditor"))
        .arg("--minutes")
        .arg(minutes)
        .output()
        .expect("dress_auditor must spawn");
    let text = format!(
        "--- stdout ---\n{}--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn committed_r3_service_close_replays_and_tamper_is_rejected() {
    let minutes = manifest_path(&format!("{R3_VECTORS}/minutes.json"));
    assert!(minutes.exists(), "the committed R3 minutes must exist");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&minutes).expect("minutes readable"))
            .expect("minutes are valid JSON");
    let body = &doc["minutes_body"];

    // The R3 declared scope (the runbook scenario shape).
    assert_eq!(body["declared"]["gip"], 2);
    assert_eq!(body["declared"]["transition"], 0);
    assert_eq!(body["declared"]["h_open"], 100);
    assert_eq!(body["declared"]["class"], "fund");

    // The scenario shape: the 5 honest ballots archived (3 FOR, 1
    // AGAINST, 1 ABSTAIN via the raw-only fallback; the deliberate
    // double vote is the rejected sixth entry), the close lands in the
    // accepted branch of P-6: participation 57.3e9 of 1e12 clears the
    // 5% Fund quorum and 33.5/(33.5+13) = 72% clears the 60% approval.
    assert_eq!(body["entries"].as_array().expect("entries").len(), 6);
    assert_eq!(body["tally"]["accepted"].as_u64().expect("accepted"), 5);
    assert_eq!(body["tally"]["rejected"].as_u64().expect("rejected"), 1);
    assert_eq!(body["tally"]["yes"].as_u64().expect("yes"), 33_500_000_000);
    assert_eq!(body["tally"]["no"].as_u64().expect("no"), 13_000_000_000);
    assert_eq!(
        body["tally"]["abstain"].as_u64().expect("abstain"),
        10_800_000_000
    );
    assert_eq!(body["tally"]["quorum_met"], true);
    assert_eq!(body["tally"]["outcome"], "accepted");
    assert!(
        body["tally"]["result_hash"].as_str().is_some(),
        "the close publishes result_hash"
    );
    // The injected faults are visible in the tally trace: the double
    // vote's serial collision (the canonical-order replay rejects the
    // second copy of the collided serial) and nothing else.
    let trace = body["trace"].as_array().expect("trace");
    let dup = trace
        .iter()
        .filter(|t| t["rejection"].as_str() == Some("duplicate_serial"))
        .count();
    assert_eq!(dup, 1, "exactly one DuplicateSerial in the close trace");
    // The gossip retransmission never completes a second stream: six
    // envelope wires were shipped (voters 0-4 plus the double), six
    // streams completed - the re-sealed retransmission of voter 0 was
    // swallowed chunk-by-chunk by the assembler (the D2c dedupe).
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(manifest_path(&format!("{R3_VECTORS}/state.json")))
            .expect("the committed collector state exists"),
    )
    .expect("state is valid JSON");
    assert_eq!(
        state["completed"]
            .as_array()
            .expect("completed streams")
            .len(),
        6,
        "the re-sealed retransmission must not complete a second stream"
    );
    let events = body["ingest_events"].as_array().expect("ingest events");
    let log = serde_json::to_string(events).expect("events serialize");
    assert!(
        log.contains("chunk:pending-or-duplicate"),
        "the retransmitted chunks must be logged as duplicates: {log}"
    );

    // The offline auditor replays the committed close clean.
    let (ok, out) = auditor(&minutes);
    assert!(ok, "the committed R3 minutes must replay clean:\n{out}");
    assert!(
        out.contains("VERDICT: replay ok"),
        "verdict line missing:\n{out}"
    );

    // One flipped byte inside the first entry's wire hex is rejected.
    let raw = std::fs::read(&minutes).expect("minutes readable");
    let marker = b"\"wire\": \"";
    let pos = raw
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("entries[].wire field must exist")
        + marker.len();
    let mut tampered = raw.clone();
    tampered[pos] = if tampered[pos] == b'0' { b'1' } else { b'0' };
    let dir = std::env::temp_dir().join(format!("dress-r3-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let tampered_path = dir.join("minutes-tampered.json");
    std::fs::write(&tampered_path, &tampered).expect("tampered minutes write");
    let (ok, out) = auditor(&tampered_path);
    assert!(!ok, "a flipped entry byte must be rejected:\n{out}");
    assert!(
        out.contains("REJECTED:"),
        "rejection reason missing:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
