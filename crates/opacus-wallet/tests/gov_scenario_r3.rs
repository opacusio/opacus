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

    // The scenario shape: 5 honest ballots archived (3 FOR, 1 AGAINST,
    // 1 ABSTAIN; the double vote is rejected at the tally, the raw
    // fallback is one of the five), the close is the no-quorum branch.
    assert_eq!(
        body["tally"]["accepted"].as_u64().expect("accepted"),
        body["entries"].as_array().expect("entries").len() as u64,
        "every archived ballot is accepted by the tally"
    );
    assert_eq!(body["tally"]["outcome"], "no_quorum");
    assert!(
        body["tally"]["result_hash"].as_str().is_some(),
        "the close publishes result_hash"
    );
    // The injected faults are visible in the event log: the duplicate
    // serial rejection and the gossip retransmission dedupe.
    let events = body["ingest_events"].as_array().expect("ingest events");
    let log = serde_json::to_string(events).expect("events serialize");
    assert!(
        log.contains("rejected:malformed:duplicate_vote"),
        "the double vote must surface in the close trace: {log}"
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
