//! GIP-2 WP-D1 tests (runbook stage R1 definition of done).
//!
//! Two layers:
//!
//! 1. `committed_r1_minutes_audit_and_tamper` (runs in CI, no prover):
//!    the `dress_auditor` bin replays the COMMITTED two-process close
//!    artifacts (`tests/vectors/dress-r1/minutes.json`) - the digest,
//!    every entry, the `archive_id`, the `result_hash`, the record
//!    wire and the full trace - and then rejects a tampered minutes
//!    file (one flipped byte, both in the entry hex and in the digest).
//! 2. `two_process_rehearsal_end_to_end` (`#[ignore]`: 9+ real prover
//!    runs at mainnet depth): the actual R1 script - declare, seven
//!    independent voter processes (raw fallback, byte-equal
//!    retransmission, the full fault matrix), collector close, auditor
//!    replay - and the cross-stage pin: the two-process close must
//!    reproduce the R0 golden `result_hash` byte-for-byte.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The committed R1 net directory (the two-process close artifacts).
const R1_VECTORS: &str = "tests/vectors/dress-r1";
/// The R0 golden vector set (the cross-stage result_hash pin).
const R0_GOLDEN: &str = "tests/vectors/golden-vectors.json";

fn manifest_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn bin(name: &str) -> &'static str {
    match name {
        "collector" => env!("CARGO_BIN_EXE_dress_collector"),
        "voter" => env!("CARGO_BIN_EXE_dress_voter"),
        "auditor" => env!("CARGO_BIN_EXE_dress_auditor"),
        other => panic!("unknown bin role {other}"),
    }
}

fn run(role: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(bin(role))
        .args(args)
        .output()
        .expect("bin must spawn");
    let text = format!(
        "--- stdout ---\n{}--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

// ---------------------------------------------------------------------------
// 1. The committed minutes replay (CI budget, zero proving)
// ---------------------------------------------------------------------------

#[test]
fn committed_r1_minutes_audit_and_tamper() {
    let minutes = manifest_path(&format!("{R1_VECTORS}/minutes.json"));
    assert!(minutes.exists(), "the committed R1 minutes must exist");

    // The auditor accepts the committed close.
    let (ok, log) = run("auditor", &["--minutes", &minutes.to_string_lossy()]);
    assert!(ok, "the committed R1 minutes must replay clean:\n{log}");
    assert!(
        log.contains("VERDICT: replay ok"),
        "verdict line missing:\n{log}"
    );

    // Tamper 1: one flipped byte inside the first entry's wire hex.
    let raw = std::fs::read(&minutes).expect("minutes readable");
    let tampered = flip_wire_hex_byte(&raw);
    let dir = std::env::temp_dir().join(format!("dress-r1-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let tampered_path = dir.join("minutes-tampered-wire.json");
    std::fs::write(&tampered_path, &tampered).expect("tampered minutes write");
    let (ok, log) = run("auditor", &["--minutes", &tampered_path.to_string_lossy()]);
    assert!(!ok, "a flipped entry byte must be rejected:\n{log}");
    assert!(
        log.contains("REJECTED:"),
        "rejection reason missing:\n{log}"
    );

    // Tamper 2: one flipped byte inside the digest string itself.
    let mut tampered = raw.clone();
    let pos =
        find(&raw, b"minutes_digest\": \"").expect("digest field") + b"minutes_digest\": \"".len();
    tampered[pos] ^= 0x01;
    let tampered_path = dir.join("minutes-tampered-digest.json");
    std::fs::write(&tampered_path, &tampered).expect("tampered minutes write");
    let (ok, log) = run("auditor", &["--minutes", &tampered_path.to_string_lossy()]);
    assert!(!ok, "a flipped digest byte must be rejected:\n{log}");

    // Not JSON at all.
    let garbage_path = dir.join("minutes-garbage.json");
    std::fs::write(&garbage_path, b"{ not json").expect("garbage write");
    let (ok, _) = run("auditor", &["--minutes", &garbage_path.to_string_lossy()]);
    assert!(!ok, "a non-JSON minutes file must be rejected");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Flip the first hex byte of the first entry's `wire` value.
fn flip_wire_hex_byte(raw: &[u8]) -> Vec<u8> {
    let marker = b"\"wire\": \"";
    let pos = find(raw, marker).expect("entries[].wire field must exist") + marker.len();
    let mut out = raw.to_vec();
    out[pos] = if out[pos] == b'0' { b'1' } else { b'0' };
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// 2. The full two-process rehearsal (real prover, run with --ignored)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "9+ real prover runs at mainnet depth; reproduces the committed R1 artifacts (cargo test -p opacus-wallet --test dress_rehearsal_two_process -- --ignored)"]
fn two_process_rehearsal_end_to_end() {
    let dir = std::env::temp_dir().join(format!("dress-r1-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let net = dir.join("net");
    let net_s = net.to_string_lossy().to_string();
    let minutes = net.join("minutes.json");

    // 1. The declaration is published first (collector pk inside).
    let (ok, log) = run("collector", &["declare", "--net", &net_s]);
    assert!(ok, "declare must succeed:\n{log}");
    assert!(
        net.join("declared.json").exists(),
        "declared.json must exist"
    );

    // 2. Independent voter processes (the R0 shape: 5 FOR, 1 AGAINST,
    //    1 ABSTAIN, one raw-only, one retransmission, the fault matrix).
    let script: [(&str, &[&str]); 7] = [
        (
            "voter",
            &[
                "--id",
                "0",
                "--choice",
                "for",
                "--net",
                &net_s,
                "--retransmit",
            ],
        ),
        (
            "voter",
            &["--id", "1", "--choice", "for", "--net", &net_s, "--raw"],
        ),
        (
            "voter",
            &[
                "--id", "2", "--choice", "for", "--net", &net_s, "--fault", "double",
            ],
        ),
        (
            "voter",
            &[
                "--id",
                "3",
                "--choice",
                "against",
                "--net",
                &net_s,
                "--fault",
                "truncated",
            ],
        ),
        (
            "voter",
            &[
                "--id", "4", "--choice", "for", "--net", &net_s, "--fault", "oversize",
            ],
        ),
        (
            "voter",
            &[
                "--id", "5", "--choice", "abstain", "--net", &net_s, "--fault", "corrupt",
            ],
        ),
        (
            "voter",
            &[
                "--id",
                "6",
                "--choice",
                "for",
                "--net",
                &net_s,
                "--fault",
                "foreign",
                "--fault",
                "relabel",
                "--fault",
                "dust-smuggle",
                "--fault",
                "garbage",
            ],
        ),
    ];
    for (role, args) in script {
        let (ok, log) = run(role, args);
        assert!(ok, "{role} {args:?} must succeed:\n{log}");
    }

    // 3. The collector ingests EVERYTHING (blind), tallies, publishes.
    let (ok, log) = run("collector", &["close", "--net", &net_s]);
    assert!(ok, "close must succeed:\n{log}");
    assert!(
        log.contains("retransmission"),
        "the retransmission must be logged:\n{log}"
    );
    for expected in [
        "rejected:proposal_mismatch",
        "rejected:header_mismatch",
        "rejected:enote:mac_mismatch",
        "rejected:truncated",
        "rejected:oversize",
    ] {
        assert!(
            log.contains(expected),
            "the fault {expected} must be logged:\n{log}"
        );
    }
    assert!(minutes.exists(), "minutes.json must be published");

    // 4. Any third party replays the minutes independently.
    let (ok, log) = run("auditor", &["--minutes", &minutes.to_string_lossy()]);
    assert!(ok, "the auditor must replay the close clean:\n{log}");

    // 5. The cross-stage pin: the two-process close reproduces the R0
    //    golden result_hash byte-for-byte (same declared scope, same
    //    accepted ballot set; the blinding differs, the decision does
    //    not).
    let golden: serde_json::Value = serde_json::from_slice(
        &std::fs::read(manifest_path(R0_GOLDEN)).expect("the R0 golden vectors exist"),
    )
    .expect("golden vectors are valid JSON");
    let minutes_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&minutes).expect("minutes readable"))
            .expect("minutes are valid JSON");
    let r1_hash = minutes_doc["minutes_body"]["tally"]["result_hash"]
        .as_str()
        .expect("result_hash");
    assert_eq!(
        r1_hash,
        golden["result_hash"].as_str().expect("golden result_hash"),
        "the R1 two-process close must reproduce the R0 golden result_hash"
    );

    // 6. A tampered minutes file is rejected end-to-end.
    let raw = std::fs::read(&minutes).expect("minutes readable");
    let tampered = flip_wire_hex_byte(&raw);
    let tampered_path = dir.join("minutes-tampered.json");
    std::fs::write(&tampered_path, &tampered).expect("tampered write");
    let (ok, log) = run("auditor", &["--minutes", &tampered_path.to_string_lossy()]);
    assert!(!ok, "the auditor must reject the tampered minutes:\n{log}");

    let _ = std::fs::remove_dir_all(&dir);
}
