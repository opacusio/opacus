//! GIP-2 WP-D1 (runbook stage R1): the `dress_collector` bin.
//!
//! Two subcommands over a drop directory (`--net`, the stand-in for the
//! network - zero node work, real serialization boundaries):
//!
//! * `declare` - the maintainer's publish step: the proposal, the
//!   collector key and the rehearsal block land in `declared.json`
//!   BEFORE any ballot exists (P-3/P-4 order). Every voter process
//!   rebuilds the anchored frontier from this file alone.
//! * `close` - the collector ingests EVERYTHING in the directory (blind
//!   minutes: undecryptable, oversized and mislabelled drops are logged
//!   as failed events in the minutes, never silently dropped, never
//!   fatal), tallies at close and publishes `minutes.json`
//!   (`{minutes_body, minutes_digest}`, blake3-pinned).
//!
//! ```sh
//! cargo run -p opacus-wallet --bin dress_collector -- declare \
//!     --gip 2 --transition 0 --h-open 100 --net ./net
//! cargo run -p opacus-wallet --bin dress_collector -- close \
//!     --net ./net --minutes ./net/minutes.json
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use opacus_crypto::ecies::NoteSecret;
use opacus_wallet::gov_transport::{BallotArchive, BallotEnvelope, ENVELOPE_MAGIC};
use opacus_wallet::tally::{decide, tally};
use serde_json::json;

#[path = "common.rs"]
mod common;
use common::{
    collector_keys, hex_encode, ingest_label, minutes_digest, outcome_label, rehearsal_tree,
    Declaration, DEFAULT_GIP, DEFAULT_H_OPEN, DEFAULT_SEED, DEFAULT_TRANSITION, DEFAULT_VOTERS,
    DEPTH,
};
use opacus_wallet::zk_spend::fp_to_bytes;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("declare") => cmd_declare(&parse_flags(&args[1..])),
        Some("close") => cmd_close(&parse_flags(&args[1..])),
        Some(other) => {
            eprintln!("unknown subcommand {other:?} (declare|close)");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: dress_collector <declare|close> [flags]");
            std::process::exit(2);
        }
    }
}

struct Flags {
    net: PathBuf,
    minutes: Option<PathBuf>,
    gip: u32,
    transition: u8,
    h_open: u64,
    seed: u64,
    voters: usize,
}

fn parse_flags(args: &[String]) -> Flags {
    let mut f = Flags {
        net: PathBuf::from("net"),
        minutes: None,
        gip: DEFAULT_GIP,
        transition: DEFAULT_TRANSITION,
        h_open: DEFAULT_H_OPEN,
        seed: DEFAULT_SEED,
        voters: DEFAULT_VOTERS,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--net" => f.net = PathBuf::from(next_value(&mut it, "--net")),
            "--minutes" => f.minutes = Some(PathBuf::from(next_value(&mut it, "--minutes"))),
            "--gip" => f.gip = next_value(&mut it, "--gip").parse().expect("--gip must be a number"),
            "--transition" => {
                f.transition = next_value(&mut it, "--transition")
                    .parse()
                    .expect("--transition must be a number")
            }
            "--h-open" => {
                f.h_open = next_value(&mut it, "--h-open")
                    .parse()
                    .expect("--h-open must be a number")
            }
            "--seed" => f.seed = next_value(&mut it, "--seed").parse().expect("--seed must be a number"),
            "--voters" => {
                f.voters = next_value(&mut it, "--voters")
                    .parse()
                    .expect("--voters must be a number")
            }
            other => panic!("unknown flag {other} (supported: --net --minutes --gip --transition --h-open --seed --voters)"),
        }
    }
    f
}

/// The next flag value (the flags are strictly pairwise; the collector
/// flags default, so a missing value is a caller bug - panic like the
/// R0 harness).
fn next_value<'a, I>(it: &mut I, name: &str) -> String
where
    I: Iterator<Item = &'a String>,
{
    it.next()
        .unwrap_or_else(|| panic!("{name} needs a value"))
        .clone()
}

/// The publish step: the declaration exists before any ballot (P-3/P-4
/// order), and the rehearsal block makes the anchored frontier
/// reproducible by every voter process.
fn cmd_declare(f: &Flags) {
    let (tree, _) = rehearsal_tree(f.seed, f.voters);
    let anchor = tree.root();
    let (_sk, pk) = collector_keys(f.seed);
    let declared = Declaration {
        gip: f.gip,
        transition: f.transition,
        h_open: f.h_open,
        anchor,
        collector_pk: pk,
        seed: f.seed,
        voters: f.voters,
    };
    fs::create_dir_all(&f.net).expect("net directory must be creatable");
    let path = f.net.join("declared.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&declared.to_json()).expect("declaration json"),
    )
    .expect("declared.json must write");
    println!("declaration published: {}", path.display());
    println!(
        "  proposal: gip={} transition={} h_open={} class=fund",
        declared.gip, declared.transition, declared.h_open
    );
    println!("  anchor:   {}", hex_encode(&fp_to_bytes(anchor)));
    println!(
        "  collector_pk: {}",
        hex_encode(declared.collector_pk.as_bytes())
    );
    println!(
        "  rehearsal: seed={} voters={} depth={} (the frontier is a pure function of the seed)",
        declared.seed, declared.voters, DEPTH
    );
    println!("voters may now drop ballots into {}", f.net.display());
}

/// The close step: blind ingest of every drop, tally, publish.
fn cmd_close(f: &Flags) {
    let declared_path = f.net.join("declared.json");
    let raw = fs::read(&declared_path).unwrap_or_else(|e| {
        panic!(
            "{} must exist (run `declare` first): {e}",
            declared_path.display()
        )
    });
    let doc: serde_json::Value = serde_json::from_slice(&raw)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", declared_path.display()));
    let declared = Declaration::from_json(&doc).expect("declared.json is malformed");

    // The collector derives its key from the declared rehearsal seed and
    // pins it against the published pk before opening anything.
    let (sk, pk) = collector_keys(declared.seed);
    assert_eq!(
        hex_encode(pk.as_bytes()),
        hex_encode(declared.collector_pk.as_bytes()),
        "the derived collector key must match the declared collector_pk"
    );

    let minutes_out = f
        .minutes
        .clone()
        .unwrap_or_else(|| f.net.join("minutes.json"));
    let minutes_name = minutes_out
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "minutes.json".to_string());

    // Deterministic arrival order: lexicographic file-name scan (the
    // drop directory stands in for the network; the arrival order is
    // whatever the scan sees, and the minutes fingerprint exactly that).
    let mut drops: Vec<PathBuf> = fs::read_dir(&f.net)
        .unwrap_or_else(|e| panic!("{} must be readable: {e}", f.net.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .filter(|p| {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string());
            name.as_deref() != Some("declared.json")
                && name.as_deref() != Some(minutes_name.as_str())
        })
        .collect();
    drops.sort();
    println!(
        "close: ingesting {} drop(s) from {} (arrival order = lexicographic file scan)",
        drops.len(),
        f.net.display()
    );

    let mut archive = BallotArchive::new(declared.gip, declared.transition, declared.h_open);
    let mut events = Vec::new();
    for path in &drops {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("{path:?} must be readable: {e}"));
        let verdict = ingest_drop(&mut archive, &sk, &bytes);
        println!("  {name} ({} bytes): {verdict}", bytes.len());
        events.push(json!({ "file": name, "bytes": bytes.len(), "result": verdict }));
    }

    // The tally (each accepted ballot's ZK proof re-verifies here) and
    // the pure P-6 decision rule.
    let proposal = declared.declared_proposal();
    let record = tally::<DEPTH, _>(&proposal, archive.entries()).expect("tally must not overflow");
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
        "declared": declared.declared_json(),
        "archive_id": hex_encode(&archive.archive_id()),
        "entries": archive
            .entries()
            .iter()
            .enumerate()
            .map(|(i, e)| json!({ "index": i, "wire": hex_encode(e) }))
            .collect::<Vec<_>>(),
        "ingest_events": events,
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
            .map(|t| {
                json!({
                    "index": t.index,
                    "sighash": t.sighash.map(|s| hex_encode(&s)),
                    "accepted": t.accepted,
                    "rejection": t.rejection.as_ref().map(common::rejection_label),
                })
            })
            .collect::<Vec<_>>(),
        "record_wire_hex": hex_encode(&record.to_bytes()),
    });
    let document = json!({
        "minutes_body": body,
        "minutes_digest": minutes_digest(&body),
    });
    fs::create_dir_all(minutes_out.parent().unwrap_or(Path::new(".")))
        .expect("minutes parent directory must be creatable");
    fs::write(
        &minutes_out,
        serde_json::to_vec_pretty(&document).expect("minutes json"),
    )
    .expect("minutes.json must write");

    println!("----------------------------------------------");
    println!(
        "close statement: outcome={} yes={} no={} abstain={} accepted={} rejected={}",
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
        "minutes published: {} (blake3-pinned: the auditor rejects any flipped byte)",
        minutes_out.display()
    );
}

/// The blind ingest router: GBE1-magic drops go to the sealed path
/// (parse, then open with the collector key), everything else to the
/// raw fallback (strict canonical ballot parse, nothing else). Every
/// verdict - accepted, retransmission or rejected - lands in the event
/// log; nothing crashes the collector, nothing is silently dropped.
fn ingest_drop(archive: &mut BallotArchive, sk: &NoteSecret, bytes: &[u8]) -> String {
    if bytes.starts_with(&ENVELOPE_MAGIC) {
        match BallotEnvelope::from_bytes(bytes) {
            Ok(env) => ingest_label(&archive.ingest_sealed(&env, sk)),
            Err(e) => format!("rejected:{}", common::transport_label(&e)),
        }
    } else {
        ingest_label(&archive.ingest_raw(bytes))
    }
}
