//! GIP-2 WP-D2d (runbook stage R3): the `gov_collector` bin - the
//! operator surface of the ballot collector service
//! ([`opacus_node::gov_service`]).
//!
//! Three subcommands over a state directory + a spool directory (the
//! ingest endpoint stand-in for the v5 note path - one sealed channel
//! blob per `*.gchunk` file):
//!
//! * `init` - load or generate the collector NODE identity and publish
//!   `collector-node.json` (the routing key the senders chunk + seal
//!   to; the ballot key stays a separate trust root declared in
//!   `declared.json`);
//! * `ingest` - drain the spool through the WP-D2c channel assembler
//!   into the [`opacus_wallet::gov_transport::BallotArchive`] and
//!   persist the state;
//! * `close` - tally, run the pure P-6 decision rule and publish the
//!   R1-schema minutes (`{minutes_body, minutes_digest}`, blake3
//!   pinned) - the R1 `dress_auditor` replays the close unchanged.
//!
//! The collector BALLOT key is the rehearsal derivation from the
//! declared seed (the same `domain_bytes` policy as the R1
//! `dress/common.rs` - no new trust root; the declared pk is verified
//! against the derived key before anything opens).
//!
//! ```sh
//! target/release/gov_collector init   --state ./gov/collector
//! target/release/gov_collector ingest --state ./gov/collector \
//!     --declared ./gov/declared.json --spool ./gov/spool
//! target/release/gov_collector close  --state ./gov/collector \
//!     --declared ./gov/declared.json --minutes ./gov/minutes.json
//! ```

use std::path::PathBuf;

use opacus_node::gov_service::{collector_keys_from_seed, GovCollectorService, DEPTH};
use opacus_wallet::tally::DeclaredProposal;
use opacus_wallet::zk_spend::fp_from_bytes;
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") => cmd_init(&parse(&args[1..])),
        Some("ingest") => cmd_ingest(&parse(&args[1..])),
        Some("close") => cmd_close(&parse(&args[1..])),
        Some(other) => {
            eprintln!("unknown subcommand {other:?} (init|ingest|close)");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: gov_collector <init|ingest|close> [flags]");
            std::process::exit(2);
        }
    }
}

struct Flags {
    state: PathBuf,
    spool: PathBuf,
    declared: PathBuf,
    minutes: Option<PathBuf>,
}

fn defaults() -> Flags {
    Flags {
        state: PathBuf::from("gov/collector"),
        spool: PathBuf::from("gov/spool"),
        declared: PathBuf::from("gov/declared.json"),
        minutes: None,
    }
}

fn parse(args: &[String]) -> Flags {
    let mut f = defaults();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--state" => f.state = PathBuf::from(val(&mut it, a)),
            "--spool" => f.spool = PathBuf::from(val(&mut it, a)),
            "--declared" => f.declared = PathBuf::from(val(&mut it, a)),
            "--minutes" => f.minutes = Some(PathBuf::from(val(&mut it, a))),
            other => {
                panic!("unknown flag {other} (supported: --state --spool --declared --minutes)")
            }
        }
    }
    f
}

fn val<'a, I: Iterator<Item = &'a String>>(it: &mut I, name: &str) -> String {
    it.next()
        .unwrap_or_else(|| panic!("{name} needs a value"))
        .clone()
}

/// The declared proposal + the collector key pair derived from the
/// declared rehearsal seed (the pk is verified against the declared
/// collector_pk BEFORE anything opens - the R1 close discipline).
struct Declared {
    proposal: DeclaredProposal,
    #[allow(dead_code)]
    seed: u64,
}

fn read_declared(path: &PathBuf) -> Declared {
    let raw = std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "{} must exist (publish the declaration first): {e}",
            path.display()
        )
    });
    let doc: serde_json::Value = serde_json::from_slice(&raw)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
    let field = |n: &str| {
        doc.get(n)
            .unwrap_or_else(|| panic!("declared.{n} missing"))
            .clone()
    };
    let class = field("class").as_str().expect("declared.class").to_string();
    assert_eq!(class, "fund", "the rehearsal class is fund");
    let anchor_hex = field("anchor")
        .as_str()
        .expect("declared.anchor")
        .to_string();
    let anchor_bytes: [u8; 32] = hex::decode(&anchor_hex)
        .expect("anchor hex")
        .try_into()
        .expect("anchor is 32 bytes");
    let anchor = fp_from_bytes(&anchor_bytes).expect("declared.anchor canonical");
    let rehearsal = doc
        .get("rehearsal")
        .unwrap_or_else(|| panic!("declared.rehearsal missing"));
    let seed = rehearsal
        .get("seed")
        .and_then(|s| s.as_u64())
        .expect("declared.rehearsal.seed");
    let depth = rehearsal
        .get("depth")
        .and_then(|s| s.as_u64())
        .expect("declared.rehearsal.depth");
    assert_eq!(depth as usize, DEPTH, "the rehearsal depth is pinned");
    // The declared collector_pk pins the derived key (P-4 order).
    let pk_hex = field("collector_pk")
        .as_str()
        .expect("declared.collector_pk")
        .to_string();
    let (_sk, pk) = collector_keys_from_seed(seed);
    assert_eq!(
        hex::encode(pk.as_bytes()),
        pk_hex,
        "the derived collector key must match the declared collector_pk"
    );
    Declared {
        proposal: DeclaredProposal {
            gip: field("gip").as_u64().expect("declared.gip") as u32,
            transition: field("transition").as_u64().expect("declared.transition") as u8,
            h_open: field("h_open").as_u64().expect("declared.h_open"),
            anchor,
            class: opacus_wallet::tally::VoteClass::Fund,
        },
        seed,
    }
}

fn open_service(f: &Flags) -> GovCollectorService {
    let declared = read_declared(&f.declared);
    // The rehearsal key policy: the collector BALLOT key is derived
    // from the declared seed (no new trust root); the derived pk was
    // already verified against the declared collector_pk.
    let (sk, _) = collector_keys_from_seed(declared.seed);
    GovCollectorService::open(&f.state, declared.proposal, sk).expect("collector service opens")
}

/// The maintainer/operator publish step: the collector node identity
/// is materialized and its ROUTING key is published NEXT TO THE
/// DECLARATION (the senders read the net directory like the R1
/// voters read declared.json; the secret identity stays in the state
/// dir).
fn cmd_init(f: &Flags) {
    let _ = read_declared(&f.declared);
    let svc = open_service(f);
    let node = json!({
        "node_id": svc.node_id_short(),
        "routing_pk": svc.routing_pk_hex(),
    });
    let path = f
        .declared
        .parent()
        .map(|p| p.join("collector-node.json"))
        .unwrap_or_else(|| PathBuf::from("collector-node.json"));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&node).expect("collector-node json"),
    )
    .expect("collector-node.json must write");
    println!(
        "collector initialized: state={} node_id={} routing_pk={}",
        f.state.display(),
        svc.node_id_short(),
        svc.routing_pk_hex()
    );
    println!(
        "routing key published: {} (senders chunk + seal to it, gov_channel::seal_stream)",
        path.display()
    );
}

/// Drain the spool endpoint through the channel assembler.
fn cmd_ingest(f: &Flags) {
    let mut svc = open_service(f);
    let before = svc.archived();
    let drained = svc.drain_spool(&f.spool).expect("spool drains");
    svc.save().expect("state saves");
    println!(
        "ingest: {} blob(s) consumed from {} (archived {} -> {})",
        drained,
        f.spool.display(),
        before,
        svc.archived()
    );
    for e in svc.events().iter().rev().take(drained.min(16)) {
        println!(
            "  {} ({} B): {}",
            e["file"].as_str().unwrap_or("?"),
            e["bytes"].as_u64().unwrap_or(0),
            e["result"].as_str().unwrap_or("?")
        );
    }
    println!(
        "completed streams so far: {}",
        svc.completed_streams().len()
    );
}

/// The close step: tally + P-6 + publish (the R1 minutes schema).
fn cmd_close(f: &Flags) {
    let svc = open_service(f);
    let minutes = f.minutes.clone().unwrap_or_else(|| {
        f.state
            .parent()
            .map(|p| p.join("minutes.json"))
            .unwrap_or_else(|| PathBuf::from("minutes.json"))
    });
    let stmt = svc.close(&minutes).expect("close");
    println!("----------------------------------------------");
    println!(
        "close statement: outcome={} yes={} no={} abstain={} accepted={} rejected={}",
        stmt.outcome, stmt.yes, stmt.no, stmt.abstain, stmt.accepted, stmt.rejected
    );
    println!("result_hash={}", stmt.result_hash);
    println!("archive_id={}", stmt.archive_id);
    println!(
        "minutes published: {} (blake3-pinned; the R1 dress_auditor replays it unchanged)",
        minutes.display()
    );
}
