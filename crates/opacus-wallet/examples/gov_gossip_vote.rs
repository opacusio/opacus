//! GIP-2 WP-D2d / R3 scenario sender (one rehearsal wallet process).
//!
//! Builds ONE wallet-real ballot through the WP-D2b bridge and ships
//! it over the WP-D2c gossip channel into the WP-D2d collector spool:
//!
//! 1. the wallet mirrors the declared rehearsal frontier leaf by leaf
//!    (`confirm_v4_leaf`, monotonic confirm heights) and owns exactly
//!    its own note (`add_v4_note`) - the notes actually live in the
//!    wallet, `gov_inputs_at(h_open)` is what feeds `build_ballot`;
//! 2. the ballot is proved at the rehearsal depth, verified, sealed to
//!    the declared collector key and chunked + sealed to the collector
//!    NODE routing key (`gov_channel::seal_stream`, stream id = the
//!    public `envelope_id`);
//! 3. one sealed blob per file lands in the spool directory (the
//!    `*.gchunk` endpoint stand-in for the v5 note path).
//!
//! Scenario faults: `--double` ships a second ballot on the SAME notes
//! (surfaces as `DuplicateSerial` in the close trace), `--raw` ships
//! the raw canonical ballot wire over the channel as its own stream
//! (the documented weaker fallback, sid = blake3 over the wire),
//! `--retransmit` re-seals the SAME envelope wire (fresh blob ids, the
//! same chunk plaintexts - the assembler dedupe from the D2c note).
//!
//! ```sh
//! cargo run -p opacus-wallet --example gov_gossip_vote -- \
//!     --id 0 --choice for --net ./gov --spool ./gov/spool
//! ```

#[path = "../src/bin/dress/common.rs"]
mod common;

use std::path::PathBuf;

use common::{hex_encode, parse_choice, rehearsal_tree, Declaration, DEPTH};
use opacus_crypto::keys::SpendingKey;
use opacus_crypto::CompressedRistretto;
use opacus_network::gov_channel::seal_stream;
use opacus_wallet::gov::{build_ballot, verify_ballot, verify_ballot_against_tree, Choice};
use opacus_wallet::gov_transport::BallotEnvelope;
use opacus_wallet::light_wallet::LightWallet;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut id: Option<usize> = None;
    let mut choice: Option<Choice> = None;
    let mut net = PathBuf::from("gov");
    let mut spool: Option<PathBuf> = None;
    let mut double = false;
    let mut raw = false;
    let mut retransmit = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--id" => {
                id = Some(
                    it.next()
                        .expect("--id needs a value")
                        .parse()
                        .expect("--id number"),
                )
            }
            "--choice" => {
                choice =
                    Some(parse_choice(it.next().expect("--choice needs a value")).expect("choice"))
            }
            "--net" => net = PathBuf::from(it.next().expect("--net needs a value")),
            "--spool" => spool = Some(PathBuf::from(it.next().expect("--spool needs a value"))),
            "--double" => double = true,
            "--raw" => raw = true,
            "--retransmit" => retransmit = true,
            other => panic!(
                "unknown flag {other} (--id --choice --net --spool --double --raw --retransmit)"
            ),
        }
    }
    let id = id.expect("--id is required");
    let choice = choice.expect("--choice is required");
    let spool = spool.unwrap_or_else(|| net.join("spool"));
    std::fs::create_dir_all(&spool).expect("spool dir creatable");

    // 1. The published declaration alone rebuilds the anchored frontier.
    let declared_raw = std::fs::read(net.join("declared.json"))
        .expect("declared.json must exist (the maintainer publishes it first)");
    let declared_doc: serde_json::Value =
        serde_json::from_slice(&declared_raw).expect("declared.json is valid JSON");
    let declared = Declaration::from_json(&declared_doc).expect("declared.json is malformed");
    let (_tree, notes) = rehearsal_tree(declared.seed, declared.voters);
    assert!(
        id < declared.voters,
        "voter id {id} is outside the declared voter set"
    );
    let collector_pk = declared.collector_pk;

    // The collector NODE routing key (published by `gov_collector init`):
    // the node identity routes the chunk blobs, the ballot key opens.
    let node_doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(net.join("collector-node.json"))
            .expect("collector-node.json must exist (run gov_collector init)"),
    )
    .expect("collector-node.json is valid JSON");
    let routing_bytes: [u8; 32] = common::hex_decode(
        node_doc["routing_pk"].as_str().expect("routing_pk"),
        "collector-node.routing_pk",
    )
    .expect("routing pk")
    .try_into()
    .expect("routing pk is 32 bytes");
    let routing = CompressedRistretto(routing_bytes);

    // 2. The wallet-real bridge (WP-D2b): every global leaf is
    //    confirmed in order, the voter's own note is tracked. The
    //    confirm heights are monotonic and all at-or-before h_open -
    //    the snapshot IS the declared frontier.
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let key = SpendingKey::from_mnemonic(phrase).expect("rehearsal wallet key");
    let mut wallet = LightWallet::new(&key);
    let h0 = 10u64;
    for (leaf, note) in notes.iter().enumerate() {
        if leaf == id {
            wallet
                .add_v4_note(note.clone(), h0 + leaf as u64)
                .expect("own note");
        } else {
            wallet
                .confirm_v4_leaf(note.tree_entry().expect("seeded note"), h0 + leaf as u64)
                .expect("global leaf");
        }
    }
    // The trailing dust leaf completes the frontier (owned by nobody).
    let dust = common::deterministic_note(declared.seed, declared.voters, common::DUST_LEAF_VALUE);
    wallet
        .confirm_v4_leaf(
            dust.tree_entry().expect("seeded note"),
            h0 + declared.voters as u64,
        )
        .expect("dust leaf");
    assert_eq!(
        wallet.v4_leaves(),
        declared.voters + 1,
        "the mirror is complete"
    );

    let inputs = wallet
        .gov_inputs_at(declared.h_open)
        .expect("h_open snapshot");
    assert_eq!(
        inputs.frontier.root(),
        declared.anchor,
        "the h_open snapshot root must be the declared anchor"
    );
    let indices: Vec<usize> = inputs.notes.iter().map(|(i, _)| *i).collect();
    let refs: Vec<&opacus_wallet::tx_v4::WalletNoteV4> =
        inputs.notes.iter().map(|(_, n)| n).collect();
    assert_eq!(
        refs.len(),
        1,
        "one rehearsal wallet holds exactly its own note"
    );

    // 3. One real prove per ballot; the ballots anchor at the snapshot.
    let ship_one = |choice: Choice, tag: &str| {
        let ballot = build_ballot::<DEPTH>(
            &inputs.frontier,
            &indices,
            &refs,
            declared.gip,
            declared.transition,
            declared.h_open,
            choice,
        )
        .expect("ballot builds");
        verify_ballot::<DEPTH>(&ballot).expect("ballot verifies");
        verify_ballot_against_tree::<DEPTH>(&ballot, &inputs.frontier)
            .expect("ballot anchors at the declared frontier");
        let env = BallotEnvelope::seal(&ballot, &collector_pk).expect("seal");
        let sid = env.envelope_id().expect("envelope id");
        let wire = env.to_bytes();
        let n = ship_wire(&spool, &wire, sid, &routing);
        println!(
            "voter {id} ({tag}): envelope_id={} blobs={} choice={choice:?}",
            hex_encode(&sid),
            n
        );
        (wire, sid)
    };

    let ts = |tag: &str| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis();
        println!("ts_ms={now} voter={id} step={tag}");
    };

    ts("ballot");
    let (wire, sid) = ship_one(choice, "ballot");

    if raw {
        // 4. The raw fallback over the same endpoint: the canonical
        //    ballot wire as its own stream (sid = blake3 over the wire;
        //    the collector routes it blind into ingest_raw).
        let ballot = build_ballot::<DEPTH>(
            &inputs.frontier,
            &indices,
            &refs,
            declared.gip,
            declared.transition,
            declared.h_open,
            choice,
        )
        .expect("raw ballot builds");
        let bytes = ballot.to_bytes();
        let raw_sid: [u8; 32] = *blake3::hash(&bytes).as_bytes();
        let n = ship_wire(&spool, &bytes, raw_sid, &routing);
        ts("raw-fallback");
        println!("voter {id} (raw): sid={} blobs={}", hex_encode(&raw_sid), n);
    }

    if double {
        // 5. The deliberate double vote: the SAME notes, a different
        //    choice - the serials collide and the close trace carries
        //    DuplicateSerial.
        let other = match choice {
            Choice::For => Choice::Against,
            _ => Choice::For,
        };
        ts("double-vote");
        let _ = ship_one(other, "double");
    }

    if retransmit {
        // 6. The byte-equal retransmission: the SAME envelope wire
        //    re-sealed (fresh blob ids, the same chunk plaintexts) -
        //    the assembler drops every chunk (the D2c dedupe).
        ts("retransmit");
        let n = seal_stream(&wire, sid, &routing).expect("re-seal").len();
        for b in seal_stream(&wire, sid, &routing).expect("re-seal") {
            write_blob(&spool, &b);
        }
        println!("voter {id} (retransmit): blobs={n} (assembler dedupe expected)");
    }

    println!(
        "voter {id} done: notes_confirmed={} frontier_leaves={} anchor_ok",
        wallet.v4_leaves(),
        inputs.frontier.len()
    );
}

/// Chunk + seal one wire to the collector routing key and drop one
/// file per blob into the spool. Returns the blob count.
fn ship_wire(
    spool: &std::path::Path,
    wire: &[u8],
    sid: [u8; 32],
    routing: &CompressedRistretto,
) -> usize {
    let blobs = seal_stream(wire, sid, routing).expect("chunk + seal");
    for b in &blobs {
        write_blob(spool, b);
    }
    blobs.len()
}

fn write_blob(spool: &std::path::Path, blob: &opacus_network::NoteBlob) {
    let bytes = serde_json::to_vec(blob).expect("blob json");
    let name = format!(
        "{}.gchunk",
        hex_encode(&blake3::hash(&bytes).as_bytes()[..12])
    );
    std::fs::write(spool.join(name), bytes).expect("spool write");
}
