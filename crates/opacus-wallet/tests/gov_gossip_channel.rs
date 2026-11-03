//! GIP-2 WP-D2c cross-layer test (runbook stage R3, WP-D2c definition):
//! a REAL GBE1 ballot envelope - built and proved at the rehearsal depth
//! - rides the v5 note-path gossip channel end to end.
//!
//! The loop: `build_ballot` -> `verify_ballot` -> `BallotEnvelope::seal`
//! -> `to_bytes` (the ~22.7 KB GBE1 wire) -> `chunk_stream` + `seal_stream`
//! (52 opaque note blobs, sealed to the collector NODE identity) ->
//! `GovAssembler` -> byte-equal wire back -> `from_bytes` -> `open` with
//! the collector BALLOT key -> the same ballot, re-verified and accepted
//! by the archive.
//!
//! Layer separation is the point: the network layer only ever sees
//! opaque sealed chunks keyed by the public `envelope_id`; the ballot
//! layer never touches sockets. The dev-dependency on opacus-network
//! exists ONLY for this test - the wallet's production dependency graph
//! stays node-free.

use opacus_network::gov_channel::{feed_note, seal_stream, GovAssembler};
use opacus_network::identity::NodeIdentity;
use opacus_wallet::gov::{build_ballot, verify_ballot, verify_ballot_against_tree, Choice};
use opacus_wallet::gov_transport::{ballot_keypair_from_seed, BallotEnvelope};
use opacus_wallet::tx_v4::WalletNoteV4;
use opacus_wallet::zk_spend::{fp_to_bytes, TreeState};
use opacus_zk::prelude::Fp;

/// Mainnet-shaped frontier depth (the runbook pins the rehearsal to 32).
const DEPTH: usize = 32;
/// The rehearsal proposal tag (the R0 shape).
const GIP: u32 = 2;
const TRANSITION: u8 = 0;
const H_OPEN: u64 = 100;

fn domain_fp(domain: &str, idx: usize) -> Fp {
    Fp::from(u64::from_le_bytes(
        blake3::Hasher::new()
            .update(b"opacus-gov-gossip-test-v1")
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

#[test]
fn gbe1_envelope_rides_the_gossip_channel() {
    // A small wallet-real frontier: the voter holds 12e9 atoms (>= T_MIN),
    // two padding leaves complete the shape.
    let mut tree = TreeState::new(DEPTH);
    let voter_note = deterministic_note(0, 12_000_000_000);
    tree.append(voter_note.tree_entry().expect("seeded note is well-formed"));
    for leaf in 1..3 {
        let pad = deterministic_note(leaf, 9_000_000_000 + leaf as u64);
        tree.append(pad.tree_entry().expect("seeded note is well-formed"));
    }
    assert_eq!(tree.len(), 3);

    // One real ballot at mainnet depth (the only prove in this test).
    let ballot = build_ballot::<DEPTH>(
        &tree,
        &[0],
        &[&voter_note],
        GIP,
        TRANSITION,
        H_OPEN,
        Choice::For,
    )
    .expect("ballot builds");
    verify_ballot::<DEPTH>(&ballot).expect("ballot verifies");
    verify_ballot_against_tree::<DEPTH>(&ballot, &tree).expect("ballot anchors at the frontier");

    // The ballot-layer transport: sealed GBE1 envelope + public id.
    let mut collector_seed = [0u8; 64];
    collector_seed[..32].copy_from_slice(
        blake3::Hasher::new()
            .update(b"opacus-gov-gossip-test-v1")
            .update(b"collector-0")
            .finalize()
            .as_bytes(),
    );
    collector_seed[32..].copy_from_slice(
        blake3::Hasher::new()
            .update(b"opacus-gov-gossip-test-v1")
            .update(b"collector-1")
            .finalize()
            .as_bytes(),
    );
    let collector_sk = ballot_keypair_from_seed(&collector_seed);
    let collector_pk = collector_sk.public();
    let env = BallotEnvelope::seal(&ballot, &collector_pk).expect("seal");
    let wire = env.to_bytes();
    // the GBE1 wire is the ~22.7 KB shape the channel was built for
    assert!(wire.len() > 20_000, "GBE1 wire: {}", wire.len());

    // The gossip channel: stream_id = the public envelope_id.
    let sid = env.envelope_id().expect("envelope id");
    // The collector NODE identity (a distinct trust root from the ballot
    // collector key: the node identity routes, the ballot key opens).
    let dir = std::env::temp_dir().join(format!(
        "gov-gossip-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let (identity, _) =
        NodeIdentity::load_or_generate(&dir.join("collector-identity.json")).expect("identity");

    let blobs = seal_stream(&wire, sid, &identity.pr).expect("chunk + seal");
    // 52 chunks at the GBE1 size (51 full + tail) - the v5 note cap makes
    // one blob impossible, chunking is the whole point
    assert_eq!(blobs.len(), 52);

    // The collector-side reassembly, exactly the R3 collector loop.
    let mut asm = GovAssembler::new(8, 64);
    let mut done = None;
    for b in &blobs {
        done = feed_note(b, &identity, &mut asm).expect("honest chunks never violate the channel");
    }
    let wire2 = done.expect("the final chunk completes the stream");
    assert_eq!(wire2, wire, "byte-equal envelope back from the wire");
    assert_eq!(asm.completed_streams(), 1);
    assert_eq!(asm.live_streams(), 0);

    // The ballot layer consumes the reassembled wire verbatim.
    let env2 = BallotEnvelope::from_bytes(&wire2).expect("canonical GBE1 parse");
    assert_eq!(env2.envelope_id().expect("id"), sid);
    assert_eq!(env2.gip, GIP);
    assert_eq!(env2.transition, TRANSITION);
    assert_eq!(env2.h_open, H_OPEN);
    let ballot2 = env2
        .open(&collector_sk)
        .expect("opens with the collector key");
    assert_eq!(ballot2.to_bytes(), ballot.to_bytes());
    verify_ballot::<DEPTH>(&ballot2).expect("the transported ballot still verifies");

    // Envelope-level dedupe: a fresh seal of the same envelope produces
    // NEW blob ids (fresh ECIES) but the SAME chunk plaintexts - the
    // assembler drops every retransmitted chunk.
    let again = seal_stream(&wire, sid, &identity.pr).expect("re-seal");
    for b in &again[..3] {
        assert_eq!(
            feed_note(b, &identity, &mut asm).expect("retransmission is not a violation"),
            None,
            "an already-delivered envelope must not emit twice"
        );
    }
    assert_eq!(asm.duplicate_chunks(), 3);
    assert_eq!(asm.completed_streams(), 1);

    std::fs::remove_dir_all(&dir).ok();
}
