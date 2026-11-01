//! WG-CLSAG WP-D: benchmark smoke for the monerod-facing CLSAG verify path
//! (crates/opacus-bridge/src/clsag_verify.rs).
//!
//! Ground truth is the real mainnet fixture also used by the acceptance
//! tests (tests/clsag_verify_fixture.rs): tx
//! `43bd6f459b84f14162143e28c83a0fd1d58cb8e4c328070fa79ca198a0c79a23`
//! (height 3796485, RCTTypeBulletproofPlus, 2 inputs, ring size 16).
//!
//! The smoke is fail-closed: before any timing, the honest tx must verify
//! (full tx and every input separately) and a tampered tx must be
//! rejected. Any wrong verdict exits non-zero - the printed numbers are
//! only meaningful behind that gate.
//!
//! Run: `cargo bench -p opacus-bridge --bench clsag_bench`
//! (release profile; harness = false, no new dependencies).

use std::time::Instant;

use opacus_bridge::clsag_verify::{pre_mlsag_hash, verify_clsag, verify_tx, MoneroTx, RingMember};

const FIXTURE: &str = include_str!("../tests/fixtures/clsag_mainnet_v1.json");
const WARMUP: usize = 20;
const ITERATIONS: usize = 100;

fn k32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("fixture hex");
    assert_eq!(v.len(), 32, "fixture hex field must be 32 bytes");
    v.try_into().unwrap()
}

fn load_fixture() -> (serde_json::Value, Vec<u8>, MoneroTx) {
    let fx: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture json");
    let blob = hex::decode(fx["tx_hex"].as_str().expect("tx_hex")).expect("tx hex");
    let tx = MoneroTx::parse(&blob).expect("fixture tx must parse");
    (fx, blob, tx)
}

fn rings_from(fx: &serde_json::Value) -> Vec<Vec<RingMember>> {
    fx["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|inp| {
            inp["outs"]
                .as_array()
                .expect("outs")
                .iter()
                .map(|o| RingMember {
                    dest: k32(o["key"].as_str().expect("key")),
                    mask: k32(o["mask"].as_str().expect("mask")),
                })
                .collect()
        })
        .collect()
}

fn main() {
    let (fx, blob, tx) = load_fixture();
    let rings = rings_from(&fx);
    let n_inputs = tx.clsags.len();
    let ring_size = tx.clsags[0].s.len();

    println!(
        "fixture: tx {}  height {}  rct_type {}  inputs {}  ring {}",
        &fx["tx_hash"].as_str().unwrap()[..16],
        fx["height"].as_u64().unwrap(),
        fx["rct_type"].as_u64().unwrap(),
        n_inputs,
        ring_size,
    );

    // --- fail-closed smoke gate 1: the honest mainnet tx must verify ------
    assert!(verify_tx(&tx, &rings), "honest mainnet tx must verify");
    let message = pre_mlsag_hash(&tx);
    for (i, ring) in rings.iter().enumerate() {
        assert!(
            verify_clsag(
                &message,
                &tx.clsags[i],
                &tx.vin[i].k_image,
                ring,
                &tx.pseudo_outs[i],
            ),
            "input {i} must verify"
        );
    }

    // --- fail-closed smoke gate 2: a tampered tx must be rejected ---------
    let mut tampered = tx.clone();
    tampered.clsags[0].s[0][11] ^= 0x10;
    let tampered_blob = tampered.re_serialize();
    let tampered = MoneroTx::parse(&tampered_blob).expect("tamper stays parseable");
    assert!(
        !verify_tx(&tampered, &rings),
        "tampered tx must be rejected"
    );
    println!("smoke gates OK: honest tx verifies (tx + {n_inputs} inputs), tampered tx rejected");

    // --- warmup ------------------------------------------------------------
    for _ in 0..WARMUP {
        let parsed = MoneroTx::parse(&blob).expect("warmup parse");
        std::hint::black_box(&parsed);
        std::hint::black_box(verify_tx(&tx, &rings));
    }

    // --- parse -------------------------------------------------------------
    let mut parse_ns = 0u128;
    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        let parsed = MoneroTx::parse(&blob).expect("bench parse");
        parse_ns += t0.elapsed().as_nanos();
        std::hint::black_box(&parsed);
    }

    // --- pre_mlsag_hash ----------------------------------------------------
    let mut msg_ns = 0u128;
    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        let m = pre_mlsag_hash(&tx);
        msg_ns += t0.elapsed().as_nanos();
        std::hint::black_box(&m);
    }

    // --- per-input verify_clsag --------------------------------------------
    let mut input_ns = vec![0u128; n_inputs];
    for i in 0..n_inputs {
        for _ in 0..ITERATIONS {
            let t0 = Instant::now();
            let ok = verify_clsag(
                &message,
                &tx.clsags[i],
                &tx.vin[i].k_image,
                &rings[i],
                &tx.pseudo_outs[i],
            );
            input_ns[i] += t0.elapsed().as_nanos();
            assert!(ok, "input {i} must verify during bench");
        }
    }

    // --- full verify_tx ----------------------------------------------------
    let mut verify_ns = 0u128;
    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        let ok = verify_tx(&tx, &rings);
        verify_ns += t0.elapsed().as_nanos();
        std::hint::black_box(ok);
    }

    // --- report ------------------------------------------------------------
    let it = ITERATIONS as f64;
    let parse_us = parse_ns as f64 / it / 1000.0;
    let msg_us = msg_ns as f64 / it / 1000.0;
    let verify_us = verify_ns as f64 / it / 1000.0;
    println!("parse MoneroTx:          {parse_us:9.1} us/op");
    println!("pre_mlsag_hash:          {msg_us:9.1} us/op");
    for (i, ns) in input_ns.iter().enumerate() {
        let us = *ns as f64 / it / 1000.0;
        println!("verify_clsag input {i}:     {us:9.1} us/op  (ring {ring_size})");
    }
    println!("verify_tx ({n_inputs} inputs):      {verify_us:9.1} us/op");
    let txps = 1_000_000.0 / verify_us;
    println!(
        "throughput:              {txps:9.2} tx/s  ({ITERATIONS} iterations, {WARMUP} warmup, release)"
    );
}
