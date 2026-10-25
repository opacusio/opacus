//! Prover benchmark [S4 8 budget] - WG-17 keyset-cache delivery.
//!
//! Measures the FULL v4 spend pipeline end to end at mainnet tree depth
//! 2^32 with the real IPA prover (halo2_proofs 0.3.5, Vesta), now on top
//! of the process-wide keyset cache (params keyed by k; vk/pk keyed by
//! (DEPTH, n_in, n_out)):
//!   COLD prove = the FIRST prove_v4 call of a process: builds the cache
//!                (params + keygen vk + keygen pk) then create_proof.
//!   WARM prove = steady state: keysets served from the cache, only
//!                create_proof runs. This is the regime wallets (a spend
//!                session) and the node daemon (per-tx verify) actually
//!                operate in, so the [S4 8] 10 s budget is enforced on the
//!                WARM number.
//!   WARM verify = keysets from the cache + verify_proof.
//! The COLD number is printed for the record (cold-start budget is future
//! work: EC-chain column count, membership-path count).
//!
//! Zero new dependencies: the bench drives only the public opacus-zk API
//! (the exact path wallets use) plus std::time::Instant.
//!
//! Run:
//!   cargo bench -p opacus-zk --features real-prover --bench prover
//!
//! The scenario is fully deterministic (fixed note fields, fixed blinds),
//! so numbers differ only by machine noise. Keygen is a pure function of
//! the circuit structure (never of witness values), so cached keysets are
//! bit-for-bit identical to freshly built ones; proof bytes still differ
//! across runs through transcript blinding randomness (OsRng), as before.

#[cfg(feature = "real-prover")]
fn main() {
    use opacus_zk::merkle;
    use opacus_zk::prelude::Fp;
    use opacus_zk::spend::{
        leaf_entry_v2, SpendNoteInput, SpendNoteOutput, SpendWitness, V4SpendCircuit,
    };
    use opacus_zk::v4::{blind_gen, nullifier_v4, value_commit, value_gen};
    use opacus_zk::v4_prover::{prove_v4, spend_instances, verify_v4, Fq};
    use std::time::Instant;

    const DEPTH: usize = opacus_zk::TREE_DEPTH_MAINNET; // 32 -> 2^32 leaves
    const LEAVES: usize = 64;

    // ---- deterministic scenario: 64-note tree, spend notes[0] (v = 100) ----
    let notes: Vec<(Fp, Fp, Fp, Fp, u64)> = (0..LEAVES)
        .map(|i| {
            (
                Fp::from(i as u64 + 1),
                Fp::from((i as u64 + 7) * 31),
                Fp::from((i as u64 + 11) * 17),
                Fp::from((i as u64 + 3) * 101),
                100 + i as u64,
            )
        })
        .collect();
    let entries: Vec<Fp> = notes
        .iter()
        .map(|(d, a, b, rho, v)| leaf_entry_v2(*d, *a, *b, *v, *rho))
        .collect();
    let root = merkle::build_root(&entries, DEPTH);
    let path0 = merkle::auth_path(&entries, 0, DEPTH);

    let in_val = notes[0].4; // 100
    let vg = value_gen();
    let rg = blind_gen();
    let r_in = vec![Fq::from(12_345u64)];
    let r_out = vec![Fq::from(6_789u64), Fq::from(1_011u64)];
    let rc_in = vec![value_commit(in_val, r_in[0], &vg, &rg)];
    let rc_out = vec![
        value_commit(60, r_out[0], &vg, &rg),
        value_commit(in_val - 60, r_out[1], &vg, &rg),
    ];

    let witness = SpendWitness {
        inputs: vec![SpendNoteInput {
            d: notes[0].0,
            a: notes[0].1,
            b: notes[0].2,
            rho: notes[0].3,
            v: notes[0].4,
            path: path0,
        }],
        outputs: vec![
            SpendNoteOutput { v: 60 },
            SpendNoteOutput { v: in_val - 60 },
        ],
    };
    let ns = vec![nullifier_v4(notes[0].1, notes[0].2, notes[0].3)];
    let instances = spend_instances(root, &ns, &rc_in, &rc_out);
    let k = V4SpendCircuit::<DEPTH>::required_k();

    println!("==== opacus-zk v4 spend prover bench [S4 8] (WG-17 keyset cache) ====");
    println!(
        "scenario : 1-in / 2-out, tree depth {0} (2^{0} leaves), {1} real leaves, k = {2}",
        DEPTH, LEAVES, k
    );

    // ---- prove #1: COLD - builds the process keyset cache ----
    let t = Instant::now();
    let proof_cold = prove_v4::<DEPTH>(&witness, &r_in, &r_out, 1, 2, &instances)
        .expect("honest v4 spend must prove");
    let cold_s = t.elapsed().as_secs_f64();

    // ---- prove #2: WARM - keysets from the cache (steady state) ----
    let t = Instant::now();
    let proof_warm = prove_v4::<DEPTH>(&witness, &r_in, &r_out, 1, 2, &instances)
        .expect("honest v4 spend must prove (warm)");
    let warm_s = t.elapsed().as_secs_f64();

    // ---- verify: WARM - params + vk from the cache ----
    assert_eq!(
        proof_cold.proof.len(),
        proof_warm.proof.len(),
        "proof size must be stable across cache hits"
    );
    let t = Instant::now();
    verify_v4::<DEPTH>(&proof_warm.proof, &instances, 1, 2).expect("honest v4 spend must verify");
    let verify_s = t.elapsed().as_secs_f64();

    let budget = 10.0f64;
    let pass = warm_s < budget;
    println!(
        "prove_v4 COLD (first call: params + keygen vk/pk + create_proof) = {:.2} s",
        cold_s
    );
    println!(
        "prove_v4 WARM (keyset cache hit: create_proof only)              = {:.2} s",
        warm_s
    );
    println!(
        "verify_v4 WARM (params + vk cached, verify_proof)                = {:.2} s",
        verify_s
    );
    println!("proof bytes = {}", proof_warm.proof.len());
    if pass {
        println!(
            "budget [S4 8] = 10.00 s -> steady-state prove {:.2} s WITHIN budget (cold-start {:.2} s for the record)",
            warm_s, cold_s
        );
    } else {
        println!(
            "budget [S4 8] = 10.00 s -> steady-state prove {:.2} s OVER budget by {:.2} s",
            warm_s,
            warm_s - budget
        );
    }
    println!(
        "BENCH-RESULT cold={:.2} warm={:.2} verify={:.2} k={} status={}",
        cold_s,
        warm_s,
        verify_s,
        k,
        if pass { "PASS" } else { "OVER" }
    );
    println!("BENCH-OK verify=OK");
}

#[cfg(not(feature = "real-prover"))]
fn main() {
    println!("BENCH skipped: the real-prover feature is not enabled.");
    println!("Run: cargo bench -p opacus-zk --features real-prover --bench prover");
}
