//! Prover plumbing for the v4 spend circuit [S4 8, S4 13 Phase 3].
//!
//! Additive module: nothing in the delivered Phase 2 files changes. This
//! module (a) pins the NORMATIVE reconstruction of the public instance
//! vector from tx-level fields, so the wallet and consensus cannot disagree
//! on the instance order, (b) offers a mock-prover self-check that works
//! without the `real-prover` feature, and (c) under `real-prover` wraps the
//! halo2 keygen/prove/verify dance for [`V4SpendCircuit`] (the exact flow
//! the Phase 2 real-prover test drives).
//!
//! Instance vector [S4 8], 15 slots, order normative:
//!
//! ```text
//! [root, N_0, N_1, RC_in_0.x, RC_in_0.y, RC_in_1.x, RC_in_1.y,
//!  RC_out_0.x, RC_out_0.y, ..., RC_out_3.x, RC_out_3.y]
//! ```
//!
//! Disabled slots are zero-padded; for RC points the (0, 0) pair is the
//! encoded identity of the Phase 1b fixed-base gates.

use crate::spend::{coords, V4SpendCircuit, MAX_IN, MAX_OUT, SPEND_INSTANCE_SLOTS};
use crate::v4::fq_reduce_fp;
use ff::Field;
use halo2_proofs::circuit::Value;
use pasta_curves::Fp;

// Re-exports so downstream crates (opacus-wallet) can drive the v4 pipeline
// without adding pasta_curves/group to their own manifests.
pub use group::{Curve, Group, GroupEncoding};
pub use pasta_curves::{pallas, vesta, Fq};

/// Normative public instance vector [S4 8] of a v4 spend.
///
/// `ns`/`rc_in` carry the ENABLED inputs (len <= MAX_IN), `rc_out` the
/// ENABLED outputs (len <= MAX_OUT); missing slots are zero-padded exactly
/// as the circuit's pad-zero cell expects. Panics on lengths beyond the
/// fixed topology (a programming error, never a runtime condition).
pub fn spend_instances(
    root: Fp,
    ns: &[Fp],
    rc_in: &[pallas::Point],
    rc_out: &[pallas::Point],
) -> Vec<Fp> {
    assert!(
        ns.len() <= MAX_IN && rc_in.len() <= MAX_IN && rc_out.len() <= MAX_OUT,
        "v4 topology violation: inputs/outputs beyond MAX_IN/MAX_OUT"
    );
    let mut v: Vec<Fp> = Vec::with_capacity(SPEND_INSTANCE_SLOTS);
    v.push(root);
    for i in 0..MAX_IN {
        v.push(ns.get(i).copied().unwrap_or(Fp::ZERO));
    }
    for i in 0..MAX_IN {
        match rc_in.get(i) {
            Some(p) => {
                let (x, y) = coords(p);
                v.push(x);
                v.push(y);
            }
            None => {
                v.push(Fp::ZERO);
                v.push(Fp::ZERO);
            }
        }
    }
    for j in 0..MAX_OUT {
        match rc_out.get(j) {
            Some(p) => {
                let (x, y) = coords(p);
                v.push(x);
                v.push(y);
            }
            None => {
                v.push(Fp::ZERO);
                v.push(Fp::ZERO);
            }
        }
    }
    // WG-26 [S4 12]: the 6-slot swap tail; plain transactions publish zeros.
    v.resize(SPEND_INSTANCE_SLOTS, Fp::ZERO);
    assert_eq!(v.len(), SPEND_INSTANCE_SLOTS, "instance slot invariant");
    v
}

/// WG-26 [S4 12]: normative 21-slot instance vector with the swap tail
/// published (lock, claim and refund transactions).
pub fn spend_instances_with_swap(
    root: Fp,
    ns: &[Fp],
    rc_in: &[pallas::Point],
    rc_out: &[pallas::Point],
    swap: &crate::spend::SwapPub,
) -> Vec<Fp> {
    let mut v = spend_instances(root, ns, rc_in, rc_out);
    let n = v.len();
    v[n - 6] = Fp::from(swap.flag as u64);
    v[n - 5] = Fp::from(swap.idx as u64);
    v[n - 4] = swap.h;
    v[n - 3] = swap.s0;
    v[n - 2] = swap.s1;
    v[n - 1] = swap.entry;
    v
}

/// WG-26 [S4 12]: unpack the swap tail (slots 15..20) of the normative
/// instance vector into the circuit struct fields.
fn swap_tail_of(instances: &[Fp]) -> (u8, u8, Fp, Fp, Fp) {
    assert_eq!(
        instances.len(),
        SPEND_INSTANCE_SLOTS,
        "instance slot invariant"
    );
    let small = |v: &Fp| -> u8 {
        let r = ff::PrimeField::to_repr(v);
        r.as_ref()[0]
    };
    (
        small(&instances[15]),
        small(&instances[16]),
        instances[17],
        instances[18],
        instances[19],
    )
}

/// Mock-prover self-check of a v4 spend against its normative instances.
///
/// Available WITHOUT the `real-prover` feature: wallets and consensus tests
/// can validate the full witness/instance contract cheaply before paying
/// for a real IPA proof. Errors are rendered as strings because
/// `MockProver::VerifyFailure` is not cloneable across crates.
pub fn mock_verify_v4<const DEPTH: usize>(
    witness: &crate::spend::SpendWitness,
    r_in: &[Fq],
    r_out: &[Fq],
    n_in: usize,
    n_out: usize,
    instances: &[Fp],
) -> Result<(), String> {
    assert_eq!(
        instances.len(),
        SPEND_INSTANCE_SLOTS,
        "instance slot invariant"
    );
    let (swap_flag, swap_idx, swap_h, swap_s0, swap_s1) = swap_tail_of(instances);
    let circuit: V4SpendCircuit<DEPTH> = V4SpendCircuit {
        witness: Value::known(witness.clone()),
        r_in: r_in.to_vec(),
        r_out: r_out.to_vec(),
        n_in,
        n_out,
        swap_flag,
        swap_idx,
        swap_h,
        swap_s0,
        swap_s1,
        corrupt_preimage: false,
        corrupt_swap_flag: false,
        corrupt_limb: None,
        corrupt_leaf: None,
    };
    let k = V4SpendCircuit::<DEPTH>::required_k();
    let prover = halo2_proofs::dev::MockProver::run(k, &circuit, vec![instances.to_vec()])
        .map_err(|e| format!("mock prover construction failed: {e:?}"))?;
    prover
        .verify()
        .map_err(|e| format!("mock verification failed: {e:?}"))
}

#[cfg(feature = "real-prover")]
mod real {
    use super::*;
    use halo2_proofs::plonk::{
        self, create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier,
        VerifyingKey,
    };
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    // -----------------------------------------------------------------------
    // Process-wide keyset cache (WG-17, the [S4 8] 10 s budget item).
    //
    // Keygen is a pure function of the circuit STRUCTURE: fixed-column
    // assignments, selector enablement and copy constraints are wired by the
    // enabled topology `(n_in, n_out)` - never by witness values. The
    // delivery suite already relies on exactly this: `verify_v4` derives its
    // vk from a zero-witness synthesis and validates proofs produced from a
    // real-witness keygen bit-for-bit. Caching keysets therefore cannot
    // change a single proof byte; it only removes the per-call rebuild of
    // `Params` (k), `VerifyingKey` and `ProvingKey`, which the phase split
    // measured at ~53 % of prove and ~99 % of verify wall time on the
    // reference machine.
    //
    // Locking discipline: the global cache mutex guards map lookups/inserts
    // ONLY. vk keygen runs outside the global lock (first-wins insert; a
    // racing duplicate build is discarded). pk keygen runs under the
    // entry-local pk mutex, so only proves of the SAME topology contend.
    struct V4KeyCache {
        params: HashMap<usize, Arc<Params<vesta::Affine>>>,
        keys: HashMap<(usize, usize, usize), Arc<TopologyKeys>>,
    }

    struct TopologyKeys {
        vk: VerifyingKey<vesta::Affine>,
        pk: Mutex<Option<Arc<ProvingKey<vesta::Affine>>>>,
    }

    static V4_CACHE: OnceLock<Mutex<V4KeyCache>> = OnceLock::new();

    fn v4_cache() -> &'static Mutex<V4KeyCache> {
        V4_CACHE.get_or_init(|| {
            Mutex::new(V4KeyCache {
                params: HashMap::new(),
                keys: HashMap::new(),
            })
        })
    }

    fn cached_params(k: u32) -> Arc<Params<vesta::Affine>> {
        let mut cache = v4_cache().lock().expect("v4 keyset cache poisoned");
        Arc::clone(
            cache
                .params
                .entry(k as usize)
                .or_insert_with(|| Arc::new(Params::<vesta::Affine>::new(k))),
        )
    }

    fn get_or_build_vk<const DEPTH: usize>(
        params: &Params<vesta::Affine>,
        circuit: &V4SpendCircuit<DEPTH>,
        n_in: usize,
        n_out: usize,
    ) -> Result<Arc<TopologyKeys>, plonk::Error> {
        let key = (DEPTH, n_in, n_out);
        if let Some(entry) = v4_cache()
            .lock()
            .expect("v4 keyset cache poisoned")
            .keys
            .get(&key)
        {
            return Ok(Arc::clone(entry));
        }
        // Slow path OUTSIDE the global lock: first-wins on insert, a racing
        // duplicate vk build is simply discarded.
        let vk = keygen_vk(params, circuit)?;
        let mut cache = v4_cache().lock().expect("v4 keyset cache poisoned");
        Ok(Arc::clone(cache.keys.entry(key).or_insert_with(|| {
            Arc::new(TopologyKeys {
                vk,
                pk: Mutex::new(None),
            })
        })))
    }

    fn cached_pk<const DEPTH: usize>(
        params: &Params<vesta::Affine>,
        entry: &TopologyKeys,
        circuit: &V4SpendCircuit<DEPTH>,
    ) -> Result<Arc<ProvingKey<vesta::Affine>>, plonk::Error> {
        let mut slot = entry.pk.lock().expect("v4 pk slot poisoned");
        if let Some(pk) = slot.as_ref() {
            return Ok(Arc::clone(pk));
        }
        let pk = Arc::new(keygen_pk(params, entry.vk.clone(), circuit)?);
        *slot = Some(Arc::clone(&pk));
        Ok(pk)
    }

    /// A completed v4 spend proof: raw IPA proof bytes over the 15-slot
    /// instance column. The instances are NOT repeated here on purpose:
    /// the verifier reconstructs them from the transaction fields [S4 9
    /// step 2: instances MUST equal tx fields exactly].
    #[derive(Clone, Debug)]
    pub struct V4Proof {
        pub proof: Vec<u8>,
    }

    /// Keygen + prove a v4 spend [S4 8]. `n_in`/`n_out` are the ENABLED
    /// topology (1..=MAX_IN / 1..=MAX_OUT); `instances` is the normative
    /// 15-slot vector ([`spend_instances`]).
    ///
    /// Keysets (`Params`, vk, pk) are served from the process-wide cache
    /// ([`v4_cache`]) keyed by `(k)` and `(DEPTH, n_in, n_out)`: the FIRST
    /// call of a process pays the full keygen, every later call (wallet
    /// session, node daemon) proves at steady-state cost. Proofs are
    /// bit-for-bit the same construction as an uncached build - only
    /// transcript blinding randomness (OsRng) differs, as before.
    pub fn prove_v4<const DEPTH: usize>(
        witness: &crate::spend::SpendWitness,
        r_in: &[Fq],
        r_out: &[Fq],
        n_in: usize,
        n_out: usize,
        instances: &[Fp],
    ) -> Result<V4Proof, plonk::Error> {
        assert_eq!(
            instances.len(),
            SPEND_INSTANCE_SLOTS,
            "instance slot invariant"
        );
        let (swap_flag, swap_idx, swap_h, swap_s0, swap_s1) = swap_tail_of(instances);
        assert!((1..=MAX_IN).contains(&n_in) && (1..=MAX_OUT).contains(&n_out));
        let circuit: V4SpendCircuit<DEPTH> = V4SpendCircuit {
            witness: Value::known(witness.clone()),
            r_in: r_in.to_vec(),
            r_out: r_out.to_vec(),
            n_in,
            n_out,
            swap_flag,
            swap_idx,
            swap_h,
            swap_s0,
            swap_s1,
            corrupt_preimage: false,
            corrupt_swap_flag: false,
            corrupt_limb: None,
            corrupt_leaf: None,
        };
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let params = cached_params(k);
        let entry = get_or_build_vk(&params, &circuit, n_in, n_out)?;
        let pk = cached_pk(&params, &entry, &circuit)?;
        let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(Vec::new());
        create_proof::<
            vesta::Affine,
            Challenge255<vesta::Affine>,
            OsRng,
            Blake2bWrite<Vec<u8>, vesta::Affine, Challenge255<vesta::Affine>>,
            _,
        >(
            &params,
            &pk,
            std::slice::from_ref(&circuit),
            &[&[instances]],
            OsRng,
            &mut transcript,
        )?;
        Ok(V4Proof {
            proof: transcript.finalize(),
        })
    }

    /// Verify a v4 spend proof against instances reconstructed from the
    /// transaction fields [S4 9 step 2]. The verification circuit is built
    /// witness-less with the SAME enabled topology the prover used, so the
    /// derived verifying key matches bit-for-bit.
    ///
    /// Params and vk are served from the process-wide cache (see
    /// [`prove_v4`]); steady-state verification drops to the pure
    /// `verify_proof` cost (measured ~0.07 s at k = 13).
    pub fn verify_v4<const DEPTH: usize>(
        proof: &[u8],
        instances: &[Fp],
        n_in: usize,
        n_out: usize,
    ) -> Result<(), plonk::Error> {
        assert_eq!(
            instances.len(),
            SPEND_INSTANCE_SLOTS,
            "instance slot invariant"
        );
        let (swap_flag, swap_idx, swap_h, swap_s0, swap_s1) = swap_tail_of(instances);
        assert!((1..=MAX_IN).contains(&n_in) && (1..=MAX_OUT).contains(&n_out));
        let circuit: V4SpendCircuit<DEPTH> = V4SpendCircuit {
            witness: Value::unknown(),
            r_in: vec![Fq::ZERO; n_in],
            r_out: vec![Fq::ZERO; n_out],
            n_in,
            n_out,
            swap_flag,
            swap_idx,
            swap_h,
            swap_s0,
            swap_s1,
            corrupt_preimage: false,
            corrupt_swap_flag: false,
            corrupt_limb: None,
            corrupt_leaf: None,
        };
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let params = cached_params(k);
        let entry = get_or_build_vk(&params, &circuit, n_in, n_out)?;
        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
        let strategy = SingleVerifier::new(&params);
        verify_proof::<vesta::Affine, Challenge255<vesta::Affine>, _, _>(
            &params,
            &entry.vk,
            strategy,
            &[&[instances]],
            &mut transcript,
        )?;
        Ok(())
    }
}

#[cfg(feature = "real-prover")]
pub use real::{prove_v4, verify_v4, V4Proof};

/// The Phase 3 normative embedding of the accumulator root into the
/// base-point group, bridging the two delivered representations:
/// the proof consumes the `Fp` merkle root over tree entries, while the
/// delivered `sighash_v4` takes the root as a curve point [S4 7].
///
/// `acc_root_point(root) = [root] * G` with G = the system base point
/// (`pallas::Point::generator()`, the same base as `p_leaf` and
/// `hashgen`). Deterministic, binding, and computable from the published
/// tx alone.
pub fn acc_root_point(root: Fp) -> pallas::Point {
    pallas::Point::generator() * fq_reduce_fp(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::spend::{leaf_entry_v2, SpendNoteInput, SpendNoteOutput};
    use crate::v4::{blind_gen, nullifier_v4, value_commit, value_gen};
    use ff::Field;
    use rand::rngs::OsRng;

    #[test]
    fn spend_instances_pad_normatively() {
        // 1-in / 2-out wallet topology: pads land exactly where the
        // Phase 2 docblock puts them [S4 8].
        let root = Fp::from(77u64);
        let ns = vec![Fp::from(11u64)];
        let g = pallas::Point::generator();
        let rc_in = vec![g * Fq::from(3)];
        let rc_out = vec![g * Fq::from(4), g * Fq::from(5)];
        let v = spend_instances(root, &ns, &rc_in, &rc_out);
        assert_eq!(v.len(), SPEND_INSTANCE_SLOTS);
        assert_eq!(v[0], root);
        assert_eq!(v[1], Fp::from(11u64));
        assert_eq!(v[2], Fp::ZERO); // N pad
        let (x0, y0) = coords(&rc_in[0]);
        assert_eq!(v[3], x0);
        assert_eq!(v[4], y0);
        assert_eq!(v[5], Fp::ZERO); // RC_in pad (identity encoding)
        assert_eq!(v[6], Fp::ZERO);
        let (xo0, yo0) = coords(&rc_out[0]);
        let (xo1, yo1) = coords(&rc_out[1]);
        assert_eq!(v[7], xo0);
        assert_eq!(v[8], yo0);
        assert_eq!(v[9], xo1);
        assert_eq!(v[10], yo1);
        assert_eq!(v[11], Fp::ZERO); // RC_out pads x2
        assert_eq!(v[12], Fp::ZERO);
        assert_eq!(v[13], Fp::ZERO);
        assert_eq!(v[14], Fp::ZERO);
        // Full MAX topology fills all 15 slots with real data.
        let ns2: Vec<Fp> = (0..MAX_IN).map(|i| Fp::from(i as u64 + 1)).collect();
        let rc_in2: Vec<pallas::Point> = (0..MAX_IN).map(|i| g * Fq::from(i as u64 + 10)).collect();
        let rc_out2: Vec<pallas::Point> =
            (0..MAX_OUT).map(|j| g * Fq::from(j as u64 + 20)).collect();
        let v2 = spend_instances(root, &ns2, &rc_in2, &rc_out2);
        assert_eq!(v2.len(), SPEND_INSTANCE_SLOTS);
        assert_eq!(v2[2], Fp::from(2u64));
        assert_eq!(v2[0], root);
    }

    #[test]
    fn mock_verify_v4_accepts_honest_and_rejects_tampered_instance() {
        const DEPTH: usize = 5;
        // Three honest v4 notes in the tree; spend notes[0].
        let notes: Vec<(Fp, Fp, Fp, Fp, u64)> = (0..3)
            .map(|i| {
                (
                    Fp::from(i as u64 + 1),
                    Fp::random(OsRng),
                    Fp::random(OsRng),
                    Fp::random(OsRng),
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

        let vg = value_gen();
        let rg = blind_gen();
        let r_in = vec![Fq::random(OsRng)];
        let r_out = vec![Fq::random(OsRng), Fq::random(OsRng)];
        let in_val = notes[0].4;
        let rc_in = vec![value_commit(in_val, r_in[0], &vg, &rg)];
        let rc_out = vec![
            value_commit(60, r_out[0], &vg, &rg),
            value_commit(in_val - 60, r_out[1], &vg, &rg),
        ];

        let witness = crate::spend::SpendWitness {
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
        mock_verify_v4::<DEPTH>(&witness, &r_in, &r_out, 1, 2, &instances)
            .expect("honest wallet topology must pass the mock prover");

        // A tampered instance (swapped N slot into a pad slot) must fail.
        let mut bad = instances.clone();
        bad.swap(1, 2);
        assert!(mock_verify_v4::<DEPTH>(&witness, &r_in, &r_out, 1, 2, &bad).is_err());

        // The acc_root_point bridge is deterministic and binding.
        assert_eq!(acc_root_point(Fp::ZERO), pallas::Point::identity());
        assert_eq!(
            acc_root_point(Fp::from(5u64)),
            pallas::Point::generator() * Fq::from(5)
        );
        assert_ne!(acc_root_point(root), acc_root_point(root + Fp::ONE));
    }
}
