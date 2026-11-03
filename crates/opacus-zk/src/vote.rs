//! GIP-2 WP-1: the Stage A governance ballot (ZK proof-of-balance).
//!
//! Additive module: no existing circuit file changes semantics; the
//! [`BallotCircuit`] reuses the v4 spend gadget suite ([`crate::spend`]):
//! Poseidon permutations (fixed and witness domain), the rc-limb range
//! gate, the conditional fixed-base EC chains and the commutative tree
//! steps, with three NEW domain constants for the vote chain.
//!
//! # The vote chain [GIP-2 3.2, P-2]
//!
//! ```text
//! vs_key    = Poseidon_3(a, b, DOM_VSK)     (mirrors nk = P(a, b, DOM_NK))
//! vote_rho  = Poseidon_3(rho, proposal, DOM_VRHO)
//! VS        = Poseidon_3(vs_key, vote_rho, DOM_VS)
//! ```
//!
//! The proposal identity enters the serial IN-CIRCUIT (a public instance),
//! so `VS` is a deterministic function of (note, proposal): the same note
//! voting twice on the same proposal publishes the SAME `VS` and the tally
//! rejects the duplicate (R-3), while a different proposal derives a fresh
//! `vote_rho` and nothing links the two ballots. `VS` is domain-separated
//! from the spend nullifier (`DOM_NU`) precisely so a vote never reveals
//! or burns spending capability [GIP-2 7].
//!
//! # What one ballot proves (R-1, R-2)
//!
//! One halo2 proof over a stack of `K in 1..=8` notes (GIP-2 P-2) with
//! public instances `[root, proposal, V, VS_1..VS_K]`:
//!
//! - every note's tree entry is reconstructed through the v4 leaf chain
//!   `L = [P(D, a+b, a*b)] * G + [H_leaf] * G3`, `e = P(L.x, L.y, DOM_ACC)`
//!   and walks the SAME commutative accumulator to the public `root` -
//!   membership against the snapshot anchor at `H_snap` (R-2);
//! - every note value is range-checked by the rc-limb gate, and the
//!   ballot weight `V` is constrained to `v_1 + ... + v_K` - the value
//!   sum (R-1). Membership pins each `v_i` to a REAL committed note, and
//!   committed values are `< 2^64`, so the plain field sum is sound: no
//!   modular forgery of `V` is possible without a valid membership walk;
//! - the in-circuit vote chain publishes `VS_i` derived from the SAME
//!   `(a, b, rho)` witnesses (R-3).
//!
//! # Ballot weight is public in Stage A
//!
//! `V` is a public instance (GIP-2 P-1: exact weighted voting, the
//! Pedersen-commitment aggregate being a Stage A.5 upgrade). The privacy
//! claim is over note identities, owners and the vote/linkage structure -
//! not the aggregate weight.
//!
//! # Instance vector (normative order)
//!
//! ```text
//! [root, proposal, V, VS_1, ..., VS_K]   (BALLOT_INSTANCE_SLOTS = 3 + K)
//! ```
//!
//! The binding signature over the ballot bytes is host-side
//! ([`ballot_sighash`] + [`crate::spend::sign_bind`]) under a per-ballot
//! keypair `bsk = H(owner shares, proposal)`, `bvk = [bsk] * R`; the
//! proposal enters the key derivation, so verification keys do not link
//! a voter's ballots across proposals. Unforgeability by non-owners and
//! field binding (GIP-N, choice, V, VS, anchor) follow from the Schnorr
//! verification plus the proof instances.

use crate::poseidon::poseidon_absorb;
use crate::spend::{dom_acc, SpendConfig, LEAF_CHAIN_ROWS, PERM_ROWS};
use crate::v4::{dom_leaf_v2, fq_reduce_fp, h_leaf_v2, N_LIMBS};
use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::{Curve, Group, GroupEncoding};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use pasta_curves::{pallas, Fp, Fq};

/// Rows consumed by one rc-limb range check (`SpendLimbConfig::assign`).
const LIMB_ROWS: usize = 1 + N_LIMBS;

// ---------------------------------------------------------------------------
// Vote domains [GIP-2 3.2]
// ---------------------------------------------------------------------------

/// Reduce the first 16 bytes of a blake3 digest into `Fp` (the codebase
/// domain-label convention; private copy of the v4 helper).
fn fp_from_label(label: &[u8]) -> Fp {
    let d = blake3::hash(label);
    let b = d.as_bytes();
    let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let two64 = Fp::from(u64::MAX) + Fp::ONE;
    Fp::from(hi) * two64 + Fp::from(lo)
}

/// Domain constant of the per-note vote key.
pub fn dom_vsk() -> Fp {
    fp_from_label(b"OPACUS/v4/dom/vsk")
}

/// Domain constant of the per-(note, proposal) vote seed.
pub fn dom_vrho() -> Fp {
    fp_from_label(b"OPACUS/v4/dom/vrho")
}

/// Domain constant of the vote serial (the nullifier analog, GIP-2 3.2).
pub fn dom_vs() -> Fp {
    fp_from_label(b"OPACUS/v4/dom/vs")
}

// ---------------------------------------------------------------------------
// Host-side vote chain [GIP-2 3.2 step 2]
// ---------------------------------------------------------------------------

/// Vote key `vs_key = Poseidon_3(a, b, DOM_VSK)` of one note.
pub fn vs_key(a: Fp, b: Fp) -> Fp {
    poseidon_absorb(dom_vsk(), a, b)[0]
}

/// Vote seed `vote_rho = Poseidon_3(rho, proposal, DOM_VRHO)`: the note's
/// static nullifier seed mixed with the public proposal identity.
pub fn vote_rho(rho: Fp, proposal: Fp) -> Fp {
    poseidon_absorb(dom_vrho(), rho, proposal)[0]
}

/// Vote serial `VS = Poseidon_3(vs_key, vote_rho, DOM_VS)` [GIP-2 3.2]:
/// deterministic per (note, proposal), one-time use per proposal, never a
/// spend nullifier.
pub fn vote_serial(a: Fp, b: Fp, rho: Fp, proposal: Fp) -> Fp {
    poseidon_absorb(dom_vs(), vs_key(a, b), vote_rho(rho, proposal))[0]
}

/// Public proposal identity [GIP-2 R-4, R-5]:
/// `blake3("OPACUS/v4/gov/proposal", le32(gip), transition, le64(h_open),
/// anchor_repr)` reduced into `Fp` over the first 16 bytes. Everything a
/// voter needs to replay the decision (which GIP, which status transition,
/// which snapshot anchor) is covered.
pub fn proposal_id(gip: u32, transition: u8, h_open: u64, anchor: Fp) -> Fp {
    let mut h = blake3::Hasher::new();
    h.update(b"OPACUS/v4/gov/proposal");
    h.update(&gip.to_le_bytes());
    h.update(&[transition]);
    h.update(&h_open.to_le_bytes());
    h.update(anchor.to_repr().as_ref());
    fp_from_label(h.finalize().as_bytes())
}

/// The voted decision fields of a ballot (everything outside the note
/// witnesses that the binding signature and the proposal identity bind).
#[derive(Clone, Copy, Debug)]
pub struct BallotHeader {
    /// The GIP being voted on.
    pub gip: u32,
    /// The status transition tag.
    pub transition: u8,
    /// FOR / AGAINST / ABSTAIN (wire byte).
    pub choice: u8,
    /// Vote-open height (`H_snap = H_open`, GIP-2 P-3).
    pub h_open: u64,
    /// The snapshot anchor root.
    pub anchor: Fp,
    /// The public proposal identity.
    pub proposal: Fp,
    /// The ballot weight V (public in Stage A).
    pub v: u64,
}

/// Ballot sighash [GIP-2 3.2 step 2: the binding signature covers GIP-N,
/// choice, V, VS, anchor]:
/// `S = blake3("OPACUS/v4/gov/sighash", le64(version = 1), le32(gip),
/// transition, choice, le64(h_open), anchor, proposal, le64(v),
/// VS_1..VS_K)`.
pub fn ballot_sighash(hdr: &BallotHeader, vs: &[Fp]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"OPACUS/v4/gov/sighash");
    h.update(&1u64.to_le_bytes());
    h.update(&hdr.gip.to_le_bytes());
    h.update(&[hdr.transition, hdr.choice]);
    h.update(&hdr.h_open.to_le_bytes());
    h.update(hdr.anchor.to_repr().as_ref());
    h.update(hdr.proposal.to_repr().as_ref());
    h.update(&hdr.v.to_le_bytes());
    for vs_i in vs {
        h.update(vs_i.to_repr().as_ref());
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

/// Reduce a 32-byte digest into `Fq` as a little-endian 256-bit integer
/// (private copy of the v4 helper; used by the ballot keypair).
fn fq_from_32(b: &[u8; 32]) -> Fq {
    let limb = |s: usize| u64::from_le_bytes(b[s..s + 8].try_into().unwrap());
    let two64 = Fq::from(u64::MAX) + Fq::ONE;
    let mut acc = Fq::from(limb(24));
    acc = acc * two64 + Fq::from(limb(16));
    acc = acc * two64 + Fq::from(limb(8));
    acc * two64 + Fq::from(limb(0))
}

/// Ballot signing key: `bsk = blake3("OPACUS/v4/gov/bsk", le32(count),
/// (a_i, b_i) shares in ballot order, proposal)` reduced into `Fq`.
///
/// Deterministic per (note-set, proposal): the derived verification key
/// ([`ballot_vk`]) does not link a voter's ballots across proposals, and
/// only the owner of both key shares of every note can produce it.
pub fn ballot_key(shares: &[(Fp, Fp)], proposal: Fp) -> Fq {
    let mut h = blake3::Hasher::new();
    h.update(b"OPACUS/v4/gov/bsk");
    h.update(&(shares.len() as u32).to_le_bytes());
    for (a, b) in shares {
        h.update(a.to_repr().as_ref());
        h.update(b.to_repr().as_ref());
    }
    h.update(proposal.to_repr().as_ref());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    fq_from_32(&out)
}

/// Ballot verification key `bvk = [bsk] * R` over the blinding generator
/// (the binding-signature base, [`crate::v4::blind_gen`]).
pub fn ballot_vk(shares: &[(Fp, Fp)], proposal: Fp) -> pallas::Point {
    crate::v4::blind_gen() * ballot_key(shares, proposal)
}

// ---------------------------------------------------------------------------
// Ballot circuit [GIP-2 P-2: K in 1..=8 note-proofs on the v4 mechanics]
// ---------------------------------------------------------------------------

/// Maximum notes per ballot (GIP-2 P-2).
pub const MAX_BALLOT_NOTES: usize = 8;

/// Private witness of one voted note.
#[derive(Clone, Debug)]
pub struct BallotNote {
    /// Diversifier domain.
    pub d: Fp,
    /// Owner key share 1.
    pub a: Fp,
    /// Owner key share 2.
    pub b: Fp,
    /// Per-note nullifier seed.
    pub rho: Fp,
    /// Amount, 0 <= v < 2^64 (range-checked in-circuit).
    pub v: u64,
    /// Authentication path of the note's tree entry: exactly `DEPTH`
    /// siblings, bottom-up (the commutative tree needs no direction bits).
    pub path: Vec<Fp>,
}

/// Private witness of one ballot.
#[derive(Clone, Debug)]
pub struct BallotWitness {
    /// Exactly `K` notes (the circuit is compiled per ballot size). The
    /// public proposal identity is NOT witness data: the circuit binds
    /// `VS` to the INSTANCE cell (module docs), so a prover cannot
    /// decouple the serial derivation from the published proposal.
    pub notes: Vec<BallotNote>,
}

/// The Stage A ballot circuit: one proof over `K in 1..=[`MAX_BALLOT_NOTES`]
/// notes establishing membership at the snapshot anchor, the range-checked
/// value sum `V` and the one-time vote serials `VS_i` (module docs).
#[derive(Clone, Debug)]
pub struct BallotCircuit<const DEPTH: usize, const K: usize> {
    pub witness: Value<BallotWitness>,
    /// Public proposal identity; rides the struct so the zero-witness
    /// synthesis (verification key) assigns the same instance cell value
    /// (the WG-26 swap-tail pattern of [`crate::spend::V4SpendCircuit`]).
    pub proposal: Fp,
}

impl<const DEPTH: usize, const K: usize> BallotCircuit<DEPTH, K> {
    /// Total rows of the single region (an upper bound for `required_k`).
    pub fn rows_needed() -> usize {
        // Per note: witness row + limb range check + 3 vote-chain perms +
        // u/w row + witness-domain key perm + H_leaf perm + leaf chain +
        // entry perm + DEPTH tree steps.
        let per_note = 1
            + LIMB_ROWS
            + 3 * PERM_ROWS
            + 1
            + 2 * PERM_ROWS
            + LEAF_CHAIN_ROWS
            + PERM_ROWS
            + DEPTH * PERM_ROWS;
        // Proposal row + notes + (K - 1) weight-sum rows + margin row.
        1 + K * per_note + (K - 1) + 1
    }

    /// Smallest k such that the circuit fits, with a margin for blinding.
    pub fn required_k() -> u32 {
        let rows = Self::rows_needed() + 64;
        let mut k = 1u32;
        while (1usize << k) < rows {
            k += 1;
        }
        k
    }

    /// Normative public instance vector (module docs): disabled slots do
    /// not exist - the circuit is compiled per ballot size, so `vs` MUST
    /// carry exactly `K` serials.
    pub fn ballot_instances(root: Fp, proposal: Fp, v: u64, vs: &[Fp]) -> Vec<Fp> {
        assert_eq!(
            vs.len(),
            K,
            "ballot instance invariant: VS count must equal the compiled K"
        );
        let mut out = Vec::with_capacity(3 + K);
        out.push(root);
        out.push(proposal);
        out.push(Fp::from(v));
        out.extend_from_slice(vs);
        out
    }
}

impl<const DEPTH: usize, const K: usize> Circuit<Fp> for BallotCircuit<DEPTH, K> {
    type Config = SpendConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            witness: Value::unknown(),
            proposal: self.proposal,
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        SpendConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Witness-shape invariant: the BUILDER asserts notes.len() == K
        // before proving (the zero-witness synthesis of keygen/verify must
        // not depend on witness shape at all).
        let (root_cells, prop_cells, vs_cells, v_acc) = layouter.assign_region(
            || "gov-ballot",
            |mut region| {
                let wv = self.witness.clone();
                let mut base = 0usize;

                // Public proposal cell (row 0): assigned from the struct
                // field so zero-witness keygen synthesis carries it too.
                let prop_cell = region.assign_advice(
                    || "proposal",
                    config.tree_sum,
                    base,
                    || Value::known(self.proposal),
                )?;
                let prop_cells = vec![prop_cell.clone()];
                base += 1;

                let mut vs_cells = Vec::with_capacity(K);
                let mut root_cells = Vec::with_capacity(K);
                let mut v_cells: Vec<AssignedCell<Fp, Fp>> = Vec::with_capacity(K);

                for i in 0..K {
                    let inp = wv.clone().map(|w| w.notes[i].clone());

                    // Witness row [a, b, rho, D].
                    let a_cell = region.assign_advice(
                        || "in-a",
                        config.wit[0],
                        base,
                        || inp.clone().map(|n| n.a),
                    )?;
                    let b_cell = region.assign_advice(
                        || "in-b",
                        config.wit[1],
                        base,
                        || inp.clone().map(|n| n.b),
                    )?;
                    let rho_cell = region.assign_advice(
                        || "in-rho",
                        config.wit[2],
                        base,
                        || inp.clone().map(|n| n.rho),
                    )?;
                    let d_cell = region.assign_advice(
                        || "in-d",
                        config.wit[3],
                        base,
                        || inp.clone().map(|n| n.d),
                    )?;
                    base += 1;

                    // In-range value [GIP-2 3.2: in-range value-sum]:
                    // rc-limb gate, 4 x 16-bit boolean limbs.
                    let v_val = inp.clone().map(|n| n.v);
                    let v_cell = config.limb.assign(&mut region, base, v_val, false)?;
                    v_cells.push(v_cell.clone());
                    base += LIMB_ROWS;

                    // Vote chain: vs_key -> vote_rho -> VS. The proposal
                    // cell feeds vote_rho IN-CIRCUIT, so VS is bound to the
                    // public proposal (R-3 determinism).
                    let vk_cell = config.perm(
                        &mut region,
                        base,
                        dom_vsk(),
                        a_cell.clone(),
                        b_cell.clone(),
                    )?;
                    base += PERM_ROWS;
                    let vr_cell = config.perm(
                        &mut region,
                        base,
                        dom_vrho(),
                        rho_cell.clone(),
                        prop_cell.clone(),
                    )?;
                    base += PERM_ROWS;
                    let vs_cell = config.perm(&mut region, base, dom_vs(), vk_cell, vr_cell)?;
                    vs_cells.push(vs_cell);
                    base += PERM_ROWS;

                    // Key part [S4 3]: u = a + b, w = a * b, then
                    // s = P(D, u, w) with the WITNESS domain D.
                    a_cell.copy_advice(|| "key-src-a", &mut region, config.tree_src[0], base)?;
                    b_cell.copy_advice(|| "key-src-b", &mut region, config.tree_src[1], base)?;
                    let u_cell = region.assign_advice(
                        || "key-u",
                        config.tree_sum,
                        base,
                        || a_cell.value().cloned() + b_cell.value().cloned(),
                    )?;
                    let w_cell = region.assign_advice(
                        || "key-w",
                        config.tree_prod,
                        base,
                        || a_cell.value().cloned() * b_cell.value().cloned(),
                    )?;
                    config.s_add.enable(&mut region, base)?;
                    config.s_mul.enable(&mut region, base)?;
                    base += 1;
                    let s_cell = config.perm_wd(&mut region, base, &d_cell, u_cell, w_cell)?;
                    base += PERM_ROWS;

                    // Leaf hash [S4 3]: H_leaf = P(v, rho, DOM_LEAF_V2) from
                    // the range-checked v cell.
                    let h_cell =
                        config.perm(&mut region, base, dom_leaf_v2(), v_cell, rho_cell.clone())?;
                    base += PERM_ROWS;

                    // Leaf chain [S4 3, S4 8]: L = [s] * G + [h] * G3.
                    let sh_val: Value<(Fp, Fp)> = inp.clone().map(|n| {
                        let s0 = poseidon_absorb(n.d, n.a + n.b, n.a * n.b)[0];
                        let h0 = h_leaf_v2(n.v, n.rho);
                        (s0, h0)
                    });
                    let (lx, ly) = config.assign_leaf_chain(
                        &mut region,
                        base,
                        &s_cell,
                        &h_cell,
                        sh_val,
                        false,
                    )?;
                    base += LEAF_CHAIN_ROWS;

                    // Tree entry (Phase 2 convention): e = P(L.x, L.y, DOM_ACC).
                    let e_cell = config.perm(&mut region, base, dom_acc(), lx, ly)?;
                    base += PERM_ROWS;

                    // Membership path [S4 1 P1]: DEPTH commutative tree
                    // steps from the reconstructed entry to the public root.
                    let path_val = inp.map(|n| n.path);
                    let mut node = e_cell;
                    for t in 0..DEPTH {
                        let sib = path_val
                            .clone()
                            .map(|v| v.get(t).copied().unwrap_or(Fp::ZERO));
                        node = config.tree_step(&mut region, base, node, sib)?;
                        base += PERM_ROWS;
                    }
                    root_cells.push(node);
                }

                // Weight sum [GIP-2 P-1 W1]: acc = v_1 + ... + v_K through
                // the linear operand gate; acc is the public V instance.
                let mut acc = v_cells[0].clone();
                for v_cell in v_cells.iter().skip(1) {
                    acc.copy_advice(|| "sum-acc", &mut region, config.tree_src[0], base)?;
                    v_cell.copy_advice(|| "sum-v", &mut region, config.tree_src[1], base)?;
                    let next = region.assign_advice(
                        || "sum-next",
                        config.tree_sum,
                        base,
                        || acc.value().cloned() + v_cell.value().cloned(),
                    )?;
                    config.s_add.enable(&mut region, base)?;
                    acc = next;
                    base += 1;
                }

                Ok((root_cells, prop_cells, vs_cells, acc))
            },
        )?;

        // Normative instance order: slot 0 = root (every note walks to the
        // SAME root), slot 1 = proposal, slot 2 = V, slots 3.. = VS_i.
        for c in root_cells.iter() {
            layouter.constrain_instance(c.cell(), config.instance, 0)?;
        }
        for c in prop_cells.iter() {
            layouter.constrain_instance(c.cell(), config.instance, 1)?;
        }
        layouter.constrain_instance(v_acc.cell(), config.instance, 2)?;
        for (i, c) in vs_cells.iter().enumerate() {
            layouter.constrain_instance(c.cell(), config.instance, 3 + i)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Prover plumbing (the v4_prover pattern)
// ---------------------------------------------------------------------------

/// Mock-prover self-check of a ballot against its normative instances.
/// Available WITHOUT the `real-prover` feature: builder tests validate the
/// full witness/instance contract cheaply before paying for a real IPA
/// proof.
pub fn mock_verify_ballot<const DEPTH: usize, const K: usize>(
    witness: &BallotWitness,
    instances: &[Fp],
) -> Result<(), String> {
    assert_eq!(
        instances.len(),
        3 + K,
        "ballot instance invariant: expected 3 + K slots"
    );
    let circuit: BallotCircuit<DEPTH, K> = BallotCircuit {
        witness: Value::known(witness.clone()),
        proposal: instances[1],
    };
    let k = BallotCircuit::<DEPTH, K>::required_k();
    let prover = halo2_proofs::dev::MockProver::run(k, &circuit, vec![instances.to_vec()])
        .map_err(|e| format!("mock prover construction failed: {e:?}"))?;
    prover
        .verify()
        .map_err(|e| format!("mock verification failed: {e:?}"))
}

// ---------------------------------------------------------------------------
// Size-agnostic entry points (the wallet dispatches on the ballot size)
// ---------------------------------------------------------------------------

/// Normative instance vector for a ballot of ANY size `1..=MAX_BALLOT_NOTES`
/// (`k = vs.len()`): `[root, proposal, V, VS_1..VS_k]`.
pub fn ballot_instances_sized(anchor: Fp, proposal: Fp, v: u64, vs: &[Fp]) -> Vec<Fp> {
    let k = vs.len();
    assert!(
        (1..=MAX_BALLOT_NOTES).contains(&k),
        "ballot instance invariant: a ballot carries 1..={MAX_BALLOT_NOTES} notes"
    );
    match k {
        1 => BallotCircuit::<1, 1>::ballot_instances(anchor, proposal, v, vs),
        2 => BallotCircuit::<1, 2>::ballot_instances(anchor, proposal, v, vs),
        3 => BallotCircuit::<1, 3>::ballot_instances(anchor, proposal, v, vs),
        4 => BallotCircuit::<1, 4>::ballot_instances(anchor, proposal, v, vs),
        5 => BallotCircuit::<1, 5>::ballot_instances(anchor, proposal, v, vs),
        6 => BallotCircuit::<1, 6>::ballot_instances(anchor, proposal, v, vs),
        7 => BallotCircuit::<1, 7>::ballot_instances(anchor, proposal, v, vs),
        _ => BallotCircuit::<1, 8>::ballot_instances(anchor, proposal, v, vs),
    }
}

#[cfg(feature = "real-prover")]
mod sized_real {
    use super::*;

    /// Keygen + prove a ballot of ANY size (`K` from the witness shape).
    pub fn prove_ballot_sized<const DEPTH: usize>(
        witness: &BallotWitness,
        instances: &[Fp],
    ) -> Result<Vec<u8>, halo2_proofs::plonk::Error> {
        let k = witness.notes.len();
        match k {
            1 => real::prove_ballot::<DEPTH, 1>(witness, instances).map(|p| p.proof),
            2 => real::prove_ballot::<DEPTH, 2>(witness, instances).map(|p| p.proof),
            3 => real::prove_ballot::<DEPTH, 3>(witness, instances).map(|p| p.proof),
            4 => real::prove_ballot::<DEPTH, 4>(witness, instances).map(|p| p.proof),
            5 => real::prove_ballot::<DEPTH, 5>(witness, instances).map(|p| p.proof),
            6 => real::prove_ballot::<DEPTH, 6>(witness, instances).map(|p| p.proof),
            7 => real::prove_ballot::<DEPTH, 7>(witness, instances).map(|p| p.proof),
            _ => real::prove_ballot::<DEPTH, 8>(witness, instances).map(|p| p.proof),
        }
    }

    /// Verify a ballot proof of ANY size (`K` from the instance count).
    pub fn verify_ballot_sized<const DEPTH: usize>(
        proof: &[u8],
        instances: &[Fp],
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let k = instances.len() - 3;
        match k {
            1 => real::verify_ballot::<DEPTH, 1>(proof, instances),
            2 => real::verify_ballot::<DEPTH, 2>(proof, instances),
            3 => real::verify_ballot::<DEPTH, 3>(proof, instances),
            4 => real::verify_ballot::<DEPTH, 4>(proof, instances),
            5 => real::verify_ballot::<DEPTH, 5>(proof, instances),
            6 => real::verify_ballot::<DEPTH, 6>(proof, instances),
            7 => real::verify_ballot::<DEPTH, 7>(proof, instances),
            _ => real::verify_ballot::<DEPTH, 8>(proof, instances),
        }
    }
}

#[cfg(feature = "real-prover")]
pub use sized_real::{prove_ballot_sized, verify_ballot_sized};

#[cfg(feature = "real-prover")]
mod real {
    use super::*;
    use halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
    };
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use pasta_curves::vesta;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    // Process-wide keyset cache (the WG-17 pattern of v4_prover.rs):
    // keygen is a pure function of the circuit STRUCTURE, so caching
    // keysets cannot change a single proof byte. Ballot keysets are keyed
    // by (DEPTH, K) - the compiled ballot size.
    struct BallotKeyCache {
        params: HashMap<usize, Arc<Params<vesta::Affine>>>,
        keys: HashMap<(usize, usize), Arc<BallotKeys>>,
    }

    struct BallotKeys {
        vk: VerifyingKey<vesta::Affine>,
        pk: Mutex<Option<Arc<ProvingKey<vesta::Affine>>>>,
    }

    static BALLOT_CACHE: OnceLock<Mutex<BallotKeyCache>> = OnceLock::new();

    fn ballot_cache() -> &'static Mutex<BallotKeyCache> {
        BALLOT_CACHE.get_or_init(|| {
            Mutex::new(BallotKeyCache {
                params: HashMap::new(),
                keys: HashMap::new(),
            })
        })
    }

    fn cached_params(k: u32) -> Arc<Params<vesta::Affine>> {
        let mut cache = ballot_cache().lock().expect("ballot keyset cache poisoned");
        Arc::clone(
            cache
                .params
                .entry(k as usize)
                .or_insert_with(|| Arc::new(Params::<vesta::Affine>::new(k))),
        )
    }

    fn get_or_build_vk<const DEPTH: usize, const K: usize>(
        params: &Params<vesta::Affine>,
        circuit: &BallotCircuit<DEPTH, K>,
    ) -> Result<Arc<BallotKeys>, halo2_proofs::plonk::Error> {
        let key = (DEPTH, K);
        if let Some(entry) = ballot_cache()
            .lock()
            .expect("ballot keyset cache poisoned")
            .keys
            .get(&key)
        {
            return Ok(Arc::clone(entry));
        }
        // Slow path OUTSIDE the global lock: first-wins on insert.
        let vk = keygen_vk(params, circuit)?;
        let mut cache = ballot_cache().lock().expect("ballot keyset cache poisoned");
        Ok(Arc::clone(cache.keys.entry(key).or_insert_with(|| {
            Arc::new(BallotKeys {
                vk,
                pk: Mutex::new(None),
            })
        })))
    }

    fn cached_pk<const DEPTH: usize, const K: usize>(
        params: &Params<vesta::Affine>,
        entry: &BallotKeys,
        circuit: &BallotCircuit<DEPTH, K>,
    ) -> Result<Arc<ProvingKey<vesta::Affine>>, halo2_proofs::plonk::Error> {
        let mut slot = entry.pk.lock().expect("ballot pk slot poisoned");
        if let Some(pk) = slot.as_ref() {
            return Ok(Arc::clone(pk));
        }
        let pk = Arc::new(keygen_pk(params, entry.vk.clone(), circuit)?);
        *slot = Some(Arc::clone(&pk));
        Ok(pk)
    }

    /// A completed ballot proof: raw IPA proof bytes over the (3 + K)-slot
    /// instance column. The instances are NOT repeated here on purpose:
    /// the verifier reconstructs them from the ballot fields.
    #[derive(Clone, Debug)]
    pub struct BallotProof {
        pub proof: Vec<u8>,
    }

    /// Keygen + prove one ballot. Keysets are served from the process-wide
    /// cache keyed by (DEPTH, K); the first call of a process pays the
    /// full keygen, later calls prove at steady-state cost.
    pub fn prove_ballot<const DEPTH: usize, const K: usize>(
        witness: &BallotWitness,
        instances: &[Fp],
    ) -> Result<BallotProof, halo2_proofs::plonk::Error> {
        assert_eq!(instances.len(), 3 + K, "ballot instance invariant");
        assert_eq!(witness.notes.len(), K, "ballot witness invariant");
        let circuit: BallotCircuit<DEPTH, K> = BallotCircuit {
            witness: Value::known(witness.clone()),
            proposal: instances[1],
        };
        let k = BallotCircuit::<DEPTH, K>::required_k();
        let params = cached_params(k);
        let entry = get_or_build_vk(&params, &circuit)?;
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
        Ok(BallotProof {
            proof: transcript.finalize(),
        })
    }

    /// Verify a ballot proof against instances reconstructed from the
    /// ballot fields. The verification circuit is built witness-less with
    /// the proposal taken FROM the instance vector, so the derived
    /// verifying key matches bit-for-bit.
    pub fn verify_ballot<const DEPTH: usize, const K: usize>(
        proof: &[u8],
        instances: &[Fp],
    ) -> Result<(), halo2_proofs::plonk::Error> {
        assert_eq!(instances.len(), 3 + K, "ballot instance invariant");
        let circuit: BallotCircuit<DEPTH, K> = BallotCircuit {
            witness: Value::unknown(),
            proposal: instances[1],
        };
        let k = BallotCircuit::<DEPTH, K>::required_k();
        let params = cached_params(k);
        let entry = get_or_build_vk(&params, &circuit)?;
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
pub use real::{prove_ballot, verify_ballot, BallotProof};

/// The compressed encoding of a ballot verification key (33 bytes: the
/// standard Pallas compressed point form via `GroupEncoding`).
pub fn ballot_vk_bytes(shares: &[(Fp, Fp)], proposal: Fp) -> [u8; 32] {
    let enc = ballot_vk(shares, proposal).to_affine().to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(enc.as_ref());
    out
}

/// Parse a canonical [`ballot_vk_bytes`] encoding. Returns `None` on any
/// non-canonical or identity encoding.
pub fn ballot_vk_from_bytes(bytes: &[u8; 32]) -> Option<pallas::Point> {
    let p = <pallas::Affine as GroupEncoding>::from_bytes(bytes)
        .into_option()?
        .to_curve();
    if bool::from(p.is_identity()) {
        return None;
    }
    Some(p)
}

/// The Stage A tally-side duplicate-VS primitive (GIP-2 R-3, Stage A:
/// the tally engine enforces uniqueness publicly; WP-2 formalizes the
/// engine, this is the seen-set contract the builder tests rely on).
#[derive(Default)]
pub struct SeenSet {
    seen: std::collections::HashSet<[u8; 32]>,
}

impl SeenSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a serial; `false` when the SAME serial was already seen
    /// (a duplicate vote on this proposal).
    pub fn insert(&mut self, vs: Fp) -> bool {
        let repr: [u8; 32] = vs.to_repr();
        self.seen.insert(repr)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Reduce an `Fp` value into `Fq` (the Pallas scalar field) preserving the
/// integer value modulo the group order (re-export of the v4 helper for
/// ballot tooling).
pub fn fq_of(x: Fp) -> Fq {
    fq_reduce_fp(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::spend::{leaf_entry_v2, sign_bind, verify_bind};
    use crate::v4::nullifier_v4;
    use ff::Field;
    use rand::rngs::OsRng;

    const DEPTH: usize = 4;

    struct TestNote {
        d: Fp,
        a: Fp,
        b: Fp,
        rho: Fp,
        v: u64,
    }

    fn note_entry(n: &TestNote) -> Fp {
        leaf_entry_v2(n.d, n.a, n.b, n.v, n.rho)
    }

    fn random_notes(count: usize) -> Vec<TestNote> {
        (0..count)
            .map(|i| TestNote {
                d: Fp::random(OsRng),
                a: Fp::random(OsRng),
                b: Fp::random(OsRng),
                rho: Fp::random(OsRng),
                v: 1000 + i as u64,
            })
            .collect()
    }

    /// Tree over `notes` + fixture proposal identity.
    fn fixture(notes: &[TestNote]) -> (Vec<Fp>, Fp, Fp) {
        let entries: Vec<Fp> = notes.iter().map(note_entry).collect();
        let root = merkle::build_root(&entries, DEPTH);
        let anchor_point = crate::v4_prover::acc_root_point(root);
        let proposal = proposal_id(2, 0, 100, root);
        (entries, root, {
            let _ = anchor_point;
            proposal
        })
    }

    fn ballot_of(
        notes: &[TestNote],
        chosen: &[usize],
        entries: &[Fp],
        proposal: Fp,
    ) -> (BallotWitness, Vec<Fp>, u64) {
        let mut wnotes = Vec::with_capacity(chosen.len());
        let mut vs = Vec::with_capacity(chosen.len());
        let mut v_total: u64 = 0;
        for &idx in chosen {
            let n = &notes[idx];
            let path = merkle::auth_path(entries, idx, DEPTH);
            wnotes.push(BallotNote {
                d: n.d,
                a: n.a,
                b: n.b,
                rho: n.rho,
                v: n.v,
                path,
            });
            vs.push(vote_serial(n.a, n.b, n.rho, proposal));
            v_total = v_total.checked_add(n.v).expect("test value sum");
        }
        (BallotWitness { notes: wnotes }, vs, v_total)
    }

    #[test]
    fn vote_chain_is_domain_separated_and_deterministic() {
        let n = &random_notes(1)[0];
        let prop_a = proposal_id(2, 0, 100, Fp::from(7u64));
        let prop_b = proposal_id(3, 0, 100, Fp::from(7u64));

        // Deterministic per (note, proposal): the duplicate-vote property.
        assert_eq!(
            vote_serial(n.a, n.b, n.rho, prop_a),
            vote_serial(n.a, n.b, n.rho, prop_a)
        );
        // Fresh serial per proposal: no cross-proposal linkage.
        assert_ne!(
            vote_serial(n.a, n.b, n.rho, prop_a),
            vote_serial(n.a, n.b, n.rho, prop_b)
        );
        // NEVER a spend nullifier: DOM_VS != DOM_NU with the same witness.
        assert_ne!(
            vote_serial(n.a, n.b, n.rho, prop_a),
            nullifier_v4(n.a, n.b, n.rho)
        );
    }

    #[test]
    fn proposal_id_binds_the_decision_fields() {
        let anchor = Fp::from(11u64);
        let base = proposal_id(2, 0, 100, anchor);
        assert_eq!(base, proposal_id(2, 0, 100, anchor), "deterministic");
        assert_ne!(base, proposal_id(3, 0, 100, anchor), "gip enters");
        assert_ne!(base, proposal_id(2, 1, 100, anchor), "transition enters");
        assert_ne!(base, proposal_id(2, 0, 101, anchor), "h_open enters");
        assert_ne!(
            base,
            proposal_id(2, 0, 100, anchor + Fp::ONE),
            "anchor enters"
        );
    }

    #[test]
    fn ballot_keypair_binds_and_stays_unlinked() {
        let shares = vec![(Fp::from(3u64), Fp::from(5u64))];
        let prop_a = proposal_id(2, 0, 100, Fp::from(7u64));
        let prop_b = proposal_id(4, 0, 100, Fp::from(7u64));

        let vk_a = ballot_vk_bytes(&shares, prop_a);
        assert_eq!(vk_a, ballot_vk_bytes(&shares, prop_a), "deterministic");
        assert_ne!(
            vk_a,
            ballot_vk_bytes(&shares, prop_b),
            "no cross-proposal linkage"
        );
        assert!(ballot_vk_from_bytes(&vk_a).is_some());
        assert!(
            ballot_vk_from_bytes(&[0u8; 32]).is_none(),
            "identity rejected"
        );

        let v = 5_000u64;
        let hdr = BallotHeader {
            gip: 2,
            transition: 0,
            choice: 0,
            h_open: 100,
            anchor: Fp::from(7u64),
            proposal: prop_a,
            v,
        };
        let s = ballot_sighash(&hdr, &[Fp::from(1u64)]);
        let sk = ballot_key(&shares, prop_a);
        let sig = sign_bind(&s, sk, &ballot_vk(&shares, prop_a));
        assert!(verify_bind(&s, &ballot_vk(&shares, prop_a), &sig));
        let s2 = ballot_sighash(&BallotHeader { choice: 1, ..hdr }, &[Fp::from(1u64)]);
        assert!(
            !verify_bind(&s2, &ballot_vk(&shares, prop_a), &sig),
            "choice flip detected"
        );
        // A non-owner (no shares) cannot derive the key.
        let other = ballot_key(&[(Fp::from(4u64), Fp::from(5u64))], prop_a);
        let sig_other = sign_bind(
            &s,
            other,
            &ballot_vk(&[(Fp::from(4u64), Fp::from(5u64))], prop_a),
        );
        assert!(!verify_bind(&s, &ballot_vk(&shares, prop_a), &sig_other));
    }

    #[test]
    fn ballot_rows_stay_in_the_gip2_k_budget() {
        // GIP-2 P-2: K=8 at mainnet depth must land at k = 13.
        let rows = BallotCircuit::<32, 8>::rows_needed();
        assert!(rows <= 1 << 13, "K=8/DEPTH=32 rows {rows} exceed k=13");
        assert_eq!(BallotCircuit::<32, 8>::required_k(), 13);
        // Small-depth test shape stays cheap.
        assert_eq!(BallotCircuit::<DEPTH, 1>::required_k(), 9);
    }

    #[test]
    fn mock_honest_ballot_k1_accepts_and_instances_match_host() {
        let notes = random_notes(2);
        let (entries, root, proposal) = fixture(&notes);
        let (witness, vs, v) = ballot_of(&notes, &[0], &entries, proposal);
        let instances = BallotCircuit::<DEPTH, 1>::ballot_instances(root, proposal, v, &vs);
        assert_eq!(instances.len(), 3 + 1);
        assert_eq!(
            instances[3], vs[0],
            "in-circuit VS must equal the host derivation"
        );
        assert_eq!(instances[2], Fp::from(v));
        mock_verify_ballot::<DEPTH, 1>(&witness, &instances)
            .expect("honest single-note ballot must pass");
    }

    #[test]
    fn mock_honest_ballot_k4_accepts() {
        let notes = random_notes(5);
        let (entries, root, proposal) = fixture(&notes);
        let (witness, vs, v) = ballot_of(&notes, &[0, 1, 2, 3], &entries, proposal);
        let instances = BallotCircuit::<DEPTH, 4>::ballot_instances(root, proposal, v, &vs);
        mock_verify_ballot::<DEPTH, 4>(&witness, &instances)
            .expect("honest four-note ballot must pass");
    }

    #[test]
    fn mock_rejects_tampered_instances_and_foreign_notes() {
        let notes = random_notes(4);
        let (entries, root, proposal) = fixture(&notes);
        let (witness, vs, v) = ballot_of(&notes, &[0, 1], &entries, proposal);

        // Tampered VS slot.
        let mut bad = BallotCircuit::<DEPTH, 2>::ballot_instances(root, proposal, v, &vs);
        bad[3] += Fp::ONE;
        assert!(mock_verify_ballot::<DEPTH, 2>(&witness, &bad).is_err());

        // Tampered anchor root.
        let mut bad_root = BallotCircuit::<DEPTH, 2>::ballot_instances(root, proposal, v, &vs);
        bad_root[0] = root + Fp::ONE;
        assert!(mock_verify_ballot::<DEPTH, 2>(&witness, &bad_root).is_err());

        // Over-claimed weight (the value-sum gate must hold it).
        let mut bad_v = BallotCircuit::<DEPTH, 2>::ballot_instances(root, proposal, v + 1, &vs);
        bad_v[2] = Fp::from(v + 1);
        assert!(mock_verify_ballot::<DEPTH, 2>(&witness, &bad_v).is_err());

        // A note that is NOT in the tree: the fabricated path cannot walk
        // to the anchor root (membership binds the vote chain).
        let foreign = TestNote {
            d: Fp::random(OsRng),
            a: Fp::random(OsRng),
            b: Fp::random(OsRng),
            rho: Fp::random(OsRng),
            v: 7000,
        };
        let fw = BallotWitness {
            notes: vec![BallotNote {
                d: foreign.d,
                a: foreign.a,
                b: foreign.b,
                rho: foreign.rho,
                v: foreign.v,
                path: merkle::auth_path(&entries, 0, DEPTH),
            }],
        };
        let fvs = vec![vote_serial(foreign.a, foreign.b, foreign.rho, proposal)];
        let finstances =
            BallotCircuit::<DEPTH, 1>::ballot_instances(root, proposal, foreign.v, &fvs);
        assert!(mock_verify_ballot::<DEPTH, 1>(&fw, &finstances).is_err());
    }

    #[test]
    fn seen_set_rejects_the_duplicate_serial() {
        let notes = random_notes(1);
        let proposal = proposal_id(2, 0, 100, Fp::from(9u64));
        let mut seen = SeenSet::new();
        let vs = vote_serial(notes[0].a, notes[0].b, notes[0].rho, proposal);
        assert!(seen.insert(vs));
        // The same note voting again on the SAME proposal derives the
        // same serial (R-3) and the tally rejects it.
        assert!(!seen.insert(vote_serial(notes[0].a, notes[0].b, notes[0].rho, proposal)));
        // A different proposal derives a fresh serial.
        let other = proposal_id(2, 0, 101, Fp::from(9u64));
        assert!(seen.insert(vote_serial(notes[0].a, notes[0].b, notes[0].rho, other)));
        assert_eq!(seen.len(), 2);
    }

    #[cfg(feature = "real-prover")]
    #[test]
    fn real_prover_honest_ballot_loop() {
        let notes = random_notes(2);
        let (entries, root, proposal) = fixture(&notes);
        let (witness, vs, v) = ballot_of(&notes, &[0], &entries, proposal);
        let instances = BallotCircuit::<DEPTH, 1>::ballot_instances(root, proposal, v, &vs);

        let proof = crate::vote::real::prove_ballot::<DEPTH, 1>(&witness, &instances)
            .expect("honest ballot must prove");
        crate::vote::real::verify_ballot::<DEPTH, 1>(&proof.proof, &instances)
            .expect("honest ballot must verify");

        // A tampered instance vector must fail verification.
        let mut bad = instances.clone();
        bad[2] = Fp::from(v + 1);
        assert!(crate::vote::real::verify_ballot::<DEPTH, 1>(&proof.proof, &bad).is_err());
    }
}
