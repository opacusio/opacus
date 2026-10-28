//! GHOST v0.4 Phase 1a: foundations for in-circuit value conservation.
//!
//! Implements the cryptographic core of the v0.4 specification
//! (`docs/specs/v0.4-value-conservation.md`, referenced below as [S4]):
//!
//! - **hashgen generators** [S4 2]: `V`, `R`, `G3` derived from blake3 with
//!   published test vectors (nothing-up-my-sleeve; no trapdoor).
//! - **v0.4 domain constants** [S4 2]: `DOM_LEAF_V2`, `DOM_NK`, `DOM_NU`.
//! - **value commitment** [S4 4]: `RC = v*V + r*R` (host-side construction;
//!   the in-circuit fixed-base gate is Phase 1b).
//! - **nullifier** [S4 5]: `nk = Poseidon_3(a, b, DOM_NK)`,
//!   `N = Poseidon_3(nk, rho, DOM_NU)` - host-side AND in-circuit (the
//!   `v4-hash` gate proves `nk`/`N` from the `(a, b, rho)` witnesses).
//! - **leaf v2** [S4 3]: `H_leaf = Poseidon_3(v, rho, DOM_LEAF_V2)`,
//!   `L = P(D, a+b, a*b) + H_leaf * G3` - host-side AND the in-circuit
//!   hash part of the `leaf-v2` gate (`H_leaf`).
//! - **rc-limb gate** [S4 8]: 4 x 16-bit limb decomposition of a 64-bit
//!   value with a running-sum range check, in-circuit.
//!
//! Phase 1b (next delivery) adds the windowed fixed-base scalar
//! multiplication chip [S4 8] that computes `RC` and the `H_leaf * G3`
//! term inside the circuit and exposes them as public instances.
//!
//! Phase 1 code-audit notes (spec section 12 anticipated these):
//! - The v0.3.0 circuit already derives the nullifier in-circuit from the
//!   same witness as membership (`circuit.rs`, step 4), so the v0.4
//!   nullifier work is the new key schema `(a, b, rho)` plus witness
//!   sharing, not a from-scratch gate.
//! - v0.3.0 has NO elliptic-curve point arithmetic (everything is `Fp`
//!   field arithmetic). Phase 1a therefore introduces the point layer
//!   host-side: points are Pallas points (`pasta_curves::pallas::Point`),
//!   whose base field equals the halo2 circuit field `Fp` used throughout
//!   opacus-zk, so point coordinates are circuit-native field elements.
//! - `P(D, x, y)` [S4 3] is defined as `[Poseidon_3(x, y, D)] * G` where
//!   `G` is the Pallas generator: the Poseidon output scalar is reduced
//!   into the Pallas scalar field `Fq` and multiplied into the base point.
//!   The reduction follows the existing opacus-zk little-endian limb
//!   convention (`poseidon::fp_from_16`).
//! - The v0.4 domain constants follow the same convention: the first 16
//!   bytes of `blake3("GHOST/v4/dom/<name>")` are reduced into `Fp` (the
//!   field the existing Poseidon instance operates over).

use ff::{Field, PrimeField};
use group::Group;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::{pallas, Fp, Fq};

use crate::poseidon::poseidon_absorb;

// ---------------------------------------------------------------------------
// v0.4 domain constants [S4 2]
// ---------------------------------------------------------------------------

/// Reduce the first 16 bytes of a blake3 digest into `Fp`, matching the
/// existing opacus-zk convention (`poseidon::fp_from_16`).
fn fp_from_label(label: &[u8]) -> Fp {
    let d = blake3::hash(label);
    let b = d.as_bytes();
    let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let two64 = Fp::from(u64::MAX) + Fp::ONE;
    Fp::from(hi) * two64 + Fp::from(lo)
}

/// Domain constant for the leaf-v2 value/rho hash.
pub fn dom_leaf_v2() -> Fp {
    fp_from_label(b"GHOST/v4/dom/leaf2")
}

/// Domain constant for the nullifier key.
pub fn dom_nk() -> Fp {
    fp_from_label(b"GHOST/v4/dom/nk")
}

/// Domain constant for the nullifier.
pub fn dom_nu() -> Fp {
    fp_from_label(b"GHOST/v4/dom/nu")
}

/// Domain constant for swap hashlocks [S4 12, WG-26].
pub fn dom_swap() -> Fp {
    fp_from_label(b"GHOST/v4/dom/swap")
}

/// Split a 32-byte swap preimage into two canonical 16-byte lanes [S4 12
/// 3.1]: each lane carries exactly 128 bits, so the field reduction never
/// wraps and the lane pair round-trips the preimage byte-for-byte.
pub fn swap_lanes(preimage: &[u8; 32]) -> (Fp, Fp) {
    let lane = |s: usize| {
        let mut b = [0u8; 16];
        b.copy_from_slice(&preimage[s..s + 16]);
        let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(b[8..16].try_into().unwrap());
        let two64 = Fp::from(u64::MAX) + Fp::ONE;
        Fp::from(hi) * two64 + Fp::from(lo)
    };
    (lane(0), lane(16))
}

/// Swap hashlock commitment [S4 12 3.1]: H = Poseidon_3(dom_swap, s0, s1)
/// over the canonical lanes of the 32-byte preimage. The bridge blake3
/// hashlock_of stays the XMR-leg lock; one preimage feeds both chains.
pub fn hashlock_swap(preimage: &[u8; 32]) -> (Fp, Fp, Fp) {
    let (s0, s1) = swap_lanes(preimage);
    (poseidon_absorb(dom_swap(), s0, s1)[0], s0, s1)
}

// ---------------------------------------------------------------------------
// hashgen [S4 2]
// ---------------------------------------------------------------------------

/// Reduce a 32-byte digest into `Fq` (the Pallas scalar field) as a
/// little-endian 256-bit integer via Horner evaluation with 2^64.
fn fq_from_32(b: &[u8; 32]) -> Fq {
    let limb = |s: usize| u64::from_le_bytes(b[s..s + 8].try_into().unwrap());
    let two64 = Fq::from(u64::MAX) + Fq::ONE;
    let mut acc = Fq::from(limb(24));
    acc = acc * two64 + Fq::from(limb(16));
    acc = acc * two64 + Fq::from(limb(8));
    acc * two64 + Fq::from(limb(0))
}

/// Reduce an `Fp` element (circuit field) into `Fq` (Pallas scalar field):
/// the integer value is preserved modulo the group order.
pub fn fq_reduce_fp(x: Fp) -> Fq {
    let repr = x.to_repr();
    fq_from_32(&repr)
}

/// `hashgen(name) = [blake3("GHOST/v4/gen/" + name) mod q] * G`.
///
/// The discrete logarithms between any two hashgen outputs are unknown by
/// construction (blake3 outputs, no trapdoor) [S4 2, S4 11].
pub fn hashgen(name: &str) -> pallas::Point {
    let mut label = Vec::with_capacity(13 + name.len());
    label.extend_from_slice(b"GHOST/v4/gen/");
    label.extend_from_slice(name.as_bytes());
    let d = blake3::hash(&label);
    pallas::Point::generator() * fq_from_32(d.as_bytes())
}

/// Value generator `V` for value commitments.
pub fn value_gen() -> pallas::Point {
    hashgen("value")
}

/// Blinding generator `R` for value commitments.
pub fn blind_gen() -> pallas::Point {
    hashgen("blind")
}

/// Leaf generator `G3` (value-binding term of the accumulator leaf).
pub fn leaf_gen() -> pallas::Point {
    hashgen("leaf")
}

// ---------------------------------------------------------------------------
// Host-side v0.4 primitives [S4 3-5]
// ---------------------------------------------------------------------------

/// Value commitment `RC = v * V + r * R` [S4 4].
///
/// `r` is uniform in `Fq` (the Pallas scalar field); wallets generate it at
/// spend time. The host value MUST equal the Phase 1b in-circuit synthesis.
pub fn value_commit(v: u64, r: Fq, v_gen: &pallas::Point, r_gen: &pallas::Point) -> pallas::Point {
    v_gen * Fq::from(v) + r_gen * r
}

/// Nullifier key `nk = Poseidon_3(a, b, DOM_NK)` [S4 5].
pub fn nullifier_key(a: Fp, b: Fp) -> Fp {
    poseidon_absorb(dom_nk(), a, b)[0]
}

/// Nullifier `N = Poseidon_3(nk, rho, DOM_NU)` [S4 5].
pub fn nullifier_from_key(nk: Fp, rho: Fp) -> Fp {
    poseidon_absorb(dom_nu(), nk, rho)[0]
}

/// Nullifier from the owner key shares and the per-note seed.
pub fn nullifier_v4(a: Fp, b: Fp, rho: Fp) -> Fp {
    nullifier_from_key(nullifier_key(a, b), rho)
}

/// Leaf-v2 value/rho hash `H_leaf = Poseidon_3(v, rho, DOM_LEAF_V2)` [S4 3].
pub fn h_leaf_v2(v: u64, rho: Fp) -> Fp {
    poseidon_absorb(dom_leaf_v2(), Fp::from(v), rho)[0]
}

/// Key part of the accumulator leaf:
/// `P(D, x, y) = [Poseidon_3(x, y, D)] * G` [S4 3].
pub fn p_leaf(d: Fp, x: Fp, y: Fp) -> pallas::Point {
    pallas::Point::generator() * fq_reduce_fp(poseidon_absorb(d, x, y)[0])
}

/// Accumulator leaf v2 [S4 3]:
/// `L = P(D, a+b, a*b) + H_leaf * G3`.
///
/// Linearity binds `(D, a+b, a*b, v, rho)`: a membership proof for `L`
/// attests the key AND the note seed/value term together.
pub fn leaf_v2(d: Fp, a: Fp, b: Fp, v: u64, rho: Fp) -> pallas::Point {
    p_leaf(d, a + b, a * b) + leaf_gen() * fq_reduce_fp(h_leaf_v2(v, rho))
}

// ---------------------------------------------------------------------------
// rc-limb gate [S4 8]: 4 x 16-bit limb decomposition + running-sum check
// ---------------------------------------------------------------------------

/// Number of 16-bit limbs per range-checked value.
pub const N_LIMBS: usize = 4;
/// Bits per limb.
pub const LIMB_BITS: usize = 16;

/// Configuration of the rc-limb gate.
///
/// Layout (single region, 5 rows):
///
/// ```text
/// row 0      : v, limbs [l0..l3], acc = 0          (s_top, s_start)
/// rows 1..=4 : 16 bit cells + acc = limb value     (s_bits)
/// ```
///
/// Constraints:
/// - `s_start`: the accumulator starts at zero;
/// - `s_bits` (rows 1..=4): `acc = sum_k 2^k * bit_k` plus per-bit
///   booleanity, so `acc` is the limb value reconstructed from bits;
/// - each limb cell is constrained equal to its block accumulator;
/// - `s_top` (row 0): `v = l0 + 2^16*l1 + 2^32*l2 + 2^48*l3`.
///
/// Together: `v` is reproduced exactly from 64 boolean cells grouped into
/// four 16-bit limbs, which is the range check [S4 4, S4 8].
#[derive(Clone, Debug)]
pub struct LimbRangeConfig {
    /// Range-checked value (row 0).
    pub v: Column<Advice>,
    /// Limb cells (row 0).
    pub limb: [Column<Advice>; N_LIMBS],
    /// Block accumulator (rows 1..=4).
    pub acc: Column<Advice>,
    /// Bit cells, 16 per block row.
    pub bits: [Column<Advice>; LIMB_BITS],
    /// Block sum gate.
    pub s_bits: Selector,
    /// Accumulator start gate.
    pub s_start: Selector,
    /// Top-level reconstruction gate.
    pub s_top: Selector,
    /// Public instance carrying `v`.
    pub instance_v: Column<Instance>,
}

impl LimbRangeConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let v = meta.advice_column();
        let limb = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let acc = meta.advice_column();
        let bits = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let s_bits = meta.selector();
        let s_start = meta.selector();
        let s_top = meta.selector();
        let instance_v = meta.instance_column();

        meta.enable_equality(v);
        for c in limb.iter().chain(bits.iter()) {
            meta.enable_equality(*c);
        }
        meta.enable_equality(acc);
        meta.enable_equality(instance_v);

        // Block sum: acc = sum_k 2^k * bit_k (degree 2).
        meta.create_gate("rc-limb-block-sum", |meta| {
            let sel = meta.query_selector(s_bits);
            let a = meta.query_advice(acc, Rotation::cur());
            let mut sum = meta.query_advice(bits[0], Rotation::cur());
            for k in 1..LIMB_BITS {
                sum = sum
                    + Expression::Constant(Fp::from(1u64 << k))
                        * meta.query_advice(bits[k], Rotation::cur());
            }
            let mut constraints: Vec<Expression<Fp>> = Vec::with_capacity(1 + LIMB_BITS);
            constraints.push(sel.clone() * (a - sum));
            for c in bits.iter() {
                let b = meta.query_advice(*c, Rotation::cur());
                constraints.push(sel.clone() * (b.clone() * (b - Expression::Constant(Fp::ONE))));
            }
            constraints
        });

        // Accumulator starts at zero.
        meta.create_gate("rc-limb-start", |meta| {
            let sel = meta.query_selector(s_start);
            let a = meta.query_advice(acc, Rotation::cur());
            vec![sel * a]
        });

        // v = l0 + 2^16*l1 + 2^32*l2 + 2^48*l3 (degree 1).
        meta.create_gate("rc-limb-top", |meta| {
            let sel = meta.query_selector(s_top);
            let vv = meta.query_advice(v, Rotation::cur());
            let l0 = meta.query_advice(limb[0], Rotation::cur());
            let l1 = meta.query_advice(limb[1], Rotation::cur());
            let l2 = meta.query_advice(limb[2], Rotation::cur());
            let l3 = meta.query_advice(limb[3], Rotation::cur());
            let two16 = Expression::Constant(Fp::from(1u64 << 16));
            let two32 = Expression::Constant(Fp::from(1u64 << 32));
            let two48 = Expression::Constant(Fp::from(1u64 << 48));
            vec![sel * (vv - l0 - two16 * l1 - two32 * l2 - two48 * l3)]
        });

        Self {
            v,
            limb,
            acc,
            bits,
            s_bits,
            s_start,
            s_top,
            instance_v,
        }
    }

    /// Assign the region for one value. `corrupt` flips one bit cell so the
    /// negative test produces an invalid decomposition.
    pub fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        v: Value<u64>,
        corrupt: bool,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let zero = || Value::known(Fp::ZERO);

        let v_cell = region.assign_advice(|| "v", self.v, 0, || v.map(Fp::from))?;
        let mut limb_cells = Vec::with_capacity(N_LIMBS);
        for j in 0..N_LIMBS {
            let l = v.map(|x| Fp::from((x >> (LIMB_BITS * j)) & 0xFFFF));
            let c = region.assign_advice(|| format!("limb{}", j), self.limb[j], 0, || l)?;
            limb_cells.push(c);
        }
        region.assign_advice(|| "acc-init", self.acc, 0, zero)?;
        self.s_start.enable(region, 0)?;
        self.s_top.enable(region, 0)?;

        for j in 0..N_LIMBS {
            let row = 1 + j;
            let mut bit_vals = [Value::known(Fp::ZERO); LIMB_BITS];
            for k in 0..LIMB_BITS {
                let mut b = v.map(|x| Fp::from((x >> (LIMB_BITS * j + k)) & 1));
                if corrupt && j == 1 && k == 5 {
                    b = b.map(|x| Fp::ONE - x);
                }
                bit_vals[k] = b;
            }
            for k in 0..LIMB_BITS {
                region.assign_advice(
                    || format!("bit-{}-{}", j, k),
                    self.bits[k],
                    row,
                    || bit_vals[k],
                )?;
            }
            let limb_val = v.map(|x| Fp::from((x >> (LIMB_BITS * j)) & 0xFFFF));
            let acc_cell =
                region.assign_advice(|| format!("acc-{}", j), self.acc, row, || limb_val)?;
            self.s_bits.enable(region, row)?;
            region.constrain_equal(limb_cells[j].cell(), acc_cell.cell())?;
        }

        Ok(v_cell)
    }
}

/// Rows used by the rc-limb gate region.
pub const LIMB_ROWS: usize = 1 + N_LIMBS;

/// Standalone test circuit wrapping the rc-limb gate: the range-checked
/// value is exposed as a public instance.
#[derive(Clone, Debug)]
pub struct LimbRangeCircuit {
    pub v: Value<u64>,
    pub corrupt: bool,
}

impl Circuit<Fp> for LimbRangeCircuit {
    type Config = LimbRangeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            v: Value::unknown(),
            corrupt: self.corrupt,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        LimbRangeConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let v_cell = layouter.assign_region(
            || "rc-limb",
            |mut region| config.assign(&mut region, self.v, self.corrupt),
        )?;
        layouter.constrain_instance(v_cell.cell(), config.instance_v, 0)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// v4-hash gate [S4 5, S4 8]: Poseidon chains for nk / N / H_leaf
// ---------------------------------------------------------------------------

/// Rows consumed by one permutation (64 round rows + 1 final row).
const V4_ROWS_PER_PERM: usize = crate::poseidon::ROUNDS + 1;

/// Configuration of the v4-hash gate: the opacus-zk Poseidon round gadget
/// (identical constraint set to `circuit.rs`, factored out for the v0.4
/// hash chains; unification happens with the Phase 2 circuit integration).
#[derive(Clone, Debug)]
pub struct V4HashConfig {
    /// Poseidon state columns [s0, s1, s2].
    pub state: [Column<Advice>; 3],
    /// Absorb input columns [in0, in1].
    pub absorb: [Column<Advice>; 2],
    /// Round-constant columns.
    pub rc: [Column<Fixed>; 3],
    /// Capacity domain constant (D at round 0, 0 elsewhere).
    pub domain: Column<Fixed>,
    /// Absorb flag (1 at round 0, 0 elsewhere).
    pub is_absorb: Column<Fixed>,
    /// Poseidon round gate.
    pub s_round: Selector,
    /// Initial-state-is-zero gate.
    pub s_init: Selector,
    /// Public instance column (squeezed output).
    pub instance: Column<Instance>,
}

impl V4HashConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let absorb = [meta.advice_column(), meta.advice_column()];
        let rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let domain = meta.fixed_column();
        let is_absorb = meta.fixed_column();
        let s_round = meta.selector();
        let s_init = meta.selector();
        let instance = meta.instance_column();

        for c in state.iter().chain(absorb.iter()) {
            meta.enable_equality(*c);
        }
        meta.enable_equality(instance);

        // Poseidon round transition with fused absorb + input masking
        // (identical to the v0.3.0 gate).
        meta.create_gate("v4-poseidon-round", |meta| {
            let sel = meta.query_selector(s_round);
            let s0 = meta.query_advice(state[0], Rotation::cur());
            let s1 = meta.query_advice(state[1], Rotation::cur());
            let s2 = meta.query_advice(state[2], Rotation::cur());
            let in0 = meta.query_advice(absorb[0], Rotation::cur());
            let in1 = meta.query_advice(absorb[1], Rotation::cur());
            let rc0 = meta.query_fixed(rc[0]);
            let rc1 = meta.query_fixed(rc[1]);
            let rc2 = meta.query_fixed(rc[2]);
            let dom = meta.query_fixed(domain);
            let flag = meta.query_fixed(is_absorb);
            let n0 = meta.query_advice(state[0], Rotation::next());
            let n1 = meta.query_advice(state[1], Rotation::next());
            let n2 = meta.query_advice(state[2], Rotation::next());

            let u0 = s0 + in0.clone() + rc0;
            let u1 = s1 + in1.clone() + rc1;
            let u2 = s2 + dom + rc2;

            let fiv = |x: Expression<Fp>| {
                let a = x.clone();
                let b = a.clone() * a;
                b.clone() * b * x
            };
            let p0 = fiv(u0);
            let p1 = fiv(u1);
            let p2 = fiv(u2);

            let m = |v: u64| Expression::Constant(Fp::from(v));
            let o0 = m(2) * p0.clone() + m(1) * p1.clone() + m(1) * p2.clone();
            let o1 = m(1) * p0.clone() + m(2) * p1.clone() + m(1) * p2.clone();
            let o2 = m(1) * p0 + m(1) * p1 + m(2) * p2;

            let one = Expression::Constant(Fp::ONE);
            let mask0 = in0 * (one.clone() - flag.clone());
            let mask1 = in1 * (one - flag);

            vec![
                sel.clone() * (n0 - o0),
                sel.clone() * (n1 - o1),
                sel.clone() * (n2 - o2),
                sel.clone() * mask0,
                sel * mask1,
            ]
        });

        meta.create_gate("v4-init-zero", |meta| {
            let sel = meta.query_selector(s_init);
            let s0 = meta.query_advice(state[0], Rotation::cur());
            let s1 = meta.query_advice(state[1], Rotation::cur());
            let s2 = meta.query_advice(state[2], Rotation::cur());
            let zero = Expression::Constant(Fp::ZERO);
            vec![
                sel.clone() * (s0 - zero.clone()),
                sel.clone() * (s1 - zero.clone()),
                sel * (s2 - zero),
            ]
        });

        Self {
            state,
            absorb,
            rc,
            domain,
            is_absorb,
            s_round,
            s_init,
            instance,
        }
    }

    /// Assign one full permutation starting at `base`, with the absorb
    /// inputs taken from already-assigned cells (witness sharing).
    pub fn perm_cells(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        domain: Fp,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let rcs = crate::poseidon::round_constants();
        let zero = || Value::known(Fp::ZERO);
        let in0v = a.value().cloned();
        let in1v = b.value().cloned();
        a.copy_advice(|| "v4-in0", region, self.absorb[0], base)?;
        b.copy_advice(|| "v4-in1", region, self.absorb[1], base)?;

        let mut s = [zero(), zero(), zero()];
        for r in 0..crate::poseidon::ROUNDS {
            for k in 0..3 {
                region.assign_advice(
                    || format!("state{}-r{}", k, r),
                    self.state[k],
                    base + r,
                    || s[k],
                )?;
            }
            let iv0 = if r == 0 { in0v } else { zero() };
            let iv1 = if r == 0 { in1v } else { zero() };
            region.assign_advice(|| "in0", self.absorb[0], base + r, || iv0)?;
            region.assign_advice(|| "in1", self.absorb[1], base + r, || iv1)?;
            region.assign_fixed(|| "rc0", self.rc[0], base + r, || Value::known(rcs[r][0]))?;
            region.assign_fixed(|| "rc1", self.rc[1], base + r, || Value::known(rcs[r][1]))?;
            region.assign_fixed(|| "rc2", self.rc[2], base + r, || Value::known(rcs[r][2]))?;
            let dom = if r == 0 { domain } else { Fp::ZERO };
            let flag = if r == 0 { Fp::ONE } else { Fp::ZERO };
            region.assign_fixed(|| "domain", self.domain, base + r, || Value::known(dom))?;
            region.assign_fixed(|| "absorb", self.is_absorb, base + r, || Value::known(flag))?;
            self.s_round.enable(region, base + r)?;

            let rc0 = Value::known(rcs[r][0]);
            let rc1 = Value::known(rcs[r][1]);
            let rc2 = Value::known(rcs[r][2]);
            let domv = Value::known(dom);
            let u0 = s[0] + iv0 + rc0;
            let u1 = s[1] + iv1 + rc1;
            let u2 = s[2] + domv + rc2;
            let fiv = |x: Value<Fp>| {
                let a = x;
                let b = a * a;
                b * b * x
            };
            let p0 = fiv(u0);
            let p1 = fiv(u1);
            let p2 = fiv(u2);
            let two = Value::known(Fp::from(2u64));
            let n0 = p0 * two + p1 + p2;
            let n1 = p0 + p1 * two + p2;
            let n2 = p0 + p1 + p2 * two;
            s = [n0, n1, n2];
        }

        let fr = base + crate::poseidon::ROUNDS;
        let mut out = None;
        for k in 0..3 {
            let c =
                region.assign_advice(|| format!("state{}-final", k), self.state[k], fr, || s[k])?;
            if k == 0 {
                out = Some(c);
            }
        }
        region.assign_advice(|| "in0", self.absorb[0], fr, zero)?;
        region.assign_advice(|| "in1", self.absorb[1], fr, zero)?;
        region.assign_fixed(|| "rc0", self.rc[0], fr, zero)?;
        region.assign_fixed(|| "rc1", self.rc[1], fr, zero)?;
        region.assign_fixed(|| "rc2", self.rc[2], fr, zero)?;
        region.assign_fixed(|| "domain", self.domain, fr, zero)?;
        region.assign_fixed(|| "absorb", self.is_absorb, fr, zero)?;

        Ok(out.expect("state0 cell"))
    }
}

/// Rows used by a two-permutation v4-hash region (nk and N).
pub const NULLIFIER_HASH_ROWS: usize = 3 + 2 * V4_ROWS_PER_PERM;
/// Rows used by a one-permutation v4-hash region (H_leaf).
pub const LEAF_HASH_ROWS: usize = 1 + V4_ROWS_PER_PERM;

/// Test circuit: proves `N = Poseidon_3(Poseidon_3(a, b, DOM_NK), rho,
/// DOM_NU)` from the witness `(a, b, rho)`, exposing `N` as a public
/// instance. This is the nullifier gate of [S4 5, S4 8] in its wallet
/// topology shape.
#[derive(Clone, Debug)]
pub struct V4NullifierCircuit {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
    pub rho: Value<Fp>,
    pub corrupt: bool,
}

impl Circuit<Fp> for V4NullifierCircuit {
    type Config = V4HashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
            rho: Value::unknown(),
            corrupt: self.corrupt,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        V4HashConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let n_cell = layouter.assign_region(
            || "v4-nullifier",
            |mut region| {
                let a_cell = region.assign_advice(|| "a", config.absorb[0], 0, || self.a)?;
                let b_cell = region.assign_advice(|| "b", config.absorb[1], 0, || self.b)?;
                // A lying prover derives N from a tampered rho; the published
                // instance still carries the honest N, so verification fails.
                let rho_used = if self.corrupt {
                    self.rho.map(|x| x + Fp::ONE)
                } else {
                    self.rho
                };
                let rho_cell = region.assign_advice(|| "rho", config.state[0], 1, || rho_used)?;
                let nk_cell = config.perm_cells(&mut region, 2, dom_nk(), a_cell, b_cell)?;
                config.perm_cells(
                    &mut region,
                    2 + V4_ROWS_PER_PERM,
                    dom_nu(),
                    nk_cell,
                    rho_cell,
                )
            },
        )?;
        layouter.constrain_instance(n_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}

/// Test circuit: proves `H_leaf = Poseidon_3(v, rho, DOM_LEAF_V2)` from the
/// witness `(v, rho)`, exposing `H_leaf` as a public instance. This is the
/// hash part of the leaf-v2 gate of [S4 3, S4 8] (the `H_leaf * G3` term
/// needs the Phase 1b fixed-base chip).
#[derive(Clone, Debug)]
pub struct V4LeafHashCircuit {
    pub v: Value<u64>,
    pub rho: Value<Fp>,
    pub corrupt: bool,
}

impl Circuit<Fp> for V4LeafHashCircuit {
    type Config = V4HashConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            v: Value::unknown(),
            rho: Value::unknown(),
            corrupt: self.corrupt,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        V4HashConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let h_cell = layouter.assign_region(
            || "v4-leaf-hash",
            |mut region| {
                let v_used = if self.corrupt {
                    self.v.map(|x| x + 1)
                } else {
                    self.v
                };
                let v_cell =
                    region.assign_advice(|| "v", config.absorb[0], 0, || v_used.map(Fp::from))?;
                let rho_cell = region.assign_advice(|| "rho", config.absorb[1], 0, || self.rho)?;
                config.perm_cells(&mut region, 1, dom_leaf_v2(), v_cell, rho_cell)
            },
        )?;
        layouter.constrain_instance(h_cell.cell(), config.instance, 0)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Curve, GroupEncoding};
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    /// k budget from [S4 8]: the v4 design MUST stay within k = 13.
    const K_BUDGET: u32 = 13;
    const K_BUDGET_ROWS: usize = 1 << K_BUDGET;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn domain_constants_are_distinct_and_stable() {
        let d0 = dom_leaf_v2();
        let d1 = dom_nk();
        let d2 = dom_nu();
        assert_ne!(d0, d1);
        assert_ne!(d0, d2);
        assert_ne!(d1, d2);
        // Pinned test vectors [S4 2]: stable across releases and platforms.
        assert_eq!(hex(&d0.to_repr()), DOM_LEAF_V2_HEX);
        assert_eq!(hex(&d1.to_repr()), DOM_NK_HEX);
        assert_eq!(hex(&d2.to_repr()), DOM_NU_HEX);
    }

    #[test]
    fn hashgen_vectors_are_stable() {
        let v = value_gen();
        let r = blind_gen();
        let g3 = leaf_gen();
        // Pinned test vectors [S4 2, S4 11]: compressed encodings.
        assert_eq!(hex(&v.to_affine().to_bytes()), VALUE_GEN_HEX);
        assert_eq!(hex(&r.to_affine().to_bytes()), BLIND_GEN_HEX);
        assert_eq!(hex(&g3.to_affine().to_bytes()), LEAF_GEN_HEX);
        // Distinct generators, none is the identity.
        assert_ne!(v, r);
        assert_ne!(v, g3);
        assert_ne!(r, g3);
        assert_ne!(v, pallas::Point::identity());
        assert_ne!(r, pallas::Point::identity());
        assert_ne!(g3, pallas::Point::identity());
    }

    #[test]
    fn hashgen_is_deterministic_per_name() {
        assert_eq!(hashgen("value"), value_gen());
        assert_eq!(hashgen("value"), value_gen());
        assert_ne!(hashgen("value"), hashgen("blind"));
    }

    #[test]
    fn fp_to_fq_reduction_preserves_small_values() {
        // Small integers reduce to the same integer.
        for x in [0u64, 1, 2, 12345, u64::MAX] {
            let fp = Fp::from(x);
            let fq = fq_reduce_fp(fp);
            let back = fq.to_repr();
            let lo = u64::from_le_bytes(back[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(back[8..16].try_into().unwrap());
            assert_eq!(lo, x);
            assert_eq!(hi, 0);
        }
    }

    #[test]
    fn value_commit_is_homomorphic() {
        let vg = value_gen();
        let rg = blind_gen();
        let r1 = Fq::random(OsRng);
        let r2 = Fq::random(OsRng);
        let rc1 = value_commit(100, r1, &vg, &rg);
        let rc2 = value_commit(250, r2, &vg, &rg);
        let rc12 = value_commit(350, r1 + r2, &vg, &rg);
        assert_eq!(rc1 + rc2, rc12);
        // With zero blinding the value term is visible: RC(v, 0) = [v]V.
        assert_eq!(value_commit(7, Fq::ZERO, &vg, &rg), vg * Fq::from(7u64));
        // Random blinding hides the value.
        assert_ne!(value_commit(100, Fq::random(OsRng), &vg, &rg), rc1);
    }

    #[test]
    fn nullifier_v4_links_witnesses() {
        let a = Fp::random(OsRng);
        let b = Fp::random(OsRng);
        let rho = Fp::random(OsRng);
        let nk = nullifier_key(a, b);
        let n = nullifier_from_key(nk, rho);
        assert_eq!(n, nullifier_v4(a, b, rho));
        // Deterministic per note...
        assert_eq!(nullifier_v4(a, b, rho), nullifier_v4(a, b, rho));
        // ...but bound to every witness component [S4 5].
        assert_ne!(nullifier_v4(a + Fp::ONE, b, rho), n);
        assert_ne!(nullifier_v4(a, b + Fp::ONE, rho), n);
        assert_ne!(nullifier_v4(a, b, rho + Fp::ONE), n);
        // N never leaks the nullifier key.
        assert_ne!(n, nk);
    }

    #[test]
    fn leaf_v2_binds_key_and_note_terms() {
        let d = Fp::random(OsRng);
        let a = Fp::random(OsRng);
        let b = Fp::random(OsRng);
        let rho = Fp::random(OsRng);
        let l = leaf_v2(d, a, b, 42, rho);
        // Deterministic...
        assert_eq!(leaf_v2(d, a, b, 42, rho), l);
        // ...and linear in both parts [S4 3].
        assert_ne!(leaf_v2(d, a, b, 43, rho), l);
        assert_ne!(leaf_v2(d, a, b, 42, rho + Fp::ONE), l);
        assert_ne!(leaf_v2(d, a + Fp::ONE, b, 42, rho), l);
        assert_ne!(leaf_v2(d + Fp::ONE, a, b, 42, rho), l);
        // Recompute from the pieces: p_leaf + [H_leaf]G3.
        let key_part = p_leaf(d, a + b, a * b);
        let g3 = leaf_gen();
        let value_part = g3 * fq_reduce_fp(h_leaf_v2(42, rho));
        assert_eq!(key_part + value_part, l);
        // The key part alone differs from the composed leaf.
        assert_ne!(key_part, l);
    }

    #[test]
    fn rc_limb_gate_accepts_valid_values() {
        let cases: Vec<u64> = vec![0, 1, 2, 0xFFFF, 0x10000, 0x1234567890ABCDEF, u64::MAX];
        for v in cases {
            let circuit = LimbRangeCircuit {
                v: Value::known(v),
                corrupt: false,
            };
            let prover = MockProver::run(8, &circuit, vec![vec![Fp::from(v)]]).unwrap();
            prover.verify().unwrap();
        }
        // Row budget [S4 8]: the gate itself is tiny, but assert the budget
        // invariant anyway so a future regression is caught immediately.
        const _: () = assert!(LIMB_ROWS < K_BUDGET_ROWS);
    }

    #[test]
    fn rc_limb_gate_rejects_corrupted_decomposition() {
        let v = 0x1234567890ABCDEFu64;
        let circuit = LimbRangeCircuit {
            v: Value::known(v),
            corrupt: true,
        };
        let prover = MockProver::run(8, &circuit, vec![vec![Fp::from(v)]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_nullifier_gate_matches_host_and_rejects_lies() {
        let a = Fp::random(OsRng);
        let b = Fp::random(OsRng);
        let rho = Fp::random(OsRng);
        let n = nullifier_v4(a, b, rho);

        let circuit = V4NullifierCircuit {
            a: Value::known(a),
            b: Value::known(b),
            rho: Value::known(rho),
            corrupt: false,
        };
        let prover = MockProver::run(9, &circuit, vec![vec![n]]).unwrap();
        prover.verify().unwrap();
        const _: () = assert!(NULLIFIER_HASH_ROWS < K_BUDGET_ROWS);

        // A published N derived from a DIFFERENT note must fail [S4 5].
        let wrong_n = nullifier_v4(a, b, rho + Fp::ONE);
        let prover = MockProver::run(9, &circuit, vec![vec![wrong_n]]).unwrap();
        assert!(prover.verify().is_err());

        // A corrupted witness (rho tampered in-circuit) must fail.
        let bad = V4NullifierCircuit {
            a: Value::known(a),
            b: Value::known(b),
            rho: Value::known(rho),
            corrupt: true,
        };
        let prover = MockProver::run(9, &bad, vec![vec![n]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_leaf_hash_gate_matches_host_and_rejects_lies() {
        let v = 777u64;
        let rho = Fp::random(OsRng);
        let h = h_leaf_v2(v, rho);

        let circuit = V4LeafHashCircuit {
            v: Value::known(v),
            rho: Value::known(rho),
            corrupt: false,
        };
        let prover = MockProver::run(9, &circuit, vec![vec![h]]).unwrap();
        prover.verify().unwrap();
        assert!(LEAF_HASH_ROWS < K_BUDGET_ROWS);

        let wrong_h = h_leaf_v2(v, rho + Fp::ONE);
        let prover = MockProver::run(9, &circuit, vec![vec![wrong_h]]).unwrap();
        assert!(prover.verify().is_err());

        let bad = V4LeafHashCircuit {
            v: Value::known(v),
            rho: Value::known(rho),
            corrupt: true,
        };
        let prover = MockProver::run(9, &bad, vec![vec![h]]).unwrap();
        assert!(prover.verify().is_err());
    }

    // Pinned test vectors (blake3-derived, stable across platforms).
    const DOM_LEAF_V2_HEX: &str =
        "ef5fb9e6b52e8fd2ad13a41cb5bbe7d700000000000000000000000000000000";
    const DOM_NK_HEX: &str = "05aaa5ef73643808a460509a993602b000000000000000000000000000000000";
    const DOM_NU_HEX: &str = "c7877750c65441e2063ff5598b3c8a6400000000000000000000000000000000";
    const VALUE_GEN_HEX: &str = "aa6ee3702b714724c674cd327429f8574f821b1160a0b83929a2b5ee967c0b05";
    const BLIND_GEN_HEX: &str = "ef50f50cf65eb62760ff7d35c03356fc4fac2728b39805b73e20ef7473b4cfb2";
    const LEAF_GEN_HEX: &str = "cfa9b76b3ef032d07635c7faafc029305f548fe634fdd9634b1df44ac441b50a";
}

// ---------------------------------------------------------------------------
// WG-26 swap hashlock primitives [S4 12]
// ---------------------------------------------------------------------------

#[cfg(test)]
mod swap_wg26_tests {
    use super::*;

    const PREIMAGE_A: [u8; 32] = [
        0x2a, 0xb3, 0x11, 0x7c, 0x0f, 0xe4, 0x5d, 0x92, 0x68, 0x01, 0xda, 0x4f, 0xc3, 0x76, 0x18,
        0xa9, 0x5e, 0x20, 0xbb, 0x87, 0x6c, 0xf1, 0x03, 0x49, 0xd0, 0xaa, 0x5b, 0x16, 0xe7, 0x82,
        0x39, 0x4c,
    ];
    const PREIMAGE_B: [u8; 32] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x00, 0x22, 0x44, 0x66, 0x88, 0xaa, 0xcc,
        0xee, 0x1f, 0x3e, 0x5d, 0x7c, 0x9b, 0xba, 0xd9, 0xf8, 0x07, 0x26, 0x45, 0x64, 0x83, 0xa2,
        0xc1, 0xe0,
    ];

    #[test]
    fn dom_swap_is_the_frozen_label() {
        assert_eq!(dom_swap(), fp_from_label(b"GHOST/v4/dom/swap"));
        assert_ne!(dom_swap(), dom_leaf_v2());
        assert_ne!(dom_swap(), dom_nk());
        assert_ne!(dom_swap(), dom_nu());
    }

    #[test]
    fn lanes_roundtrip_and_stay_canonical() {
        let (s0, s1) = swap_lanes(&PREIMAGE_A);
        // Canonical 128-bit lanes: the top half of the canonical
        // representation stays zero, and the low half IS the preimage chunk.
        for (lane, chunk) in [(s0, 0usize), (s1, 16usize)] {
            let r = lane.to_repr();
            let b = r.as_ref();
            assert!(b[16..32].iter().all(|x| *x == 0));
            assert_eq!(&b[0..16], &PREIMAGE_A[chunk..chunk + 16]);
        }
        // Distinct preimages split into distinct lane pairs.
        let (t0, t1) = swap_lanes(&PREIMAGE_B);
        assert_ne!((s0, s1), (t0, t1));
    }

    #[test]
    fn hashlock_swap_matches_the_poseidon_convention() {
        let (h, s0, s1) = hashlock_swap(&PREIMAGE_A);
        let (r0, r1) = swap_lanes(&PREIMAGE_A);
        assert_eq!((s0, s1), (r0, r1));
        assert_eq!(h, poseidon_absorb(dom_swap(), s0, s1)[0]);
        // Deterministic, preimage-sensitive, nonzero (H = 0 is reserved).
        let (h2, _, _) = hashlock_swap(&PREIMAGE_A);
        assert_eq!(h, h2);
        let (h3, _, _) = hashlock_swap(&PREIMAGE_B);
        assert_ne!(h, h3);
        assert!(h != Fp::ZERO);
    }
}
