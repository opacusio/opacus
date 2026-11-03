//! OPACUS v0.4 Phase 1b: the rc-fixed-base gate.
//!
//! Implements the fixed-base part of the v0.4 specification
//! (`docs/specs/v0.4-value-conservation.md`, referenced below as [S4]):
//!
//! - **rc-fixed-base gate** [S4 4, S4 8]: `RC = v * V + r * R` is computed
//!   in-circuit as a REAL group element: the scalar is witnessed bit by
//!   bit and every set bit adds the fixed window multiple `[2^i] * B` to
//!   an accumulator via a conditional elliptic-curve addition gate. The
//!   synthesized result is exposed as a public instance and cross-checked
//!   against the host-side [`crate::v4::value_commit`] in tests.
//! - **leaf-v2 G3 term** [S4 3, S4 8]: the `H_leaf * G3` term of the
//!   accumulator leaf is computed in-circuit from `H_leaf`; the Phase 1a
//!   v4-hash gate ([`crate::v4::V4HashConfig`]) supplies the permutation.
//!
//! # Design: per-bit conditional EC addition [S4 8]
//!
//! All bases (V, R, G3) are hashgen constants [S4 2], so every window
//! multiple `2^i * B` is a fixed point whose coordinates are constants of
//! the circuit. The scalar (256 bits, bit 255 forced to zero) is witnessed
//! as single-bit cells; starting from the encoded identity `(0, 0)`, bit
//! `i` transitions the accumulator
//!
//! ```text
//!   (X', Y') = (X, Y) + [2^i] * B   if bit_i = 1   (EC addition)
//!   (X', Y') = (X, Y)               if bit_i = 0
//! ```
//!
//! using the incomplete affine formulas witnessed by a slope cell `lam`:
//!
//! ```text
//!   lam = (Y - Wy) / (X - Wx),  X' = lam^2 - X - Wx,  Y' = lam (X - X') - Y
//! ```
//!
//! with three guard mechanisms:
//!
//! - **identity branch**: the accumulator starts at the encoded identity
//!   `(0, 0)`. A boolean cell `iota` selects the branch `O + W = W`;
//!   `iota = 1` forces `X = Y = 0`, so it can only fire on the true
//!   identity.
//! - **non-zero denominator guard**: a cell `din` with
//!   `(X - Wx) * din = 1` proves the slope denominator is invertible, so
//!   the degenerate `A = +/- W` cases are unsatisfiable.
//! - **masked identity is self-breaking**: a lying `iota = 0` on a true
//!   identity still yields a fully determined transition, so it cannot
//!   forge an arbitrary point; it only fails the host cross-check.
//!
//! Every transition is therefore fully determined by the witnessed bits:
//! the final accumulator is exactly `[s mod q] * B` with no prover
//! freedom, which is the binding required by [S4 4]. For an honest prover
//! the degenerate `A = W` collision is a ~2^-252 event per bit and cannot
//! be reached without breaking the discrete log.
//!
//! # Witness sharing [S4 8]
//!
//! The value-commit circuit runs the accumulation for `v` over the SAME
//! rows and bit columns that the rc-limb gate uses for the limb
//! decomposition of `v` (the very same cells), so `RC` is provably built
//! from the range-checked limbs; the blinding scalar `r` and the leaf
//! scalar `H_leaf` are witnessed as fresh bit cells.
//!
//! # Public instances
//!
//! Points are represented in-circuit as affine `(Fp, Fp)` pairs; the
//! canonical byte encoding and the `(0, 0)` identity convention are
//! consensus concerns [S4 11] settled in Phase 2/4.
//!
//! - [`V4ValueCommitCircuit`]: instance slots `[RC.x, RC.y]`.
//! - [`V4LeafTermCircuit`]: instance slots `[H_leaf, term.x, term.y]`
//!   with `term = [H_leaf] * G3`.
//!
//! Phase 2 assembles these gates into the full v4 spend topology
//! (MAX_IN = 2, MAX_OUT = 4) with the normative instance order [S4 8].

use ff::{Field, PrimeField};
use group::Curve;
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::{pallas, Fp, Fq};

use crate::v4::{
    blind_gen, dom_leaf_v2, leaf_gen, value_gen, LimbRangeConfig, V4HashConfig, LEAF_HASH_ROWS,
    LIMB_BITS, N_LIMBS,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Bits handled per accumulation row (one bit per bit column).
pub const FB_ROW_BITS: usize = 16;
/// Accumulation rows for one 255-bit scalar (the Pallas group order needs
/// 255 bits; the last cell of the last row is a forced zero pad).
pub const FB_SCALAR_ROWS: usize = 16;
/// Window multiples per base: coordinates of `[2^i] * B`, i in 0..256.
pub const FB_MULTIPLES: usize = 256;
/// Accumulation rows of the rc-fixed-base region: 4 limb rows for `v`
/// plus 16 rows for the blinding scalar `r`.
pub const VALUE_ACC_ROWS: usize = N_LIMBS + FB_SCALAR_ROWS;
/// Rows of the rc-fixed-base region: init row + accumulation rows. The
/// final accumulator cells (last row, `x[FB_ROW_BITS]`/`y[FB_ROW_BITS]`)
/// ARE the exposed `RC`.
pub const VALUE_COMMIT_ROWS: usize = 1 + VALUE_ACC_ROWS;
/// Rows of the leaf-term fixed-base region: init row + accumulation rows.
pub const LEAF_TERM_FB_ROWS: usize = 1 + FB_SCALAR_ROWS;
/// Total rows of the leaf-term circuit region: Phase 1a hash region plus
/// the fixed-base region.
pub const LEAF_TERM_ROWS: usize = LEAF_HASH_ROWS + LEAF_TERM_FB_ROWS;
/// An arbitrary bit index inside the scalar blocks used by the negative
/// tests to flip one witnessed bit cell.
const FB_CORRUPT_BIT: usize = 100;

// ---------------------------------------------------------------------------
// Window multiples [S4 2, S4 8]
// ---------------------------------------------------------------------------

/// Window multiples of a fixed base: `multiples[i]` holds the `(x, y)`
/// coordinates of `[2^i] * base`. Derived deterministically from the
/// hashgen generators at synthesis time; no trapdoor exists in the bases
/// [S4 2, S4 11]. Panics if a multiple is the identity, which cannot
/// happen for the hashgen generators.
pub fn fb_multiples(base: pallas::Point) -> Vec<(Fp, Fp)> {
    let mut multiples = Vec::with_capacity(FB_MULTIPLES);
    let mut acc = base;
    for _ in 0..FB_MULTIPLES {
        let aff = acc.to_affine();
        let c = aff.coordinates().unwrap();
        multiples.push((*c.x(), *c.y()));
        acc = acc + acc;
    }
    multiples
}

/// Bit `idx` (little-endian) of a 32-byte field representation. Index 255
/// and beyond is a forced zero: both Pasta field primes are below 2^255.
fn bit_of(repr: &[u8; 32], idx: usize) -> Fp {
    if idx < 255 {
        Fp::from(((repr[idx / 8] >> (idx % 8)) & 1) as u64)
    } else {
        Fp::ZERO
    }
}

// ---------------------------------------------------------------------------
// Host-side EC addition chain [S4 8]
// ---------------------------------------------------------------------------

/// One conditional EC addition of the accumulator with a fixed window
/// multiple `w`. Returns `(x1, y1, lam, iota, din)`: the new accumulator,
/// the witnessed slope, the identity-branch flag and the denominator
/// inverse. The `delta.invert()` call panics on `A = W`, which is
/// unreachable for honest witnesses (see the module docs).
fn ec_step(acc: (Fp, Fp), w: (Fp, Fp)) -> (Fp, Fp, Fp, Fp, Fp) {
    let (x0, y0) = acc;
    let (wx, wy) = w;
    if x0 == Fp::ZERO && y0 == Fp::ZERO {
        // identity branch: O + W = W
        (wx, wy, Fp::ZERO, Fp::ONE, Fp::ZERO)
    } else {
        let delta = x0 - wx;
        let din = delta.invert().unwrap();
        let lam = din * (y0 - wy);
        let x1 = lam * lam - x0 - wx;
        let y1 = lam * (x0 - x1) - y0;
        (x1, y1, lam, Fp::ZERO, din)
    }
}

/// Witness values of one accumulation row: the per-bit transition cells
/// plus the accumulator chain `x[0..=16]`, `y[0..=16]` (`x[0]` is the
/// incoming accumulator, `x[16]` the outgoing one).
struct RowVals {
    lam: [Fp; FB_ROW_BITS],
    iota: [Fp; FB_ROW_BITS],
    din: [Fp; FB_ROW_BITS],
    x: [Fp; FB_ROW_BITS + 1],
    y: [Fp; FB_ROW_BITS + 1],
}
impl Clone for RowVals {
    fn clone(&self) -> Self {
        Self {
            lam: self.lam,
            iota: self.iota,
            din: self.din,
            x: self.x,
            y: self.y,
        }
    }
}

/// Runs the conditional EC addition chain row by row. `bits_rows[j][k]` is
/// the witnessed bit `16*j + k`; `mults_rows[j][k]` is the window multiple
/// `[2^(16*j + k)] * B`. The chain starts at the encoded identity.
fn chain_rows(
    bits_rows: &[[Fp; FB_ROW_BITS]],
    mults_rows: &[[(Fp, Fp); FB_ROW_BITS]],
) -> Vec<RowVals> {
    let mut acc = (Fp::ZERO, Fp::ZERO);
    let mut out = Vec::with_capacity(bits_rows.len());
    for (bits, mults) in bits_rows.iter().zip(mults_rows.iter()) {
        let mut rv = RowVals {
            lam: [Fp::ZERO; FB_ROW_BITS],
            iota: [Fp::ZERO; FB_ROW_BITS],
            din: [Fp::ZERO; FB_ROW_BITS],
            x: [Fp::ZERO; FB_ROW_BITS + 1],
            y: [Fp::ZERO; FB_ROW_BITS + 1],
        };
        rv.x[0] = acc.0;
        rv.y[0] = acc.1;
        for k in 0..FB_ROW_BITS {
            let b = bits[k];
            let (x1, y1, lam, iota, din) = if b == Fp::ZERO {
                (acc.0, acc.1, Fp::ZERO, Fp::ZERO, Fp::ZERO)
            } else {
                ec_step(acc, mults[k])
            };
            rv.lam[k] = lam;
            rv.iota[k] = iota;
            rv.din[k] = din;
            rv.x[k + 1] = x1;
            rv.y[k + 1] = y1;
            acc = (x1, y1);
        }
        out.push(rv);
    }
    out
}

// ---------------------------------------------------------------------------
// FbConfig: the conditional fixed-base EC addition gates [S4 4, S4 8]
// ---------------------------------------------------------------------------

/// Configuration of the fixed-base accumulation gates.
///
/// One accumulation row carries 16 bits and performs 16 conditional EC
/// additions unrolled across dedicated columns:
///
/// ```text
///   bits[k]     : witnessed bit 16*j + k (shared with the limb gate rows)
///   x[0..=16]   : accumulator x chain across the row
///   y[0..=16]   : accumulator y chain across the row
///   lam[k]      : slope of the k-th addition
///   iota[k]     : identity-branch flag of the k-th addition
///   din[k]      : inverse of the slope denominator (x - Wx)
///   fx_x[k]     : fixed x coordinate of [2^(16*j + k)] * B
///   fx_y[k]     : fixed y coordinate of [2^(16*j + k)] * B
/// ```
///
/// The row gate links `x[0]` of row j to `x[16]` of row j-1 through a
/// `Rotation::prev()` query, so the chain is continuous across rows
/// without copy constraints. `x[FB_ROW_BITS]`/`y[FB_ROW_BITS]` of the
/// LAST accumulation row are the exposed result.
#[derive(Clone, Debug)]
pub struct FbConfig {
    /// Bit cells, 16 per accumulation row.
    pub bits: [Column<Advice>; FB_ROW_BITS],
    /// Accumulator x chain (17 cells per row).
    pub x: [Column<Advice>; FB_ROW_BITS + 1],
    /// Accumulator y chain (17 cells per row).
    pub y: [Column<Advice>; FB_ROW_BITS + 1],
    /// Slope cells, one per addition.
    pub lam: [Column<Advice>; FB_ROW_BITS],
    /// Identity-branch flags, one per addition.
    pub iota: [Column<Advice>; FB_ROW_BITS],
    /// Slope-denominator inverse cells, one per addition.
    pub din: [Column<Advice>; FB_ROW_BITS],
    /// Window multiple x coordinates (constants per row and bit).
    pub fx_x: [Column<Fixed>; FB_ROW_BITS],
    /// Window multiple y coordinates (constants per row and bit).
    pub fx_y: [Column<Fixed>; FB_ROW_BITS],
    /// Top cell carrying the leaf scalar (leaf-term mode only).
    pub h_top: Column<Advice>,
    /// Accumulation row gate.
    pub s_acc: Selector,
    /// Accumulator starts at the encoded identity.
    pub s_init: Selector,
    /// Decomposed bits reproduce the source scalar (leaf-term mode only).
    pub s_top: Selector,
    /// Public instance column carrying the synthesized point.
    pub instance: Column<Instance>,
}

impl FbConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>, bits: [Column<Advice>; FB_ROW_BITS]) -> Self {
        let x: [Column<Advice>; FB_ROW_BITS + 1] = std::array::from_fn(|_| meta.advice_column());
        let y: [Column<Advice>; FB_ROW_BITS + 1] = std::array::from_fn(|_| meta.advice_column());
        let lam: [Column<Advice>; FB_ROW_BITS] = std::array::from_fn(|_| meta.advice_column());
        let iota: [Column<Advice>; FB_ROW_BITS] = std::array::from_fn(|_| meta.advice_column());
        let din: [Column<Advice>; FB_ROW_BITS] = std::array::from_fn(|_| meta.advice_column());
        let fx_x: [Column<Fixed>; FB_ROW_BITS] = std::array::from_fn(|_| meta.fixed_column());
        let fx_y: [Column<Fixed>; FB_ROW_BITS] = std::array::from_fn(|_| meta.fixed_column());
        let h_top = meta.advice_column();
        let s_acc = meta.selector();
        let s_init = meta.selector();
        let s_top = meta.selector();
        let instance = meta.instance_column();

        meta.enable_equality(x[FB_ROW_BITS]);
        meta.enable_equality(y[FB_ROW_BITS]);
        meta.enable_equality(h_top);
        meta.enable_equality(instance);

        // Accumulator starts at the encoded identity (0, 0).
        meta.create_gate("fb-init", |meta| {
            let sel = meta.query_selector(s_init);
            let x_out = meta.query_advice(x[FB_ROW_BITS], Rotation::cur());
            let y_out = meta.query_advice(y[FB_ROW_BITS], Rotation::cur());
            vec![sel.clone() * x_out, sel * y_out]
        });

        // The accumulation row: 16 conditional EC additions, unrolled.
        meta.create_gate("fb-acc", |meta| {
            let sel = meta.query_selector(s_acc);
            let xs: Vec<Expression<Fp>> = (0..=FB_ROW_BITS)
                .map(|k| meta.query_advice(x[k], Rotation::cur()))
                .collect();
            let ys: Vec<Expression<Fp>> = (0..=FB_ROW_BITS)
                .map(|k| meta.query_advice(y[k], Rotation::cur()))
                .collect();
            let lam: Vec<Expression<Fp>> = (0..FB_ROW_BITS)
                .map(|k| meta.query_advice(lam[k], Rotation::cur()))
                .collect();
            let iota: Vec<Expression<Fp>> = (0..FB_ROW_BITS)
                .map(|k| meta.query_advice(iota[k], Rotation::cur()))
                .collect();
            let din: Vec<Expression<Fp>> = (0..FB_ROW_BITS)
                .map(|k| meta.query_advice(din[k], Rotation::cur()))
                .collect();
            let x_prev = meta.query_advice(x[FB_ROW_BITS], Rotation::prev());
            let y_prev = meta.query_advice(y[FB_ROW_BITS], Rotation::prev());

            let one = Expression::Constant(Fp::ONE);

            // Chain continuity across rows.
            let mut cs = vec![
                sel.clone() * (xs[0].clone() - x_prev),
                sel.clone() * (ys[0].clone() - y_prev),
            ];
            for k in 0..FB_ROW_BITS {
                let b = meta.query_advice(bits[k], Rotation::cur());
                let wx = meta.query_fixed(fx_x[k]);
                let wy = meta.query_fixed(fx_y[k]);
                let it = iota[k].clone();
                let lm = lam[k].clone();
                let dn = din[k].clone();
                let x0 = xs[k].clone();
                let y0 = ys[k].clone();
                let x1 = xs[k + 1].clone();
                let y1 = ys[k + 1].clone();
                let delta = x0.clone() - wx.clone();
                let not_b = one.clone() - b.clone();
                let not_it = one.clone() - it.clone();

                // Booleanity of the bit and of the branch flag.
                cs.push(sel.clone() * (b.clone() * (b.clone() - one.clone())));
                cs.push(sel.clone() * (it.clone() * (it.clone() - one.clone())));
                // iota = 1 forces the true identity.
                cs.push(sel.clone() * (it.clone() * x0.clone()));
                cs.push(sel.clone() * (it.clone() * y0.clone()));
                // bit = 0: the accumulator is unchanged.
                cs.push(sel.clone() * (not_b.clone() * (x1.clone() - x0.clone())));
                cs.push(sel.clone() * (not_b.clone() * (y1.clone() - y0.clone())));
                // bit = 1, identity branch: O + W = W.
                cs.push(sel.clone() * (b.clone() * it.clone() * (x1.clone() - wx.clone())));
                cs.push(sel.clone() * (b.clone() * it.clone() * (y1.clone() - wy.clone())));
                // bit = 1, addition branch: incomplete affine formulas with
                // the slope and a proven-invertible denominator.
                cs.push(
                    sel.clone()
                        * (b.clone()
                            * not_it.clone()
                            * (delta.clone() * lm.clone() - (y0.clone() - wy.clone()))),
                );
                cs.push(
                    sel.clone()
                        * (b.clone() * not_it.clone() * (delta.clone() * dn.clone() - one.clone())),
                );
                cs.push(
                    sel.clone()
                        * (b.clone()
                            * not_it.clone()
                            * (x1.clone() - lm.clone() * lm.clone() + x0.clone() + wx.clone())),
                );
                cs.push(
                    sel.clone()
                        * (b.clone()
                            * not_it.clone()
                            * (y1.clone() - lm.clone() * (x0.clone() - x1.clone()) + y0.clone())),
                );
            }
            cs
        });

        // Decomposed bits reproduce the source scalar exactly (leaf-term
        // mode): the weights are built by repeated multiplication with
        // 2^16 so no shift ever exceeds the u64 range.
        meta.create_gate("fb-top", |meta| {
            let sel = meta.query_selector(s_top);
            let h = meta.query_advice(h_top, Rotation::cur());
            let two16 = Fp::from(1u64 << 16);
            let mut sum = Expression::Constant(Fp::ZERO);
            let mut w = Fp::ONE;
            for j in 0..FB_SCALAR_ROWS {
                let mut row_sum = Expression::Constant(Fp::ZERO);
                for k in 0..FB_ROW_BITS {
                    let b = meta.query_advice(bits[k], Rotation((j as i32) + 1));
                    row_sum = row_sum + b * Expression::Constant(Fp::from(1u64 << k));
                }
                sum = sum + row_sum * Expression::Constant(w);
                w *= two16;
            }
            vec![sel * (h - sum)]
        });

        Self {
            bits,
            x,
            y,
            lam,
            iota,
            din,
            fx_x,
            fx_y,
            h_top,
            s_acc,
            s_init,
            s_top,
            instance,
        }
    }

    /// Assign the window multiple coordinates for one accumulation row.
    fn assign_fx(
        &self,
        region: &mut Region<'_, Fp>,
        row: usize,
        multiples: &[(Fp, Fp)],
        bit_base: usize,
    ) -> Result<(), Error> {
        for k in 0..FB_ROW_BITS {
            let (cx, cy) = multiples[bit_base + k];
            region.assign_fixed(
                || format!("fx-x-{}", bit_base + k),
                self.fx_x[k],
                row,
                || Value::known(cx),
            )?;
            region.assign_fixed(
                || format!("fx-y-{}", bit_base + k),
                self.fx_y[k],
                row,
                || Value::known(cy),
            )?;
        }
        Ok(())
    }

    /// Assign one row of bit cells from a plain 32-byte representation
    /// (the blinding scalar path).
    fn assign_bit_row(
        &self,
        region: &mut Region<'_, Fp>,
        row: usize,
        bit_base: usize,
        repr: &[u8; 32],
        corrupt_idx: Option<usize>,
    ) -> Result<(), Error> {
        for k in 0..FB_ROW_BITS {
            let idx = bit_base + k;
            let mut bit = bit_of(repr, idx);
            if corrupt_idx == Some(idx) {
                bit = Fp::ONE - bit;
            }
            region.assign_advice(
                || format!("bit-{}", idx),
                self.bits[k],
                row,
                || Value::known(bit),
            )?;
        }
        Ok(())
    }

    /// Assign the chain cells (lam, iota, din, x[0..=16], y[0..=16]) of one
    /// accumulation row from the host-side witness values.
    fn assign_chain_row(
        &self,
        region: &mut Region<'_, Fp>,
        row: usize,
        row_idx: usize,
        rows_val: &Value<Vec<RowVals>>,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        for k in 0..FB_ROW_BITS {
            region.assign_advice(
                || format!("lam-{}-{}", row_idx, k),
                self.lam[k],
                row,
                || rows_val.clone().map(|rv| rv[row_idx].lam[k]),
            )?;
            region.assign_advice(
                || format!("iota-{}-{}", row_idx, k),
                self.iota[k],
                row,
                || rows_val.clone().map(|rv| rv[row_idx].iota[k]),
            )?;
            region.assign_advice(
                || format!("din-{}-{}", row_idx, k),
                self.din[k],
                row,
                || rows_val.clone().map(|rv| rv[row_idx].din[k]),
            )?;
        }
        let mut x_out = None;
        let mut y_out = None;
        for k in 0..=FB_ROW_BITS {
            let cx = region.assign_advice(
                || format!("acc-x-{}-{}", row_idx, k),
                self.x[k],
                row,
                || rows_val.clone().map(|rv| rv[row_idx].x[k]),
            )?;
            let cy = region.assign_advice(
                || format!("acc-y-{}-{}", row_idx, k),
                self.y[k],
                row,
                || rows_val.clone().map(|rv| rv[row_idx].y[k]),
            )?;
            if k == FB_ROW_BITS {
                x_out = Some(cx);
                y_out = Some(cy);
            }
        }
        Ok((x_out.unwrap(), y_out.unwrap()))
    }
}

// ---------------------------------------------------------------------------
// rc-fixed-base gate [S4 4, S4 8]
// ---------------------------------------------------------------------------

/// Configuration of the rc-fixed-base gate [S4 8]: the rc-limb gate plus
/// the conditional EC addition chain over the SHARED bit columns, so the
/// synthesized `RC` is provably built from the range-checked limbs of `v`
/// and the witnessed bits of `r`. The limb config's own instance column
/// stays unused here (only `RC` is public at this stage).
#[derive(Clone, Debug)]
pub struct V4ValueCommitConfig {
    /// rc-limb gate (range check of `v`).
    pub limb: LimbRangeConfig,
    /// Fixed-base EC addition chain.
    pub fb: FbConfig,
}

impl V4ValueCommitConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let limb = LimbRangeConfig::configure(meta);
        let fb = FbConfig::configure(meta, limb.bits);
        Self { limb, fb }
    }

    /// Assign the whole rc-fixed-base region [S4 8]:
    ///
    /// - rows 0..=4: the rc-limb gate (range check of `v`); its bit cells
    ///   double as the accumulation bits of the value blocks (witness
    ///   sharing [S4 8]);
    /// - row 0: the accumulators start at the encoded identity `(0, 0)`;
    /// - rows 1..20: the conditional EC addition chain - rows 1..=4 add
    ///   `[v] * V` from the limb witnesses, rows 5..20 add `[r] * R` from
    ///   the witnessed blinding bits;
    /// - the outgoing accumulator cells of row 20 ARE the encoded `RC`.
    pub fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        v: Value<u64>,
        r: Fq,
        corrupt: bool,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        // Rows 0..=4: rc-limb gate over the shared bit columns.
        self.limb.assign(region, v, false)?;

        let repr = r.to_repr();
        let mults_v = fb_multiples(value_gen());
        let mults_r = fb_multiples(blind_gen());
        let corrupt_idx = if corrupt { Some(FB_CORRUPT_BIT) } else { None };

        // The whole chain is computed on concrete values inside one
        // Value::map lift: the v-part bits depend on the witnessed `v`,
        // the r-part on the concrete blinding representation.
        let rows_val: Value<Vec<RowVals>> = v.map(|v0| {
            let mut bits_rows: Vec<[Fp; FB_ROW_BITS]> = Vec::with_capacity(VALUE_ACC_ROWS);
            let mut mults_rows: Vec<[(Fp, Fp); FB_ROW_BITS]> = Vec::with_capacity(VALUE_ACC_ROWS);
            for j in 0..N_LIMBS {
                let mut bits = [Fp::ZERO; FB_ROW_BITS];
                let mut mults = [(Fp::ZERO, Fp::ZERO); FB_ROW_BITS];
                for k in 0..FB_ROW_BITS {
                    bits[k] = Fp::from((v0 >> (LIMB_BITS * j + k)) & 1);
                    mults[k] = mults_v[LIMB_BITS * j + k];
                }
                bits_rows.push(bits);
                mults_rows.push(mults);
            }
            for j in 0..FB_SCALAR_ROWS {
                let mut bits = [Fp::ZERO; FB_ROW_BITS];
                let mut mults = [(Fp::ZERO, Fp::ZERO); FB_ROW_BITS];
                for k in 0..FB_ROW_BITS {
                    let idx = FB_ROW_BITS * j + k;
                    let mut b = bit_of(&repr, idx);
                    if corrupt_idx == Some(idx) {
                        b = Fp::ONE - b;
                    }
                    bits[k] = b;
                    mults[k] = mults_r[idx];
                }
                bits_rows.push(bits);
                mults_rows.push(mults);
            }
            chain_rows(&bits_rows, &mults_rows)
        });

        // Row 0: accumulators start at the encoded identity.
        region.assign_advice(
            || "acc-x-init",
            self.fb.x[FB_ROW_BITS],
            0,
            || Value::known(Fp::ZERO),
        )?;
        region.assign_advice(
            || "acc-y-init",
            self.fb.y[FB_ROW_BITS],
            0,
            || Value::known(Fp::ZERO),
        )?;
        self.fb.s_init.enable(region, 0)?;

        let mut x_out = None;
        let mut y_out = None;
        for j in 0..VALUE_ACC_ROWS {
            let row = 1 + j;
            let bit_base = if j < N_LIMBS {
                LIMB_BITS * j
            } else {
                FB_ROW_BITS * (j - N_LIMBS)
            };
            if j >= N_LIMBS {
                self.fb
                    .assign_bit_row(region, row, bit_base, &repr, corrupt_idx)?;
            }
            let multiples: &[(Fp, Fp)] = if j < N_LIMBS { &mults_v } else { &mults_r };
            self.fb.assign_fx(region, row, multiples, bit_base)?;
            let (cx, cy) = self.fb.assign_chain_row(region, row, j, &rows_val)?;
            self.fb.s_acc.enable(region, row)?;
            x_out = Some(cx);
            y_out = Some(cy);
        }

        // The outgoing cells of the last accumulation row are RC.
        Ok((x_out.unwrap(), y_out.unwrap()))
    }
}

/// Test circuit for the rc-fixed-base gate [S4 4, S4 8]: synthesizes
/// `RC = v * V + r * R` from the limb witnesses and the blinding bits and
/// exposes `(RC.x, RC.y)` as public instances (2 slots per encoded point
/// [S4 8]). The host-side counterpart is [`crate::v4::value_commit`]; the
/// tests cross-check both.
#[derive(Clone, Debug)]
pub struct V4ValueCommitCircuit {
    /// Spent or created amount, 0 <= v < 2^64 (range-checked by the limb gate).
    pub v: Value<u64>,
    /// Value-commitment blinding (host data; the in-circuit witness is its
    /// 255-bit decomposition).
    pub r: Fq,
    /// Flip one witnessed blinding bit (negative tests only).
    pub corrupt: bool,
}

impl Circuit<Fp> for V4ValueCommitCircuit {
    type Config = V4ValueCommitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            v: Value::unknown(),
            r: Fq::ZERO,
            corrupt: self.corrupt,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        V4ValueCommitConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let (x_cell, y_cell) = layouter.assign_region(
            || "rc-fixed-base",
            |mut region| config.assign(&mut region, self.v, self.r, self.corrupt),
        )?;
        layouter.constrain_instance(x_cell.cell(), config.fb.instance, 0)?;
        layouter.constrain_instance(y_cell.cell(), config.fb.instance, 1)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// leaf-v2 G3 term [S4 3, S4 8]
// ---------------------------------------------------------------------------

/// Configuration of the leaf-v2 G3-term gate: the Phase 1a v4-hash
/// permutation produces `H_leaf`, the fixed-base EC addition chain
/// computes `term = [H_leaf] * G3`.
#[derive(Clone, Debug)]
pub struct V4LeafTermConfig {
    /// v4-hash permutation (Phase 1a).
    pub hash: V4HashConfig,
    /// Fixed-base accumulation (base G3).
    pub fb: FbConfig,
}

impl V4LeafTermConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let hash = V4HashConfig::configure(meta);
        let bits: [Column<Advice>; FB_ROW_BITS] = std::array::from_fn(|_| meta.advice_column());
        let fb = FbConfig::configure(meta, bits);
        Self { hash, fb }
    }

    /// Assign the fixed-base region for `term = [H_leaf] * G3` [S4 3, S4 8]:
    /// row 0 carries the copy of `H_leaf` and the identity accumulators,
    /// rows 1..=16 witness the 255 bits of `H_leaf` and accumulate, the
    /// outgoing accumulator cells of row 16 are the encoded term.
    fn assign_term(
        &self,
        region: &mut Region<'_, Fp>,
        h: AssignedCell<Fp, Fp>,
        corrupt: bool,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        let h_val = h.value().cloned();

        h.copy_advice(|| "h-top", region, self.fb.h_top, 0)?;
        region.assign_advice(
            || "acc-x-init",
            self.fb.x[FB_ROW_BITS],
            0,
            || Value::known(Fp::ZERO),
        )?;
        region.assign_advice(
            || "acc-y-init",
            self.fb.y[FB_ROW_BITS],
            0,
            || Value::known(Fp::ZERO),
        )?;
        self.fb.s_init.enable(region, 0)?;
        self.fb.s_top.enable(region, 0)?;

        let multiples = fb_multiples(leaf_gen());
        let corrupt_idx = if corrupt { Some(FB_CORRUPT_BIT) } else { None };

        let rows_val: Value<Vec<RowVals>> = h_val.map(|h0| {
            let repr = h0.to_repr();
            let mut bits_rows: Vec<[Fp; FB_ROW_BITS]> = Vec::with_capacity(FB_SCALAR_ROWS);
            let mut mults_rows: Vec<[(Fp, Fp); FB_ROW_BITS]> = Vec::with_capacity(FB_SCALAR_ROWS);
            for j in 0..FB_SCALAR_ROWS {
                let mut bits = [Fp::ZERO; FB_ROW_BITS];
                let mut mults = [(Fp::ZERO, Fp::ZERO); FB_ROW_BITS];
                for k in 0..FB_ROW_BITS {
                    let idx = FB_ROW_BITS * j + k;
                    let mut b = bit_of(&repr, idx);
                    if corrupt_idx == Some(idx) {
                        b = Fp::ONE - b;
                    }
                    bits[k] = b;
                    mults[k] = multiples[idx];
                }
                bits_rows.push(bits);
                mults_rows.push(mults);
            }
            chain_rows(&bits_rows, &mults_rows)
        });

        let mut x_out = None;
        let mut y_out = None;
        for j in 0..FB_SCALAR_ROWS {
            let row = 1 + j;
            let bit_base = FB_ROW_BITS * j;
            self.fb.assign_fx(region, row, &multiples, bit_base)?;
            for k in 0..FB_ROW_BITS {
                let idx = bit_base + k;
                region.assign_advice(
                    || format!("hbit-{}", idx),
                    self.fb.bits[k],
                    row,
                    || {
                        let mut b = h_val.map(|h0| bit_of(&h0.to_repr(), idx));
                        if corrupt_idx == Some(idx) {
                            b = b.map(|x| Fp::ONE - x);
                        }
                        b
                    },
                )?;
            }
            let (cx, cy) = self.fb.assign_chain_row(region, row, j, &rows_val)?;
            self.fb.s_acc.enable(region, row)?;
            x_out = Some(cx);
            y_out = Some(cy);
        }

        Ok((x_out.unwrap(), y_out.unwrap()))
    }
}

/// Test circuit for the leaf-v2 G3-term gate [S4 3, S4 8]: computes
/// `H_leaf = Poseidon_3(v, rho, DOM_LEAF_V2)` with the Phase 1a hash gate
/// and `term = [H_leaf] * G3` with the fixed-base chain; exposes
/// `[H_leaf, term.x, term.y]` as public instances. The host-side
/// counterpart is `leaf_gen() * fq_reduce_fp(h_leaf_v2(v, rho))`.
#[derive(Clone, Debug)]
pub struct V4LeafTermCircuit {
    pub v: Value<u64>,
    pub rho: Value<Fp>,
    pub corrupt: bool,
}

impl Circuit<Fp> for V4LeafTermCircuit {
    type Config = V4LeafTermConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            v: Value::unknown(),
            rho: Value::unknown(),
            corrupt: self.corrupt,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        V4LeafTermConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let h_cell = layouter.assign_region(
            || "leaf-v2-hash",
            |mut region| {
                let v_cell = region.assign_advice(
                    || "v",
                    config.hash.absorb[0],
                    0,
                    || self.v.map(Fp::from),
                )?;
                let rho_cell =
                    region.assign_advice(|| "rho", config.hash.absorb[1], 0, || self.rho)?;
                config
                    .hash
                    .perm_cells(&mut region, 1, dom_leaf_v2(), v_cell, rho_cell)
            },
        )?;
        // AssignedCell is not Copy and assign_region takes FnMut, so the
        // captured cell must be cloned, not moved (E0507/E0382 otherwise).
        let (x_cell, y_cell) = layouter.assign_region(
            || "leaf-v2-term",
            |mut region| config.assign_term(&mut region, h_cell.clone(), self.corrupt),
        )?;
        layouter.constrain_instance(h_cell.cell(), config.hash.instance, 0)?;
        layouter.constrain_instance(x_cell.cell(), config.fb.instance, 0)?;
        layouter.constrain_instance(y_cell.cell(), config.fb.instance, 1)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::{fq_reduce_fp, h_leaf_v2, value_commit};
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    /// Row budget from [S4 8]: the v4 design MUST stay within k = 13.
    const K_BUDGET_ROWS: usize = 1 << 13;

    fn coords(p: &pallas::Point) -> (Fp, Fp) {
        let aff = p.to_affine();
        let c = aff.coordinates().unwrap();
        (*c.x(), *c.y())
    }

    #[test]
    fn fb_multiples_match_point_arithmetic() {
        let multiples = fb_multiples(value_gen());
        assert_eq!(multiples.len(), FB_MULTIPLES);
        // multiples[0] is the base itself...
        assert_eq!(multiples[0], coords(&value_gen()));
        // ...and multiples[i + 1] is the double of multiples[i].
        let mut acc = value_gen();
        for i in 0..8 {
            acc = acc + acc;
            assert_eq!(multiples[i + 1], coords(&acc));
        }
        // Deterministic across calls.
        assert_eq!(fb_multiples(leaf_gen()), fb_multiples(leaf_gen()));
        // Distinct hashgen bases give distinct tables [S4 2].
        assert_ne!(fb_multiples(value_gen())[1], fb_multiples(blind_gen())[1]);
    }

    #[test]
    fn rc_fixed_base_gate_matches_host() {
        let vg = value_gen();
        let rg = blind_gen();
        let cases: Vec<(u64, Fq)> = vec![
            (1, Fq::from(7u64)),
            (0xFFFFFFFFFFFFFFFFu64, Fq::from(0x1234_5678_9ABC_DEF0u64)),
            (123456789, Fq::random(OsRng)),
            (0, Fq::random(OsRng)),
        ];
        for (v, r) in cases {
            let circuit = V4ValueCommitCircuit {
                v: Value::known(v),
                r,
                corrupt: false,
            };
            let (x, y) = coords(&value_commit(v, r, &vg, &rg));
            let prover = MockProver::run(8, &circuit, vec![vec![], vec![x, y]]).unwrap();
            prover.verify().unwrap();
        }
        const _: () = assert!(VALUE_COMMIT_ROWS < K_BUDGET_ROWS);
    }

    #[test]
    fn rc_fixed_base_gate_handles_zero_commitment() {
        // v = 0 and r = 0 synthesize the identity, encoded as (0, 0) in the
        // gate's coordinate convention; canonical point encodings are a
        // consensus concern [S4 11], settled in Phase 2/4.
        let circuit = V4ValueCommitCircuit {
            v: Value::known(0),
            r: Fq::ZERO,
            corrupt: false,
        };
        let prover = MockProver::run(8, &circuit, vec![vec![], vec![Fp::ZERO, Fp::ZERO]]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn rc_fixed_base_gate_rejects_lies() {
        let vg = value_gen();
        let rg = blind_gen();
        let v = 123456789u64;
        let r = Fq::from(0xDEAD_BEEF_CAFE_F00Du64);
        let (hx, hy) = coords(&value_commit(v, r, &vg, &rg));

        // A flipped blinding bit breaks the accumulation against the
        // honest published RC.
        let circuit = V4ValueCommitCircuit {
            v: Value::known(v),
            r,
            corrupt: true,
        };
        let prover = MockProver::run(8, &circuit, vec![vec![], vec![hx, hy]]).unwrap();
        assert!(prover.verify().is_err());

        // A published RC derived from a different blinding must fail [S4 4].
        let (ox, oy) = coords(&value_commit(v, r + Fq::ONE, &vg, &rg));
        let circuit = V4ValueCommitCircuit {
            v: Value::known(v),
            r,
            corrupt: false,
        };
        let prover = MockProver::run(8, &circuit, vec![vec![], vec![ox, oy]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn leaf_v2_term_gate_matches_host() {
        let v = 4242u64;
        let rho = Fp::random(OsRng);
        let h = h_leaf_v2(v, rho);
        let expected = leaf_gen() * fq_reduce_fp(h);
        let (tx, ty) = coords(&expected);

        let circuit = V4LeafTermCircuit {
            v: Value::known(v),
            rho: Value::known(rho),
            corrupt: false,
        };
        let prover = MockProver::run(9, &circuit, vec![vec![h], vec![tx, ty]]).unwrap();
        prover.verify().unwrap();
        const _: () = assert!(LEAF_TERM_ROWS < K_BUDGET_ROWS);
    }

    #[test]
    fn leaf_v2_term_gate_rejects_lies() {
        let v = 99u64;
        let rho = Fp::from(0x0F0F_0F0F_0F0F_0F0Fu64);
        let h = h_leaf_v2(v, rho);
        let (tx, ty) = coords(&(leaf_gen() * fq_reduce_fp(h)));

        // A flipped decomposition bit breaks the reconstructed term.
        let circuit = V4LeafTermCircuit {
            v: Value::known(v),
            rho: Value::known(rho),
            corrupt: true,
        };
        let prover = MockProver::run(9, &circuit, vec![vec![h], vec![tx, ty]]).unwrap();
        assert!(prover.verify().is_err());

        // A published H_leaf of a different note must fail [S4 3].
        let wrong_h = h_leaf_v2(v, rho + Fp::ONE);
        let circuit = V4LeafTermCircuit {
            v: Value::known(v),
            rho: Value::known(rho),
            corrupt: false,
        };
        let prover = MockProver::run(9, &circuit, vec![vec![wrong_h], vec![tx, ty]]).unwrap();
        assert!(prover.verify().is_err());
    }
}
