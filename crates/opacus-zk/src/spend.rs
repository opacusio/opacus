//! GHOST v0.4 Phase 2: the full v4 spend circuit.
//!
//! Assembles the Phase 1a/1b gates into the single-proof v4 spend of the
//! specification (`docs/specs/v0.4-value-conservation.md`, referenced below
//! as [S4]), per [S4 8] "Circuit layout":
//!
//! - **membership** [S4 1 P1, S4 3]: for every spent note the circuit
//!   reconstructs the accumulator leaf v2 from the witnesses
//!   `(D, a, b, rho, v)`, converts it to the tree entry (below) and walks
//!   the commutative Poseidon tree (`tree-add`/`tree-mul`, v0.3.0 style) up
//!   to the public root.
//! - **nullifier** [S4 1 P2, S4 5]: `nk = Poseidon_3(a, b, DOM_NK)` and
//!   `N = Poseidon_3(nk, rho, DOM_NU)` are derived in-circuit from the SAME
//!   `(a, b, rho)` witnesses that feed the membership statement.
//! - **value commitments** [S4 1 P3, S4 4, S4 8]: for every input and
//!   output value the rc-limb gate range-checks `v` and the rc-fixed-base
//!   chain synthesizes `RC = v * V + r * R` from the shared limb witnesses
//!   plus the witnessed bits of `r`; the affine coordinates of every RC are
//!   public instances.
//! - **leaf-v2 gate** [S4 3, S4 8]: `H_leaf = Poseidon_3(v, rho,
//!   DOM_LEAF_V2)` and the G3 term of the leaf are folded into the
//!   membership path (Phase 1b machinery, multi-base form).
//!
//! # The v4 accumulator tree entry (Phase 2 convention)
//!
//! The tree machinery of v0.3.0 (`crate::merkle`, `tree-add`/`tree-mul`
//! gates) hashes `Fp` elements: `node' = H_tree(node + sib, node * sib)`.
//! The v0.4 leaf is the Pallas POINT `L = P(D, a+b, a*b) + H_leaf * G3`
//! [S4 3]. This module fixes the normative Phase 2 convention:
//!
//! ```text
//!   tree_entry(L) = Poseidon_3(L.x, L.y, DOM_ACC)
//! ```
//!
//! with `DOM_ACC = blake3("GHOST/v4/dom/acc")` reduced into `Fp` (the
//! [S4 2] domain pattern; pinned test vector below). `tree_entry` is a
//! public function of the point alone, so consensus can maintain the
//! frontier over `tree_entry(L_j)` while publishing `L_j` [S4 3, S4 9],
//! and the circuit reconstructs `(L.x, L.y)` in-circuit.
//!
//! The circuit computes the leaf point as ONE multi-base fixed-base chain
//! (the Phase 1b rc-fixed-base machinery, generalized): rows 1..16
//! accumulate `[s] * G` from the witnessed bits of
//! `s = Poseidon_3(a+b, a*b, D)` (the key part `[s] * G` of `P(D, a+b,
//! a*b)`), rows 17..32 accumulate `[h] * G3` from the witnessed bits of
//! `h = H_leaf`. The outgoing accumulator of row 32 is `L = [s] * G +
//! [h] * G3`. Two `fb-top` gates tie each bit block to its scalar cell
//! (`s_cell`, `H_leaf`), so the membership entry provably binds
//! `(D, a+b, a*b)` via the nullifier chain and `(v, rho)` via the leaf
//! hash chain - the same witnesses [S4 5].
//!
//! # Public instances (order normative [S4 8])
//!
//! ```text
//!   slot 0                 acc_root
//!   slots 1..=MAX_IN       N_i                (padded inputs: 0)
//!   next MAX_IN * 2        RC_in_i (x, y)     (padded inputs: (0, 0))
//!   next MAX_OUT * 2       RC_out_j (x, y)    (padded outputs: (0, 0))
//! ```
//!
//! MAX_IN = 2, MAX_OUT = 4, so the instance column is exactly 15 slots.
//! The `(0, 0)` padding is the encoded identity of the Phase 1b fixed-base
//! gates; the verifier-side homomorphic balance [S4 6] treats padded RCs
//! as the identity and still checks
//! `sum(RC_in) - sum(RC_out) - fee * V = O`.
//!
//! # Balance and the binding signature (host side [S4 6])
//!
//! Conservation is enforced OUTSIDE the circuit by the verifier over the
//! public points (`bvk`) plus the Schnorr binding signature over the base
//! `R` with key `bsk = sum(r_in) - sum(r_out)`: an unbalanced transaction
//! yields `bvk = d * V + bsk * R` with `d != 0`, and signing it requires
//! the unknown `dlog_R(V)` [S4 2, S4 6, S4 11]. The circuit's job is to
//! make every RC a function of the range-checked witnesses only.
//!
//! # Row budget
//!
//! The full MAX topology at mainnet depth (2^32 leaves, DEPTH = 32) uses
//! `rows_needed(32) = 5103` rows, well inside the k = 13 budget of [S4 8]
//! (8192 rows). The wallet topology (1-in / 2-out) at DEPTH = 4 (tests)
//! fits k = 11.

use ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::{Curve, Group, GroupEncoding};
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::{pallas, Fp, Fq};

use crate::poseidon::{self, poseidon_absorb, ROUNDS};
use crate::v4::{
    blind_gen, dom_leaf_v2, dom_nk, dom_nu, h_leaf_v2, leaf_gen, leaf_v2, value_gen, LIMB_BITS,
    N_LIMBS,
};

// ---------------------------------------------------------------------------
// Constants [S4 8]
// ---------------------------------------------------------------------------

/// Maximum number of spent notes per transaction [S4 7, S4 8].
pub const MAX_IN: usize = 2;
/// Maximum number of created notes per transaction [S4 7, S4 8].
pub const MAX_OUT: usize = 4;

/// Rows consumed by one Poseidon permutation (64 round rows + final row).
pub const PERM_ROWS: usize = ROUNDS + 1;
/// Rows of one value region: rc-limb (5 rows) + fixed-base RC chain.
pub const VALUE_REGION_ROWS: usize = 1 + N_LIMBS + 2 * 16;
/// Rows of the leaf chain: init row + 16 rows for `[s] * G` + 16 rows for
/// `[h] * G3`.
pub const LEAF_CHAIN_ROWS: usize = 1 + 2 * 16;
/// Instance slots of the normative v4 spend instance vector [S4 8].
pub const SPEND_INSTANCE_SLOTS: usize = 1 + MAX_IN + 2 * MAX_IN + 2 * MAX_OUT;

// ---------------------------------------------------------------------------
// v0.4 domain constant for the accumulator tree entry [S4 2]
// ---------------------------------------------------------------------------

/// Reduce the first 16 bytes of a blake3 digest into `Fp` (the
/// `poseidon::fp_from_16` convention; private copy of the v4 helper).
fn fp_from_label(label: &[u8]) -> Fp {
    let d = blake3::hash(label);
    let b = d.as_bytes();
    let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let two64 = Fp::from(u64::MAX) + Fp::ONE;
    Fp::from(hi) * two64 + Fp::from(lo)
}

/// Reduce a 32-byte digest into `Fq` as a little-endian 256-bit integer
/// (private copy of the v4 helper; used by the binding signature).
fn fq_from_32(b: &[u8; 32]) -> Fq {
    let limb = |s: usize| u64::from_le_bytes(b[s..s + 8].try_into().unwrap());
    let two64 = Fq::from(u64::MAX) + Fq::ONE;
    let mut acc = Fq::from(limb(24));
    acc = acc * two64 + Fq::from(limb(16));
    acc = acc * two64 + Fq::from(limb(8));
    acc * two64 + Fq::from(limb(0))
}

/// Domain constant of the accumulator tree entry (this module's Phase 2
/// convention, see the module docs).
pub fn dom_acc() -> Fp {
    fp_from_label(b"GHOST/v4/dom/acc")
}

/// Affine coordinates of a Pallas point (the Phase 1b `coords` helper).
pub fn coords(p: &pallas::Point) -> (Fp, Fp) {
    let aff = p.to_affine();
    let c = aff.coordinates().unwrap();
    (*c.x(), *c.y())
}

/// The v4 accumulator tree entry of a leaf point (Phase 2 convention):
/// `tree_entry(L) = Poseidon_3(L.x, L.y, DOM_ACC)`.
///
/// Consensus-side this is computable from the published leaf alone, so the
/// frontier stays an `Fp` Merkle tree over entries while the transaction
/// carries the points [S4 3, S4 9].
pub fn tree_rep(l: &pallas::Point) -> Fp {
    let (x, y) = coords(l);
    poseidon_absorb(dom_acc(), x, y)[0]
}

/// Tree entry of the accumulator leaf v2:
/// `tree_entry(leaf_v2(D, a, b, v, rho))`.
pub fn leaf_entry_v2(d: Fp, a: Fp, b: Fp, v: u64, rho: Fp) -> Fp {
    tree_rep(&leaf_v2(d, a, b, v, rho))
}

// ---------------------------------------------------------------------------
// Sighash and the binding signature [S4 6, S4 7]
// ---------------------------------------------------------------------------

/// Transaction sighash [S4 7]:
/// `S = blake3("GHOST/v4/sighash", le64(version = 4), acc_root, N_1..N_n,
/// L_1..L_m, RC_in_1..RC_in_n, RC_out_1..RC_out_m, le64(fee))`.
///
/// Points are compressed (`GroupEncoding::to_bytes`), field elements are
/// canonical little-endian (`to_repr`). Every serialized field consumed by
/// verification is covered [S4 7, S4 11].
pub fn sighash_v4(
    root: &pallas::Point,
    ns: &[Fp],
    leaves: &[pallas::Point],
    rc_in: &[pallas::Point],
    rc_out: &[pallas::Point],
    fee: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"GHOST/v4/sighash");
    h.update(&4u64.to_le_bytes());
    h.update(root.to_affine().to_bytes().as_ref());
    for n in ns {
        h.update(n.to_repr().as_ref());
    }
    for l in leaves {
        h.update(l.to_affine().to_bytes().as_ref());
    }
    for rc in rc_in {
        h.update(rc.to_affine().to_bytes().as_ref());
    }
    for rc in rc_out {
        h.update(rc.to_affine().to_bytes().as_ref());
    }
    h.update(&fee.to_le_bytes());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

/// Wallet-side balance check [S4 6]: with the signer's own blinding sum
/// `bsk = sum(r_in) - sum(r_out)`, an honest transaction satisfies
/// `bvk = bsk * R`. The VERIFIER-side check is the binding signature
/// alone (`verify_bind`): it succeeds only when the signer knows the
/// discrete logarithm of `bvk` with respect to `R`, which requires
/// `sum(v_in) - sum(v_out) - fee = d = 0` because `dlog_R(V)` is unknown
/// [S4 2, S4 6, S4 11].
pub fn balance_holds(rc_in: &[pallas::Point], rc_out: &[pallas::Point], fee: u64, bsk: Fq) -> bool {
    binding_vk(rc_in, rc_out, fee) == blind_gen() * bsk
}

/// Binding signing key [S4 6]: `bsk = sum(r_in) - sum(r_out) (mod order)`.
pub fn binding_sk(r_in: &[Fq], r_out: &[Fq]) -> Fq {
    let mut acc = Fq::ZERO;
    for r in r_in {
        acc += r;
    }
    for r in r_out {
        acc -= r;
    }
    acc
}

/// Binding verification key [S4 6]:
/// `bvk = sum(RC_in) - sum(RC_out) - fee * V`.
pub fn binding_vk(rc_in: &[pallas::Point], rc_out: &[pallas::Point], fee: u64) -> pallas::Point {
    let mut acc = pallas::Point::identity();
    for rc in rc_in {
        acc += rc;
    }
    for rc in rc_out {
        acc -= rc;
    }
    acc - value_gen() * Fq::from(fee)
}

/// Fiat-Shamir challenge of the binding signature:
/// `e = H("GHOST/v4/bind", S, bvk)` reduced into `Fq` [S4 6].
fn bind_challenge(s: &[u8; 32], bvk: &pallas::Point) -> Fq {
    let mut h = blake3::Hasher::new();
    h.update(b"GHOST/v4/bind");
    h.update(s);
    h.update(bvk.to_affine().to_bytes().as_ref());
    fq_from_32(h.finalize().as_bytes())
}

/// Binding signature [S4 6]: 64-byte Schnorr over the base `R` with
/// public key `bvk`. Encoding: `A = [rx] R` (compressed, 32 bytes) followed
/// by `z = rx + e * bsk` (canonical little-endian, 32 bytes). The nonce is
/// derived deterministically (blake3 over the key, sighash and bvk);
/// production wallets SHOULD re-derive it with hedged randomness, which
/// does not change the verification equation.
pub fn sign_bind(s: &[u8; 32], bsk: Fq, bvk: &pallas::Point) -> [u8; 64] {
    let r_gen = blind_gen();
    let mut h = blake3::Hasher::new();
    h.update(b"GHOST/v4/bind/nonce");
    h.update(bsk.to_repr().as_ref());
    h.update(s);
    h.update(bvk.to_affine().to_bytes().as_ref());
    let rx = fq_from_32(h.finalize().as_bytes());
    let e = bind_challenge(s, bvk);
    let a = r_gen * rx;
    let z = rx + e * bsk;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(a.to_affine().to_bytes().as_ref());
    sig[32..].copy_from_slice(z.to_repr().as_ref());
    sig
}

/// Verify a binding signature under `bvk` over the sighash `S` [S4 6]:
/// `z * R = A + e * bvk`. Returns false on any non-canonical encoding.
pub fn verify_bind(s: &[u8; 32], bvk: &pallas::Point, sig: &[u8; 64]) -> bool {
    let r_gen = blind_gen();
    let e = bind_challenge(s, bvk);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&sig[..32]);
    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&sig[32..]);
    let a = match <pallas::Affine as GroupEncoding>::from_bytes(&a_bytes).into_option() {
        Some(a) => a.to_curve(),
        None => return false,
    };
    let z = match Fq::from_repr(z_bytes).into_option() {
        Some(z) => z,
        None => return false,
    };
    r_gen * z == a + bvk * e
}

// ---------------------------------------------------------------------------
// Host-side EC addition chain (Phase 1b helpers, multi-base form) [S4 8]
// ---------------------------------------------------------------------------

/// Bit `idx` (little-endian) of a 32-byte field representation. Index 255
/// and beyond is a forced zero: both Pasta field primes are below 2^255.
fn bit_of(repr: &[u8; 32], idx: usize) -> Fp {
    if idx < 255 {
        Fp::from(((repr[idx / 8] >> (idx % 8)) & 1) as u64)
    } else {
        Fp::ZERO
    }
}

/// One conditional EC addition of the accumulator with a fixed window
/// multiple `w` (Phase 1b `ec_step`).
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

/// Witness values of one accumulation row (Phase 1b `RowVals`).
struct RowVals {
    lam: [Fp; 16],
    iota: [Fp; 16],
    din: [Fp; 16],
    x: [Fp; 17],
    y: [Fp; 17],
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

/// Runs the conditional EC addition chain row by row (Phase 1b
/// `chain_rows`): `bits_rows[j][k]` is the witnessed bit `16*j + k`;
/// `mults_rows[j][k]` is the window multiple `[2^(16*j + k)] * B_j` (the
/// base MAY differ per row block). The chain starts at the encoded
/// identity.
fn chain_rows(bits_rows: &[[Fp; 16]], mults_rows: &[[(Fp, Fp); 16]]) -> Vec<RowVals> {
    let mut acc = (Fp::ZERO, Fp::ZERO);
    let mut out = Vec::with_capacity(bits_rows.len());
    for (bits, mults) in bits_rows.iter().zip(mults_rows.iter()) {
        let mut rv = RowVals {
            lam: [Fp::ZERO; 16],
            iota: [Fp::ZERO; 16],
            din: [Fp::ZERO; 16],
            x: [Fp::ZERO; 17],
            y: [Fp::ZERO; 17],
        };
        rv.x[0] = acc.0;
        rv.y[0] = acc.1;
        for k in 0..16 {
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
// SpendHashConfig: Poseidon permutations with optional witness domain
// ---------------------------------------------------------------------------

/// Configuration of the spend Poseidon gadget: the v0.3.0/Phase 1a round
/// gate generalized so that the CAPACITY input at round 0 is either a
/// fixed protocol domain constant (nullifier, leaf, tree, entry chains)
/// or a witnessed diversifier cell `D` (the key chain `s = P(D, a+b,
/// a*b)` [S4 3]). A witness domain cannot live in the fixed `domain`
/// column (fixed cells are part of the verification key), so the witness
/// variant feeds a dedicated advice column that the masking constraints
/// force to zero outside round 0 - mirroring the absorb-input masking of
/// the v0.3.0 gate.
#[derive(Clone, Debug)]
pub struct SpendHashConfig {
    /// Poseidon state columns [s0, s1, s2].
    pub state: [Column<Advice>; 3],
    /// Absorb input columns [in0, in1].
    pub absorb: [Column<Advice>; 2],
    /// Witness domain cell (round 0 only; zero in fixed-domain mode).
    pub dom_in: Column<Advice>,
    /// Round-constant columns.
    pub rc: [Column<Fixed>; 3],
    /// Fixed protocol domain (capacity) constant.
    pub domain: Column<Fixed>,
    /// Absorb flag (1 at round 0, 0 elsewhere).
    pub is_absorb: Column<Fixed>,
    /// Poseidon round gate.
    pub s_round: Selector,
    /// Initial-state-is-zero gate.
    pub s_init: Selector,
}

impl SpendHashConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let absorb = [meta.advice_column(), meta.advice_column()];
        let dom_in = meta.advice_column();
        let rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let domain = meta.fixed_column();
        let is_absorb = meta.fixed_column();
        let s_round = meta.selector();
        let s_init = meta.selector();

        for c in state.iter().chain(absorb.iter()) {
            meta.enable_equality(*c);
        }
        meta.enable_equality(dom_in);

        // Poseidon round transition with fused absorb + input masking,
        // generalized for the witness domain (identical algebra to the
        // v0.3.0 gate otherwise).
        meta.create_gate("spend-poseidon-round", |meta| {
            let sel = meta.query_selector(s_round);
            let s0 = meta.query_advice(state[0], Rotation::cur());
            let s1 = meta.query_advice(state[1], Rotation::cur());
            let s2 = meta.query_advice(state[2], Rotation::cur());
            let in0 = meta.query_advice(absorb[0], Rotation::cur());
            let in1 = meta.query_advice(absorb[1], Rotation::cur());
            let din = meta.query_advice(dom_in, Rotation::cur());
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
            let u2 = s2 + dom + din.clone() + rc2;

            let fiv = |x: Expression<Fp>| {
                let a = x.clone();
                let b = a.clone() * a;
                b.clone() * b * x // x^5
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
            let mask1 = in1 * (one.clone() - flag.clone());
            let maskd = din * (one - flag);

            vec![
                sel.clone() * (n0 - o0),
                sel.clone() * (n1 - o1),
                sel.clone() * (n2 - o2),
                sel.clone() * mask0,
                sel.clone() * mask1,
                sel * maskd,
            ]
        });

        // Initial state must be zero; the domain enters through the fixed
        // `domain` column and/or the masked witness cell.
        meta.create_gate("spend-poseidon-init", |meta| {
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
            dom_in,
            rc,
            domain,
            is_absorb,
            s_round,
            s_init,
        }
    }

    /// Assign one full permutation starting at `base` and return the
    /// squeezed output cell. `domain` is the fixed protocol constant
    /// (ignored when `dom_cell` is given); `dom_cell` is the witnessed
    /// diversifier cell of the key chain.
    #[allow(clippy::too_many_arguments)]
    pub fn perm_cells(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        domain: Fp,
        dom_cell: Option<&AssignedCell<Fp, Fp>>,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let rcs = poseidon::round_constants();
        let zero = || Value::known(Fp::ZERO);
        let in0v = a.value().cloned();
        let in1v = b.value().cloned();
        // Fixed-domain mode: the domain rides the FIXED column only and
        // the witness cell stays zero (otherwise the domain would enter
        // the capacity slot twice). Witness-domain mode: the opposite.
        let (domv, fd) = match dom_cell {
            Some(c) => (c.value().cloned(), Fp::ZERO),
            None => (Value::known(Fp::ZERO), domain),
        };
        a.copy_advice(|| "spend-in0", region, self.absorb[0], base)?;
        b.copy_advice(|| "spend-in1", region, self.absorb[1], base)?;

        let mut s = [zero(), zero(), zero()];
        for r in 0..ROUNDS {
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
            let dv = if r == 0 { domv } else { zero() };
            region.assign_advice(|| "in0", self.absorb[0], base + r, || iv0)?;
            region.assign_advice(|| "in1", self.absorb[1], base + r, || iv1)?;
            region.assign_advice(|| "dom-in", self.dom_in, base + r, || dv)?;
            region.assign_fixed(|| "rc0", self.rc[0], base + r, || Value::known(rcs[r][0]))?;
            region.assign_fixed(|| "rc1", self.rc[1], base + r, || Value::known(rcs[r][1]))?;
            region.assign_fixed(|| "rc2", self.rc[2], base + r, || Value::known(rcs[r][2]))?;
            let dom = if r == 0 { fd } else { Fp::ZERO };
            let flag = if r == 0 { Fp::ONE } else { Fp::ZERO };
            region.assign_fixed(|| "domain", self.domain, base + r, || Value::known(dom))?;
            region.assign_fixed(|| "absorb", self.is_absorb, base + r, || Value::known(flag))?;
            self.s_round.enable(region, base + r)?;

            // Honest simulation of the next state (mirrors the gate).
            let rc0 = Value::known(rcs[r][0]);
            let rc1 = Value::known(rcs[r][1]);
            let rc2 = Value::known(rcs[r][2]);
            let u0 = s[0] + iv0 + rc0;
            let u1 = s[1] + iv1 + rc1;
            let u2 = s[2] + dv + Value::known(dom) + rc2;
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

        let fr = base + ROUNDS;
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
        region.assign_advice(|| "dom-in", self.dom_in, fr, zero)?;
        region.assign_fixed(|| "rc0", self.rc[0], fr, zero)?;
        region.assign_fixed(|| "rc1", self.rc[1], fr, zero)?;
        region.assign_fixed(|| "rc2", self.rc[2], fr, zero)?;
        region.assign_fixed(|| "domain", self.domain, fr, zero)?;
        region.assign_fixed(|| "absorb", self.is_absorb, fr, zero)?;

        Ok(out.expect("state0 cell"))
    }
}

// ---------------------------------------------------------------------------
// SpendLimbConfig: 4 x 16-bit limb decomposition + running sum [S4 4, S4 8]
// ---------------------------------------------------------------------------

/// Configuration of the rc-limb gate (Phase 1a machinery, private copy
/// without an instance column: the spend circuit exposes RC instead of
/// the raw value). Layout: row 0 carries `v`, the limbs and the zero
/// accumulator; rows 1..=4 carry 16 bit cells each plus the block
/// accumulator; the limb cells are copy-constrained to their block
/// accumulators and the top gate reconstructs `v` from the limbs.
#[derive(Clone, Debug)]
pub struct SpendLimbConfig {
    /// Range-checked value (row 0).
    pub v: Column<Advice>,
    /// Limb cells (row 0).
    pub limb: [Column<Advice>; N_LIMBS],
    /// Block accumulator (rows 1..=4).
    pub acc: Column<Advice>,
    /// Bit cells, 16 per block row (shared with the fixed-base chain).
    pub bits: [Column<Advice>; LIMB_BITS],
    /// Block sum gate.
    pub s_bits: Selector,
    /// Accumulator start gate.
    pub s_start: Selector,
    /// Top-level reconstruction gate.
    pub s_top: Selector,
}

impl SpendLimbConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let v = meta.advice_column();
        let limb = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let acc = meta.advice_column();
        let bits = std::array::from_fn(|_| meta.advice_column());
        let s_bits = meta.selector();
        let s_start = meta.selector();
        let s_top = meta.selector();

        meta.enable_equality(v);
        for c in limb.iter().chain(bits.iter()) {
            meta.enable_equality(*c);
        }
        meta.enable_equality(acc);

        // Block sum: acc = sum_k 2^k * bit_k (degree 2) plus per-bit
        // booleanity.
        meta.create_gate("spend-limb-block-sum", |meta| {
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
        meta.create_gate("spend-limb-start", |meta| {
            let sel = meta.query_selector(s_start);
            let a = meta.query_advice(acc, Rotation::cur());
            vec![sel * a]
        });

        // v = l0 + 2^16*l1 + 2^32*l2 + 2^48*l3 (degree 1).
        meta.create_gate("spend-limb-top", |meta| {
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
        }
    }

    /// Assign the limb region for one value at row offset `base`
    /// (Phase 1a `LimbRangeConfig::assign`, offset-adapted). Returns the
    /// value cell for witness sharing with the leaf hash chain.
    pub fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        v: Value<u64>,
        corrupt: bool,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let zero = || Value::known(Fp::ZERO);

        let v_cell = region.assign_advice(|| "v", self.v, base, || v.map(Fp::from))?;
        let mut limb_cells = Vec::with_capacity(N_LIMBS);
        for j in 0..N_LIMBS {
            let l = v.map(|x| Fp::from((x >> (LIMB_BITS * j)) & 0xFFFF));
            let c = region.assign_advice(|| format!("limb{}", j), self.limb[j], base, || l)?;
            limb_cells.push(c);
        }
        region.assign_advice(|| "acc-init", self.acc, base, zero)?;
        self.s_start.enable(region, base)?;
        self.s_top.enable(region, base)?;

        for j in 0..N_LIMBS {
            let row = base + 1 + j;
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

// ---------------------------------------------------------------------------
// SpendFbConfig: conditional fixed-base EC addition gates [S4 4, S4 8]
// ---------------------------------------------------------------------------

/// Window multiples per base: coordinates of `[2^i] * B`, i in 0..256.
pub const FB_MULTIPLES: usize = 256;
/// Accumulation rows of one 255-bit scalar block (16 rows x 16 bits).
pub const FB_SCALAR_ROWS: usize = 16;
/// Index of the corrupted bit cell in the negative tests.
const FB_CORRUPT_BIT: usize = 100;

/// Window multiples of a fixed base (Phase 1b `fb_multiples`): `out[i]`
/// holds the `(x, y)` coordinates of `[2^i] * base`. Panics if a multiple
/// is the identity, which cannot happen for the hashgen generators and
/// the Pallas generator.
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

/// Configuration of the fixed-base accumulation gates (Phase 1b
/// machinery, private copy without an instance column, plus the shared
/// `top_val` cell of the leaf-chain scalar-binding gates).
///
/// One accumulation row carries 16 bits and performs 16 conditional EC
/// additions unrolled across dedicated columns; the row gate links
/// `x[0]` of row j to `x[16]` of row j-1 through a `Rotation::prev()`
/// query, so the chain is continuous across rows without copy
/// constraints. The `fb-top` gate ties a 16-row bit block to the scalar
/// cell copied into `top_val` directly above the block (leaf chain).
#[derive(Clone, Debug)]
pub struct SpendFbConfig {
    /// Bit cells, 16 per accumulation row (shared with the limb gate).
    pub bits: [Column<Advice>; 16],
    /// Accumulator x chain (17 cells per row).
    pub x: [Column<Advice>; 17],
    /// Accumulator y chain (17 cells per row).
    pub y: [Column<Advice>; 17],
    /// Slope cells, one per addition.
    pub lam: [Column<Advice>; 16],
    /// Identity-branch flags, one per addition.
    pub iota: [Column<Advice>; 16],
    /// Slope-denominator inverse cells, one per addition.
    pub din: [Column<Advice>; 16],
    /// Window multiple x coordinates (constants per row and bit).
    pub fx_x: [Column<Fixed>; 16],
    /// Window multiple y coordinates (constants per row and bit).
    pub fx_y: [Column<Fixed>; 16],
    /// Scalar cell tied to a bit block by `fb-top` (leaf chain).
    pub top_val: Column<Advice>,
    /// Accumulation row gate.
    pub s_acc: Selector,
    /// Accumulator starts at the encoded identity.
    pub s_init: Selector,
    /// Decomposed bits reproduce the `top_val` scalar (leaf chain).
    pub s_top: Selector,
}

impl SpendFbConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>, bits: [Column<Advice>; 16]) -> Self {
        let x: [Column<Advice>; 17] = std::array::from_fn(|_| meta.advice_column());
        let y: [Column<Advice>; 17] = std::array::from_fn(|_| meta.advice_column());
        let lam: [Column<Advice>; 16] = std::array::from_fn(|_| meta.advice_column());
        let iota: [Column<Advice>; 16] = std::array::from_fn(|_| meta.advice_column());
        let din: [Column<Advice>; 16] = std::array::from_fn(|_| meta.advice_column());
        let fx_x: [Column<Fixed>; 16] = std::array::from_fn(|_| meta.fixed_column());
        let fx_y: [Column<Fixed>; 16] = std::array::from_fn(|_| meta.fixed_column());
        let top_val = meta.advice_column();
        let s_acc = meta.selector();
        let s_init = meta.selector();
        let s_top = meta.selector();

        meta.enable_equality(x[16]);
        meta.enable_equality(y[16]);
        meta.enable_equality(top_val);

        // Accumulator starts at the encoded identity (0, 0).
        meta.create_gate("spend-fb-init", |meta| {
            let sel = meta.query_selector(s_init);
            let x_out = meta.query_advice(x[16], Rotation::cur());
            let y_out = meta.query_advice(y[16], Rotation::cur());
            vec![sel.clone() * x_out, sel * y_out]
        });

        // The accumulation row: 16 conditional EC additions, unrolled.
        meta.create_gate("spend-fb-acc", |meta| {
            let sel = meta.query_selector(s_acc);
            let xs: Vec<Expression<Fp>> = (0..=16)
                .map(|k| meta.query_advice(x[k], Rotation::cur()))
                .collect();
            let ys: Vec<Expression<Fp>> = (0..=16)
                .map(|k| meta.query_advice(y[k], Rotation::cur()))
                .collect();
            let lam: Vec<Expression<Fp>> = (0..16)
                .map(|k| meta.query_advice(lam[k], Rotation::cur()))
                .collect();
            let iota: Vec<Expression<Fp>> = (0..16)
                .map(|k| meta.query_advice(iota[k], Rotation::cur()))
                .collect();
            let din: Vec<Expression<Fp>> = (0..16)
                .map(|k| meta.query_advice(din[k], Rotation::cur()))
                .collect();
            let x_prev = meta.query_advice(x[16], Rotation::prev());
            let y_prev = meta.query_advice(y[16], Rotation::prev());

            let one = Expression::Constant(Fp::ONE);

            // Chain continuity across rows.
            let mut cs = vec![
                sel.clone() * (xs[0].clone() - x_prev),
                sel.clone() * (ys[0].clone() - y_prev),
            ];
            for k in 0..16 {
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

        // Decomposed bits reproduce the `top_val` scalar exactly: the gate
        // row sits directly ABOVE its 16 bit rows; the weights are built
        // by repeated multiplication with 2^16 so no shift ever exceeds
        // the u64 range.
        meta.create_gate("spend-fb-top", |meta| {
            let sel = meta.query_selector(s_top);
            let top = meta.query_advice(top_val, Rotation::cur());
            let two16 = Fp::from(1u64 << 16);
            let mut sum = Expression::Constant(Fp::ZERO);
            let mut w = Fp::ONE;
            for j in 0..FB_SCALAR_ROWS {
                let mut row_sum = Expression::Constant(Fp::ZERO);
                for k in 0..16 {
                    let b = meta.query_advice(bits[k], Rotation((j as i32) + 1));
                    row_sum = row_sum + b * Expression::Constant(Fp::from(1u64 << k));
                }
                sum = sum + row_sum * Expression::Constant(w);
                w *= two16;
            }
            vec![sel * (top - sum)]
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
            top_val,
            s_acc,
            s_init,
            s_top,
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
        for k in 0..16 {
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

    /// Assign one row of bit cells from a plain 32-byte representation.
    fn assign_bit_row(
        &self,
        region: &mut Region<'_, Fp>,
        row: usize,
        bit_base: usize,
        repr: &[u8; 32],
        corrupt_idx: Option<usize>,
    ) -> Result<(), Error> {
        for k in 0..16 {
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

    /// Assign the chain cells (lam, iota, din, x[0..=16], y[0..=16]) of
    /// one accumulation row from the host-side witness values. Returns
    /// the outgoing accumulator cells (x[16], y[16]).
    fn assign_chain_row(
        &self,
        region: &mut Region<'_, Fp>,
        row: usize,
        row_idx: usize,
        rows_val: &Value<Vec<RowVals>>,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        for k in 0..16 {
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
        for k in 0..=16 {
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
            if k == 16 {
                x_out = Some(cx);
                y_out = Some(cy);
            }
        }
        Ok((x_out.unwrap(), y_out.unwrap()))
    }
}

// ---------------------------------------------------------------------------
// SpendConfig: the composed configuration [S4 8]
// ---------------------------------------------------------------------------

/// Configuration of the full v4 spend circuit: limb + fixed-base chains
/// (RC and the leaf point), the generalized Poseidon gadget (nullifier,
/// leaf hash, tree walk, tree entry, witness-domain key chain) and the
/// commutative tree-step gates. All cells live in ONE region (the v0.3.0
/// single-region style [S4 8]).
#[derive(Clone, Debug)]
pub struct SpendConfig {
    /// Witness cells of one input note: [a, b, rho, D].
    pub wit: [Column<Advice>; 4],
    /// rc-limb gate (range check of every value).
    pub limb: SpendLimbConfig,
    /// Fixed-base EC addition chains.
    pub fb: SpendFbConfig,
    /// Poseidon gadget (fixed and witness domains).
    pub hash: SpendHashConfig,
    /// Tree-step operand columns [node, sibling].
    pub tree_src: [Column<Advice>; 2],
    /// Tree-step linear operand cell (sum).
    pub tree_sum: Column<Advice>,
    /// Tree-step quadratic operand cell (product).
    pub tree_prod: Column<Advice>,
    /// Tree/key linear operand gate (`z = a + b`).
    pub s_add: Selector,
    /// Tree/key quadratic operand gate (`z = a * b`).
    pub s_mul: Selector,
    /// The normative 15-slot public instance column [S4 8].
    pub instance: Column<Instance>,
}

impl SpendConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let wit = std::array::from_fn(|_| meta.advice_column());
        let limb = SpendLimbConfig::configure(meta);
        let fb = SpendFbConfig::configure(meta, limb.bits);
        let hash = SpendHashConfig::configure(meta);
        let tree_src = [meta.advice_column(), meta.advice_column()];
        let tree_sum = meta.advice_column();
        let tree_prod = meta.advice_column();
        let s_add = meta.selector();
        let s_mul = meta.selector();
        let instance = meta.instance_column();

        for c in wit.iter().chain(tree_src.iter()) {
            meta.enable_equality(*c);
        }
        meta.enable_equality(tree_sum);
        meta.enable_equality(tree_prod);
        meta.enable_equality(instance);

        // Linear operand: z = src0 + src1 (tree step and key part).
        meta.create_gate("spend-tree-add", |meta| {
            let sel = meta.query_selector(s_add);
            let a = meta.query_advice(tree_src[0], Rotation::cur());
            let b = meta.query_advice(tree_src[1], Rotation::cur());
            let z = meta.query_advice(tree_sum, Rotation::cur());
            vec![sel * (z - a - b)]
        });

        // Quadratic operand: z = src0 * src1 (tree step and key part).
        meta.create_gate("spend-tree-mul", |meta| {
            let sel = meta.query_selector(s_mul);
            let a = meta.query_advice(tree_src[0], Rotation::cur());
            let b = meta.query_advice(tree_src[1], Rotation::cur());
            let z = meta.query_advice(tree_prod, Rotation::cur());
            vec![sel * (z - a * b)]
        });

        Self {
            wit,
            limb,
            fb,
            hash,
            tree_src,
            tree_sum,
            tree_prod,
            s_add,
            s_mul,
            instance,
        }
    }

    /// One fixed-domain Poseidon permutation.
    fn perm(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        domain: Fp,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        self.hash.perm_cells(region, base, domain, None, a, b)
    }

    /// One witness-domain Poseidon permutation (the key chain).
    fn perm_wd(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        d_cell: &AssignedCell<Fp, Fp>,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        self.hash
            .perm_cells(region, base, Fp::ZERO, Some(d_cell), a, b)
    }

    /// One commutative tree step: `node' = H_tree(node, sib)` with the
    /// linear/quadratic operand gates tying `sum` and `prod` to the
    /// operands (v0.3.0 style). `sib_val` is the witnessed sibling.
    fn tree_step(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        node_cell: AssignedCell<Fp, Fp>,
        sib_val: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let node_val = node_cell.value().cloned();
        node_cell.copy_advice(|| "tree-node", region, self.tree_src[0], base)?;
        region.assign_advice(|| "tree-sib", self.tree_src[1], base, || sib_val)?;

        let sum = node_val + sib_val;
        let prod = node_val * sib_val;
        let sum_cell = region.assign_advice(|| "tree-sum", self.tree_sum, base, || sum)?;
        let prod_cell = region.assign_advice(|| "tree-prod", self.tree_prod, base, || prod)?;

        self.s_add.enable(region, base)?;
        self.s_mul.enable(region, base)?;

        self.perm(
            region,
            base,
            poseidon::domains()[poseidon::DOMAIN_TREE],
            sum_cell,
            prod_cell,
        )
    }

    /// Assign one value region (rc-limb + rc-fixed-base chain) at row
    /// offset `base` [S4 4, S4 8]:
    ///
    /// - `base + 0..=4`: the rc-limb gate over the shared bit columns;
    /// - `base + 0`: the accumulators start at the encoded identity;
    /// - `base + 1..=20`: rows 1..=4 add `[v] * V` from the limb
    ///   witnesses, rows 5..20 add `[r] * R` from the witnessed blinding
    ///   bits;
    /// - the outgoing accumulator cells of `base + 20` ARE the encoded
    ///   `RC = v * V + r * R`.
    ///
    /// Returns `(v_cell, RC.x, RC.y)`.
    fn assign_value(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        v: Value<u64>,
        r: Fq,
        corrupt: bool,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        // Rows base..=base+4: rc-limb gate over the shared bit columns.
        let v_cell = self.limb.assign(region, base, v, corrupt)?;

        let repr = r.to_repr();
        let mults_v = fb_multiples(value_gen());
        let mults_r = fb_multiples(blind_gen());
        let corrupt_idx = if corrupt { Some(FB_CORRUPT_BIT) } else { None };

        // The whole chain is computed on concrete values inside one
        // Value::map lift: the v-part bits depend on the witnessed `v`,
        // the r-part on the concrete blinding representation.
        let rows_val: Value<Vec<RowVals>> = v.map(|v0| {
            let mut bits_rows: Vec<[Fp; 16]> = Vec::with_capacity(N_LIMBS + FB_SCALAR_ROWS);
            let mut mults_rows: Vec<[(Fp, Fp); 16]> = Vec::with_capacity(N_LIMBS + FB_SCALAR_ROWS);
            for j in 0..N_LIMBS {
                let mut bits = [Fp::ZERO; 16];
                let mut mults = [(Fp::ZERO, Fp::ZERO); 16];
                for k in 0..16 {
                    bits[k] = Fp::from((v0 >> (LIMB_BITS * j + k)) & 1);
                    mults[k] = mults_v[LIMB_BITS * j + k];
                }
                bits_rows.push(bits);
                mults_rows.push(mults);
            }
            for j in 0..FB_SCALAR_ROWS {
                let mut bits = [Fp::ZERO; 16];
                let mut mults = [(Fp::ZERO, Fp::ZERO); 16];
                for k in 0..16 {
                    let idx = 16 * j + k;
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

        // Row base: accumulators start at the encoded identity.
        region.assign_advice(
            || "acc-x-init",
            self.fb.x[16],
            base,
            || Value::known(Fp::ZERO),
        )?;
        region.assign_advice(
            || "acc-y-init",
            self.fb.y[16],
            base,
            || Value::known(Fp::ZERO),
        )?;
        self.fb.s_init.enable(region, base)?;

        let mut x_out = None;
        let mut y_out = None;
        for j in 0..(N_LIMBS + FB_SCALAR_ROWS) {
            let row = base + 1 + j;
            let bit_base = if j < N_LIMBS {
                LIMB_BITS * j
            } else {
                16 * (j - N_LIMBS)
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

        Ok((v_cell, x_out.unwrap(), y_out.unwrap()))
    }

    /// Assign the v4 leaf chain at row offset `base` [S4 3, S4 8]:
    ///
    /// - `base + 0`: the accumulator starts at the encoded identity and
    ///   the `fb-top` gate ties the FIRST bit block to the key scalar
    ///   `s_cell = Poseidon_3(a+b, a*b, D)` (copied into `top_val`);
    /// - `base + 1..=16`: rows accumulating `[s] * G` from the witnessed
    ///   bits of `s` (base G, Pallas generator);
    /// - `base + 16`: the `fb-top` gate ties the SECOND bit block to
    ///   `H_leaf` (copied into `top_val`);
    /// - `base + 17..=32`: rows accumulating `[h] * G3` from the
    ///   witnessed bits of `h = H_leaf` (base G3);
    /// - the outgoing accumulator cells of `base + 32` are
    ///   `L = [s] * G + [h] * G3`.
    ///
    /// `s_host`/`h_host` are the honest host-side values of the two
    /// scalars (one witness lift); the in-circuit cells they are tied to
    /// carry the same values for an honest prover and are forced to by
    /// the permutation gates.
    fn assign_leaf_chain(
        &self,
        region: &mut Region<'_, Fp>,
        base: usize,
        s_cell: &AssignedCell<Fp, Fp>,
        h_cell: &AssignedCell<Fp, Fp>,
        sh_val: Value<(Fp, Fp)>,
        corrupt: bool,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        // Top cells: row base carries the key scalar, row base + 16 the
        // leaf hash.
        s_cell.copy_advice(|| "top-s", region, self.fb.top_val, base)?;
        h_cell.copy_advice(|| "top-h", region, self.fb.top_val, base + FB_SCALAR_ROWS)?;

        // Row base: accumulators start at the encoded identity.
        region.assign_advice(
            || "leaf-acc-x-init",
            self.fb.x[16],
            base,
            || Value::known(Fp::ZERO),
        )?;
        region.assign_advice(
            || "leaf-acc-y-init",
            self.fb.y[16],
            base,
            || Value::known(Fp::ZERO),
        )?;
        self.fb.s_init.enable(region, base)?;
        self.fb.s_top.enable(region, base)?;
        self.fb.s_top.enable(region, base + FB_SCALAR_ROWS)?;

        let mults_g = fb_multiples(pallas::Point::generator());
        let mults_g3 = fb_multiples(leaf_gen());
        let corrupt_idx = if corrupt { Some(FB_CORRUPT_BIT) } else { None };

        let rows_val: Value<Vec<RowVals>> = sh_val.map(|(s0, h0)| {
            let s_repr = s0.to_repr();
            let h_repr = h0.to_repr();
            let mut bits_rows: Vec<[Fp; 16]> = Vec::with_capacity(2 * FB_SCALAR_ROWS);
            let mut mults_rows: Vec<[(Fp, Fp); 16]> = Vec::with_capacity(2 * FB_SCALAR_ROWS);
            for j in 0..FB_SCALAR_ROWS {
                let mut bits = [Fp::ZERO; 16];
                let mut mults = [(Fp::ZERO, Fp::ZERO); 16];
                for k in 0..16 {
                    let idx = 16 * j + k;
                    bits[k] = bit_of(&s_repr, idx);
                    mults[k] = mults_g[idx];
                }
                bits_rows.push(bits);
                mults_rows.push(mults);
            }
            for j in 0..FB_SCALAR_ROWS {
                let mut bits = [Fp::ZERO; 16];
                let mut mults = [(Fp::ZERO, Fp::ZERO); 16];
                for k in 0..16 {
                    let idx = 16 * j + k;
                    let mut b = bit_of(&h_repr, idx);
                    if corrupt_idx == Some(idx) {
                        b = Fp::ONE - b;
                    }
                    bits[k] = b;
                    mults[k] = mults_g3[idx];
                }
                bits_rows.push(bits);
                mults_rows.push(mults);
            }
            chain_rows(&bits_rows, &mults_rows)
        });

        let mut x_out = None;
        let mut y_out = None;
        for j in 0..(2 * FB_SCALAR_ROWS) {
            let row = base + 1 + j;
            let bit_base = 16 * (j % FB_SCALAR_ROWS);
            let multiples: &[(Fp, Fp)] = if j < FB_SCALAR_ROWS {
                &mults_g
            } else {
                &mults_g3
            };
            self.fb.assign_fx(region, row, multiples, bit_base)?;
            for k in 0..16 {
                let idx = bit_base + k;
                region.assign_advice(
                    || format!("scalar-bit-{}", idx),
                    self.fb.bits[k],
                    row,
                    || {
                        let mut b = sh_val.map(|(s0, h0)| {
                            let repr = if j < FB_SCALAR_ROWS {
                                s0.to_repr()
                            } else {
                                h0.to_repr()
                            };
                            bit_of(&repr, idx)
                        });
                        if corrupt && j >= FB_SCALAR_ROWS && corrupt_idx == Some(idx) {
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

// ---------------------------------------------------------------------------
// Witness and circuit [S4 8]
// ---------------------------------------------------------------------------

/// Private witness of one spent note.
#[derive(Clone, Debug)]
pub struct SpendNoteInput {
    /// Diversifier domain of the address [S4 3].
    pub d: Fp,
    /// Owner key shares; only the spender knows both [S4 3].
    pub a: Fp,
    pub b: Fp,
    /// Per-note nullifier seed [S4 3].
    pub rho: Fp,
    /// Amount, 0 <= v < 2^64 [S4 3].
    pub v: u64,
    /// Authentication path of the note's tree entry: exactly `DEPTH`
    /// siblings, bottom-up [S4 1 P1].
    pub path: Vec<Fp>,
}

/// Private witness of one created note.
#[derive(Clone, Debug)]
pub struct SpendNoteOutput {
    /// Amount, 0 <= v < 2^64 [S4 3].
    pub v: u64,
}

/// Private witness of a v4 spend: `inputs.len() in 1..=MAX_IN` and
/// `outputs.len() in 1..=MAX_OUT`; smaller transactions are padded with
/// disabled rows and zeroed instance slots [S4 7, S4 8]. The blinding
/// scalars ride on the circuit struct (the Phase 1b pattern): their
/// lengths MUST match `n_in`/`n_out`.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    pub inputs: Vec<SpendNoteInput>,
    pub outputs: Vec<SpendNoteOutput>,
}

/// Cells bound to the public instances after the region is assigned.
struct SpendCells {
    root_cells: Vec<AssignedCell<Fp, Fp>>,
    n_cells: Vec<Option<AssignedCell<Fp, Fp>>>,
    rc_in: Vec<Option<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>)>>,
    rc_out: Vec<Option<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>)>>,
    zero_cell: AssignedCell<Fp, Fp>,
}

/// The full v4 spend circuit [S4 8]: one proof establishes membership,
/// nullifier derivation, value-commitment construction and (through the
/// public instances) the verifier-side balance and binding signature.
#[derive(Clone, Debug)]
pub struct V4SpendCircuit<const DEPTH: usize> {
    pub witness: Value<SpendWitness>,
    /// Value-commitment blinding of every input (spend-time secret).
    pub r_in: Vec<Fq>,
    /// Value-commitment blinding of every output (spend-time secret).
    pub r_out: Vec<Fq>,
    /// Number of enabled inputs, 1..=MAX_IN (wallet topology: 1).
    pub n_in: usize,
    /// Number of enabled outputs, 1..=MAX_OUT (wallet topology: 2).
    pub n_out: usize,
    /// Flip one limb bit cell of the given input (negative tests only).
    pub corrupt_limb: Option<usize>,
    /// Flip one leaf-hash bit cell of the given input (negative tests
    /// only): the leaf point, tree entry and root all shift, so an honest
    /// root instance no longer verifies.
    pub corrupt_leaf: Option<usize>,
}

impl<const DEPTH: usize> V4SpendCircuit<DEPTH> {
    /// Total rows of the single region at the FULL MAX topology
    /// (padded inputs/outputs only shrink the footprint) [S4 8].
    pub fn rows_needed() -> usize {
        MAX_IN
            * (1                          // witness row [a, b, rho, D]
                + VALUE_REGION_ROWS       // rc-limb + RC chain
                + 2 * PERM_ROWS           // nk, N
                + 1                       // key u/w row
                + PERM_ROWS               // key chain (witness domain)
                + PERM_ROWS               // H_leaf
                + LEAF_CHAIN_ROWS         // leaf chain [s]G + [h]G3
                + PERM_ROWS               // tree entry
                + DEPTH * PERM_ROWS)      // membership path
            + MAX_OUT * VALUE_REGION_ROWS
            + 1 // pad-zero row
    }

    /// Smallest k such that the circuit fits, with a margin for the
    /// instance rows and blinding [S4 8: k <= 13].
    pub fn required_k() -> u32 {
        let rows = Self::rows_needed() + 64;
        let mut k = 1u32;
        while (1usize << k) < rows {
            k += 1;
        }
        k
    }
}

impl<const DEPTH: usize> Circuit<Fp> for V4SpendCircuit<DEPTH> {
    type Config = SpendConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            witness: Value::unknown(),
            r_in: vec![Fq::ZERO; self.n_in],
            r_out: vec![Fq::ZERO; self.n_out],
            n_in: self.n_in,
            n_out: self.n_out,
            corrupt_limb: self.corrupt_limb,
            corrupt_leaf: self.corrupt_leaf,
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
        debug_assert!((1..=MAX_IN).contains(&self.n_in));
        debug_assert!((1..=MAX_OUT).contains(&self.n_out));
        debug_assert_eq!(self.r_in.len(), self.n_in);
        debug_assert_eq!(self.r_out.len(), self.n_out);

        let cells = layouter.assign_region(
            || "v4-spend",
            |mut region| {
                let mut base = 0usize;
                let wv = self.witness.clone();
                let mut root_cells: Vec<AssignedCell<Fp, Fp>> = Vec::new();
                let mut n_cells: Vec<Option<AssignedCell<Fp, Fp>>> =
                    (0..MAX_IN).map(|_| None).collect();
                let mut rc_in: Vec<Option<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>)>> =
                    (0..MAX_IN).map(|_| None).collect();
                let mut rc_out: Vec<Option<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>)>> =
                    (0..MAX_OUT).map(|_| None).collect();

                for i in 0..MAX_IN {
                    if i >= self.n_in {
                        continue;
                    }
                    let inp = wv.clone().map(|w| w.inputs[i].clone());

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

                    // Value region: RC_in_i = v * V + r * R [S4 4, S4 8].
                    let v_val = inp.clone().map(|n| n.v);
                    let (v_cell, rcx, rcy) = config.assign_value(
                        &mut region,
                        base,
                        v_val,
                        self.r_in[i],
                        self.corrupt_limb == Some(i),
                    )?;
                    rc_in[i] = Some((rcx, rcy));
                    base += VALUE_REGION_ROWS;

                    // Nullifier chain [S4 5]: nk = P(a, b, DOM_NK) and
                    // N = P(nk, rho, DOM_NU) from the SAME (a, b, rho)
                    // witnesses that feed the membership statement below.
                    let nk_cell =
                        config.perm(&mut region, base, dom_nk(), a_cell.clone(), b_cell.clone())?;
                    base += PERM_ROWS;
                    let n_cell =
                        config.perm(&mut region, base, dom_nu(), nk_cell, rho_cell.clone())?;
                    n_cells[i] = Some(n_cell);
                    base += PERM_ROWS;

                    // Key part [S4 3]: u = a + b and w = a * b via the
                    // linear/quadratic operand gates, then
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
                    // the SAME (v, rho) witnesses (v from the limb gate, so
                    // the RC and the leaf carry the same amount).
                    let h_cell =
                        config.perm(&mut region, base, dom_leaf_v2(), v_cell, rho_cell.clone())?;
                    base += PERM_ROWS;

                    // Leaf chain [S4 3, S4 8]: L = [s] * G + [h] * G3 as one
                    // multi-base fixed-base accumulation.
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
                        self.corrupt_leaf == Some(i),
                    )?;
                    base += LEAF_CHAIN_ROWS;

                    // Tree entry (Phase 2 convention):
                    // e = P(L.x, L.y, DOM_ACC).
                    let e_cell = config.perm(&mut region, base, dom_acc(), lx, ly)?;
                    base += PERM_ROWS;

                    // Membership path [S4 1 P1]: DEPTH commutative tree steps
                    // from the reconstructed entry up to the public root.
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

                for j in 0..MAX_OUT {
                    if j >= self.n_out {
                        continue;
                    }
                    let out = wv.clone().map(|w| w.outputs[j].clone());
                    let v_val = out.map(|n| n.v);
                    let (_v_cell, rcx, rcy) =
                        config.assign_value(&mut region, base, v_val, self.r_out[j], false)?;
                    rc_out[j] = Some((rcx, rcy));
                    base += VALUE_REGION_ROWS;
                }

                // The pad-zero cell: constrained to every padded instance
                // slot below [S4 8] (padded inputs contribute 0 for N and the
                // encoded identity (0, 0) for RC; padded outputs contribute
                // (0, 0) for RC).
                let zero_cell = region.assign_advice(
                    || "pad-zero",
                    config.wit[0],
                    base,
                    || Value::known(Fp::ZERO),
                )?;

                Ok(SpendCells {
                    root_cells,
                    n_cells,
                    rc_in,
                    rc_out,
                    zero_cell,
                })
            },
        )?;

        // Normative instance order [S4 8]: slot 0 = root (every enabled
        // input walks to the SAME root and is constrained to it),
        // slots 1..=MAX_IN = N_i, then 2 slots per RC_in_i, then 2 slots
        // per RC_out_j. Padded slots are forced to zero through the
        // pad-zero cell.
        for c in cells.root_cells.iter() {
            layouter.constrain_instance(c.cell(), config.instance, 0)?;
        }
        for i in 0..MAX_IN {
            let row_n = 1 + i;
            match &cells.n_cells[i] {
                Some(c) => layouter.constrain_instance(c.cell(), config.instance, row_n)?,
                None => {
                    layouter.constrain_instance(cells.zero_cell.cell(), config.instance, row_n)?
                }
            }
            let row_x = 1 + MAX_IN + 2 * i;
            let row_y = row_x + 1;
            match &cells.rc_in[i] {
                Some((cx, cy)) => {
                    layouter.constrain_instance(cx.cell(), config.instance, row_x)?;
                    layouter.constrain_instance(cy.cell(), config.instance, row_y)?;
                }
                None => {
                    layouter.constrain_instance(cells.zero_cell.cell(), config.instance, row_x)?;
                    layouter.constrain_instance(cells.zero_cell.cell(), config.instance, row_y)?;
                }
            }
        }
        let rc_out_base = 1 + MAX_IN + 2 * MAX_IN;
        for j in 0..MAX_OUT {
            let row_x = rc_out_base + 2 * j;
            let row_y = row_x + 1;
            match &cells.rc_out[j] {
                Some((cx, cy)) => {
                    layouter.constrain_instance(cx.cell(), config.instance, row_x)?;
                    layouter.constrain_instance(cy.cell(), config.instance, row_y)?;
                }
                None => {
                    layouter.constrain_instance(cells.zero_cell.cell(), config.instance, row_x)?;
                    layouter.constrain_instance(cells.zero_cell.cell(), config.instance, row_y)?;
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::v4::{fq_reduce_fp, nullifier_v4, p_leaf, value_commit};
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    /// Row budget from [S4 8]: the v4 design MUST stay within k = 13.
    const K_BUDGET_ROWS: usize = 1 << 13;
    /// Test tree depth (the v0.3.0 test convention).
    const DEPTH: usize = 4;

    #[derive(Clone)]
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

    /// Builds `count` random notes and the tree over their entries.
    fn tree_fixture(count: usize) -> (Vec<TestNote>, Vec<Fp>, Fp) {
        let notes: Vec<TestNote> = (0..count)
            .map(|i| TestNote {
                d: Fp::random(OsRng),
                a: Fp::random(OsRng),
                b: Fp::random(OsRng),
                rho: Fp::random(OsRng),
                v: 100 + i as u64,
            })
            .collect();
        let entries: Vec<Fp> = notes.iter().map(note_entry).collect();
        let root = merkle::build_root(&entries, DEPTH);
        (notes, entries, root)
    }

    /// Wallet topology (1-in / 2-out) with honest instances in the
    /// normative 15-slot order [S4 8]. Returns the circuit, the instance
    /// vector and the value commitments (host-side) for cross-checks.
    fn wallet_fixture() -> (V4SpendCircuit<DEPTH>, Vec<Fp>, TestNote, Vec<pallas::Point>) {
        let (notes, entries, root) = tree_fixture(5);
        let path = merkle::auth_path(&entries, 2, DEPTH);
        let vg = value_gen();
        let rg = blind_gen();

        let r0 = Fq::random(OsRng);
        let r_out0 = Fq::random(OsRng);
        let r_out1 = Fq::random(OsRng);

        let rc_in0 = value_commit(notes[2].v, r0, &vg, &rg);
        let rc_out0 = value_commit(60, r_out0, &vg, &rg);
        let rc_out1 = value_commit(40, r_out1, &vg, &rg);

        let circuit = V4SpendCircuit::<DEPTH> {
            witness: Value::known(SpendWitness {
                inputs: vec![SpendNoteInput {
                    d: notes[2].d,
                    a: notes[2].a,
                    b: notes[2].b,
                    rho: notes[2].rho,
                    v: notes[2].v,
                    path,
                }],
                outputs: vec![SpendNoteOutput { v: 60 }, SpendNoteOutput { v: 40 }],
            }),
            r_in: vec![r0],
            r_out: vec![r_out0, r_out1],
            n_in: 1,
            n_out: 2,
            corrupt_limb: None,
            corrupt_leaf: None,
        };

        let (inx, iny) = coords(&rc_in0);
        let (o0x, o0y) = coords(&rc_out0);
        let (o1x, o1y) = coords(&rc_out1);
        // Normative order [S4 8]: [root, N_0, N_1, RC_in_0.x, RC_in_0.y,
        // RC_in_1.x, RC_in_1.y, RC_out_0.x, RC_out_0.y, RC_out_1.x,
        // RC_out_1.y, RC_out_2.x, RC_out_2.y, RC_out_3.x, RC_out_3.y]
        // with zero pads for the disabled slots.
        let instances = vec![
            root,
            nullifier_v4(notes[2].a, notes[2].b, notes[2].rho),
            Fp::ZERO,
            inx,
            iny,
            Fp::ZERO,
            Fp::ZERO,
            o0x,
            o0y,
            o1x,
            o1y,
            Fp::ZERO,
            Fp::ZERO,
            Fp::ZERO,
            Fp::ZERO,
        ];
        assert_eq!(instances.len(), SPEND_INSTANCE_SLOTS);
        let rcs = vec![rc_in0, rc_out0, rc_out1];
        (circuit, instances, notes[2].clone(), rcs)
    }

    #[test]
    fn v4_spend_happy_path_wallet_topology() {
        let (circuit, instances, note, _rcs) = wallet_fixture();

        // Host cross-checks: the published instances equal the host v0.4
        // primitives [S4 3, S4 5, S4 8].
        assert_eq!(
            note_entry(&note),
            tree_rep(&leaf_v2(note.d, note.a, note.b, note.v, note.rho))
        );
        assert_eq!(nullifier_v4(note.a, note.b, note.rho), instances[1]);

        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        prover.verify().unwrap();

        // Row budget [S4 8]: the FULL MAX topology at mainnet depth must
        // stay inside k = 13.
        assert!(V4SpendCircuit::<DEPTH>::rows_needed() < K_BUDGET_ROWS);
        assert!(V4SpendCircuit::<32>::rows_needed() < K_BUDGET_ROWS);
        assert_eq!(V4SpendCircuit::<32>::required_k(), 13);
    }

    #[test]
    fn v4_spend_full_max_topology() {
        let (notes, entries, root) = tree_fixture(6);
        let path0 = merkle::auth_path(&entries, 0, DEPTH);
        let path1 = merkle::auth_path(&entries, 1, DEPTH);
        let vg = value_gen();
        let rg = blind_gen();

        let r_in: Vec<Fq> = (0..MAX_IN).map(|_| Fq::random(OsRng)).collect();
        let r_out: Vec<Fq> = (0..MAX_OUT).map(|_| Fq::random(OsRng)).collect();

        let total_in: u64 = notes[0].v + notes[1].v;
        // The fee is a verifier-side concern [S4 6]; the in-circuit
        // balance is total_in = sum(out_vals).
        let out_vals = [total_in - 3 * 50, 50, 50, 50];

        let circuit = V4SpendCircuit::<DEPTH> {
            witness: Value::known(SpendWitness {
                inputs: vec![
                    SpendNoteInput {
                        d: notes[0].d,
                        a: notes[0].a,
                        b: notes[0].b,
                        rho: notes[0].rho,
                        v: notes[0].v,
                        path: path0,
                    },
                    SpendNoteInput {
                        d: notes[1].d,
                        a: notes[1].a,
                        b: notes[1].b,
                        rho: notes[1].rho,
                        v: notes[1].v,
                        path: path1,
                    },
                ],
                outputs: (0..MAX_OUT)
                    .map(|j| SpendNoteOutput { v: out_vals[j] })
                    .collect(),
            }),
            r_in: r_in.clone(),
            r_out: r_out.clone(),
            n_in: MAX_IN,
            n_out: MAX_OUT,
            corrupt_limb: None,
            corrupt_leaf: None,
        };

        let mut instances: Vec<Fp> = Vec::with_capacity(SPEND_INSTANCE_SLOTS);
        instances.push(root);
        for i in 0..MAX_IN {
            instances.push(nullifier_v4(notes[i].a, notes[i].b, notes[i].rho));
        }
        let rc_in: Vec<pallas::Point> = (0..MAX_IN)
            .map(|i| value_commit(notes[i].v, circuit.r_in[i], &vg, &rg))
            .collect();
        let rc_out: Vec<pallas::Point> = (0..MAX_OUT)
            .map(|j| value_commit(out_vals[j], circuit.r_out[j], &vg, &rg))
            .collect();
        for rc in rc_in.iter() {
            let (x, y) = coords(rc);
            instances.push(x);
            instances.push(y);
        }
        for rc in rc_out.iter() {
            let (x, y) = coords(rc);
            instances.push(x);
            instances.push(y);
        }
        assert_eq!(instances.len(), SPEND_INSTANCE_SLOTS);

        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn v4_spend_rejects_forged_nullifier() {
        let (circuit, mut instances, note, _rcs) = wallet_fixture();
        // A nullifier derived from a DIFFERENT note must fail [S4 5].
        instances[1] = nullifier_v4(note.a, note.b, note.rho + Fp::ONE);
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_spend_rejects_wrong_root() {
        let (circuit, mut instances, _note, _rcs) = wallet_fixture();
        // A root the membership path does not lead to must fail [S4 1 P1].
        instances[0] += Fp::ONE;
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_spend_rejects_corrupted_limb() {
        let (mut circuit, instances, _note, _rcs) = wallet_fixture();
        // A lying limb decomposition must fail the range check [S4 4].
        circuit.corrupt_limb = Some(0);
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_spend_rejects_forged_leaf_term() {
        let (mut circuit, instances, _note, _rcs) = wallet_fixture();
        // A forged leaf term shifts the tree entry, so the honest root
        // no longer verifies [S4 3].
        circuit.corrupt_leaf = Some(0);
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_spend_rejects_nonzero_padding_slot() {
        let (circuit, mut instances, _note, _rcs) = wallet_fixture();
        // Padded instance slots are forced to zero [S4 8].
        instances[2] = Fp::random(OsRng);
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_spend_instance_order_is_normative() {
        let (circuit, mut instances, _note, _rcs) = wallet_fixture();
        // Swapping RC_out_0.x and RC_out_1.x violates the normative
        // instance order [S4 8].
        instances.swap(7, 9);
        let k = V4SpendCircuit::<DEPTH>::required_k();
        let prover = MockProver::run(k, &circuit, vec![instances]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn v4_tree_rep_binds_leaf_components() {
        let d = Fp::random(OsRng);
        let a = Fp::random(OsRng);
        let b = Fp::random(OsRng);
        let rho = Fp::random(OsRng);
        let e = leaf_entry_v2(d, a, b, 42, rho);
        // Deterministic...
        assert_eq!(leaf_entry_v2(d, a, b, 42, rho), e);
        // ...and bound to every component [S4 3].
        assert_ne!(leaf_entry_v2(d, a, b, 43, rho), e);
        assert_ne!(leaf_entry_v2(d, a, b, 42, rho + Fp::ONE), e);
        assert_ne!(leaf_entry_v2(d, a + Fp::ONE, b, 42, rho), e);
        // The key part is SYMMETRIC in (a, b) by design [S4 3]: the leaf
        // binds (a+b, a*b), which do not distinguish the shares.
        assert_eq!(leaf_entry_v2(d, b, a, 42, rho), e);
        assert_ne!(leaf_entry_v2(d + Fp::ONE, a, b, 42, rho), e);
        // The entry is a function of the leaf point alone.
        let l = leaf_v2(d, a, b, 42, rho);
        assert_eq!(tree_rep(&l), e);
        // Distinct from the key part alone (the G3 term matters).
        assert_ne!(tree_rep(&p_leaf(d, a + b, a * b)), e);
    }

    #[test]
    fn v4_balance_and_bind_sig_roundtrip() {
        let vg = value_gen();
        let rg = blind_gen();
        let rc_in = vec![value_commit(100, Fq::from(7), &vg, &rg)];
        let rc_out = vec![
            value_commit(60, Fq::from(3), &vg, &rg),
            value_commit(40, Fq::from(5), &vg, &rg),
        ];
        let fee = 0u64;

        // With honest values bvk = bsk * R [S4 6].
        let bsk = binding_sk(&[Fq::from(7)], &[Fq::from(3), Fq::from(5)]);
        let bvk = binding_vk(&rc_in, &rc_out, fee);
        assert_eq!(bvk, rg * bsk);
        assert!(balance_holds(&rc_in, &rc_out, fee, bsk));

        let s = sighash_v4(
            &pallas::Point::generator(),
            &[Fp::from(1u64)],
            &[],
            &rc_in,
            &rc_out,
            fee,
        );
        let sig = sign_bind(&s, bsk, &bvk);
        assert!(verify_bind(&s, &bvk, &sig));
        // Tampered sighash must fail.
        let mut s2 = s;
        s2[0] ^= 1;
        assert!(!verify_bind(&s2, &bvk, &sig));
        // Tampered signature must fail.
        let mut sig2 = sig;
        sig2[40] ^= 1;
        assert!(!verify_bind(&s, &bvk, &sig2));
    }

    #[test]
    fn v4_unbalanced_tx_is_rejected() {
        // An inflated output shifts bvk by d * V with d != 0; the balance
        // check fails and NO ONE can sign under the shifted bvk without
        // dlog_R(V) [S4 6, S4 11].
        let vg = value_gen();
        let rg = blind_gen();
        let rc_in = vec![value_commit(100, Fq::from(7), &vg, &rg)];
        let rc_out = vec![
            value_commit(61, Fq::from(3), &vg, &rg),
            value_commit(40, Fq::from(5), &vg, &rg),
        ];
        let bsk = binding_sk(&[Fq::from(7)], &[Fq::from(3), Fq::from(5)]);
        assert!(!balance_holds(&rc_in, &rc_out, 0, bsk));

        let bvk = binding_vk(&rc_in, &rc_out, 0);
        assert_ne!(bvk, rg * bsk);

        let s = sighash_v4(&pallas::Point::generator(), &[], &[], &rc_in, &rc_out, 0);
        // The honest bsk signature verifies under the TRUE bvk but not
        // under the shifted one.
        let sig = sign_bind(&s, bsk, &(rg * bsk));
        assert!(verify_bind(&s, &(rg * bsk), &sig));
        assert!(!verify_bind(&s, &bvk, &sig));
        // Signing with an arbitrary key under the shifted bvk fails:
        // that key's bvk would differ.
        let forged = sign_bind(&s, Fq::from(999), &bvk);
        assert!(!verify_bind(&s, &bvk, &forged));
    }

    #[test]
    fn v4_fee_is_part_of_the_balance() {
        // fee = 1: inputs 100 cover outputs 60 + 39 plus the fee [S4 6].
        let vg = value_gen();
        let rg = blind_gen();
        let rc_in = vec![value_commit(100, Fq::from(7), &vg, &rg)];
        let rc_out = vec![
            value_commit(60, Fq::from(3), &vg, &rg),
            value_commit(39, Fq::from(4), &vg, &rg),
        ];
        let bsk = binding_sk(&[Fq::from(7)], &[Fq::from(3), Fq::from(4)]);
        assert!(balance_holds(&rc_in, &rc_out, 1, bsk));
        assert!(!balance_holds(&rc_in, &rc_out, 0, bsk));
        let bvk = binding_vk(&rc_in, &rc_out, 1);
        assert_eq!(bvk, rg * bsk);
    }

    #[test]
    fn v4_sighash_covers_every_field() {
        let g = pallas::Point::generator();
        let root = g * Fq::from(17);
        let ns = vec![Fp::from(11u64)];
        let leaves = vec![g * Fq::from(2)];
        let rc_in = vec![g * Fq::from(3)];
        let rc_out = vec![g * Fq::from(4)];
        let base = sighash_v4(&root, &ns, &leaves, &rc_in, &rc_out, 5);
        // Every serialized field consumed by verification is covered
        // [S4 7, S4 11].
        assert_ne!(
            sighash_v4(&(root + g), &ns, &leaves, &rc_in, &rc_out, 5),
            base
        );
        assert_ne!(
            sighash_v4(&root, &[Fp::from(12u64)], &leaves, &rc_in, &rc_out, 5),
            base
        );
        assert_ne!(sighash_v4(&root, &ns, &[], &rc_in, &rc_out, 5), base);
        assert_ne!(sighash_v4(&root, &ns, &leaves, &[], &rc_out, 5), base);
        assert_ne!(sighash_v4(&root, &ns, &leaves, &rc_in, &[], 5), base);
        assert_ne!(sighash_v4(&root, &ns, &leaves, &rc_in, &rc_out, 6), base);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn v4_dom_acc_is_stable() {
        let d = dom_acc();
        // Pinned test vector [S4 2]: stable across releases and platforms.
        assert_eq!(hex(&d.to_repr()), DOM_ACC_HEX);
        assert_ne!(d, crate::v4::dom_leaf_v2());
        assert_ne!(d, crate::v4::dom_nk());
        assert_ne!(d, crate::v4::dom_nu());
    }

    #[test]
    fn v4_fq_reduce_keeps_entry_scalars_consistent() {
        // The leaf chain multiplies [h] * G3 with h taken from the Fp
        // representation; the host leaf uses fq_reduce_fp(h). These agree
        // because p < q (both Pasta primes are below 2^255).
        let h = h_leaf_v2(777, Fp::from(123456789u64));
        let host = leaf_gen() * fq_reduce_fp(h);
        let bits_scalar = {
            let repr = h.to_repr();
            let mut acc = Fq::ZERO;
            for idx in (0..255).rev() {
                acc = acc + acc + Fq::from(u64::from(bit_of(&repr, idx) == Fp::ONE));
            }
            acc
        };
        assert_eq!(leaf_gen() * bits_scalar, host);
    }

    // Pinned test vector (blake3-derived, stable across platforms).
    const DOM_ACC_HEX: &str = "303dfa0e04d8ec09da5be1d62e99f01200000000000000000000000000000000";
}

// ---------------------------------------------------------------------------
// Real-prover bench [S4 13 phase 2: prove time benched]
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "real-prover"))]
mod real_tests {
    use super::*;
    use crate::merkle;
    use crate::v4::{nullifier_v4, value_commit};
    use halo2_proofs::{
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use pasta_curves::vesta;
    use rand::rngs::OsRng;
    use std::time::Instant;

    /// Prove/verify roundtrip of the FULL MAX topology at mainnet depth
    /// (2^32 leaves) [S4 8]. The wall-clock proving time is printed for
    /// the [S4 8] budget check (MUST stay under 10 s on the reference
    /// machine; the printed number is the Phase 2 bench record).
    #[test]
    fn v4_spend_prove_verify_mainnet_depth() {
        const DEPTH: usize = 32;
        let k = V4SpendCircuit::<DEPTH>::required_k();

        let notes: Vec<(Fp, Fp, Fp, Fp, u64)> = (0..2)
            .map(|_| {
                (
                    Fp::random(OsRng),
                    Fp::random(OsRng),
                    Fp::random(OsRng),
                    Fp::random(OsRng),
                    100u64,
                )
            })
            .collect();
        let entries: Vec<Fp> = notes
            .iter()
            .map(|(d, a, b, rho, v)| leaf_entry_v2(*d, *a, *b, *v, *rho))
            .collect();
        let root = merkle::build_root(&entries, DEPTH);
        let path0 = merkle::auth_path(&entries, 0, DEPTH);
        let path1 = merkle::auth_path(&entries, 1, DEPTH);

        let vg = value_gen();
        let rg = blind_gen();
        let r_in: Vec<Fq> = (0..MAX_IN).map(|_| Fq::random(OsRng)).collect();
        let r_out: Vec<Fq> = (0..MAX_OUT).map(|_| Fq::random(OsRng)).collect();

        let circuit = V4SpendCircuit::<DEPTH> {
            witness: Value::known(SpendWitness {
                inputs: vec![
                    SpendNoteInput {
                        d: notes[0].0,
                        a: notes[0].1,
                        b: notes[0].2,
                        rho: notes[0].3,
                        v: notes[0].4,
                        path: path0,
                    },
                    SpendNoteInput {
                        d: notes[1].0,
                        a: notes[1].1,
                        b: notes[1].2,
                        rho: notes[1].3,
                        v: notes[1].4,
                        path: path1,
                    },
                ],
                outputs: (0..MAX_OUT).map(|_| SpendNoteOutput { v: 50 }).collect(),
            }),
            r_in: r_in.clone(),
            r_out: r_out.clone(),
            n_in: MAX_IN,
            n_out: MAX_OUT,
            corrupt_limb: None,
            corrupt_leaf: None,
        };

        let total_in: u64 = notes[0].4 + notes[1].4;
        let out_vals = [total_in - 3 * 50, 50, 50, 50];
        let mut instances: Vec<Fp> = Vec::with_capacity(SPEND_INSTANCE_SLOTS);
        instances.push(root);
        for i in 0..MAX_IN {
            instances.push(nullifier_v4(notes[i].1, notes[i].2, notes[i].3));
        }
        for i in 0..MAX_IN {
            let rc = value_commit(notes[i].4, r_in[i], &vg, &rg);
            let (x, y) = coords(&rc);
            instances.push(x);
            instances.push(y);
        }
        for j in 0..MAX_OUT {
            let rc = value_commit(out_vals[j], r_out[j], &vg, &rg);
            let (x, y) = coords(&rc);
            instances.push(x);
            instances.push(y);
        }
        assert_eq!(instances.len(), SPEND_INSTANCE_SLOTS);

        let t0 = Instant::now();
        let params = Params::<vesta::Affine>::new(k);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
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
            &[&[instances.as_slice()]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        let elapsed = t0.elapsed();
        println!(
            "v4 spend prove (full MAX topology, DEPTH = {}, k = {}, rows = {}): {:.2?}",
            DEPTH,
            k,
            V4SpendCircuit::<DEPTH>::rows_needed(),
            elapsed
        );

        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&params);
        verify_proof::<vesta::Affine, Challenge255<vesta::Affine>, _, _>(
            &params,
            &vk,
            strategy,
            &[&[instances.as_slice()]],
            &mut transcript,
        )
        .unwrap();

        // A tampered public root must not verify.
        let mut bad = instances.clone();
        bad[0] += Fp::ONE;
        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&params);
        assert!(
            verify_proof::<vesta::Affine, Challenge255<vesta::Affine>, _, _>(
                &params,
                &vk,
                strategy,
                &[&[bad.as_slice()]],
                &mut transcript,
            )
            .is_err()
        );
    }
}
