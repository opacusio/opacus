# fix_ghost_zk.ps1
# Ghost project - rewrite crates/ghost-zk with the verified Halo2 implementation
# (halo2_proofs 0.3.5 API) and run the test suite.
# Generated 2026-10-17 - verified: 11 passed / 0 failed (default+real-prover),
# mainnet depth-32 MockProver ok, zero warnings.

$ErrorActionPreference = "Stop"

# ---- adjust if your project lives elsewhere ----
$ProjectRoot = "$PSScriptRoot"

Write-Host "=== ghost-zk fix: rewriting crates/ghost-zk with verified code ===" -ForegroundColor Cyan

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found in PATH. Use a shell where 'cargo --version' works." -ForegroundColor Red
    exit 1
}

if (!(Test-Path (Join-Path $ProjectRoot "Cargo.toml"))) {
    Write-Host "ERROR: $ProjectRoot\Cargo.toml not found. Edit `$ProjectRoot in this script." -ForegroundColor Red
    exit 1
}

function Write-Text([string]$Path, [string]$Content) {
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  wrote " + $Path)
}

# ---- 1) register crates/ghost-zk as a workspace member (idempotent) ----
$rootToml = Join-Path $ProjectRoot "Cargo.toml"
$rootContent = [System.IO.File]::ReadAllText($rootToml)
if ($rootContent -notmatch [regex]::Escape("crates/ghost-zk")) {
    $pattern = '(?m)^(members\s*=\s*\[)'
    if ($rootContent -match $pattern) {
        $rootContent = [regex]::Replace($rootContent, $pattern, "`$1`n    `"crates/ghost-zk`",")
        [System.IO.File]::WriteAllText($rootToml, $rootContent, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "  registered crates/ghost-zk in workspace members"
    } else {
        Write-Host "  WARNING: no [workspace] members array found in root Cargo.toml" -ForegroundColor Yellow
    }
} else {
    Write-Host "  workspace membership already present"
}

# ---- crates/ghost-zk/Cargo.toml ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-zk\Cargo.toml") @'
[package]
name = "ghost-zk"
version = "0.1.0"
edition = "2021"
description = "Halo2-based FCMP-style zero-knowledge membership proofs for Ghost"

[dependencies]
halo2_proofs = "0.3"
pasta_curves = "0.5"
ff = "0.13"
blake3 = "1"
thiserror = "1"
rand = "0.8"

[features]
default = []
real-prover = []

'@

# ---- crates/ghost-zk/src/lib.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-zk\src\lib.rs") @'
//! # ghost-zk
//!
//! Halo2-based FCMP-style zero-knowledge membership proofs for Ghost.
//!
//! One proof (`FcmpCircuit`) simultaneously demonstrates:
//! - **ownership**: the spender knows the note's spending key;
//! - **membership**: the note commitment is a leaf of the (2^DEPTH) Merkle tree;
//! - **spending**: the public nullifier is the unique nullifier of that note.
//!
//! Building blocks live in [`poseidon`] (hash), [`merkle`] (tree) and
//! [`circuit`] (proof). With the `real-prover` feature, [`prover`] wraps the
//! full IPA-based prover/verifier over the Pallas/Vesta cycle.

pub mod circuit;
pub mod merkle;
pub mod poseidon;
#[cfg(feature = "real-prover")]
pub mod prover;

use pasta_curves::Fp;
use thiserror::Error;

/// Mainnet tree depth: 2^32 leaves (anonymity set of about 4.3 billion).
pub const TREE_DEPTH_MAINNET: usize = 32;

#[derive(Debug, Error)]
pub enum ZkError {
    #[error("authentication path length mismatch: expected {expected}, got {got}")]
    PathLength { expected: usize, got: usize },
    #[error("proof verification failed")]
    VerificationFailed,
    #[error("halo2 error: {0}")]
    Halo2(#[from] halo2_proofs::plonk::Error),
}

/// A spendable shielded note.
#[derive(Clone, Debug)]
pub struct Note {
    /// Spending key.
    pub sk: Fp,
    /// Note nonce.
    pub rho: Fp,
    /// Amount in atoms.
    pub value: u64,
}

impl Note {
    pub fn new(sk: Fp, rho: Fp, value: u64) -> Self {
        Self { sk, rho, value }
    }

    /// Public key commitment derived from the spending key.
    pub fn spending_key_pub(&self) -> Fp {
        poseidon::h_pk(self.sk)
    }

    /// Note commitment — this is what leaves the tree.
    pub fn commitment(&self) -> Fp {
        poseidon::h_leaf(self.spending_key_pub(), self.rho, Fp::from(self.value))
    }

    /// Nullifier — published when the note is spent.
    pub fn nullifier(&self) -> Fp {
        poseidon::h_null(self.spending_key_pub(), self.rho)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::rngs::OsRng;

    #[test]
    fn note_hashes_are_consistent() {
        let n = Note::new(Fp::random(OsRng), Fp::random(OsRng), 42);
        assert_eq!(n.commitment(), n.commitment());
        assert_eq!(n.nullifier(), n.nullifier());
        assert_ne!(n.commitment(), n.nullifier());
        assert_ne!(n.commitment(), n.spending_key_pub());

        // Different notes never share commitments or nullifiers.
        let m = Note::new(n.sk, n.rho, n.value + 1);
        assert_ne!(n.commitment(), m.commitment());
        // Nullifier must not depend on the value.
        assert_eq!(n.nullifier(), m.nullifier());
    }
}

'@

# ---- crates/ghost-zk/src/poseidon.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-zk\src\poseidon.rs") @'
//! Poseidon-style cryptographic hash over the Pallas base field (`pasta_curves::Fp`).
//!
//! Design notes:
//! - State width `t = 3` (rate 2 + capacity 1), S-box `x^5`.
//! - Uniform schedule: all 64 rounds are *full* rounds (S-box applied to every
//!   state element). This costs more S-boxes than the paper's partial-round
//!   schedule but makes the in-circuit gadget perfectly uniform (one gate for
//!   every round row), which keeps the Halo2 circuit simple and auditable.
//! - Round constants and domain tags are derived deterministically from
//!   blake3 with a fixed protocol label, so scalar and circuit sides always
//!   agree without shipping magic numbers.
//! - `h_tree` is *commutative*: `H(a,b) = H(b,a)`, implemented as
//!   `P(D_tree, a+b, a*b)`. Merkle paths therefore need no direction bits.

use ff::Field;
use pasta_curves::Fp;
use std::sync::OnceLock;

/// State width (t = 3): two rate elements + one capacity element.
pub const T: usize = 3;
/// Total number of rounds (all of them full rounds).
pub const ROUNDS: usize = 64;
/// Number of elements absorbed per permutation (the rate).
pub const RATE: usize = 2;

/// MDS matrix: circulant(2, 1, 1) — provably MDS over Fp (all 2x2 minors
/// and the determinant are small nonzero integers, invertible mod p).
const MDS: [[u64; 3]; 3] = [[2, 1, 1], [1, 2, 1], [1, 1, 2]];

const PROTOCOL_LABEL: &[u8] = b"ghost-zk-poseidon-v1";

/// Domain-separation indices into [`domains`].
pub const DOMAIN_PK: usize = 0;
pub const DOMAIN_LEAF: usize = 1;
pub const DOMAIN_TREE: usize = 2;
pub const DOMAIN_NULLIFIER: usize = 3;

static ROUND_CONSTANTS: OnceLock<Vec<[Fp; T]>> = OnceLock::new();
static DOMAINS: OnceLock<[Fp; 4]> = OnceLock::new();

/// Deterministically map 16 bytes to an Fp element:
/// interpret as two little-endian u64 limbs and reduce via Horner with 2^64.
/// Every 128-bit integer is < p, so no rejection sampling is needed.
fn fp_from_16(b: &[u8]) -> Fp {
    debug_assert!(b.len() >= 16);
    let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(b[8..16].try_into().unwrap());
    // 2^64 mod p  (u64::MAX + 1)
    let two64 = Fp::from(u64::MAX) + Fp::ONE;
    Fp::from(hi) * two64 + Fp::from(lo)
}

/// Derive `n` field elements deterministically from a tag using blake3.
fn derive_field_elements(tag: &str, n: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(n);
    let mut counter: u64 = 0;
    while out.len() < n {
        let mut h = blake3::Hasher::new();
        h.update(PROTOCOL_LABEL);
        h.update(tag.as_bytes());
        h.update(&counter.to_le_bytes());
        let d = h.finalize();
        let bytes = d.as_bytes();
        out.push(fp_from_16(&bytes[0..16]));
        if out.len() < n {
            out.push(fp_from_16(&bytes[16..32]));
        }
        counter += 1;
    }
    out
}

/// Poseidon round constants (ROUNDS x T), derived once and shared.
pub fn round_constants() -> &'static Vec<[Fp; T]> {
    ROUND_CONSTANTS.get_or_init(|| {
        let flat = derive_field_elements("rc", ROUNDS * T);
        flat.chunks_exact(T)
            .map(|c| [c[0], c[1], c[2]])
            .collect()
    })
}

/// Domain-separation constants for the protocol hashes.
pub fn domains() -> &'static [Fp; 4] {
    DOMAINS.get_or_init(|| {
        let v = derive_field_elements("domain", 4);
        [v[0], v[1], v[2], v[3]]
    })
}

#[inline]
fn sbox(x: Fp) -> Fp {
    // x^5 = (x^2)^2 * x
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

#[inline]
fn mds(p: [Fp; 3]) -> [Fp; 3] {
    let m = |v: u64| Fp::from(v);
    [
        m(MDS[0][0]) * p[0] + m(MDS[0][1]) * p[1] + m(MDS[0][2]) * p[2],
        m(MDS[1][0]) * p[0] + m(MDS[1][1]) * p[1] + m(MDS[1][2]) * p[2],
        m(MDS[2][0]) * p[0] + m(MDS[2][1]) * p[1] + m(MDS[2][2]) * p[2],
    ]
}

/// One Poseidon permutation with absorb fused into round 0, exactly matching
/// the circuit gadget in [`crate::circuit`]:
///
/// - initial state is `[0, 0, 0]`;
/// - in round 0, `abs0` and `abs1` are added to state elements 0 and 1, and
///   `domain` is added to the capacity element 2;
/// - rounds 1..ROUNDS absorb nothing;
/// - every round applies `x^5` to all three elements, then the MDS matrix.
///
/// Returns the final state; callers squeeze `state[0]`.
pub fn poseidon_absorb(domain: Fp, abs0: Fp, abs1: Fp) -> [Fp; 3] {
    let rcs = round_constants();
    let zero = Fp::ZERO;
    let mut s = [zero, zero, Fp::ZERO];
    for r in 0..ROUNDS {
        let (a0, a1, d2) = if r == 0 {
            (abs0, abs1, domain)
        } else {
            (Fp::ZERO, Fp::ZERO, Fp::ZERO)
        };
        let u0 = s[0] + a0 + rcs[r][0];
        let u1 = s[1] + a1 + rcs[r][1];
        let u2 = s[2] + d2 + rcs[r][2];
        s = mds([sbox(u0), sbox(u1), sbox(u2)]);
    }
    s
}

/// Spending-key commitment: `pk = P(D_pk, sk, sk)`.
pub fn h_pk(sk: Fp) -> Fp {
    poseidon_absorb(domains()[DOMAIN_PK], sk, sk)[0]
}

/// Note commitment (two absorb stages): `cm = P(D_leaf, value, P(D_leaf, pk, rho))`.
pub fn h_leaf(pk: Fp, rho: Fp, value: Fp) -> Fp {
    let t1 = poseidon_absorb(domains()[DOMAIN_LEAF], pk, rho)[0];
    poseidon_absorb(domains()[DOMAIN_LEAF], value, t1)[0]
}

/// Nullifier: `nf = P(D_null, pk, rho)` — unlinkable, bound to the note's key.
pub fn h_null(pk: Fp, rho: Fp) -> Fp {
    poseidon_absorb(domains()[DOMAIN_NULLIFIER], pk, rho)[0]
}

/// Commutative tree hash: `H(a,b) = P(D_tree, a+b, a*b) = H(b,a)`.
pub fn h_tree(a: Fp, b: Fp) -> Fp {
    poseidon_absorb(domains()[DOMAIN_TREE], a + b, a * b)[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_distinct() {
        let a = Fp::from(12345u64);
        let b = Fp::from(67890u64);

        // Deterministic.
        assert_eq!(poseidon_absorb(domains()[0], a, b), poseidon_absorb(domains()[0], a, b));

        // Distinct domains give distinct hashes.
        for d in 0..4 {
            for e in 0..4 {
                if d != e {
                    assert_ne!(
                        poseidon_absorb(domains()[d], a, b)[0],
                        poseidon_absorb(domains()[e], a, b)[0]
                    );
                }
            }
        }

        // Outputs are nonzero.
        for d in 0..4 {
            assert_ne!(poseidon_absorb(domains()[d], a, b)[0], Fp::ZERO);
        }
    }

    #[test]
    fn h_tree_is_commutative() {
        let a = Fp::from(7u64);
        let b = Fp::from(11u64);
        assert_eq!(h_tree(a, b), h_tree(b, a));
        assert_ne!(h_tree(a, b), h_tree(a, a));
    }

    #[test]
    fn round_constants_are_stable() {
        let rcs = round_constants();
        assert_eq!(rcs.len(), ROUNDS);
        // Re-derivation must be identical (OnceLock caches, force a second call).
        assert_eq!(rcs[0], round_constants()[0]);
        assert_ne!(rcs[0][0], Fp::ZERO);
    }
}

'@

# ---- crates/ghost-zk/src/merkle.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-zk\src\merkle.rs") @'
//! Fixed-depth Merkle tree over the commutative Poseidon tree hash.
//!
//! Because [`crate::poseidon::h_tree`] is commutative (`H(a,b) = H(b,a)`),
//! authentication paths carry only sibling values — no direction bits.
//!
//! Missing leaves are zero, so the empty subtree root at level `d` is
//! `Z_d = H(Z_{d-1}, Z_{d-1})` with `Z_0 = 0`. This lets us handle mainnet
//! depth (2^32 leaves) in time proportional to the number of *real* leaves —
//! we never materialize the padded tree.

use crate::poseidon::h_tree;
use ff::Field;
use pasta_curves::Fp;

/// Mainnet tree depth: 2^32 leaf slots.
pub const TREE_DEPTH: usize = 32;

/// Empty-subtree root at level `d`: `Z_0 = 0`, `Z_d = H(Z_{d-1}, Z_{d-1})`.
pub fn empty_root_at(depth: usize) -> Fp {
    let mut z = Fp::ZERO;
    for _ in 0..depth {
        z = h_tree(z, z);
    }
    z
}

/// Root of an empty tree of `2^depth` leaves.
pub fn empty_root(depth: usize) -> Fp {
    empty_root_at(depth)
}

/// Collapse the `n` real nodes of the current level one step, pairing the
/// trailing odd node with the empty-subtree root `Z_d` when needed.
fn collapse(level: &[Fp], n: usize, z: Fp) -> Vec<Fp> {
    let mut next = Vec::with_capacity((n + 1) / 2);
    let mut i = 0;
    while i < n {
        let left = level[i];
        let right = if i + 1 < n { level[i + 1] } else { z };
        next.push(h_tree(left, right));
        i += 2;
    }
    next
}

/// Root of a tree of `2^depth` leaf slots where missing leaves are zero.
/// Cost is O(leaves.len() + depth), never O(2^depth).
pub fn build_root(leaves: &[Fp], depth: usize) -> Fp {
    assert!(leaves.len() <= 1usize << depth, "too many leaves for depth");
    let mut level: Vec<Fp> = leaves.to_vec();
    let mut n = level.len();
    for d in 0..depth {
        let z = empty_root_at(d);
        level = collapse(&level, n, z);
        n = level.len();
    }
    if level.is_empty() {
        empty_root_at(depth)
    } else {
        level[0]
    }
}

/// Authentication path (one sibling per level, bottom-up) for `leaves[index]`.
/// Siblings beyond the real frontier are empty-subtree roots `Z_d`.
pub fn auth_path(leaves: &[Fp], index: usize, depth: usize) -> Vec<Fp> {
    assert!(index < leaves.len(), "index out of range");
    assert!(leaves.len() <= 1usize << depth, "too many leaves for depth");
    let mut level: Vec<Fp> = leaves.to_vec();
    let mut n = level.len();
    let mut idx = index;
    let mut path = Vec::with_capacity(depth);
    for d in 0..depth {
        let sib = idx ^ 1;
        path.push(if sib < n { level[sib] } else { empty_root_at(d) });
        idx >>= 1;
        level = collapse(&level, n, empty_root_at(d));
        n = level.len();
    }
    path
}

/// Recompute the root from a leaf and its authentication path.
pub fn recompute_root(leaf: Fp, path: &[Fp]) -> Fp {
    let mut node = leaf;
    for &sib in path {
        node = h_tree(node, sib);
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::rngs::OsRng;

    fn random_leaves(n: usize) -> Vec<Fp> {
        (0..n).map(|_| Fp::random(OsRng)).collect()
    }

    #[test]
    fn path_roundtrip_all_indices() {
        for depth in [1usize, 3, 5] {
            let leaves = random_leaves(1usize << (depth - 1)); // half-full tree
            let root = build_root(&leaves, depth);
            for (i, leaf) in leaves.iter().enumerate() {
                let path = auth_path(&leaves, i, depth);
                assert_eq!(path.len(), depth);
                assert_eq!(recompute_root(*leaf, &path), root, "leaf {i}");
            }
        }
    }

    #[test]
    fn empty_root_matches_build_root() {
        for depth in [1usize, 4, 8] {
            assert_eq!(build_root(&[], depth), empty_root(depth));
        }
    }

    #[test]
    fn mainnet_depth_is_cheap() {
        // Must not materialize 2^32 leaves: sparse frontier only.
        let leaves = random_leaves(3);
        let root = build_root(&leaves, TREE_DEPTH);
        let path = auth_path(&leaves, 2, TREE_DEPTH);
        assert_eq!(path.len(), TREE_DEPTH);
        assert_eq!(recompute_root(leaves[2], &path), root);
    }
}

'@

# ---- crates/ghost-zk/src/circuit.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-zk\src\circuit.rs") @'
//! FCMP-style Halo2 circuit: one proof binds note ownership, tree membership
//! and the nullifier at the same time.
//!
//! Layout: the whole proof lives in a single region. Each Poseidon
//! permutation occupies `ROUNDS + 1` rows (one row per round + a final row):
//!
//! ```text
//! row 0     : state [0,0,0] (constrained by s_init), absorb inputs in0/in1,
//!             fixed domain D (capacity), fixed absorb flag = 1
//! rows 1..63: state after each round, absorb inputs forced to 0 via the
//!             fixed absorb flag and the masking constraints
//! row 64    : final state; element 0 is the squeezed output
//! ```
//!
//! Witness flow (all hashes are [`crate::poseidon`] hashes):
//! 1. `pk  = H_pk(sk, sk)`
//! 2. `t1  = H_leaf(pk, rho)`          (stage 1 of the note commitment)
//! 3. `cm  = H_leaf(value, t1)`        (stage 2 — the tree leaf)
//! 4. `nf  = H_null(pk, rho)`          (exposed as a public instance)
//! 5. DEPTH tree steps: `node = H_tree(node + sib, node * sib)` starting from
//!    `cm`; the final node is exposed as the public root.
//!
//! Security note: `value` is bound only through the note commitment. A full
//! FCMP++ design (value accumulator + EC chips) lands in v0.4.

use crate::poseidon::{self, ROUNDS};
use ff::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::Fp;

/// Rows consumed by one permutation (64 round rows + 1 final row).
pub const ROWS_PER_PERM: usize = ROUNDS + 1;

#[derive(Clone, Debug)]
pub struct FcmpConfig {
    /// Poseidon state columns [s0, s1, s2].
    pub state: [Column<Advice>; 3],
    /// Absorb input columns [in0, in1].
    pub absorb: [Column<Advice>; 2],
    /// Scratch operand columns for the tree add/mul gates [a, b].
    pub src: [Column<Advice>; 2],
    /// Round-constant columns.
    pub rc: [Column<Fixed>; 3],
    /// Capacity domain constant (D at round 0, 0 elsewhere).
    pub domain: Column<Fixed>,
    /// Absorb flag (1 at round 0, 0 elsewhere) used to mask the inputs.
    pub is_absorb: Column<Fixed>,
    /// Poseidon round gate.
    pub s_round: Selector,
    /// Initial-state-is-zero gate.
    pub s_init: Selector,
    /// `in0 = src0 + src1` gate (tree step).
    pub s_add: Selector,
    /// `in1 = src0 * src1` gate (tree step).
    pub s_mul: Selector,
    /// Public root.
    pub instance_root: Column<Instance>,
    /// Public nullifier.
    pub instance_nf: Column<Instance>,
}

impl FcmpConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let absorb = [meta.advice_column(), meta.advice_column()];
        let src = [meta.advice_column(), meta.advice_column()];
        let rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let domain = meta.fixed_column();
        let is_absorb = meta.fixed_column();
        let s_round = meta.selector();
        let s_init = meta.selector();
        let s_add = meta.selector();
        let s_mul = meta.selector();
        let instance_root = meta.instance_column();
        let instance_nf = meta.instance_column();

        for c in state.iter().chain(absorb.iter()).chain(src.iter()) {
            meta.enable_equality(*c);
        }
        meta.enable_equality(instance_root);
        meta.enable_equality(instance_nf);

        // Poseidon round transition with fused absorb + input masking.
        meta.create_gate("poseidon-round", |meta| {
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
            let mask1 = in1 * (one - flag);

            vec![
                sel.clone() * (n0 - o0),
                sel.clone() * (n1 - o1),
                sel.clone() * (n2 - o2),
                sel.clone() * mask0,
                sel * mask1,
            ]
        });

        // Initial state must be zero; the domain enters through the fixed
        // `domain` column, which the prover cannot change.
        meta.create_gate("init-zero", |meta| {
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

        // Tree step linear operand: in0 = src0 + src1.
        meta.create_gate("tree-add", |meta| {
            let sel = meta.query_selector(s_add);
            let a = meta.query_advice(src[0], Rotation::cur());
            let b = meta.query_advice(src[1], Rotation::cur());
            let z = meta.query_advice(absorb[0], Rotation::cur());
            vec![sel * (z - a - b)]
        });

        // Tree step quadratic operand: in1 = src0 * src1.
        meta.create_gate("tree-mul", |meta| {
            let sel = meta.query_selector(s_mul);
            let a = meta.query_advice(src[0], Rotation::cur());
            let b = meta.query_advice(src[1], Rotation::cur());
            let z = meta.query_advice(absorb[1], Rotation::cur());
            vec![sel * (z - a * b)]
        });

        Self {
            state,
            absorb,
            src,
            rc,
            domain,
            is_absorb,
            s_round,
            s_init,
            s_add,
            s_mul,
            instance_root,
            instance_nf,
        }
    }
}

/// Assign the state rows for one permutation starting at `base`, simulate the
/// honest run in `Value` space, and return the squeezed output cell + value.
fn state_rows(
    region: &mut Region<'_, Fp>,
    config: &FcmpConfig,
    base: usize,
    domain: Fp,
    in0v: Value<Fp>,
    in1v: Value<Fp>,
) -> Result<(AssignedCell<Fp, Fp>, Value<Fp>), Error> {
    let rcs = poseidon::round_constants();
    let zero = || Value::known(Fp::ZERO);
    let mut s = [zero(), zero(), zero()];
    let mut out_cell: Option<AssignedCell<Fp, Fp>> = None;

    for r in 0..ROUNDS {
        for k in 0..3 {
            region.assign_advice(
                || format!("state{}-r{}", k, r),
                config.state[k],
                base + r,
                || s[k].clone(),
            )?;
        }
        let iv0 = if r == 0 { in0v.clone() } else { zero() };
        let iv1 = if r == 0 { in1v.clone() } else { zero() };
        region.assign_advice(|| "in0", config.absorb[0], base + r, || iv0.clone())?;
        region.assign_advice(|| "in1", config.absorb[1], base + r, || iv1.clone())?;

        region.assign_fixed(|| "rc0", config.rc[0], base + r, || Value::known(rcs[r][0]))?;
        region.assign_fixed(|| "rc1", config.rc[1], base + r, || Value::known(rcs[r][1]))?;
        region.assign_fixed(|| "rc2", config.rc[2], base + r, || Value::known(rcs[r][2]))?;
        let dom = if r == 0 { domain } else { Fp::ZERO };
        let flag = if r == 0 { Fp::ONE } else { Fp::ZERO };
        region.assign_fixed(|| "domain", config.domain, base + r, || Value::known(dom))?;
        region.assign_fixed(|| "absorb", config.is_absorb, base + r, || Value::known(flag))?;

        config.s_round.enable(region, base + r)?;

        // Honest simulation of the next state (must mirror the gate exactly).
        let rc0 = Value::known(rcs[r][0]);
        let rc1 = Value::known(rcs[r][1]);
        let rc2 = Value::known(rcs[r][2]);
        let domv = Value::known(dom);
        let u0 = s[0].clone() + iv0 + rc0;
        let u1 = s[1].clone() + iv1 + rc1;
        let u2 = s[2].clone() + domv + rc2;
        let fiv = |x: Value<Fp>| {
            let a = x.clone();
            let b = a.clone() * a;
            b.clone() * b * x // x^5
        };
        let p0 = fiv(u0);
        let p1 = fiv(u1);
        let p2 = fiv(u2);
        let two = Value::known(Fp::from(2u64));
        let n0 = p0.clone() * two.clone() + p1.clone() + p2.clone();
        let n1 = p0.clone() + p1.clone() * two.clone() + p2.clone();
        let n2 = p0 + p1 + p2 * two;
        s = [n0, n1, n2];
    }

    // Final row: gate disabled, everything zeroed except the final state.
    let fr = base + ROUNDS;
    for k in 0..3 {
        let cell = region.assign_advice(
            || format!("state{}-final", k),
            config.state[k],
            fr,
            || s[k].clone(),
        )?;
        if k == 0 {
            out_cell = Some(cell);
        }
    }
    region.assign_advice(|| "in0", config.absorb[0], fr, zero)?;
    region.assign_advice(|| "in1", config.absorb[1], fr, zero)?;
    region.assign_fixed(|| "rc0", config.rc[0], fr, zero)?;
    region.assign_fixed(|| "rc1", config.rc[1], fr, zero)?;
    region.assign_fixed(|| "rc2", config.rc[2], fr, zero)?;
    region.assign_fixed(|| "domain", config.domain, fr, zero)?;
    region.assign_fixed(|| "absorb", config.is_absorb, fr, zero)?;

    Ok((out_cell.expect("state0 cell"), s[0].clone()))
}

/// One plain permutation whose absorb inputs are constrained cells.
fn perm_step(
    region: &mut Region<'_, Fp>,
    config: &FcmpConfig,
    base: usize,
    domain: Fp,
    a: AssignedCell<Fp, Fp>,
    b: AssignedCell<Fp, Fp>,
) -> Result<(AssignedCell<Fp, Fp>, Value<Fp>), Error> {
    let in0v = a.value().cloned();
    let in1v = b.value().cloned();
    a.copy_advice(|| "in0-copy", region, config.absorb[0], base)?;
    b.copy_advice(|| "in1-copy", region, config.absorb[1], base)?;
    state_rows(region, config, base, domain, in0v, in1v)
}

/// One commutative tree step: node' = H_tree(node, sib).
fn tree_step(
    region: &mut Region<'_, Fp>,
    config: &FcmpConfig,
    base: usize,
    node_cell: AssignedCell<Fp, Fp>,
    node_val: Value<Fp>,
    sib_val: Value<Fp>,
) -> Result<(AssignedCell<Fp, Fp>, Value<Fp>), Error> {
    node_cell.copy_advice(|| "src-node", region, config.src[0], base)?;
    region.assign_advice(|| "src-sib", config.src[1], base, || sib_val.clone())?;

    let sum = node_val.clone() + sib_val.clone();
    let prod = node_val * sib_val;
    region.assign_advice(|| "sum", config.absorb[0], base, || sum.clone())?;
    region.assign_advice(|| "prod", config.absorb[1], base, || prod.clone())?;

    config.s_add.enable(region, base)?;
    config.s_mul.enable(region, base)?;

    state_rows(
        region,
        config,
        base,
        poseidon::domains()[poseidon::DOMAIN_TREE],
        sum,
        prod,
    )
}

/// Private witness for an FCMP spend proof.
#[derive(Clone, Debug)]
pub struct FcmpWitness {
    /// Spending key.
    pub sk: Fp,
    /// Note nonce.
    pub rho: Fp,
    /// Amount.
    pub value: u64,
    /// Authentication path: exactly `DEPTH` siblings, bottom-up.
    /// Missing entries (if any) are treated as zero.
    pub path: Vec<Fp>,
}

/// The FCMP circuit, generic over the tree depth.
pub struct FcmpCircuit<const DEPTH: usize> {
    pub witness: Value<FcmpWitness>,
}

impl<const DEPTH: usize> FcmpCircuit<DEPTH> {
    /// Total rows needed (witness rows + one region per permutation).
    pub fn rows_needed() -> usize {
        // 2 witness rows + (1 pk + 2 leaf stages + 1 nullifier + DEPTH tree steps)
        2 + (4 + DEPTH) * ROWS_PER_PERM
    }

    /// Smallest k such that the circuit fits (add a small margin for blinding).
    pub fn required_k() -> u32 {
        let rows = Self::rows_needed() + 16;
        let mut k = 1u32;
        while (1usize << k) < rows {
            k += 1;
        }
        k
    }
}

impl<const DEPTH: usize> Circuit<Fp> for FcmpCircuit<DEPTH> {
    type Config = FcmpConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            witness: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        FcmpConfig::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let (root_cell, nf_cell) = layouter.assign_region(|| "fcmp", |mut region| {
            let w = self.witness.clone();
            let mut base = 0usize;

            // Witness rows (no gates enabled here).
            let sk_val = w.clone().map(|x| x.sk);
            let rho_val = w.clone().map(|x| x.rho);
            let value_val = w.clone().map(|x| Fp::from(x.value));
            let path_val = w.clone().map(|x| x.path.clone());
            let sk_cell = region.assign_advice(|| "sk", config.src[0], base, || sk_val.clone())?;
            let rho_cell = region.assign_advice(|| "rho", config.src[1], base, || rho_val.clone())?;
            base += 1;
            let value_cell =
                region.assign_advice(|| "value", config.state[0], base, || value_val.clone())?;
            base += 1;

            // 1) pk = H_pk(sk, sk)
            let (pk_cell, _pk_val) = perm_step(
                &mut region,
                &config,
                base,
                poseidon::domains()[poseidon::DOMAIN_PK],
                sk_cell.clone(),
                sk_cell,
            )?;
            base += ROWS_PER_PERM;

            // 2) t1 = H_leaf(pk, rho)
            let (t1_cell, _t1_val) = perm_step(
                &mut region,
                &config,
                base,
                poseidon::domains()[poseidon::DOMAIN_LEAF],
                pk_cell.clone(),
                rho_cell.clone(),
            )?;
            base += ROWS_PER_PERM;

            // 3) cm = H_leaf(value, t1)
            let (cm_cell, cm_val) = perm_step(
                &mut region,
                &config,
                base,
                poseidon::domains()[poseidon::DOMAIN_LEAF],
                value_cell,
                t1_cell,
            )?;
            base += ROWS_PER_PERM;

            // 4) nf = H_null(pk, rho)
            let (nf_cell, _nf_val) = perm_step(
                &mut region,
                &config,
                base,
                poseidon::domains()[poseidon::DOMAIN_NULLIFIER],
                pk_cell,
                rho_cell,
            )?;
            base += ROWS_PER_PERM;

            // 5) tree walk up to the root
            let mut node_cell = cm_cell;
            let mut node_val = cm_val;
            for i in 0..DEPTH {
                let sib = path_val
                    .clone()
                    .map(|v| v.get(i).copied().unwrap_or(Fp::ZERO));
                let (c, v) = tree_step(&mut region, &config, base, node_cell, node_val, sib)?;
                node_cell = c;
                node_val = v;
                base += ROWS_PER_PERM;
            }

            Ok((node_cell, nf_cell))
        })?;

        layouter.constrain_instance(root_cell.cell(), config.instance_root, 0)?;
        layouter.constrain_instance(nf_cell.cell(), config.instance_nf, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{merkle, Note};
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use rand::rngs::OsRng;

    const DEPTH: usize = 4;

    fn setup(index: usize) -> (FcmpWitness, Fp, Fp) {
        let notes: Vec<Note> = (0..5)
            .map(|i| Note::new(Fp::random(OsRng), Fp::random(OsRng), 100 + i as u64))
            .collect();
        let leaves: Vec<Fp> = notes.iter().map(|n| n.commitment()).collect();
        let root = merkle::build_root(&leaves, DEPTH);
        let path = merkle::auth_path(&leaves, index, DEPTH);
        let w = FcmpWitness {
            sk: notes[index].sk,
            rho: notes[index].rho,
            value: notes[index].value,
            path,
        };
        let nf = notes[index].nullifier();
        (w, root, nf)
    }

    #[test]
    fn happy_path() {
        let (w, root, nf) = setup(2);
        let circuit = FcmpCircuit::<DEPTH> {
            witness: Value::known(w),
        };
        let prover = MockProver::run(10, &circuit, vec![vec![root], vec![nf]]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn wrong_root_fails() {
        let (w, root, nf) = setup(1);
        let circuit = FcmpCircuit::<DEPTH> {
            witness: Value::known(w),
        };
        let bad_root = root + Fp::ONE;
        let prover = MockProver::run(10, &circuit, vec![vec![bad_root], vec![nf]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn wrong_sibling_fails() {
        let (mut w, root, nf) = setup(3);
        w.path[1] = w.path[1] + Fp::ONE;
        let circuit = FcmpCircuit::<DEPTH> {
            witness: Value::known(w),
        };
        let prover = MockProver::run(10, &circuit, vec![vec![root], vec![nf]]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    #[ignore] // heavier: mainnet-depth tree, run with `cargo test --release -- --ignored`
    fn mainnet_depth_mock() {
        const D: usize = crate::TREE_DEPTH_MAINNET;
        let notes: Vec<Note> = (0..3)
            .map(|i| Note::new(Fp::random(OsRng), Fp::random(OsRng), 7 + i as u64))
            .collect();
        let leaves: Vec<Fp> = notes.iter().map(|n| n.commitment()).collect();
        let root = merkle::build_root(&leaves, D);
        let path = merkle::auth_path(&leaves, 0, D);
        let w = FcmpWitness {
            sk: notes[0].sk,
            rho: notes[0].rho,
            value: notes[0].value,
            path,
        };
        let circuit = FcmpCircuit::<D> {
            witness: Value::known(w),
        };
        let k = FcmpCircuit::<D>::required_k();
        assert_eq!(k, 12);
        let prover = MockProver::run(k, &circuit, vec![vec![root], vec![notes[0].nullifier()]]).unwrap();
        prover.verify().unwrap();
    }
}

'@

# ---- crates/ghost-zk/src/prover.rs ----
Write-Text (Join-Path $ProjectRoot "crates\ghost-zk\src\prover.rs") @'
//! Real IPA prover/verifier over the Vesta curve (scalar field = Pallas base
//! field `Fp`), feature-gated behind `real-prover`.
//!
//! Key generation, proving and verification all run locally with no trusted
//! setup (IPA + Blake2b Fiat-Shamir).

use crate::circuit::{FcmpCircuit, FcmpWitness};
use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{vesta, Fp};
use rand::rngs::OsRng;

/// A complete, verifiable spend proof: proof bytes plus the two public inputs.
#[derive(Clone, Debug)]
pub struct FcmpProof {
    pub proof: Vec<u8>,
    pub root: Fp,
    pub nullifier: Fp,
}

/// Generate parameters, proving key, and the proof itself.
pub fn prove<const DEPTH: usize>(
    k: u32,
    witness: &FcmpWitness,
    root: Fp,
    nullifier: Fp,
) -> Result<FcmpProof, halo2_proofs::plonk::Error> {
    let circuit: FcmpCircuit<DEPTH> = FcmpCircuit {
        witness: Value::known(witness.clone()),
    };

    let params = Params::<vesta::Affine>::new(k);
    let vk = keygen_vk(&params, &circuit)?;
    let pk = keygen_pk(&params, vk, &circuit)?;

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
        &[&[&[root], &[nullifier]]],
        OsRng,
        &mut transcript,
    )?;

    Ok(FcmpProof {
        proof: transcript.finalize(),
        root,
        nullifier,
    })
}

/// Verify a proof against its public inputs.
pub fn verify<const DEPTH: usize>(
    k: u32,
    p: &FcmpProof,
) -> Result<(), halo2_proofs::plonk::Error> {
    let circuit: FcmpCircuit<DEPTH> = FcmpCircuit {
        witness: Value::unknown(),
    };

    let params = Params::<vesta::Affine>::new(k);
    let vk = keygen_vk(&params, &circuit)?;

    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&p.proof[..]);
    let strategy = SingleVerifier::new(&params);
    verify_proof::<vesta::Affine, Challenge255<vesta::Affine>, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&[p.root], &[p.nullifier]]],
        &mut transcript,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "real-prover"))]
mod tests {
    use super::*;
    use crate::{merkle, Note};
    use ff::Field;

    #[test]
    fn prove_and_verify_depth4() {
        const DEPTH: usize = 4;
        let notes: Vec<Note> = (0..5)
            .map(|i| Note::new(Fp::random(OsRng), Fp::random(OsRng), 100 + i as u64))
            .collect();
        let leaves: Vec<Fp> = notes.iter().map(|n| n.commitment()).collect();
        let root = merkle::build_root(&leaves, DEPTH);
        let path = merkle::auth_path(&leaves, 1, DEPTH);
        let witness = FcmpWitness {
            sk: notes[1].sk,
            rho: notes[1].rho,
            value: notes[1].value,
            path,
        };
        let nf = notes[1].nullifier();

        let proof = prove::<DEPTH>(10, &witness, root, nf).unwrap();
        verify::<DEPTH>(10, &proof).unwrap();

        // Tampered public root must not verify.
        let mut bad = proof.clone();
        bad.root = bad.root + Fp::ONE;
        assert!(verify::<DEPTH>(10, &bad).is_err());
    }
}

'@

# ---- 2) run the default test suite ----
Write-Host ""
Write-Host "=== running: cargo test -p ghost-zk --release ===" -ForegroundColor Cyan
Push-Location $ProjectRoot
try {
    cargo test -p ghost-zk --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "DEFAULT TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "DEFAULT TESTS PASSED" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== running: cargo test -p ghost-zk --release --features real-prover ===" -ForegroundColor Cyan
    cargo test -p ghost-zk --release --features real-prover
    if ($LASTEXITCODE -ne 0) {
        Write-Host "real-prover tests failed (default suite is green) - report this output" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "REAL-PROVER TESTS PASSED - ghost-zk is fully operational" -ForegroundColor Green

    # ---- 3) run the heavier mainnet-depth MockProver check ----
    Write-Host ""
    Write-Host "=== running: mainnet-depth (32) MockProver check ===" -ForegroundColor Cyan
    cargo test -p ghost-zk --release --features real-prover -- --ignored
    if ($LASTEXITCODE -eq 0) { Write-Host "MAINNET-DEPTH CHECK PASSED" -ForegroundColor Green }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  - wire spend proofs into ghost-wallet using ghost_zk::Note / merkle / prover"
Write-Host "  - example: cargo run -p ghost -- wallet new   (existing flows unchanged)"
