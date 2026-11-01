//! Monerod-facing CLSAG verification (WG-CLSAG WP-B).
//!
//! Real, byte-compatible verification of Monero CLSAG ring signatures from
//! monerod data, so the Ghost side can cryptographically confirm the Monero
//! legs of atomic swaps (lock / claim / refund). Normative reference is the
//! Monero implementation, not the paper text (docs/WG-CLSAG-verify-scope.md
//! section 5):
//!
//! - monero/src/ringct/rctSigs.cpp: `verRctCLSAGSimple`, `get_pre_mlsag_hash`
//! - monero/src/ringct/rctTypes.h: `clsag` struct, RCTTypeCLSAG = 5,
//!   RCTTypeBulletproofPlus = 6
//! - monero/src/crypto/crypto-ops.c: `ge_fromfe_frombytes_vartime`
//! - monero/src/ringct/rctOps.cpp: `hash_to_p3`, `hash_to_scalar`
//! - domain tags (monero/src/cryptonote_config.h): `CLSAG_agg_0`,
//!   `CLSAG_agg_1`, `CLSAG_round`
//!
//! Verification only: this module does not sign monerod CLSAGs and does not
//! touch the bridge-internal adaptor primitive in [`crate::clsag`]. The
//! hash-to-point here is monero's elligator map (`ge_fromfe_frombytes_vartime`
//! on the key image), NOT the blake3 try-and-increment of the v0.3 primitive.
//!
//! Fail-closed structural checks before any cryptographic work: scalars must
//! be canonical (< l), points must decompress, key image and auxiliary image
//! must not be degenerate (identity / small order), ring size must be >= 2,
//! the parsed lengths must consume the signature buffer exactly, and unknown
//! tx types are rejected instead of guessed.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha3::{Digest, Keccak256};

// ---------------------------------------------------------------------------
// Pinned constants (monero/src/cryptonote_config.h + rctTypes.h)
// ---------------------------------------------------------------------------

/// rctTypes.h: RCTTypeCLSAG.
pub const RCT_TYPE_CLSAG: u8 = 5;
/// rctTypes.h: RCTTypeBulletproofPlus.
pub const RCT_TYPE_BULLETPROOF_PLUS: u8 = 6;

pub(crate) const HASH_KEY_CLSAG_AGG_0: &[u8] = b"CLSAG_agg_0";
pub(crate) const HASH_KEY_CLSAG_AGG_1: &[u8] = b"CLSAG_agg_1";
pub(crate) const HASH_KEY_CLSAG_ROUND: &[u8] = b"CLSAG_round";

// Field constants of monero's ge_fromfe_frombytes_vartime
// (monero/src/crypto/crypto-ops-data.c), as 32-byte little-endian values mod
// p = 2^255 - 19. Each was validated against its defining identity:
// sqrtm1^2 = -1, ma = -486662, ma2 = -486662^2,
// fffb1^2 = -2A(A+2), fffb2^2 = +2A(A+2),
// fffb3^2 = -i*A(A+2), fffb4^2 = +i*A(A+2).
const FE_SQRTM1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];
const FE_MA_BYTES: [u8; 32] = [
    0xe7, 0x92, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
const FE_MA2_BYTES: [u8; 32] = [
    0xc9, 0xe3, 0x3d, 0xdb, 0xc8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];
const FE_FFFB1_BYTES: [u8; 32] = [
    0xee, 0x41, 0x1c, 0x32, 0x75, 0x69, 0xa7, 0x22, 0x8d, 0x73, 0x2a, 0xb9, 0xa8, 0x04, 0x94, 0xd1,
    0xe3, 0x19, 0xfb, 0x41, 0x37, 0xc5, 0xa9, 0x20, 0x17, 0x1b, 0xd6, 0xda, 0xef, 0xfb, 0x71, 0x7e,
];
const FE_FFFB2_BYTES: [u8; 32] = [
    0xe0, 0x9a, 0x7c, 0x60, 0x83, 0x64, 0xde, 0xd2, 0xdf, 0xf7, 0x56, 0x04, 0x46, 0x03, 0xde, 0x51,
    0xbe, 0x5f, 0x16, 0xc0, 0xb7, 0x51, 0xd4, 0x91, 0xf6, 0x2c, 0x5a, 0x04, 0x0a, 0x1e, 0x06, 0x4d,
];
const FE_FFFB3_BYTES: [u8; 32] = [
    0x66, 0x2c, 0x30, 0x17, 0x87, 0x7d, 0x1b, 0x58, 0x29, 0x42, 0x96, 0xa5, 0x4e, 0xff, 0x24, 0x40,
    0xed, 0xa2, 0x0d, 0x3f, 0x40, 0x46, 0x95, 0xb8, 0xef, 0x08, 0xc2, 0x14, 0x0d, 0x11, 0x4a, 0x67,
];
const FE_FFFB4_BYTES: [u8; 32] = [
    0x86, 0x91, 0xb3, 0xb6, 0x03, 0x19, 0x3d, 0x85, 0x49, 0x4a, 0x3f, 0xa1, 0x08, 0xfc, 0x46, 0xee,
    0x2e, 0x43, 0xf7, 0x7e, 0x88, 0xf4, 0xc0, 0x26, 0xf9, 0xdb, 0x67, 0x10, 0x03, 0xf3, 0x43, 0x1a,
];

fn fe_one() -> Fe {
    Fe::one()
}

fn fe_sqrtm1() -> Fe {
    Fe::from_bytes(&FE_SQRTM1_BYTES)
}

fn fe_ma() -> Fe {
    Fe::from_bytes(&FE_MA_BYTES)
}

fn fe_ma2() -> Fe {
    Fe::from_bytes(&FE_MA2_BYTES)
}

fn fe_fffb1() -> Fe {
    Fe::from_bytes(&FE_FFFB1_BYTES)
}

fn fe_fffb2() -> Fe {
    Fe::from_bytes(&FE_FFFB2_BYTES)
}

fn fe_fffb3() -> Fe {
    Fe::from_bytes(&FE_FFFB3_BYTES)
}

fn fe_fffb4() -> Fe {
    Fe::from_bytes(&FE_FFFB4_BYTES)
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// cn_fast_hash: monero's Keccak-256 (legacy 0x01 padding, not SHA3-256).
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let d = Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// hash_to_scalar over a raw byte buffer: keccak256 then sc_reduce32
/// (rctOps.cpp `hash_to_scalar`).
pub(crate) fn hash_to_scalar(data: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak256(data))
}

/// 32-byte slot holding a domain tag at offset 0, zero padding after
/// (rctSigs.cpp: `sc_0(buf); memcpy(buf, TAG, sizeof(TAG)-1);`).
pub(crate) fn tag_slot(tag: &[u8]) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[..tag.len()].copy_from_slice(tag);
    slot
}

// ---------------------------------------------------------------------------
// fe / hash-to-point (monero crypto-ops.c ge_fromfe_frombytes_vartime)
// ---------------------------------------------------------------------------

/// Minimal fe25519 arithmetic (5 x 51-bit limbs) backing monero's
/// `ge_fromfe_frombytes_vartime` port. curve25519-dalek 4.1.3 keeps its
/// field backend `pub(crate)`, so the field is implemented here. All
/// operations are mod p = 2^255 - 19; correctness is pinned by the
/// constant-identity tests, the independent known-answer vectors of
/// `hash_to_point` and the real-mainnet fixture tests.
#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

const FE_MASK: u64 = (1u64 << 51) - 1;
/// 2p per-limb (for subtraction without underflow).
const FE_2P: [u64; 5] = [
    0x000F_FFFF_FFFF_FFDA,
    0x000F_FFFF_FFFF_FFFE,
    0x000F_FFFF_FFFF_FFFE,
    0x000F_FFFF_FFFF_FFFE,
    0x000F_FFFF_FFFF_FFFE,
];

impl Fe {
    fn zero() -> Self {
        Fe([0; 5])
    }

    fn one() -> Self {
        let mut l = [0u64; 5];
        l[0] = 1;
        Fe(l)
    }

    fn from_bytes(b: &[u8; 32]) -> Self {
        let ld = |s: usize| {
            let mut v = 0u64;
            for i in 0..8 {
                v |= u64::from(b[s + i]) << (8 * i);
            }
            v
        };
        let mut r = Fe([
            ld(0) & FE_MASK,
            (ld(6) >> 3) & FE_MASK,
            (ld(12) >> 6) & FE_MASK,
            (ld(19) >> 1) & FE_MASK,
            (ld(24) >> 12) & FE_MASK,
        ]);
        // monero fe_frombytes reduces the full 32-byte input mod p:
        // bit 255 folds back as 2^255 == 19 (mod p).
        if b[31] & 0x80 != 0 {
            r.0[0] += 19;
        }
        r
    }

    fn to_bytes(self) -> [u8; 32] {
        // carry-normalize limbs first: the quotient chain below is only
        // exact for limbs < 2^51 + small (dalek-style invariant)
        let mut l = Fe(self.0).carry().0;
        // full canonical reduction
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= FE_MASK;
        l[2] += l[1] >> 51;
        l[1] &= FE_MASK;
        l[3] += l[2] >> 51;
        l[2] &= FE_MASK;
        l[4] += l[3] >> 51;
        l[3] &= FE_MASK;
        // discard the top carry: it represents 2^255*q, already accounted
        // for by the +19q above (r = h + 19q - 2^255*q = h - p*q)
        l[4] &= FE_MASK;
        // pack 5 x 51 bits into 32 little-endian bytes
        let w0 = l[0] | (l[1] << 51);
        let w1 = (l[1] >> 13) | (l[2] << 38);
        let w2 = (l[2] >> 26) | (l[3] << 25);
        let w3 = (l[3] >> 39) | (l[4] << 12);
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    fn add(&self, o: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for (dst, (a, b)) in r.iter_mut().zip(self.0.iter().zip(o.0.iter())) {
            *dst = a + b;
        }
        Fe(r)
    }

    fn sub(&self, o: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + FE_2P[i] - o.0[i];
        }
        Fe(r).carry()
    }

    /// One carry-propagation round (keeps limbs < 2^52 + epsilon).
    fn carry(mut self) -> Fe {
        for _ in 0..2 {
            let c0 = self.0[0] >> 51;
            let c1 = self.0[1] >> 51;
            let c2 = self.0[2] >> 51;
            let c3 = self.0[3] >> 51;
            let c4 = self.0[4] >> 51;
            self.0[0] &= FE_MASK;
            self.0[1] &= FE_MASK;
            self.0[2] &= FE_MASK;
            self.0[3] &= FE_MASK;
            self.0[4] &= FE_MASK;
            self.0[1] += c0;
            self.0[2] += c1;
            self.0[3] += c2;
            self.0[4] += c3;
            self.0[0] += c4 * 19;
        }
        self
    }

    fn mul(&self, o: &Fe) -> Fe {
        let a = &self.0;
        let b = &o.0;
        let b1_19 = u128::from(b[1]) * 19;
        let b2_19 = u128::from(b[2]) * 19;
        let b3_19 = u128::from(b[3]) * 19;
        let b4_19 = u128::from(b[4]) * 19;
        let a0 = u128::from(a[0]);
        let a1 = u128::from(a[1]);
        let a2 = u128::from(a[2]);
        let a3 = u128::from(a[3]);
        let a4 = u128::from(a[4]);
        let b0 = u128::from(b[0]);
        let b1 = u128::from(b[1]);
        let b2 = u128::from(b[2]);
        let b3 = u128::from(b[3]);
        let b4 = u128::from(b[4]);

        let mut c = [0u128; 5];
        c[0] = a0 * b0 + a4 * b1_19 + a3 * b2_19 + a2 * b3_19 + a1 * b4_19;
        c[1] = a1 * b0 + a0 * b1 + a4 * b2_19 + a3 * b3_19 + a2 * b4_19;
        c[2] = a2 * b0 + a1 * b1 + a0 * b2 + a4 * b3_19 + a3 * b4_19;
        c[3] = a3 * b0 + a2 * b1 + a1 * b2 + a0 * b3 + a4 * b4_19;
        c[4] = a4 * b0 + a3 * b1 + a2 * b2 + a1 * b3 + a0 * b4;

        let mut r = [0u64; 5];
        let mut carry: u128 = 0;
        for i in 0..5 {
            let v = c[i] + carry;
            r[i] = (v & u128::from(FE_MASK)) as u64;
            carry = v >> 51;
        }
        // fold the top carry back: 2^255 == 19 (mod p); done in u128 space
        // so the x19 product can never overflow
        let mut v = carry * 19;
        let mut idx = 0;
        while v > 0 && idx < 5 {
            let t = u128::from(r[idx]) + v;
            r[idx] = (t & u128::from(FE_MASK)) as u64;
            v = t >> 51;
            idx += 1;
        }
        if v > 0 {
            r[0] += (v * 19) as u64;
        }
        Fe(r).carry()
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    fn negate(&self) -> Fe {
        Fe::zero().sub(self)
    }

    /// Square-and-multiply over a 256-bit little-endian exponent.
    fn pow_bytes(&self, exp: &[u8; 32]) -> Fe {
        let mut r = Fe::one();
        for byte_idx in (0..32).rev() {
            for bit in (0..8).rev() {
                r = r.square();
                if (exp[byte_idx] >> bit) & 1 == 1 {
                    r = r.mul(self);
                }
            }
        }
        r
    }

    /// x^(p-2).
    fn invert(&self) -> Fe {
        let mut e = [0xffu8; 32];
        e[0] = 0xeb; // p - 2, little-endian
        e[31] = 0x7f;
        self.pow_bytes(&e)
    }

    fn is_negative(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    fn is_nonzero(&self) -> bool {
        self.to_bytes() != [0u8; 32]
    }
}

impl std::ops::Add for Fe {
    type Output = Fe;
    fn add(self, o: Fe) -> Fe {
        Fe::add(&self, &o)
    }
}

impl std::ops::Sub for Fe {
    type Output = Fe;
    fn sub(self, o: Fe) -> Fe {
        Fe::sub(&self, &o)
    }
}

impl std::ops::Mul for Fe {
    type Output = Fe;
    fn mul(self, o: Fe) -> Fe {
        Fe::mul(&self, &o)
    }
}

impl std::ops::Neg for Fe {
    type Output = Fe;
    fn neg(self) -> Fe {
        self.negate()
    }
}

/// fe_pow22523: raise to the power (p-5)/8 = 2^252 - 3.
fn fe_pow22523(x: &Fe) -> Fe {
    let mut e = [0xffu8; 32];
    e[0] = 0xfd; // (p-5)/8 = 2^252 - 3, little-endian
    e[31] = 0x0f;
    x.pow_bytes(&e)
}

/// fe_divpowm1(u, v) = u * v^3 * (u*v^7)^((p-5)/8).
fn fe_divpowm1(u: &Fe, v: &Fe) -> Fe {
    let v3 = v.square() * *v;
    let uv7 = v3.square() * *v * *u;
    *u * v3 * fe_pow22523(&uv7)
}

fn fe_is_negative(x: &Fe) -> bool {
    x.is_negative()
}

fn fe_is_nonzero(x: &Fe) -> bool {
    x.is_nonzero()
}

/// monero `ge_fromfe_frombytes_vartime`: elligator-style map of a 32-byte
/// field element onto the curve, byte-compatible with crypto-ops.c. The
/// output is always a valid curve point (the C function asserts this).
pub fn ge_fromfe_frombytes_vartime(s: &[u8; 32]) -> EdwardsPoint {
    let u = Fe::from_bytes(s);
    let v = u.square() + u.square(); // 2 * u^2
    let w = v + fe_one(); // 2 * u^2 + 1
    let x = w.square() + fe_ma2() * v; // w^2 - A^2 * 2u^2
    let mut rx = fe_divpowm1(&w, &x);
    // y = X^2; x = X^2 * x_orig
    let x_sq = rx.square();
    let mut x = x_sq * x;
    let mut sign = 0u8;
    let y = w - x;
    let z;
    if fe_is_nonzero(&y) {
        let y2 = w + x;
        if fe_is_nonzero(&y2) {
            // negative branch: x *= sqrt(-1); z stays -A; no u factor
            x = x * fe_sqrtm1();
            let y3 = w - x;
            if fe_is_nonzero(&y3) {
                rx = rx * fe_fffb3();
            } else {
                rx = rx * fe_fffb4();
            }
            z = fe_ma();
            sign = 1;
        } else {
            rx = rx * fe_fffb1() * u;
            z = fe_ma() * v;
        }
    } else {
        rx = rx * fe_fffb2() * u;
        z = fe_ma() * v;
    }
    if fe_is_negative(&rx) != (sign == 1) {
        rx = -rx;
    }
    let z_out = z + w;
    let y_out = z - w;
    let x_out = rx * z_out;
    // Projective (X:Y:Z) -> compressed affine Edwards point.
    let z_inv = z_out.invert();
    let xa = x_out * z_inv;
    let ya = y_out * z_inv;
    let mut comp = ya.to_bytes();
    if fe_is_negative(&xa) {
        comp[31] |= 0x80;
    }
    CompressedEdwardsY(comp)
        .decompress()
        .expect("ge_fromfe_frombytes_vartime output is a curve point")
}

/// rctOps.cpp `hash_to_p3`: keccak256 of the key, elligator map, then
/// clear the cofactor ([8]P) — the scaling monero folds into this helper.
pub fn hash_to_p3(k: &[u8; 32]) -> EdwardsPoint {
    let h = keccak256(k);
    ge_fromfe_frombytes_vartime(&h).mul_by_cofactor()
}

// ---------------------------------------------------------------------------
// Transaction binary format (monero transaction.h serialization)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnexpectedEof,
    VarintTooLong,
    UnsupportedVersion(u64),
    UnsupportedInputType(u64),
    UnsupportedOutputType(u64),
    UnsupportedRctType(u64),
    SignatureCountMismatch,
    /// Input with an empty key_offsets list (ring size 0).
    RingSizeMismatch,
    BulletproofShape,
    EmptyInputs,
    EmptyOutputs,
    TrailingBytes,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnexpectedEof => write!(f, "unexpected end of tx blob"),
            ParseError::VarintTooLong => write!(f, "varint encoding too long"),
            ParseError::UnsupportedVersion(v) => write!(f, "unsupported tx version {v}"),
            ParseError::UnsupportedInputType(t) => write!(f, "unsupported txin type {t}"),
            ParseError::UnsupportedOutputType(t) => write!(f, "unsupported txout type {t}"),
            ParseError::UnsupportedRctType(t) => write!(f, "unsupported rct type {t}"),
            ParseError::SignatureCountMismatch => write!(f, "CLSAG count != input count"),
            ParseError::RingSizeMismatch => write!(f, "input with empty ring (ring size 0)"),
            ParseError::BulletproofShape => write!(f, "malformed bulletproof shape"),
            ParseError::EmptyInputs => write!(f, "tx has no inputs"),
            ParseError::EmptyOutputs => write!(f, "tx has no outputs"),
            ParseError::TrailingBytes => write!(f, "trailing bytes after signature buffer"),
        }
    }
}

impl std::error::Error for ParseError {}

/// txin_to_key (amount is 0 for ringct inputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub amount: u64,
    /// Relative output offsets; absolute = prefix sum.
    pub key_offsets: Vec<u64>,
    pub k_image: [u8; 32],
}

/// txout_to_key (type 2) or txout_to_tagged_key (type 3, view tags since
/// HF16) output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub amount: u64,
    /// Output target type: 2 = txout_to_key, 3 = txout_to_tagged_key.
    pub target_type: u8,
    pub key: [u8; 32],
    /// One-byte view tag, present for txout_to_tagged_key only.
    pub view_tag: Option<u8>,
}

/// monero Bulletproof (RCTTypeCLSAG range proof), prunable section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulletproofData {
    pub a: [u8; 32],
    pub s: [u8; 32],
    pub t1: [u8; 32],
    pub t2: [u8; 32],
    pub taux: [u8; 32],
    pub mu: [u8; 32],
    pub l: Vec<[u8; 32]>,
    pub r: Vec<[u8; 32]>,
    pub a_amt: [u8; 32],
    pub b_amt: [u8; 32],
    pub t_amt: [u8; 32],
}

/// monero BulletproofPlus (RCTTypeBulletproofPlus range proof).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulletproofPlusData {
    pub a: [u8; 32],
    pub a1: [u8; 32],
    pub b: [u8; 32],
    pub r1: [u8; 32],
    pub s1: [u8; 32],
    pub d1: [u8; 32],
    pub l: Vec<[u8; 32]>,
    pub r: Vec<[u8; 32]>,
}

/// Parsed CLSAG signature section. The key image `I` is not serialized in
/// the tx (rctTypes.h: "not serialized, it can be reconstructed"); it is
/// reconstructed from the matching `vin` entry at verify time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClsagSig {
    pub s: Vec<[u8; 32]>,
    pub c1: [u8; 32],
    pub d: [u8; 32],
}

/// A parsed Monero ringct transaction (v2, RCTTypeCLSAG / BulletproofPlus).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoneroTx {
    pub version: u64,
    pub unlock_time: u64,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub extra: Vec<u8>,
    pub rct_type: u8,
    pub fee: u64,
    /// outPk commitments (mask leg only; dest is not serialized).
    pub out_pks: Vec<[u8; 32]>,
    /// Compressed ecdhInfo amounts (8 bytes each, BP2+ wire format).
    pub ecdh_amounts: Vec<[u8; 8]>,
    pub bulletproofs: Vec<BulletproofData>,
    pub bulletproofs_plus: Vec<BulletproofPlusData>,
    pub clsags: Vec<ClsagSig>,
    pub pseudo_outs: Vec<[u8; 32]>,
    raw: Vec<u8>,
    prefix_len: usize,
    rct_base_len: usize,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.buf.len() - self.pos < n {
            return Err(ParseError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn varint(&mut self) -> Result<u64, ParseError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.take(1)?[0];
            if shift >= 64 {
                return Err(ParseError::VarintTooLong);
            }
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    fn key32(&mut self) -> Result<[u8; 32], ParseError> {
        let mut k = [0u8; 32];
        k.copy_from_slice(self.take(32)?);
        Ok(k)
    }

    fn key_vec(&mut self) -> Result<Vec<[u8; 32]>, ParseError> {
        let n = self.varint()? as usize;
        let mut v = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            v.push(self.key32()?);
        }
        Ok(v)
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

impl MoneroTx {
    /// Parse a full (unpruned) monero tx blob. Only version 2 ringct
    /// transactions with RCTTypeCLSAG (5) or RCTTypeBulletproofPlus (6) are
    /// accepted; everything else is rejected, never guessed. The whole
    /// buffer must be consumed exactly.
    pub fn parse(blob: &[u8]) -> Result<MoneroTx, ParseError> {
        let mut r = Reader::new(blob);
        let version = r.varint()?;
        if version != 2 {
            return Err(ParseError::UnsupportedVersion(version));
        }
        let unlock_time = r.varint()?;

        // vin
        let n_vin = r.varint()? as usize;
        if n_vin == 0 {
            return Err(ParseError::EmptyInputs);
        }
        let mut vin = Vec::with_capacity(n_vin.min(1024));
        for _ in 0..n_vin {
            let t = r.varint()?;
            if t != 2 {
                return Err(ParseError::UnsupportedInputType(t));
            }
            let amount = r.varint()?;
            let n_offsets = r.varint()? as usize;
            if n_offsets == 0 {
                return Err(ParseError::RingSizeMismatch);
            }
            let mut key_offsets = Vec::with_capacity(n_offsets.min(4096));
            for _ in 0..n_offsets {
                key_offsets.push(r.varint()?);
            }
            let k_image = r.key32()?;
            vin.push(TxIn {
                amount,
                key_offsets,
                k_image,
            });
        }

        // vout
        let n_vout = r.varint()? as usize;
        if n_vout == 0 {
            return Err(ParseError::EmptyOutputs);
        }
        let mut vout = Vec::with_capacity(n_vout.min(1024));
        for _ in 0..n_vout {
            let amount = r.varint()?;
            let t = r.varint()?;
            // 2 = txout_to_key, 3 = txout_to_tagged_key (key then view tag,
            // cryptonote_basic.h txout_to_tagged_key serialization order)
            let (key, view_tag) = match t {
                2 => (r.key32()?, None),
                3 => {
                    let key = r.key32()?;
                    let mut tag = [0u8; 1];
                    tag.copy_from_slice(r.take(1)?);
                    (key, Some(tag[0]))
                }
                _ => return Err(ParseError::UnsupportedOutputType(t)),
            };
            vout.push(TxOut {
                amount,
                target_type: t as u8,
                key,
                view_tag,
            });
        }

        // extra
        let extra_len = r.varint()? as usize;
        let extra = r.take(extra_len)?.to_vec();

        let prefix_len = r.pos;

        // rct_signatures base (rctTypes.h serialize_rctsig_base)
        let rct_type = r.varint()?;
        if rct_type != u64::from(RCT_TYPE_CLSAG) && rct_type != u64::from(RCT_TYPE_BULLETPROOF_PLUS)
        {
            return Err(ParseError::UnsupportedRctType(rct_type));
        }
        let fee = r.varint()?;

        // rct base (serialize_rctsig_base): ecdhInfo first, then outPk.
        // Neither carries a size prefix in the binary format — both counts
        // are the tx output count, known from vout.
        let mut ecdh_amounts = Vec::with_capacity(n_vout);
        for _ in 0..n_vout {
            let mut a = [0u8; 8];
            a.copy_from_slice(r.take(8)?);
            ecdh_amounts.push(a);
        }
        let mut out_pks = Vec::with_capacity(n_vout);
        for _ in 0..n_vout {
            out_pks.push(r.key32()?);
        }

        let rct_base_len = r.pos - prefix_len;

        // rctsig_prunable
        let mut bulletproofs = Vec::new();
        let mut bulletproofs_plus = Vec::new();
        if rct_type == u64::from(RCT_TYPE_BULLETPROOF_PLUS) {
            let nbp = r.varint()? as usize;
            if nbp == 0 || nbp > n_vout {
                return Err(ParseError::BulletproofShape);
            }
            for _ in 0..nbp {
                let a = r.key32()?;
                let a1 = r.key32()?;
                let b = r.key32()?;
                let r1 = r.key32()?;
                let s1 = r.key32()?;
                let d1 = r.key32()?;
                let l = r.key_vec()?;
                let rr = r.key_vec()?;
                if l.is_empty() || l.len() != rr.len() || (1u128 << l.len()) < 64 * n_vout as u128 {
                    return Err(ParseError::BulletproofShape);
                }
                bulletproofs_plus.push(BulletproofPlusData {
                    a,
                    a1,
                    b,
                    r1,
                    s1,
                    d1,
                    l,
                    r: rr,
                });
            }
        } else {
            let nbp = r.varint()? as usize;
            if nbp == 0 || nbp > n_vout {
                return Err(ParseError::BulletproofShape);
            }
            for _ in 0..nbp {
                let a = r.key32()?;
                let s = r.key32()?;
                let t1 = r.key32()?;
                let t2 = r.key32()?;
                let taux = r.key32()?;
                let mu = r.key32()?;
                let l = r.key_vec()?;
                let rr = r.key_vec()?;
                if l.is_empty() || l.len() != rr.len() || (1u128 << l.len()) < 64 * n_vout as u128 {
                    return Err(ParseError::BulletproofShape);
                }
                let a_amt = r.key32()?;
                let b_amt = r.key32()?;
                let t_amt = r.key32()?;
                bulletproofs.push(BulletproofData {
                    a,
                    s,
                    t1,
                    t2,
                    taux,
                    mu,
                    l,
                    r: rr,
                    a_amt,
                    b_amt,
                    t_amt,
                });
            }
        }

        // CLSAGs: exactly one per input; every array size below is implied
        // by the tx structure, not serialized: CLSAG count = vin count, each
        // s size = vin[0] ring size (cryptonote_basic.h derives mixin from
        // vin[0].key_offsets.len() - 1), pseudoOuts count = vin count.
        let ring_size = vin[0].key_offsets.len();
        let mut clsags = Vec::with_capacity(n_vin);
        for _ in 0..n_vin {
            let mut s = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                s.push(r.key32()?);
            }
            let c1 = r.key32()?;
            let d = r.key32()?;
            clsags.push(ClsagSig { s, c1, d });
        }

        // pseudoOuts: one 32-byte commitment per input
        let mut pseudo_outs = Vec::with_capacity(n_vin);
        for _ in 0..n_vin {
            pseudo_outs.push(r.key32()?);
        }

        if r.pos != blob.len() {
            return Err(ParseError::TrailingBytes);
        }

        Ok(MoneroTx {
            version,
            unlock_time,
            vin,
            vout,
            extra,
            rct_type: rct_type as u8,
            fee,
            out_pks,
            ecdh_amounts,
            bulletproofs,
            bulletproofs_plus,
            clsags,
            pseudo_outs,
            raw: blob.to_vec(),
            prefix_len,
            rct_base_len,
        })
    }

    /// Raw tx blob as parsed.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Serialized transaction prefix (version..extra): what monero's
    /// `get_transaction_prefix_hash` hashes.
    pub fn prefix_bytes(&self) -> &[u8] {
        &self.raw[..self.prefix_len]
    }

    /// Serialized rct signature base (type..ecdhInfo): what
    /// `serialize_rctsig_base` re-serializes for `get_pre_mlsag_hash`.
    pub fn rct_base_bytes(&self) -> &[u8] {
        &self.raw[self.prefix_len..self.prefix_len + self.rct_base_len]
    }

    /// Monero v2 transaction hash:
    /// keccak( keccak(prefix) || keccak(rct_base) || keccak(prunable) ) —
    /// the same three-chunk structure monerod uses (pruned and full txs
    /// hash identically). Verified against live mainnet data.
    pub fn tx_hash(&self) -> [u8; 32] {
        let prunable_start = self.prefix_len + self.rct_base_len;
        let mut msg = [0u8; 96];
        msg[..32].copy_from_slice(&keccak256(&self.raw[..self.prefix_len]));
        msg[32..64].copy_from_slice(&keccak256(&self.raw[self.prefix_len..prunable_start]));
        msg[64..].copy_from_slice(&keccak256(&self.raw[prunable_start..]));
        keccak256(&msg)
    }

    /// Absolute output indices per input (prefix sum of key_offsets).
    pub fn absolute_offsets(&self) -> Vec<Vec<u64>> {
        self.vin
            .iter()
            .map(|i| {
                let mut acc = 0u64;
                i.key_offsets
                    .iter()
                    .map(|d| {
                        acc += d;
                        acc
                    })
                    .collect::<Vec<u64>>()
            })
            .collect()
    }

    /// Byte-exact re-serialization from parsed fields (WG-CLSAG section 6
    /// byte-compat pin): must reproduce the original blob exactly.
    pub fn re_serialize(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(self.raw.len());
        write_varint(&mut o, self.version);
        write_varint(&mut o, self.unlock_time);
        write_varint(&mut o, self.vin.len() as u64);
        for i in &self.vin {
            write_varint(&mut o, 2); // txin_to_key
            write_varint(&mut o, i.amount);
            write_varint(&mut o, i.key_offsets.len() as u64);
            for off in &i.key_offsets {
                write_varint(&mut o, *off);
            }
            o.extend_from_slice(&i.k_image);
        }
        write_varint(&mut o, self.vout.len() as u64);
        for t in &self.vout {
            write_varint(&mut o, t.amount);
            write_varint(&mut o, u64::from(t.target_type));
            o.extend_from_slice(&t.key);
            if let Some(tag) = t.view_tag {
                o.push(tag);
            }
        }
        write_varint(&mut o, self.extra.len() as u64);
        o.extend_from_slice(&self.extra);

        // rct base: ecdhInfo then outPk, no size prefixes (counts are the
        // tx output count)
        write_varint(&mut o, u64::from(self.rct_type));
        write_varint(&mut o, self.fee);
        for e in &self.ecdh_amounts {
            o.extend_from_slice(e);
        }
        for pk in &self.out_pks {
            o.extend_from_slice(pk);
        }

        // prunable
        if self.rct_type == RCT_TYPE_BULLETPROOF_PLUS {
            write_varint(&mut o, self.bulletproofs_plus.len() as u64);
            for bp in &self.bulletproofs_plus {
                o.extend_from_slice(&bp.a);
                o.extend_from_slice(&bp.a1);
                o.extend_from_slice(&bp.b);
                o.extend_from_slice(&bp.r1);
                o.extend_from_slice(&bp.s1);
                o.extend_from_slice(&bp.d1);
                write_varint(&mut o, bp.l.len() as u64);
                for k in &bp.l {
                    o.extend_from_slice(k);
                }
                write_varint(&mut o, bp.r.len() as u64);
                for k in &bp.r {
                    o.extend_from_slice(k);
                }
            }
        } else {
            write_varint(&mut o, self.bulletproofs.len() as u64);
            for bp in &self.bulletproofs {
                o.extend_from_slice(&bp.a);
                o.extend_from_slice(&bp.s);
                o.extend_from_slice(&bp.t1);
                o.extend_from_slice(&bp.t2);
                o.extend_from_slice(&bp.taux);
                o.extend_from_slice(&bp.mu);
                write_varint(&mut o, bp.l.len() as u64);
                for k in &bp.l {
                    o.extend_from_slice(k);
                }
                write_varint(&mut o, bp.r.len() as u64);
                for k in &bp.r {
                    o.extend_from_slice(k);
                }
                o.extend_from_slice(&bp.a_amt);
                o.extend_from_slice(&bp.b_amt);
                o.extend_from_slice(&bp.t_amt);
            }
        }
        for c in &self.clsags {
            for k in &c.s {
                o.extend_from_slice(k);
            }
            o.extend_from_slice(&c.c1);
            o.extend_from_slice(&c.d);
        }
        for p in &self.pseudo_outs {
            o.extend_from_slice(p);
        }
        o
    }
}

// ---------------------------------------------------------------------------
// get_pre_mlsag_hash (rctSigs.cpp) — the CLSAG message
// ---------------------------------------------------------------------------

/// monero `get_pre_mlsag_hash` for RCTTypeCLSAG / BulletproofPlus:
/// keccak( keccak(tx_prefix) || keccak(rct_sig_base) || keccak(range-proof
/// fields) ). The range-proof field order is pinned from rctSigs.cpp
/// (V excluded — expanded from outPk.mask, already hashed in the base).
pub fn pre_mlsag_hash(tx: &MoneroTx) -> [u8; 32] {
    let h0 = keccak256(tx.prefix_bytes());
    let h1 = keccak256(tx.rct_base_bytes());
    let mut kv: Vec<u8> = Vec::new();
    if tx.rct_type == RCT_TYPE_BULLETPROOF_PLUS {
        for bp in &tx.bulletproofs_plus {
            kv.extend_from_slice(&bp.a);
            kv.extend_from_slice(&bp.a1);
            kv.extend_from_slice(&bp.b);
            kv.extend_from_slice(&bp.r1);
            kv.extend_from_slice(&bp.s1);
            kv.extend_from_slice(&bp.d1);
            for k in &bp.l {
                kv.extend_from_slice(k);
            }
            for k in &bp.r {
                kv.extend_from_slice(k);
            }
        }
    } else {
        for bp in &tx.bulletproofs {
            kv.extend_from_slice(&bp.a);
            kv.extend_from_slice(&bp.s);
            kv.extend_from_slice(&bp.t1);
            kv.extend_from_slice(&bp.t2);
            kv.extend_from_slice(&bp.taux);
            kv.extend_from_slice(&bp.mu);
            for k in &bp.l {
                kv.extend_from_slice(k);
            }
            for k in &bp.r {
                kv.extend_from_slice(k);
            }
            kv.extend_from_slice(&bp.a_amt);
            kv.extend_from_slice(&bp.b_amt);
            kv.extend_from_slice(&bp.t_amt);
        }
    }
    let h2 = keccak256(&kv);
    let mut msg = [0u8; 96];
    msg[..32].copy_from_slice(&h0);
    msg[32..64].copy_from_slice(&h1);
    msg[64..].copy_from_slice(&h2);
    keccak256(&msg)
}

// ---------------------------------------------------------------------------
// verClsag (rctSigs.cpp verRctCLSAGSimple)
// ---------------------------------------------------------------------------

/// One ring member: one-time spend pubkey `dest` and amount commitment
/// `mask` (get_outs "key"/"mask" for the absolute output index).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingMember {
    pub dest: [u8; 32],
    pub mask: [u8; 32],
}

/// Canonical scalar parse: rejects encodings >= l before any cryptographic
/// work (fail-closed, WG-19 discipline carried over from clsag.rs).
pub(crate) fn canonical_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = Scalar::from_bytes_mod_order(*bytes);
    if s.to_bytes() != *bytes {
        return None;
    }
    Some(s)
}

pub(crate) fn decompress_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

/// monero `verRctCLSAGSimple`, byte-compatible port. `message` is
/// [`pre_mlsag_hash`]; `key_image` is the txin k_image (the CLSAG I);
/// `ring` holds the (dest, mask) pairs of the input's ring in offset order;
/// `c_offset` is the input's pseudoOut.
pub fn verify_clsag(
    message: &[u8; 32],
    sig: &ClsagSig,
    key_image: &[u8; 32],
    ring: &[RingMember],
    c_offset: &[u8; 32],
) -> bool {
    let n = ring.len();

    // Fail-closed structural checks (monero verRctCLSAGSimple order).
    if n < 2 || sig.s.len() != n {
        return false;
    }
    // All signature scalars canonical (< l), pre-crypto.
    let s: Vec<Scalar> = match sig
        .s
        .iter()
        .map(canonical_scalar)
        .collect::<Option<Vec<_>>>()
    {
        Some(v) => v,
        None => return false,
    };
    let c1 = match canonical_scalar(&sig.c1) {
        Some(c) => c,
        None => return false,
    };

    // Key image: must decompress, must not be degenerate (identity or
    // small-order torsion — monero rejects I == identity and requires the
    // main subgroup; is_small_order covers both).
    let i_point = match decompress_point(key_image) {
        Some(p) if !p.is_small_order() => p,
        _ => return false,
    };

    // Pseudo-out commitment offset.
    let c_offset_point = match decompress_point(c_offset) {
        Some(p) => p,
        None => return false,
    };

    // Auxiliary image D: must decompress; [8]D must not be the identity
    // (monero "Bad auxiliary key image" + main-subgroup discipline).
    let d_point = match decompress_point(&sig.d) {
        Some(p) => p,
        None => return false,
    };
    let d8 = d_point.mul_by_cofactor();
    if d8 == EdwardsPoint::identity() {
        return false;
    }

    // Aggregation hashes (rctSigs.cpp): mu_P over CLSAG_agg_0, mu_C over
    // CLSAG_agg_1; both cover domain || dests || masks || I || D || C_offset.
    let mut mu_p_buf: Vec<u8> = Vec::with_capacity((2 * n + 4) * 32);
    mu_p_buf.extend_from_slice(&tag_slot(HASH_KEY_CLSAG_AGG_0));
    let mut mu_c_buf = Vec::with_capacity(mu_p_buf.capacity());
    mu_c_buf.extend_from_slice(&tag_slot(HASH_KEY_CLSAG_AGG_1));
    for m in ring {
        mu_p_buf.extend_from_slice(&m.dest);
        mu_c_buf.extend_from_slice(&m.dest);
    }
    for m in ring {
        mu_p_buf.extend_from_slice(&m.mask);
        mu_c_buf.extend_from_slice(&m.mask);
    }
    mu_p_buf.extend_from_slice(key_image);
    mu_p_buf.extend_from_slice(&sig.d);
    mu_p_buf.extend_from_slice(c_offset);
    mu_c_buf.extend_from_slice(key_image);
    mu_c_buf.extend_from_slice(&sig.d);
    mu_c_buf.extend_from_slice(c_offset);
    let mu_p = hash_to_scalar(&mu_p_buf);
    let mu_c = hash_to_scalar(&mu_c_buf);

    // Round hash skeleton: domain || dests || masks || C_offset || message.
    let mut c_to_hash: Vec<u8> = Vec::with_capacity((2 * n + 5) * 32);
    c_to_hash.extend_from_slice(&tag_slot(HASH_KEY_CLSAG_ROUND));
    for m in ring {
        c_to_hash.extend_from_slice(&m.dest);
    }
    for m in ring {
        c_to_hash.extend_from_slice(&m.mask);
    }
    c_to_hash.extend_from_slice(c_offset);
    c_to_hash.extend_from_slice(message);

    // Challenge chain: L_i = [s_i]G + [c*mu_P]P_i + [c*mu_C](C_i - C_offset),
    // R_i = [s_i]H(P_i) + [c*mu_P]I + [c*mu_C][8]D, c = H(... || L_i || R_i).
    let mut c = c1;
    for idx in 0..n {
        let c_p = mu_p * c;
        let c_c = mu_c * c;

        let p_i = match decompress_point(&ring[idx].dest) {
            Some(p) => p,
            None => return false,
        };
        let mask_i = match decompress_point(&ring[idx].mask) {
            Some(p) => p,
            None => return false,
        };
        let c_adj = mask_i - c_offset_point;

        let l = s[idx] * B + c_p * p_i + c_c * c_adj;
        let hi = hash_to_p3(&ring[idx].dest);
        let r = s[idx] * hi + c_p * i_point + c_c * d8;

        let mut buf = c_to_hash.clone();
        buf.extend_from_slice(&l.compress().to_bytes());
        buf.extend_from_slice(&r.compress().to_bytes());
        let c_new = hash_to_scalar(&buf);
        if c_new.to_bytes() == [0u8; 32] {
            return false;
        }
        c = c_new;
    }

    // Final check: c == c1 (mod l).
    (c - c1).to_bytes() == [0u8; 32]
}

/// Verify every CLSAG input of the tx against its ring. `rings[i]` must hold
/// the ring members of input i in key_offsets order (the fixture pipeline
/// resolves them from monerod get_outs over the absolute offsets). Returns
/// true only if every input verifies.
pub fn verify_tx(tx: &MoneroTx, rings: &[Vec<RingMember>]) -> bool {
    if tx.vin.len() != tx.clsags.len()
        || tx.clsags.len() != tx.pseudo_outs.len()
        || tx.clsags.len() != rings.len()
    {
        return false;
    }
    let message = pre_mlsag_hash(tx);
    for ((clsag, vin), (ring, pseudo_out)) in tx
        .clsags
        .iter()
        .zip(tx.vin.iter())
        .zip(rings.iter().zip(tx.pseudo_outs.iter()))
    {
        if !verify_clsag(&message, clsag, &vin.k_image, ring, pseudo_out) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Tests (synthetic, offline — the REAL monerod acceptance tests live in
// tests/clsag_verify_fixture.rs against tests/fixtures/clsag_mainnet_v1.json)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// curve order l, little-endian (canonicality boundary for tests).
    const ORDER_L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    fn scalar_bytes(v: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = v;
        b
    }

    fn point_bytes() -> [u8; 32] {
        B.compress().to_bytes()
    }

    fn k32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// Synthetic but well-shaped CLSAG tx: parse-level valid (points
    /// decompress, scalars canonical, counts consistent), signatures bogus —
    /// verification must reject deterministically.
    fn build_tx(rct_type: u8, ring_sizes: &[usize], s_len: usize, n_out: usize) -> Vec<u8> {
        let pt = point_bytes();
        let n_in = ring_sizes.len();
        let mut o = Vec::new();
        write_varint(&mut o, 2); // version
        write_varint(&mut o, 0); // unlock_time
        write_varint(&mut o, n_in as u64);
        for (i, rs) in ring_sizes.iter().enumerate() {
            write_varint(&mut o, 2); // txin_to_key
            write_varint(&mut o, 0); // amount
            write_varint(&mut o, *rs as u64);
            for j in 0..*rs {
                write_varint(&mut o, 1000 + (i * ring_sizes[0] + j) as u64);
            }
            o.extend_from_slice(&pt); // k_image
        }
        write_varint(&mut o, n_out as u64);
        for _ in 0..n_out {
            write_varint(&mut o, 0);
            write_varint(&mut o, 3); // txout_to_tagged_key (current mainnet)
            o.extend_from_slice(&pt);
            o.push(0x42); // view tag
        }
        write_varint(&mut o, 0); // extra
        write_varint(&mut o, u64::from(rct_type));
        write_varint(&mut o, 123); // fee
        for _ in 0..n_out {
            o.extend_from_slice(&[0u8; 8]); // ecdh amount (first!)
        }
        for _ in 0..n_out {
            o.extend_from_slice(&pt); // outPk mask (no count prefix)
        }
        if rct_type == RCT_TYPE_BULLETPROOF_PLUS {
            write_varint(&mut o, 1); // nbp
            for _ in 0..6 {
                o.extend_from_slice(&pt); // A, A1, B, r1, s1, d1
            }
            write_varint(&mut o, 8);
            for _ in 0..8 {
                o.extend_from_slice(&pt);
            }
            write_varint(&mut o, 8);
            for _ in 0..8 {
                o.extend_from_slice(&pt);
            }
        } else {
            write_varint(&mut o, 1); // nbp
            for _ in 0..6 {
                o.extend_from_slice(&pt); // A, S, T1, T2, taux, mu
            }
            write_varint(&mut o, 8);
            for _ in 0..8 {
                o.extend_from_slice(&pt);
            }
            write_varint(&mut o, 8);
            for _ in 0..8 {
                o.extend_from_slice(&pt);
            }
            for _ in 0..3 {
                o.extend_from_slice(&scalar_bytes(1)); // a, b, t
            }
        }
        for _ in 0..n_in {
            for j in 0..s_len {
                o.extend_from_slice(&scalar_bytes(11 + j as u8));
            }
            o.extend_from_slice(&scalar_bytes(7)); // c1
            o.extend_from_slice(&pt); // D
        }
        for _ in 0..n_in {
            o.extend_from_slice(&pt); // pseudoOut (no count prefix)
        }
        o
    }

    fn rings_for(tx: &MoneroTx) -> Vec<Vec<RingMember>> {
        tx.vin
            .iter()
            .map(|i| {
                i.key_offsets
                    .iter()
                    .map(|_| RingMember {
                        dest: point_bytes(),
                        mask: point_bytes(),
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn keccak256_matches_known_vectors() {
        assert_eq!(
            keccak256(b""),
            k32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        assert_eq!(
            keccak256(b"abc"),
            k32("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        );
    }

    #[test]
    fn hash_to_point_known_answer_vectors() {
        // Cross-implementation vectors: independent big-int Python port of
        // monero's ge_fromfe_frombytes_vartime + hash_to_p3 ([8] scaling),
        // constants validated against their defining identities.
        // both keccak outputs below have bit 255 set (last byte 0xa5 / 0xf2),
        // so the 2^255 == 19 (mod p) fold is exercised by construction
        let v1 = keccak256(&scalar_bytes(1));
        let v2 = keccak256(&scalar_bytes(2));
        let cases: [(&[u8; 32], &str); 5] = [
            (
                &keccak256(b"opacus wg-clsag elligator v1"),
                "5cf75df0fd2d044ee2e6497e16fb4382aa3c0c498ccd6048a359c09487269442",
            ),
            (
                &keccak256(b"opacus wg-clsag elligator v2"),
                "efdc6ee4cd98919117bdc5ae6eb69802c4b88e2e2c7849a91e55ff4812c97b4a",
            ),
            (
                &keccak256(b"opacus wg-clsag elligator v3"),
                "01725f7427f130979fe7fc7ccbcba03879babcd3adc6d1c607cb303c52851fe4",
            ),
            (
                &v1,
                "975e7110abf5159693666d888b8e2386a1600093ff0ebf4838d1f9f927ca6b41",
            ),
            (
                &v2,
                "f8c24dee5ad967fabbe1fbc35eda8b7d7bb02346b72457ce8f43d48c650b8996",
            ),
        ];
        for (input, expected) in cases {
            // each `input` is already keccak256(preimage): monero's
            // hash_to_p3(k) = [8] * ge_fromfe_frombytes_vartime(keccak(k))
            // hashes the raw key exactly once (rctOps.cpp hash_to_p3).
            let got = hex::encode(
                ge_fromfe_frombytes_vartime(input)
                    .mul_by_cofactor()
                    .compress()
                    .to_bytes(),
            );
            assert_eq!(got, expected, "hash_to_p3 vector mismatch");
        }
    }

    #[test]
    fn hash_to_point_deterministic_non_degenerate() {
        let a = hash_to_p3(&scalar_bytes(1));
        let b = hash_to_p3(&scalar_bytes(1));
        assert_eq!(a, b);
        let c = hash_to_p3(&scalar_bytes(2));
        assert_ne!(a, c);
        assert!(!a.is_small_order());
        let rt = CompressedEdwardsY(a.compress().to_bytes())
            .decompress()
            .unwrap();
        assert_eq!(rt, a);
    }

    #[test]
    fn hash_to_point_cofactor_cleared() {
        // hash_to_p3 folds in ge_mul8: result must equal [8] of the raw map.
        let raw = ge_fromfe_frombytes_vartime(&keccak256(&scalar_bytes(9)));
        assert_eq!(hash_to_p3(&scalar_bytes(9)), raw.mul_by_cofactor());
        let rt = CompressedEdwardsY(raw.compress().to_bytes())
            .decompress()
            .expect("elligator output roundtrips");
        assert_eq!(rt, raw);
        assert!(!hash_to_p3(&scalar_bytes(9)).is_small_order());
    }

    #[test]
    fn synthetic_parse_reserialize_roundtrip_both_types() {
        for t in [RCT_TYPE_CLSAG, RCT_TYPE_BULLETPROOF_PLUS] {
            let blob = build_tx(t, &[4, 4], 4, 2);
            let tx = MoneroTx::parse(&blob).expect("parse");
            assert_eq!(tx.rct_type, t);
            assert_eq!(tx.re_serialize(), blob, "byte-compat pin for type {t}");
            assert_eq!(tx.vin.len(), 2);
            assert_eq!(tx.clsags.len(), 2);
            assert_eq!(tx.pseudo_outs.len(), 2);
            assert_eq!(tx.out_pks.len(), tx.vout.len());
            // absolute offsets = prefix sums of the relative offsets
            assert_eq!(tx.absolute_offsets()[0][0], 1000);
            assert_eq!(tx.absolute_offsets()[0][3], 1000 + 1001 + 1002 + 1003);
        }
    }

    #[test]
    fn verify_rejects_bogus_synthetic_signature() {
        for t in [RCT_TYPE_CLSAG, RCT_TYPE_BULLETPROOF_PLUS] {
            let blob = build_tx(t, &[4, 4], 4, 2);
            let tx = MoneroTx::parse(&blob).unwrap();
            let rings = rings_for(&tx);
            assert!(!verify_tx(&tx, &rings), "bogus signature must reject");
        }
    }

    #[test]
    fn parse_rejects_unknown_rct_type_and_version() {
        assert!(matches!(
            MoneroTx::parse(&build_tx(4, &[4], 4, 2)),
            Err(ParseError::UnsupportedRctType(4))
        ));
        let mut blob = build_tx(RCT_TYPE_CLSAG, &[4], 4, 2);
        blob[0] = 1;
        assert!(matches!(
            MoneroTx::parse(&blob),
            Err(ParseError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn parse_rejects_trailing_and_truncated() {
        let mut blob = build_tx(RCT_TYPE_BULLETPROOF_PLUS, &[4, 4], 4, 2);
        blob.push(0);
        assert!(matches!(
            MoneroTx::parse(&blob),
            Err(ParseError::TrailingBytes)
        ));
        let full = build_tx(RCT_TYPE_BULLETPROOF_PLUS, &[4, 4], 4, 2);
        assert!(matches!(
            MoneroTx::parse(&full[..full.len() - 1]),
            Err(ParseError::UnexpectedEof)
        ));
    }

    #[test]
    fn verify_rejects_mixed_ring_size() {
        // monero-compatible parse: s size pinned to vin[0] only; per-input
        // verification rejects the mismatched ring.
        let blob = build_tx(RCT_TYPE_CLSAG, &[4, 5], 4, 2);
        let tx = MoneroTx::parse(&blob).unwrap();
        let rings = rings_for(&tx);
        assert!(!verify_tx(&tx, &rings));
    }

    #[test]
    fn verify_rejects_non_canonical_scalar_pre_crypto() {
        let blob = build_tx(RCT_TYPE_BULLETPROOF_PLUS, &[4], 4, 2);
        let mut tx = MoneroTx::parse(&blob).unwrap();
        // s_0 = l (>= curve order) must reject before any point arithmetic
        tx.clsags[0].s[0] = ORDER_L_LE;
        let rings = rings_for(&tx);
        assert!(!verify_tx(&tx, &rings));
        // c1 = l as well
        let mut tx = MoneroTx::parse(&blob).unwrap();
        tx.clsags[0].c1 = ORDER_L_LE;
        assert!(!verify_tx(&tx, &rings));
    }

    #[test]
    fn verify_rejects_degenerate_key_image_and_aux_image() {
        let blob = build_tx(RCT_TYPE_BULLETPROOF_PLUS, &[4], 4, 2);
        // identity key image (compressed identity = [1, 0, ..., 0])
        let mut tx = MoneroTx::parse(&blob).unwrap();
        tx.vin[0].k_image = [0u8; 32];
        tx.vin[0].k_image[0] = 1;
        let rings = rings_for(&tx);
        assert!(!verify_tx(&tx, &rings));
        // identity auxiliary image D
        let mut tx = MoneroTx::parse(&blob).unwrap();
        tx.clsags[0].d = [0u8; 32];
        tx.clsags[0].d[0] = 1;
        assert!(!verify_tx(&tx, &rings));
    }

    #[test]
    fn verify_rejects_ring_substitution() {
        let blob = build_tx(RCT_TYPE_BULLETPROOF_PLUS, &[4], 4, 2);
        let tx = MoneroTx::parse(&blob).unwrap();
        let mut rings = rings_for(&tx);
        // swap in a different real chain output
        rings[0][1].dest = (B * Scalar::from(2u8)).compress().to_bytes();
        assert!(!verify_tx(&tx, &rings));
    }

    #[test]
    fn pre_mlsag_hash_is_range_proof_sensitive() {
        let blob = build_tx(RCT_TYPE_BULLETPROOF_PLUS, &[4], 4, 2);
        let mut tx = MoneroTx::parse(&blob).unwrap();
        let base = pre_mlsag_hash(&tx);
        tx.bulletproofs_plus[0].l[0][7] ^= 0x08;
        assert_ne!(pre_mlsag_hash(&tx), base);

        let blob5 = build_tx(RCT_TYPE_CLSAG, &[4], 4, 2);
        let mut tx5 = MoneroTx::parse(&blob5).unwrap();
        let base5 = pre_mlsag_hash(&tx5);
        tx5.bulletproofs[0].r[1][3] ^= 0x20;
        assert_ne!(pre_mlsag_hash(&tx5), base5);
    }

    #[test]
    fn verify_rejects_empty_ring_and_size_mismatch() {
        let blob = build_tx(RCT_TYPE_CLSAG, &[4], 4, 2);
        let tx = MoneroTx::parse(&blob).unwrap();
        let rings = rings_for(&tx);
        assert!(!verify_clsag(
            &pre_mlsag_hash(&tx),
            &tx.clsags[0],
            &tx.vin[0].k_image,
            &[],
            &tx.pseudo_outs[0]
        ));
        let mut short = rings[0].clone();
        short.pop();
        assert!(!verify_clsag(
            &pre_mlsag_hash(&tx),
            &tx.clsags[0],
            &tx.vin[0].k_image,
            &short,
            &tx.pseudo_outs[0]
        ));
    }
}
