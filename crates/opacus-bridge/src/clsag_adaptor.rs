//! Monerod-compatible CLSAG adaptor signatures (WG-CLSAG-adaptor).
//!
//! This is the ring-level successor of [`crate::clsag`] (the v0.3
//! single-signer primitive): a Monero one-time spend is pre-signed as a
//! STANDARD CLSAG bound to a hidden swap secret `t`, the counterparty
//! completes it with `t`, and the result is a CLSAG that passes monerod's
//! `verRctCLSAGSimple` unmodified - i.e. [`crate::clsag_verify::verify_clsag`]
//! with no changes. The completed signature, once visible on the Monero
//! chain, hands the adaptor holder the secret `t` (the Monero-side half of
//! on-chain swap enforcement; the Opacus-side half is WG-27).
//!
//! Normative reference: docs/WG-CLSAG-adaptor-scope.md (design freeze).
//!
//! ```text
//!   one-time key   x                     P = [x]G, I = [x]Hp(P)
//!   blinding diff  z                     [mask_di] - [C_offset] = [z]G
//!   aux image      D = [z]Hp(P)
//!   swap secret    t                     T = [t]G, T_h = [t]Hp(P)
//!   nonce          a (deterministic)     R_G = [a]G, R_H = [a]Hp(P)
//!
//!   pre-signature  s'_di = a - t - c_di*(mu_P*x + mu_C*z)
//!   completed      s_di  = s'_di + t     (standard CLSAG response)
//!   recover        t     = s_di - s'_di  (from the on-chain signature)
//! ```
//!
//! THE KEY DESIGN RULE: `T` never enters any challenge input. The initial
//! challenge is the standard monerod one over the nonce points,
//! `c_{di+1} = H(round_skeleton || R_G || R_H)`, and every other position
//! walks exactly like monerod. `T` / `T_h` are therefore only visible in
//! the bilateral adaptor binding checks
//! `L'_di + T == R_G`, `R'_di + T_h == R_H` - completing with `t` shifts
//! `L'_di` to `R_G` and `R'_di` to `R_H`, so the completed signature closes
//! under the unmodified monerod challenge chain and is indistinguishable
//! from an honest CLSAG on-chain.
//!
//! The adaptor block { T, T_h, R_G, R_H, di } is bridge-internal, off-chain
//! bilateral data - the v5 wire tail (130 B) and the 21-slot instance
//! layout stay frozen (WG-26 design v1). The signer index `di` is shared
//! only with the counterparty; the completed signature hides it on-chain
//! exactly like any CLSAG.
//!
//! Fail-closed discipline (WG-19, carried from clsag_verify.rs / adaptor.rs):
//! all scalars canonical (< l) before any cryptographic work; all points
//! decompressible, not the identity and not small-order; degenerate secrets
//! (x, t, z == 0) rejected at signing; nonce deterministic and
//! domain-separated ("opacus-bridge/clsag-adaptor/nonce-v1" / ".../decoy-v1").

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::clsag_verify::{
    canonical_scalar, decompress_point, hash_to_p3, hash_to_scalar, tag_slot, ClsagSig, RingMember,
    HASH_KEY_CLSAG_AGG_0, HASH_KEY_CLSAG_AGG_1, HASH_KEY_CLSAG_ROUND,
};

const NONCE_TAG: &[u8] = b"opacus-bridge/clsag-adaptor/nonce-v1";
const DECOY_TAG: &[u8] = b"opacus-bridge/clsag-adaptor/decoy-v1";

/// CLSAG adaptor: a standard [`ClsigSig`-shaped signature section whose
/// signer response is the pre-signature `s'_di`, plus the bilateral
/// adaptor block. Everything except `di` is 32-byte compressed encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClsagAdaptorSig {
    /// Standard CLSAG section: s[di] = s' (pre-signature), c1, D.
    pub sig: ClsagSig,
    /// T = [t]G.
    pub t_point: [u8; 32],
    /// T_h = [t]Hp(P).
    pub t_h_point: [u8; 32],
    /// R_G = [a]G (the nonce point bound into the initial challenge).
    pub r_g: [u8; 32],
    /// R_H = [a]Hp(P).
    pub r_h: [u8; 32],
    /// Signer index in the ring. Bilateral, off-chain; hidden on-chain
    /// by the completed signature.
    pub di: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ClsagAdaptorError {
    #[error("Non-canonical secret scalar")]
    NonCanonicalSecret,
    #[error("Degenerate secret (zero scalar) or degenerate derived point")]
    DegenerateSecret,
    #[error("Ring point decompression failed")]
    BadRingPoint,
    #[error("Ring too small (n < 2)")]
    RingTooSmall,
    #[error("Signer index out of range")]
    IndexOutOfRange,
    #[error("Secret does not match the adaptor point")]
    SecretMismatch,
    #[error("Completed signature is not a valid CLSAG for this adaptor")]
    InvalidCompletion,
}

/// Little-endian u64 (monero serialization convention for scalars in
/// hashes).
fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// Aggregation hashes mu_P / mu_C (rctSigs.cpp), identical to the
/// verifier's construction: tag || dests || masks || I || D || C_offset.
fn aggregation_hash(
    tag: &[u8],
    ring: &[RingMember],
    i: &EdwardsPoint,
    d: &[u8; 32],
    c_offset: &[u8; 32],
) -> Scalar {
    let mut buf: Vec<u8> = Vec::with_capacity((2 * ring.len() + 4) * 32);
    buf.extend_from_slice(&tag_slot(tag));
    for m in ring {
        buf.extend_from_slice(&m.dest);
    }
    for m in ring {
        buf.extend_from_slice(&m.mask);
    }
    buf.extend_from_slice(&i.compress().to_bytes());
    buf.extend_from_slice(d);
    buf.extend_from_slice(c_offset);
    hash_to_scalar(&buf)
}

/// Round hash skeleton: CLSAG_round || dests || masks || C_offset ||
/// message (the verifier prefixes every challenge input with this).
fn round_skeleton(ring: &[RingMember], c_offset: &[u8; 32], message: &[u8; 32]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity((2 * ring.len() + 3) * 32);
    buf.extend_from_slice(&tag_slot(HASH_KEY_CLSAG_ROUND));
    for m in ring {
        buf.extend_from_slice(&m.dest);
    }
    for m in ring {
        buf.extend_from_slice(&m.mask);
    }
    buf.extend_from_slice(c_offset);
    buf.extend_from_slice(message);
    buf
}

/// Structural pre-checks shared by sign and verify: ring size, point
/// decompression for the whole ring, non-degenerate I / D8. Returns the
/// decompressed C_offset on success.
fn structural_checks(
    ring: &[RingMember],
    key_image: &[u8; 32],
    d: &[u8; 32],
    c_offset: &[u8; 32],
) -> Option<EdwardsPoint> {
    if ring.len() < 2 {
        return None;
    }
    let _i_point = match decompress_point(key_image) {
        Some(p) if !p.is_small_order() && p != EdwardsPoint::identity() => p,
        _ => return None,
    };
    let d_point = decompress_point(d)?;
    if d_point.mul_by_cofactor() == EdwardsPoint::identity() {
        return None;
    }
    for m in ring {
        let p = decompress_point(&m.dest)?;
        if p.mul_by_cofactor() == EdwardsPoint::identity() {
            return None;
        }
        let c = decompress_point(&m.mask)?;
        if c.mul_by_cofactor() == EdwardsPoint::identity() {
            return None;
        }
    }
    decompress_point(c_offset)
}

/// Sign a CLSAG adaptor over `message` for the ring member at `di`.
///
/// `x` is the one-time spend key (canonical, non-zero: P = [x]G),
/// `z` the blinding difference ([mask_di] - [C_offset] = [z]G, non-zero),
/// `t` the swap secret (canonical, non-zero). The response at `di` is the
/// pre-signature s'_di = a - t - c_di*(mu_P*x + mu_C*z); the adaptor block
/// carries T / T_h / R_G / R_H / di next to the standard CLSAG section.
pub fn sign_adaptor(
    x: &[u8; 32],
    z: &[u8; 32],
    t: &[u8; 32],
    message: &[u8; 32],
    ring: &[RingMember],
    c_offset: &[u8; 32],
    di: usize,
) -> Result<ClsagAdaptorSig, ClsagAdaptorError> {
    let n = ring.len();
    if n < 2 {
        return Err(ClsagAdaptorError::RingTooSmall);
    }
    if di >= n {
        return Err(ClsagAdaptorError::IndexOutOfRange);
    }
    let x_s = canonical_scalar(x).ok_or(ClsagAdaptorError::NonCanonicalSecret)?;
    let t_s = canonical_scalar(t).ok_or(ClsagAdaptorError::NonCanonicalSecret)?;
    if x_s == Scalar::ZERO || t_s == Scalar::ZERO {
        return Err(ClsagAdaptorError::DegenerateSecret);
    }
    let z_s = Scalar::from_bytes_mod_order(*z);
    if z_s == Scalar::ZERO {
        return Err(ClsagAdaptorError::DegenerateSecret);
    }

    // One-time keys and the auxiliary image D. The verifier consumes
    // D8 = [8]D in R_i, so the response relation closes only when
    // D8 == [z]Hp(P) - hence D = [z/8]Hp(P) (mul-by-8 is a bijection on
    // the prime-order subgroup, so z/8 is exact).
    let p_point = x_s * B;
    let p_bytes = p_point.compress().to_bytes();
    let hp = hash_to_p3(&p_bytes);
    let i_point = x_s * hp;
    if i_point == EdwardsPoint::identity() || i_point.is_small_order() {
        return Err(ClsagAdaptorError::DegenerateSecret);
    }
    let z_over_8 = z_s * Scalar::from(8u8).invert();
    let d_point = z_over_8 * hp;
    let d_bytes = d_point.compress().to_bytes();
    if d_point.mul_by_cofactor() == EdwardsPoint::identity() {
        return Err(ClsagAdaptorError::DegenerateSecret);
    }

    let c_offset_point = match decompress_point(c_offset) {
        Some(p) => p,
        None => return Err(ClsagAdaptorError::BadRingPoint),
    };
    structural_checks(ring, &i_point.compress().to_bytes(), &d_bytes, c_offset)
        .ok_or(ClsagAdaptorError::BadRingPoint)?;

    // Aggregation hashes and the round skeleton - identical construction
    // to the verifier.
    let mu_p = aggregation_hash(HASH_KEY_CLSAG_AGG_0, ring, &i_point, &d_bytes, c_offset);
    let mu_c = aggregation_hash(HASH_KEY_CLSAG_AGG_1, ring, &i_point, &d_bytes, c_offset);
    let skeleton = round_skeleton(ring, c_offset, message);

    // Adaptor points and deterministic nonce.
    let t_point = t_s * B;
    let t_bytes = t_point.compress().to_bytes();
    let t_h_point = t_s * hp;
    let t_h_bytes = t_h_point.compress().to_bytes();
    if t_h_point.mul_by_cofactor() == EdwardsPoint::identity() {
        return Err(ClsagAdaptorError::DegenerateSecret);
    }

    let mut nonce_buf = Vec::with_capacity(NONCE_TAG.len() + 32 * 3 + 8);
    nonce_buf.extend_from_slice(NONCE_TAG);
    nonce_buf.extend_from_slice(x);
    nonce_buf.extend_from_slice(&t_bytes);
    nonce_buf.extend_from_slice(message);
    nonce_buf.extend_from_slice(&le64(di as u64));
    let a_s = hash_to_scalar(&nonce_buf);
    if a_s == Scalar::ZERO {
        return Err(ClsagAdaptorError::DegenerateSecret);
    }
    let r_g_point = a_s * B;
    let r_g = r_g_point.compress().to_bytes();
    let r_h_point = a_s * hp;
    let r_h = r_h_point.compress().to_bytes();

    // Initial challenge: STANDARD monerod construction over the nonce
    // points - the adaptor never touches challenge inputs.
    let mut init_buf = skeleton.clone();
    init_buf.extend_from_slice(&r_g);
    init_buf.extend_from_slice(&r_h);
    let mut c = hash_to_scalar(&init_buf);
    if c == Scalar::ZERO {
        return Err(ClsagAdaptorError::DegenerateSecret);
    }

    // Walk the n-1 non-signer positions (standard challenge chain) with
    // deterministic decoy scalars; record the challenge consumed at
    // position 0 (the published c1).
    let mut s: Vec<[u8; 32]> = vec![[0u8; 32]; n];
    let mut c1: Option<Scalar> = None;
    for step in 0..n - 1 {
        let i = (di + 1 + step) % n;
        if i == 0 {
            c1 = Some(c);
        }
        let dest_i = match decompress_point(&ring[i].dest) {
            Some(p) => p,
            None => return Err(ClsagAdaptorError::BadRingPoint),
        };
        let mask_i = match decompress_point(&ring[i].mask) {
            Some(p) => p,
            None => return Err(ClsagAdaptorError::BadRingPoint),
        };
        let hp_i = hash_to_p3(&ring[i].dest);
        let c_adj = mask_i - c_offset_point;

        let mut decoy_buf = Vec::with_capacity(DECOY_TAG.len() + 32 * 3 + 16);
        decoy_buf.extend_from_slice(DECOY_TAG);
        decoy_buf.extend_from_slice(&a_s.to_bytes());
        decoy_buf.extend_from_slice(&t_bytes);
        decoy_buf.extend_from_slice(&le64(di as u64));
        decoy_buf.extend_from_slice(&le64(i as u64));
        let s_i = hash_to_scalar(&decoy_buf);

        let c_p = mu_p * c;
        let c_c = mu_c * c;
        let l = s_i * B + c_p * dest_i + c_c * c_adj;
        let r = s_i * hp_i + c_p * i_point + c_c * d_point.mul_by_cofactor();
        let mut buf = skeleton.clone();
        buf.extend_from_slice(&l.compress().to_bytes());
        buf.extend_from_slice(&r.compress().to_bytes());
        let c_new = hash_to_scalar(&buf);
        if c_new == Scalar::ZERO {
            return Err(ClsagAdaptorError::DegenerateSecret);
        }
        s[i] = s_i.to_bytes();
        c = c_new;
    }

    // Challenge consumed at the signer position; pre-signature.
    let c_di = c;
    let s_full = a_s - c_di * (mu_p * x_s + mu_c * z_s);
    let s_di = s_full - t_s;
    s[di] = s_di.to_bytes();

    // c1 is the challenge consumed at position 0. For di == 0 position 0
    // is the signer: that challenge is c_di itself.
    let c1 = c1.unwrap_or(c_di);

    Ok(ClsagAdaptorSig {
        sig: ClsagSig {
            s,
            c1: c1.to_bytes(),
            d: d_bytes,
        },
        t_point: t_bytes,
        t_h_point: t_h_bytes,
        r_g,
        r_h,
        di,
    })
}

/// Verify a CLSAG adaptor without the one-time key or the secret. Runs the
/// unmodified monerod challenge chain from c1 and, at `di`, the bilateral
/// binding checks `L'_di + T == R_G` and `R'_di + T_h == R_H` (which
/// reproduce the signer's initial challenge over the nonce points).
pub fn verify_adaptor(
    adaptor: &ClsagAdaptorSig,
    message: &[u8; 32],
    key_image: &[u8; 32],
    ring: &[RingMember],
    c_offset: &[u8; 32],
) -> bool {
    let n = ring.len();
    if n < 2 || adaptor.sig.s.len() != n || adaptor.di >= n {
        return false;
    }
    let s: Vec<Scalar> = match adaptor
        .sig
        .s
        .iter()
        .map(canonical_scalar)
        .collect::<Option<Vec<_>>>()
    {
        Some(v) => v,
        None => return false,
    };
    let c1 = match canonical_scalar(&adaptor.sig.c1) {
        Some(c) => c,
        None => return false,
    };
    let i_point = match decompress_point(key_image) {
        Some(p) if !p.is_small_order() && p != EdwardsPoint::identity() => p,
        _ => return false,
    };
    let d_point = match decompress_point(&adaptor.sig.d) {
        Some(p) => p,
        None => return false,
    };
    let d8 = d_point.mul_by_cofactor();
    if d8 == EdwardsPoint::identity() {
        return false;
    }
    let c_offset_point = match decompress_point(c_offset) {
        Some(p) => p,
        None => return false,
    };
    let t_point = match decompress_point(&adaptor.t_point) {
        Some(p) if !p.is_small_order() && p != EdwardsPoint::identity() => p,
        _ => return false,
    };
    let t_h_point = match decompress_point(&adaptor.t_h_point) {
        Some(p) if !p.is_small_order() && p != EdwardsPoint::identity() => p,
        _ => return false,
    };
    let r_g = match decompress_point(&adaptor.r_g) {
        Some(p) if !p.is_small_order() && p != EdwardsPoint::identity() => p,
        _ => return false,
    };
    let r_h = match decompress_point(&adaptor.r_h) {
        Some(p) if !p.is_small_order() && p != EdwardsPoint::identity() => p,
        _ => return false,
    };
    // Every ring point must decompress (fail-closed, like verify_clsag).
    let ring_pts: Option<Vec<(EdwardsPoint, EdwardsPoint)>> = ring
        .iter()
        .map(
            |m| match (decompress_point(&m.dest), decompress_point(&m.mask)) {
                (Some(p), Some(c)) => Some((p, c)),
                _ => None,
            },
        )
        .collect();
    let ring_pts = match ring_pts {
        Some(v) => v,
        None => return false,
    };

    let mu_p = aggregation_hash(
        HASH_KEY_CLSAG_AGG_0,
        ring,
        &i_point,
        &adaptor.sig.d,
        c_offset,
    );
    let mu_c = aggregation_hash(
        HASH_KEY_CLSAG_AGG_1,
        ring,
        &i_point,
        &adaptor.sig.d,
        c_offset,
    );
    let skeleton = round_skeleton(ring, c_offset, message);

    // Unmodified monerod walk; at di the binding checks reproduce the
    // initial challenge over the nonce points.
    let mut c = c1;
    for idx in 0..n {
        let (p_i, mask_i) = ring_pts[idx];
        let hp_i = hash_to_p3(&ring[idx].dest);
        let c_p = mu_p * c;
        let c_c = mu_c * c;
        let c_adj = mask_i - c_offset_point;

        let l = s[idx] * B + c_p * p_i + c_c * c_adj;
        let r = s[idx] * hp_i + c_p * i_point + c_c * d8;

        let (l_next, r_next) = if idx == adaptor.di {
            // Bilateral adaptor binding: completing with t must shift
            // L' to R_G and R' to R_H.
            if l + t_point != r_g || r + t_h_point != r_h {
                return false;
            }
            (r_g, r_h)
        } else {
            (l, r)
        };

        let mut buf = skeleton.clone();
        buf.extend_from_slice(&l_next.compress().to_bytes());
        buf.extend_from_slice(&r_next.compress().to_bytes());
        let c_new = hash_to_scalar(&buf);
        if c_new == Scalar::ZERO {
            return false;
        }
        c = c_new;
    }

    // Closure: the challenge chain returns to c1 (monerod check).
    (c - c1).to_bytes() == [0u8; 32]
}

/// Complete the adaptor with the swap secret: s_di = s'_di + t. The result
/// is a standard CLSAG that passes the unmodified monerod-compatible
/// [`crate::clsag_verify::verify_clsag`].
pub fn complete(adaptor: &ClsagAdaptorSig, t: &[u8; 32]) -> Result<ClsagSig, ClsagAdaptorError> {
    let t_s = canonical_scalar(t).ok_or(ClsagAdaptorError::NonCanonicalSecret)?;
    let t_point = match decompress_point(&adaptor.t_point) {
        Some(p) => p,
        None => return Err(ClsagAdaptorError::SecretMismatch),
    };
    if t_s * B != t_point {
        return Err(ClsagAdaptorError::SecretMismatch);
    }
    let s_di = match canonical_scalar(&adaptor.sig.s[adaptor.di]) {
        Some(s) => s,
        None => return Err(ClsagAdaptorError::InvalidCompletion),
    };
    let mut sig = adaptor.sig.clone();
    sig.s[adaptor.di] = (s_di + t_s).to_bytes();
    Ok(sig)
}

/// Recover the swap secret from the completed on-chain signature:
/// t = s_di - s'_di, accepted only if canonical and consistent with BOTH
/// adaptor points ([t]G == T and [t]Hp(P_di) == T_h).
pub fn recover_secret(
    full: &ClsagSig,
    adaptor: &ClsagAdaptorSig,
    ring: &[RingMember],
) -> Option<[u8; 32]> {
    if full.s.len() != adaptor.sig.s.len() || adaptor.di >= ring.len() {
        return None;
    }
    let s_full = canonical_scalar(&full.s[adaptor.di])?;
    let s_pre = canonical_scalar(&adaptor.sig.s[adaptor.di])?;
    let t = s_full - s_pre;
    let t_point = decompress_point(&adaptor.t_point)?;
    if t * B != t_point {
        return None;
    }
    let dest = decompress_point(&ring[adaptor.di].dest)?;
    let t_h_point = decompress_point(&adaptor.t_h_point)?;
    if t * hash_to_p3(&dest.compress().to_bytes()) != t_h_point {
        return None;
    }
    Some(t.to_bytes())
}

// ---------------------------------------------------------------------------
// Tests (synthetic rings; the CLSAG algebra only consumes ring points and
// C_offset - zero-amount commitments are valid for the signature scheme,
// amounts / range proofs are out of scope per the scope doc section 6)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clsag_verify::{keccak256, verify_clsag};

    fn der_scalar(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut buf = tag.to_vec();
        for p in parts {
            buf.extend_from_slice(p);
        }
        keccak256(&buf)
    }

    fn nz_scalar(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        // hash_to_scalar reduces mod l, so the encoding is canonical.
        let mut buf = tag.to_vec();
        for p in parts {
            buf.extend_from_slice(p);
        }
        let mut out = hash_to_scalar(&buf).to_bytes();
        while out == [0u8; 32] {
            out = hash_to_scalar(&out).to_bytes();
        }
        out
    }

    struct Synth {
        ring: Vec<RingMember>,
        x: [u8; 32],
        z: [u8; 32],
        c_offset: [u8; 32],
        message: [u8; 32],
        key_image: [u8; 32],
    }

    /// Synthetic ring: decoys are [r]B dest / [q]B mask (prime-order,
    /// non-degenerate); the real member's mask satisfies
    /// [mask_di] - [C_offset] = [z]G with C_offset = [k]G.
    fn synth_ring(n: usize, di: usize, tag: &[u8]) -> Synth {
        assert!(n >= 2 && di < n);
        let x = nz_scalar(tag, &[b"x"]);
        let z = nz_scalar(tag, &[b"z"]);
        let k = nz_scalar(tag, &[b"k"]);
        let message = der_scalar(tag, &[b"msg"]);
        let x_s = Scalar::from_bytes_mod_order(x);
        let z_s = Scalar::from_bytes_mod_order(z);
        let k_s = Scalar::from_bytes_mod_order(k);

        let c_offset = (k_s * B).compress().to_bytes();
        let p_point = x_s * B;
        let key_image = (x_s * hash_to_p3(&p_point.compress().to_bytes()))
            .compress()
            .to_bytes();

        let mut ring = Vec::with_capacity(n);
        for i in 0..n {
            if i == di {
                ring.push(RingMember {
                    dest: p_point.compress().to_bytes(),
                    mask: ((k_s + z_s) * B).compress().to_bytes(),
                });
            } else {
                let r = nz_scalar(tag, &[b"dest", &le64(i as u64)]);
                let q = nz_scalar(tag, &[b"mask", &le64(i as u64)]);
                ring.push(RingMember {
                    dest: (Scalar::from_bytes_mod_order(r) * B).compress().to_bytes(),
                    mask: (Scalar::from_bytes_mod_order(q) * B).compress().to_bytes(),
                });
            }
        }
        Synth {
            ring,
            x,
            z,
            c_offset,
            message,
            key_image,
        }
    }

    fn sign_ok(s: &Synth, t: &[u8; 32], di: usize) -> ClsagAdaptorSig {
        sign_adaptor(&s.x, &s.z, t, &s.message, &s.ring, &s.c_offset, di)
            .expect("honest sign must succeed")
    }

    #[test]
    fn p1_honest_loop_sign_verify_complete_recover() {
        let s = synth_ring(16, 3, b"p1");
        let t = nz_scalar(b"p1", &[b"t"]);
        let ad = sign_ok(&s, &t, 3);
        assert!(verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
        // The completed signature passes the UNMODIFIED monerod-compatible
        // verifier - the acceptance gate.
        let full = complete(&ad, &t).expect("completion must succeed");
        assert!(verify_clsag(
            &s.message,
            &full,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
        let rec = recover_secret(&full, &ad, &s.ring).expect("recovery must succeed");
        assert_eq!(rec, t);
    }

    #[test]
    fn p2_deterministic_signing() {
        let s = synth_ring(8, 5, b"p2");
        let t = nz_scalar(b"p2", &[b"t"]);
        let a = sign_ok(&s, &t, 5);
        let b = sign_ok(&s, &t, 5);
        assert_eq!(a, b);
    }

    #[test]
    fn p3_recovery_consistency_tg_thp() {
        let s = synth_ring(4, 1, b"p3");
        let t = nz_scalar(b"p3", &[b"t"]);
        let ad = sign_ok(&s, &t, 1);
        let t_s = Scalar::from_bytes_mod_order(t);
        let t_pt = decompress_point(&ad.t_point).expect("T decompresses");
        let t_h_pt = decompress_point(&ad.t_h_point).expect("T_h decompresses");
        let dest = decompress_point(&s.ring[1].dest).expect("dest decompresses");
        assert_eq!(t_s * B, t_pt);
        assert_eq!(t_s * hash_to_p3(&dest.compress().to_bytes()), t_h_pt);
    }

    #[test]
    fn p4_challenge_sequence_identity_adaptor_vs_completed() {
        let s = synth_ring(8, 2, b"p4");
        let t = nz_scalar(b"p4", &[b"t"]);
        let ad = sign_ok(&s, &t, 2);
        let full = complete(&ad, &t).expect("completion must succeed");
        assert!(verify_clsag(
            &s.message,
            &full,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));

        // The adaptor's initial challenge equals the completed signature's
        // challenge chain input at di+1: walking the COMPLETED signature
        // with the standard formula must reproduce H(skel || R_G || R_H)
        // at that position, and close on c1.
        let i_point = decompress_point(&s.key_image).unwrap();
        let d8 = decompress_point(&ad.sig.d).unwrap().mul_by_cofactor();
        let c_offset_point = decompress_point(&s.c_offset).unwrap();
        let mu_p = aggregation_hash(
            HASH_KEY_CLSAG_AGG_0,
            &s.ring,
            &i_point,
            &ad.sig.d,
            &s.c_offset,
        );
        let mu_c = aggregation_hash(
            HASH_KEY_CLSAG_AGG_1,
            &s.ring,
            &i_point,
            &ad.sig.d,
            &s.c_offset,
        );
        let skeleton = round_skeleton(&s.ring, &s.c_offset, &s.message);
        let mut c = canonical_scalar(&full.c1).unwrap();
        for idx in 0..s.ring.len() {
            let p_i = decompress_point(&s.ring[idx].dest).unwrap();
            let mask_i = decompress_point(&s.ring[idx].mask).unwrap();
            let hp_i = hash_to_p3(&s.ring[idx].dest);
            let c_p = mu_p * c;
            let c_c = mu_c * c;
            let l = Scalar::from_bytes_mod_order(full.s[idx]) * B
                + c_p * p_i
                + c_c * (mask_i - c_offset_point);
            let r = Scalar::from_bytes_mod_order(full.s[idx]) * hp_i + c_p * i_point + c_c * d8;
            let mut buf = skeleton.clone();
            buf.extend_from_slice(&l.compress().to_bytes());
            buf.extend_from_slice(&r.compress().to_bytes());
            c = hash_to_scalar(&buf);
            if idx == ad.di {
                let mut init = skeleton.clone();
                init.extend_from_slice(&ad.r_g);
                init.extend_from_slice(&ad.r_h);
                assert_eq!(c.to_bytes(), hash_to_scalar(&init).to_bytes());
            }
        }
        assert_eq!(c.to_bytes(), full.c1);
    }

    #[test]
    fn p5_di_zero_and_di_last_edges() {
        for di in [0usize, 15usize] {
            let mut tag = b"p5".to_vec();
            tag.extend_from_slice(&le64(di as u64));
            let s = synth_ring(16, di, &tag);
            let t = nz_scalar(b"p5", &[b"t"]);
            let ad = sign_ok(&s, &t, di);
            assert!(verify_adaptor(
                &ad,
                &s.message,
                &s.key_image,
                &s.ring,
                &s.c_offset
            ));
            let full = complete(&ad, &t).expect("completion must succeed");
            assert!(verify_clsag(
                &s.message,
                &full,
                &s.key_image,
                &s.ring,
                &s.c_offset
            ));
        }
    }

    #[test]
    fn p6_ring_size_two() {
        let s = synth_ring(2, 0, b"p6");
        let t = nz_scalar(b"p6", &[b"t"]);
        let ad = sign_ok(&s, &t, 0);
        assert!(verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
        let full = complete(&ad, &t).expect("completion must succeed");
        assert!(verify_clsag(
            &s.message,
            &full,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n1_wrong_t_point_rejected() {
        let s = synth_ring(8, 4, b"n1");
        let t = nz_scalar(b"n1", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        ad.t_point = (Scalar::from_bytes_mod_order(nz_scalar(b"n1", &[b"other"])) * B)
            .compress()
            .to_bytes();
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n2_wrong_t_h_point_rejected() {
        let s = synth_ring(8, 4, b"n2");
        let t = nz_scalar(b"n2", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        let other = nz_scalar(b"n2", &[b"other"]);
        let dest = decompress_point(&s.ring[4].dest).unwrap();
        ad.t_h_point = (Scalar::from_bytes_mod_order(other)
            * hash_to_p3(&dest.compress().to_bytes()))
        .compress()
        .to_bytes();
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n3_wrong_r_g_rejected() {
        let s = synth_ring(8, 4, b"n3");
        let t = nz_scalar(b"n3", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        ad.r_g = (Scalar::from_bytes_mod_order(nz_scalar(b"n3", &[b"other"])) * B)
            .compress()
            .to_bytes();
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n4_wrong_r_h_rejected() {
        let s = synth_ring(8, 4, b"n4");
        let t = nz_scalar(b"n4", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        let other = nz_scalar(b"n4", &[b"other"]);
        let dest = decompress_point(&s.ring[4].dest).unwrap();
        ad.r_h = (Scalar::from_bytes_mod_order(other) * hash_to_p3(&dest.compress().to_bytes()))
            .compress()
            .to_bytes();
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n5_wrong_di_rejected() {
        let s = synth_ring(8, 4, b"n5");
        let t = nz_scalar(b"n5", &[b"t"]);
        let ad = sign_ok(&s, &t, 4);
        let mut shifted = ad.clone();
        shifted.di = 5;
        assert!(!verify_adaptor(
            &shifted,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
        let mut oob = ad.clone();
        oob.di = 8;
        assert!(!verify_adaptor(
            &oob,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
        assert!(matches!(
            sign_adaptor(&s.x, &s.z, &t, &s.message, &s.ring, &s.c_offset, 8),
            Err(ClsagAdaptorError::IndexOutOfRange)
        ));
    }

    #[test]
    fn n6_tampered_pre_signature_at_di_rejected() {
        let s = synth_ring(8, 4, b"n6");
        let t = nz_scalar(b"n6", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        let mut v = *ad.sig.s[4].last().unwrap();
        v ^= 0x01;
        let mut tampered = [0u8; 32];
        tampered[..31].copy_from_slice(&ad.sig.s[4][..31]);
        tampered[31] = v;
        ad.sig.s[4] = tampered;
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n7_tampered_decoy_response_rejected() {
        let s = synth_ring(8, 4, b"n7");
        let t = nz_scalar(b"n7", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        ad.sig.s[0][0] ^= 0x01;
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n8_degenerate_t_point_rejected() {
        let s = synth_ring(8, 4, b"n8");
        let t = nz_scalar(b"n8", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        ad.t_point = EdwardsPoint::identity().compress().to_bytes();
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
        // Small-order torsion point (0, p-1), order 2.
        let mut small = [0u8; 32];
        small[0] = 0xec;
        for b in small.iter_mut().take(31).skip(1) {
            *b = 0xff;
        }
        small[31] = 0x7f;
        ad.t_point = small;
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n9_non_canonical_pre_signature_rejected() {
        let s = synth_ring(8, 4, b"n9");
        let t = nz_scalar(b"n9", &[b"t"]);
        let mut ad = sign_ok(&s, &t, 4);
        // s' + l: canonical parse fails before any crypto.
        let l = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut sum = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = ad.sig.s[4][i] as u16 + l[i] as u16 + carry;
            sum[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        ad.sig.s[4] = sum;
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n10_ring_substitution_rejected() {
        let s = synth_ring(8, 4, b"n10");
        let t = nz_scalar(b"n10", &[b"t"]);
        let ad = sign_ok(&s, &t, 4);
        let mut ring2 = s.ring.clone();
        ring2.swap(0, 1);
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &ring2,
            &s.c_offset
        ));
        assert!(!verify_clsag(
            &s.message,
            &complete(&ad, &t).unwrap(),
            &s.key_image,
            &ring2,
            &s.c_offset
        ));
    }

    #[test]
    fn n11_completion_with_wrong_secret_rejected() {
        let s = synth_ring(8, 4, b"n11");
        let t = nz_scalar(b"n11", &[b"t"]);
        let ad = sign_ok(&s, &t, 4);
        let wrong = nz_scalar(b"n11", &[b"wrong"]);
        // complete() checks [t]G == T: a wrong t is an error, never a
        // signature.
        assert!(matches!(
            complete(&ad, &wrong),
            Err(ClsagAdaptorError::SecretMismatch)
        ));
        // Even a full section forged by shifting s with the wrong offset
        // fails the monerod verifier.
        let wrong_s = Scalar::from_bytes_mod_order(wrong);
        let s_di = canonical_scalar(&ad.sig.s[4]).unwrap();
        let mut forged = ad.sig.clone();
        forged.s[4] = (s_di + wrong_s).to_bytes();
        assert!(!verify_clsag(
            &s.message,
            &forged,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n12_non_canonical_secret_rejected_at_sign_and_complete() {
        let s = synth_ring(8, 4, b"n12");
        let t = nz_scalar(b"n12", &[b"t"]);
        let l = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        assert!(matches!(
            sign_adaptor(&l, &s.z, &t, &s.message, &s.ring, &s.c_offset, 4),
            Err(ClsagAdaptorError::NonCanonicalSecret)
        ));
        let ad = sign_ok(&s, &t, 4);
        assert!(matches!(
            complete(&ad, &l),
            Err(ClsagAdaptorError::NonCanonicalSecret)
        ));
    }

    #[test]
    fn n13_wrong_message_rejected() {
        let s = synth_ring(8, 4, b"n13");
        let t = nz_scalar(b"n13", &[b"t"]);
        let ad = sign_ok(&s, &t, 4);
        let msg2 = der_scalar(b"n13", &[b"other"]);
        assert!(!verify_adaptor(
            &ad,
            &msg2,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
        let full = complete(&ad, &t).unwrap();
        assert!(!verify_clsag(
            &msg2,
            &full,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n14_wrong_c_offset_rejected() {
        let s = synth_ring(8, 4, b"n14");
        let t = nz_scalar(b"n14", &[b"t"]);
        let ad = sign_ok(&s, &t, 4);
        let off2 = (Scalar::from_bytes_mod_order(nz_scalar(b"n14", &[b"other"])) * B)
            .compress()
            .to_bytes();
        assert!(!verify_adaptor(
            &ad,
            &s.message,
            &s.key_image,
            &s.ring,
            &off2
        ));
        let full = complete(&ad, &t).unwrap();
        assert!(!verify_clsag(
            &s.message,
            &full,
            &s.key_image,
            &s.ring,
            &off2
        ));
    }

    #[test]
    fn n15_wrong_key_image_or_d_rejected() {
        let s = synth_ring(8, 4, b"n15");
        let t = nz_scalar(b"n15", &[b"t"]);
        let ad = sign_ok(&s, &t, 4);
        let ki2 = (Scalar::from_bytes_mod_order(nz_scalar(b"n15", &[b"other"])) * B)
            .compress()
            .to_bytes();
        assert!(!verify_adaptor(&ad, &s.message, &ki2, &s.ring, &s.c_offset));
        let mut ad2 = ad.clone();
        ad2.sig.d[0] ^= 0x01;
        assert!(!verify_adaptor(
            &ad2,
            &s.message,
            &s.key_image,
            &s.ring,
            &s.c_offset
        ));
    }

    #[test]
    fn n16_recovery_from_tampered_full_signature_fails() {
        let s = synth_ring(8, 4, b"n16");
        let t = nz_scalar(b"n16", &[b"t"]);
        let ad = sign_ok(&s, &t, 4);
        let full_ok = complete(&ad, &t).unwrap();
        // Tampered s in the on-chain signature: t no longer matches T.
        let mut full = full_ok.clone();
        full.s[4][0] ^= 0x01;
        assert!(recover_secret(&full, &ad, &s.ring).is_none());
        // Tampered T_h: the Hp consistency check fails even though [t]G
        // still matches T.
        let mut ad2 = ad.clone();
        ad2.t_h_point[0] ^= 0x01;
        assert!(recover_secret(&full_ok, &ad2, &s.ring).is_none());
        // Shifted signer index: the scalar difference is between two decoy
        // responses and cannot match T.
        let mut ad3 = ad.clone();
        ad3.di = 5;
        assert!(recover_secret(&full_ok, &ad3, &s.ring).is_none());
    }

    #[test]
    fn n17_zero_and_degenerate_secrets_rejected_at_sign() {
        let s = synth_ring(8, 4, b"n17");
        let t = nz_scalar(b"n17", &[b"t"]);
        let zero = [0u8; 32];
        assert!(matches!(
            sign_adaptor(&zero, &s.z, &t, &s.message, &s.ring, &s.c_offset, 4),
            Err(ClsagAdaptorError::DegenerateSecret)
        ));
        assert!(matches!(
            sign_adaptor(&s.x, &zero, &t, &s.message, &s.ring, &s.c_offset, 4),
            Err(ClsagAdaptorError::DegenerateSecret)
        ));
        assert!(matches!(
            sign_adaptor(&s.x, &s.z, &zero, &s.message, &s.ring, &s.c_offset, 4),
            Err(ClsagAdaptorError::DegenerateSecret)
        ));
        assert!(sign_adaptor(&s.x, &s.z, &t, &s.message, &s.ring, &s.c_offset, 4).is_ok());
    }

    #[test]
    fn n18_ring_too_small_rejected() {
        let s = synth_ring(4, 1, b"n18");
        let t = nz_scalar(b"n18", &[b"t"]);
        let one = [s.ring[0].clone()];
        assert!(matches!(
            sign_adaptor(&s.x, &s.z, &t, &s.message, &one, &s.c_offset, 0),
            Err(ClsagAdaptorError::RingTooSmall)
        ));
    }
}
