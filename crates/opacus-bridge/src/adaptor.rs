//! Adaptor signatures for the XMR <-> GHOST swap secret (WG-18).
//!
//! A Schnorr adaptor signature over the ed25519 basepoint: the signer
//! produces a signature that only becomes a valid full Schnorr signature
//! once it is completed with a hidden scalar `t` - the swap secret. The
//! hidden scalar is exactly what the counterparty needs, and completing
//! (or verifying against) the adaptor proves knowledge of it without
//! revealing it:
//!
//! ```text
//!   secret    t  in F_l            SwapSecret::t
//!   point     T = [t] * B          published with the offer / lock
//!   adaptor   s' = r - t + e * a   (a = signing key, r = nonce)
//!   verify    s' * B + T == R + e * A
//!   complete  s  = s' + t          full Schnorr sig (R, s)
//!   recover   t  = s - s'          from the completed signature
//! ```
//!
//! The nonce is deterministic (SHA-3 over the signing key, the adaptor
//! point and the message), so signing never depends on system
//! randomness and the nonce is never reused across distinct messages.
//! The scheme is an internal bridge primitive - it intentionally does
//! NOT reproduce the ed25519 standard challenge encoding (dom2/F
//! flags); Monero-side CLSAG adaptor integration stays a v0.3 item.
//!
//! Replaces the v0.2 `verify_placeholder` stub (a non-zero-byte check)
//! flagged by the security audit: verification is now the real group
//! equation over curve25519.
//!
//! WG-19 hardening: verification rejects degenerate adaptor points
//! `T` (identity / small order - a consistent zero-secret adaptor
//! used to pass) and enforces canonical `s` encodings (BIP-340
//! style), closing the `+(l)` malleability of completed signatures.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum AdaptorError {
    #[error("Invalid adaptor signature")]
    InvalidSignature,
    #[error("Invalid curve point encoding")]
    InvalidPoint,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SwapSecret {
    pub t: [u8; 32],
}

impl SwapSecret {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // Canonical field element: adaptor arithmetic (complete/recover)
        // reduces modulo the group order, so the secret is stored reduced
        // and complete/recover round-trips stay byte-exact. Struct-literal
        // secrets that exceed the order still work - every consumer goes
        // through `Scalar::from_bytes_mod_order`.
        Self {
            t: Scalar::random(rng).to_bytes(),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.t);
        hasher.finalize().into()
    }
}

/// Domain-separated SHA-3 tag: keeps every hash in this module independent
/// of the swap hashlock, offer ids and other bridge hashes.
const NONCE_TAG: &[u8] = b"ghost-bridge/adaptor/nonce-v1";
const CHALLENGE_TAG: &[u8] = b"ghost-bridge/adaptor/chal-v1";

/// Reduce a 64-byte hash into the scalar field (wide reduction, no bias
/// concern for the nonce/challenge of a Schnorr scheme over F_l).
fn scalar_from_hash64(digest: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(digest)
}

/// The public point `[t] * B` of a swap secret (compressed edwards).
pub fn derive_point(t: &[u8; 32]) -> [u8; 32] {
    (Scalar::from_bytes_mod_order(*t) * B).compress().to_bytes()
}

/// Schnorr challenge `e = SHA3_256(tag || R || A || msg)` reduced into the
/// scalar field. Verifier and signer MUST hash the same compressed bytes.
fn challenge(r_point: &[u8; 32], a_pub: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha3_256::new();
    h.update(CHALLENGE_TAG);
    h.update(r_point);
    h.update(a_pub);
    h.update(msg);
    let d: [u8; 32] = h.finalize().into();
    Scalar::from_bytes_mod_order(d)
}

/// Decompress a curve point or fail with [`AdaptorError::InvalidPoint`].
fn decompress(bytes: &[u8; 32]) -> Result<EdwardsPoint, AdaptorError> {
    CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or(AdaptorError::InvalidPoint)
}

/// Parse a scalar from its canonical (reduced) little-endian encoding.
/// Non-canonical encodings `n >= l` are rejected instead of being
/// silently reduced (BIP-340-style canonical-s policy, WG-19): the
/// difference is invisible to the group equation but yields two
/// distinct byte encodings of one signature (malleability).
fn canonical_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = Scalar::from_bytes_mod_order(*bytes);
    if s.to_bytes() != *bytes {
        return None;
    }
    Some(s)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdaptorSignature {
    /// Nonce commitment `R = [r] * B` (compressed).
    pub r_point: [u8; 32],
    /// Hidden signature `s' = r - t + e * a` (canonical scalar bytes).
    pub s_adaptor: [u8; 32],
    /// The hidden secret's point `T = [t] * B` (compressed).
    pub t_point: [u8; 32],
}

impl AdaptorSignature {
    /// Sign `msg` under the secret key `a` with the swap secret `t` as the
    /// adaptor: the result is a valid adaptor signature that only the
    /// holder of `t` can complete into a full Schnorr signature.
    ///
    /// Nonce: `r = SHA3_512(tag || a || T || msg)` - deterministic and
    /// message-bound, so two signatures never share a nonce.
    pub fn sign(sk: &[u8; 32], t: &SwapSecret, msg: &[u8]) -> Self {
        let a = Scalar::from_bytes_mod_order(*sk);
        let a_pub = (a * B).compress().to_bytes();
        let t_point = derive_point(&t.t);
        let mut h = Sha3_512::new();
        h.update(NONCE_TAG);
        h.update(sk);
        h.update(t_point);
        h.update(msg);
        let r = scalar_from_hash64(&h.finalize().into());
        let r_point = (r * B).compress().to_bytes();
        let e = challenge(&r_point, &a_pub, msg);
        let s_adaptor = r - Scalar::from_bytes_mod_order(t.t) + e * a;
        AdaptorSignature {
            r_point,
            s_adaptor: s_adaptor.to_bytes(),
            t_point,
        }
    }

    /// Verify the adaptor signature against the public key `a_pub` over
    /// `msg`: `s' * B + T == R + e * A`. Completing with the true secret
    /// turns this equation into the full Schnorr verification
    /// `s * B == R + e * A`.
    ///
    /// WG-19: degenerate adaptor points (identity / small order `T`) and
    /// non-canonical `s'` encodings are rejected (BIP-340-style).
    pub fn verify(&self, msg: &[u8], a_pub: &[u8; 32]) -> bool {
        let (Ok(r_point), Ok(a)) = (decompress(&self.r_point), decompress(a_pub)) else {
            return false;
        };
        let Ok(t_point) = decompress(&self.t_point) else {
            return false;
        };
        // WG-19: reject degenerate adaptor points. T = identity is the
        // consistent zero-secret adaptor (s' = r + e * a used to verify
        // while carrying no secret), and small-order T leaves the hidden
        // scalar under-determined. Honest sign() can never emit one:
        // [t] * B with t in F_l always lands in the prime-order subgroup.
        if t_point.is_small_order() {
            return false;
        }
        let Some(s_adaptor) = canonical_scalar(&self.s_adaptor) else {
            return false;
        };
        let e = challenge(&self.r_point, a_pub, msg);
        let lhs = s_adaptor * B + t_point;
        lhs == r_point + e * a
    }

    /// Complete the adaptor with the swap secret: returns the full 64-byte
    /// Schnorr signature `(R, s)` with `s = s' + t`. Passing a secret whose
    /// point differs from `t_point` yields a signature that fails Schnorr
    /// verification (the equation only closes for the true `t`).
    pub fn complete(&self, t: &SwapSecret) -> [u8; 64] {
        let s = Scalar::from_bytes_mod_order(self.s_adaptor) + Scalar::from_bytes_mod_order(t.t);
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r_point);
        out[32..].copy_from_slice(&s.to_bytes());
        out
    }

    /// Recover the hidden swap secret from a completed signature: the
    /// scalar difference `t = s - s'` is checked against the published
    /// adaptor point `T = [t] * B` before it is returned, so a mismatched
    /// (adaptor, signature) pair yields `None` instead of a wrong secret.
    pub fn recover_secret(full_sig: &[u8; 64], adaptor: &AdaptorSignature) -> Option<SwapSecret> {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&full_sig[32..]);
        let t =
            Scalar::from_bytes_mod_order(s_bytes) - Scalar::from_bytes_mod_order(adaptor.s_adaptor);
        if (t * B).compress().to_bytes() != adaptor.t_point {
            return None;
        }
        Some(SwapSecret { t: t.to_bytes() })
    }
}

/// Verify a completed (full) Schnorr signature `(R, s)` over `msg` under
/// `a_pub`: `s * B == R + e * A`. This is the check the counterparty runs
/// on the completed signature that revealed the swap secret.
///
/// WG-19: `s` must be canonically encoded (`s < l`, BIP-340-style): a
/// `+(l)`-shifted re-encoding of a valid signature is rejected instead
/// of silently reducing to the same scalar (malleability fix).
pub fn verify_full(full_sig: &[u8; 64], msg: &[u8], a_pub: &[u8; 32]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&full_sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&full_sig[32..]);
    let Ok(r_point) = decompress(&r_bytes) else {
        return false;
    };
    let Ok(a) = decompress(a_pub) else {
        return false;
    };
    let Some(s) = canonical_scalar(&s_bytes) else {
        return false;
    };
    let e = challenge(&r_bytes, a_pub, msg);
    s * B == r_point + e * a
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let sk = SwapSecret::generate(&mut OsRng).t;
        let a = Scalar::from_bytes_mod_order(sk);
        let a_pub = (a * B).compress().to_bytes();
        (sk, a_pub)
    }

    const MSG: &[u8] = b"ghost-bridge: claim xmr with preimage";

    #[test]
    fn adaptor_sign_verify_roundtrip() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        assert!(sig.verify(MSG, &a_pub));
        // The adaptor point must be the secret's point.
        assert_eq!(sig.t_point, derive_point(&t.t));
    }

    #[test]
    fn adaptor_verify_rejects_wrong_message() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        assert!(!sig.verify(b"different message", &a_pub));
    }

    #[test]
    fn adaptor_verify_rejects_wrong_pubkey() {
        let (sk, _) = keypair();
        let (_, a_pub2) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        assert!(!sig.verify(MSG, &a_pub2));
    }

    #[test]
    fn adaptor_verify_rejects_tampered_s() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let mut sig = AdaptorSignature::sign(&sk, &t, MSG);
        sig.s_adaptor[0] ^= 0x01;
        assert!(!sig.verify(MSG, &a_pub));
    }

    #[test]
    fn adaptor_verify_rejects_garbage_points() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let mut sig = AdaptorSignature::sign(&sk, &t, MSG);
        // Non-canonical / non-decompressible r_point.
        sig.r_point = [0xff; 32];
        assert!(!sig.verify(MSG, &a_pub));
        let mut sig2 = AdaptorSignature::sign(&sk, &t, MSG);
        sig2.t_point = [0xff; 32];
        assert!(!sig2.verify(MSG, &a_pub));
    }

    #[test]
    fn complete_produces_valid_full_schnorr() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        let full = sig.complete(&t);
        assert!(verify_full(&full, MSG, &a_pub));
        assert!(!verify_full(&full, b"other", &a_pub));
    }

    #[test]
    fn complete_with_wrong_secret_fails_verification() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let wrong = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        let full = sig.complete(&wrong);
        assert!(!verify_full(&full, MSG, &a_pub));
    }

    #[test]
    fn recover_secret_matches_original() {
        let (sk, _) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        let full = sig.complete(&t);
        let recovered = AdaptorSignature::recover_secret(&full, &sig).expect("secret recovers");
        assert_eq!(recovered.t, t.t);
        // And the recovered secret verifies as the adaptor's hidden point.
        assert_eq!(derive_point(&recovered.t), sig.t_point);
    }

    #[test]
    fn recover_secret_rejects_mismatched_pair() {
        let (sk, _) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        // Completed with a DIFFERENT secret -> the difference is not the
        // adaptor's hidden scalar -> rejected by the T = [t] * B check.
        let wrong = SwapSecret::generate(&mut OsRng);
        let full = sig.complete(&wrong);
        assert!(AdaptorSignature::recover_secret(&full, &sig).is_none());
        // Truncated/garbage full signature must not panic either.
        assert!(AdaptorSignature::recover_secret(&[0u8; 64], &sig).is_none());
    }

    #[test]
    fn derive_point_is_deterministic_and_binding() {
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        assert_eq!(derive_point(&t1), derive_point(&t1));
        assert_ne!(derive_point(&t1), derive_point(&t2));
        // Zero secret maps to the identity point encoding; derive_point
        // stays pure math, while verify() rejects the degenerate adaptor
        // (see verify_rejects_zero_secret_adaptor).
        let zero = derive_point(&[0u8; 32]);
        assert!(decompress(&zero).is_ok());
    }

    #[test]
    fn secret_hash_is_deterministic() {
        let t = SwapSecret::generate(&mut OsRng);
        assert_eq!(t.hash(), t.hash());
        let mut flipped = t.t;
        flipped[0] ^= 1;
        assert_ne!(t.hash(), SwapSecret { t: flipped }.hash());
    }

    #[test]
    fn deterministic_nonce_repeats_only_for_identical_inputs() {
        let (sk, _) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let s1 = AdaptorSignature::sign(&sk, &t, MSG);
        let s2 = AdaptorSignature::sign(&sk, &t, MSG);
        assert_eq!(s1.r_point, s2.r_point);
        assert_eq!(s1.s_adaptor, s2.s_adaptor);
        let s3 = AdaptorSignature::sign(&sk, &t, b"another msg");
        assert_ne!(s1.r_point, s3.r_point);
    }

    // -- WG-19 hardening tests ----------------------------------------------

    /// Little-endian encoding of the ed25519 group order
    /// l = 2^252 + 27742317777372353535851937790883648493.
    fn order_le() -> [u8; 32] {
        const ORDER_HEX: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";
        let mut b = [0u8; 32];
        for i in 0..32 {
            b[i] = u8::from_str_radix(&ORDER_HEX[2 * i..2 * i + 2], 16).expect("valid hex");
        }
        b
    }

    /// Little-endian 32-byte addition (no modular reduction): n = s + l
    /// fits in 32 bytes whenever s < l, and n mod l == s.
    fn le_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            out[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "le_add overflow");
        out
    }

    #[test]
    fn verify_rejects_zero_secret_adaptor() {
        let (sk, a_pub) = keypair();
        // A consistent zero-secret adaptor: t = 0 -> T = identity and
        // s' = r + e * a closes the group equation while carrying no
        // secret. Pre-WG-19 this PASSED verification.
        let zero = SwapSecret { t: [0u8; 32] };
        let sig = AdaptorSignature::sign(&sk, &zero, MSG);
        assert_eq!(sig.t_point, derive_point(&zero.t));
        assert!(!sig.verify(MSG, &a_pub));
    }

    #[test]
    fn verify_rejects_small_order_t_point() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let mut sig = AdaptorSignature::sign(&sk, &t, MSG);
        // Order-8 torsion point: decompresses fine, not the identity,
        // but outside the prime-order subgroup - rejected as policy
        // (the group equation alone would reject it too).
        sig.t_point = EIGHT_TORSION[1].compress().to_bytes();
        assert!(!sig.verify(MSG, &a_pub));
    }

    #[test]
    fn verify_rejects_non_canonical_s_adaptor() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let mut sig = AdaptorSignature::sign(&sk, &t, MSG);
        // s' + l encodes the same scalar non-canonically: the pre-WG-19
        // verifier reduced it silently and the equation closed.
        let shifted = le_add(&sig.s_adaptor, &order_le());
        assert_ne!(shifted, sig.s_adaptor);
        sig.s_adaptor = shifted;
        assert!(!sig.verify(MSG, &a_pub));
    }

    #[test]
    fn verify_full_rejects_non_canonical_s() {
        let (sk, a_pub) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = AdaptorSignature::sign(&sk, &t, MSG);
        let full = sig.complete(&t);
        assert!(verify_full(&full, MSG, &a_pub));
        // Malleated re-encoding s + l of the same scalar: pre-WG-19 the
        // verifier accepted it (from_bytes_mod_order silently reduced);
        // now rejected, killing the +(l) malleability.
        let mut malleated = [0u8; 64];
        malleated[..32].copy_from_slice(&full[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&full[32..]);
        let shifted = le_add(&s_bytes, &order_le());
        malleated[32..].copy_from_slice(&shifted);
        assert!(!verify_full(&malleated, MSG, &a_pub));
    }
}
