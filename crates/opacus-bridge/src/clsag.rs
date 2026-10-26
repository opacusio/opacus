//! CLSAG-style one-time adaptor signature for the Monero side of the swap
//! (WG-20, v0.3 backlog item "Monero CLSAG adaptor-integration").
//!
//! This is the key-image counterpart of [`crate::adaptor`]: the same Schnorr
//! adaptor algebra, extended with the CryptoNote one-time linkability tag so
//! a Monero-side spend under a one-time key binds the swap secret `t`.
//!
//! ```text
//!   one-time key   x                    the XMR spend key of the swap leg
//!   pubkey         P = [x] * G
//!   hash-to-point  H(P)                 see `hp` below
//!   key image      I = [x] * H(P)       unique per x: two spends under the
//!                                       same one-time key share I (linkable)
//!   adaptor        s' = a - t + e * x   (nonce a, challenge e)
//!   verify         s' * G + T     == R_g + e * P
//!                  s' * H(P) + T_h == R_h + e * I
//!   complete       s  = s' + t          full one-time signature (R_g, R_h, s)
//!   recover        t  = s - s'          from the completed signature
//! ```
//!
//! Both bases move together: `T = [t] * G` and `T_h = [t] * H(P)` are
//! published with the adaptor, and completing on `G` while failing on
//! `H(P)` is impossible for the same `t` - the challenge binds every
//! published point plus the message.
//!
//! Hash-to-point policy: `hp` is a domain-separated blake3 try-and-increment
//! into the curve (`decompress` + cofactor clearing), so outputs are always
//! in the prime-order subgroup. It intentionally is NOT byte-identical to
//! Monero's `ge_fromfe_frombytes_vartime` (that port needs dalek-internal
//! field APIs); the scheme is a bridge-internal primitive and monerod
//! byte-compatibility lands with on-chain CLSAG verification (v0.4).
//!
//! Policies carried over from the WG-19 hardening of `adaptor.rs`:
//! degenerate (identity / small-order) key images and adaptor points are
//! rejected, and `s` encodings must be canonical (BIP-340-style), killing
//! the +(l) malleation of completed signatures.
//!
//! The nonce is deterministic (blake3 over the signing key, both nonce
//! commitments, the published points and the message), so signing never
//! depends on system randomness and nonces never repeat across messages.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as B;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::adaptor::SwapSecret;

const NONCE_TAG: &[u8] = b"ghost-bridge/clsag/nonce-v1";
const NONCE_WIDE_TAG: &[u8] = b"ghost-bridge/clsag/nonce-wide-v1";
const CHALLENGE_TAG: &[u8] = b"ghost-bridge/clsag/chal-v1";
const HP_TAG: &[u8] = b"ghost-bridge/clsag/hp-v1";

/// Decompress a curve point, or `None` on non-canonical / non-decompressible
/// encodings.
fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

/// Parse a scalar from its canonical (reduced) little-endian encoding.
/// Non-canonical encodings `n >= l` are rejected instead of being silently
/// reduced (BIP-340-style canonical-s policy, WG-19).
fn canonical_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = Scalar::from_bytes_mod_order(*bytes);
    if s.to_bytes() != *bytes {
        return None;
    }
    Some(s)
}

/// Hash-to-point: domain-separated blake3 try-and-increment.
///
/// Streams `tag || m || counter` through blake3 until the output decodes as
/// a curve point (each attempt succeeds with probability ~1/2), then clears
/// the cofactor, so the result always lies in the prime-order subgroup.
/// Deterministic, platform-independent and terminating (a.s. after 2 tries;
/// the counter is a safety valve, not part of the security argument).
fn hp(m: &[u8; 32]) -> EdwardsPoint {
    let mut ctr: u32 = 0;
    loop {
        let mut h = blake3::Hasher::new();
        h.update(HP_TAG);
        h.update(m);
        h.update(&ctr.to_be_bytes());
        let bytes: [u8; 32] = h.finalize().into();
        if let Some(p) = CompressedEdwardsY(bytes).decompress() {
            return p.mul_by_cofactor();
        }
        ctr += 1;
    }
}

/// One-time key material: the compressed spend pubkey `P = [x] * G` and the
/// matching key image `I = [x] * H(P)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneTimeKeys {
    pub p: [u8; 32],
    pub image: [u8; 32],
}

/// WG-21: structural (wire-level) validation of a one-time key binding:
/// both points must decompress, neither may be degenerate (identity or
/// small-order torsion), and the image must differ from the key. The
/// cryptographic image equation needs the secret and is checked at
/// lock/claim time instead.
pub fn validate_one_time_binding(p: &[u8; 32], image: &[u8; 32]) -> bool {
    let (Some(pk), Some(img)) = (decompress(p), decompress(image)) else {
        return false;
    };
    if pk.is_small_order() || img.is_small_order() {
        return false;
    }
    pk != img
}

/// Derive the one-time public key and key image for a spend key.
pub fn one_time_keys(sk: &[u8; 32]) -> OneTimeKeys {
    let x = Scalar::from_bytes_mod_order(*sk);
    let p = (x * B).compress();
    let image = x * hp(&p.to_bytes());
    OneTimeKeys {
        p: p.to_bytes(),
        image: image.compress().to_bytes(),
        // WG-21: (p, image) travel on the wire as the offer-side binding
        // (swap_p2p::OfferAdaptor); derivation stays deterministic here.
    }
}

/// Deterministic wide nonce: 64 bytes of blake3 output reduced mod l, over
/// every input the signature depends on (key, both bases' commitments, the
/// published adaptor points and the message).
fn wide_nonce(
    sk: &[u8; 32],
    p: &[u8; 32],
    image: &[u8; 32],
    t_point: &[u8; 32],
    t_point_h: &[u8; 32],
    msg: &[u8],
) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(NONCE_TAG);
    h.update(sk);
    h.update(p);
    h.update(image);
    h.update(t_point);
    h.update(t_point_h);
    h.update(msg);
    let h1: [u8; 32] = h.finalize().into();
    let mut h2 = blake3::Hasher::new();
    h2.update(NONCE_WIDE_TAG);
    h2.update(&h1);
    let h2: [u8; 32] = h2.finalize().into();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&h1);
    wide[32..].copy_from_slice(&h2);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Challenge `e = blake3(tag || R_g || R_h || P || I || T || T_h || msg)`
/// reduced into the scalar field. Verifier and signer MUST hash the same
/// compressed bytes; the adaptor points are part of the transcript.
#[allow(clippy::too_many_arguments)]
fn challenge(
    r_g: &[u8; 32],
    r_h: &[u8; 32],
    p: &[u8; 32],
    image: &[u8; 32],
    t_point: &[u8; 32],
    t_point_h: &[u8; 32],
    msg: &[u8],
) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(CHALLENGE_TAG);
    h.update(r_g);
    h.update(r_h);
    h.update(p);
    h.update(image);
    h.update(t_point);
    h.update(t_point_h);
    h.update(msg);
    let d: [u8; 32] = h.finalize().into();
    Scalar::from_bytes_mod_order(d)
}

/// A CLSAG-style one-time adaptor signature over the swap secret `t`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClsagAdaptor {
    /// Nonce commitment on the basepoint: `R_g = [a] * G`.
    pub r_g: [u8; 32],
    /// Nonce commitment on the hash point: `R_h = [a] * H(P)`.
    pub r_h: [u8; 32],
    /// Hidden signature `s' = a - t + e * x` (canonical scalar bytes).
    pub s_adaptor: [u8; 32],
    /// The hidden secret's point `T = [t] * G` (compressed).
    pub t_point: [u8; 32],
    /// The hidden secret's point on the hash base: `T_h = [t] * H(P)`.
    pub t_point_h: [u8; 32],
}

impl ClsagAdaptor {
    /// Sign `msg` under the one-time spend key `x` with the swap secret `t`
    /// as the adaptor. Only the holder of `t` can complete this into a full
    /// one-time signature; completing it leaks `t` (see [`Self::recover`]).
    pub fn sign(sk: &[u8; 32], t: &SwapSecret, msg: &[u8]) -> Self {
        let keys = one_time_keys(sk);
        let x = Scalar::from_bytes_mod_order(*sk);
        let hp_p = hp(&keys.p);
        let t_sc = Scalar::from_bytes_mod_order(t.t);
        let t_point = (t_sc * B).compress().to_bytes();
        let t_point_h = (t_sc * hp_p).compress().to_bytes();
        let alpha = wide_nonce(sk, &keys.p, &keys.image, &t_point, &t_point_h, msg);
        let r_g = (alpha * B).compress().to_bytes();
        let r_h = (alpha * hp_p).compress().to_bytes();
        let e = challenge(&r_g, &r_h, &keys.p, &keys.image, &t_point, &t_point_h, msg);
        let s = alpha + e * x - t_sc;
        ClsagAdaptor {
            r_g,
            r_h,
            s_adaptor: s.to_bytes(),
            t_point,
            t_point_h,
        }
    }

    /// Verify the adaptor against the one-time pubkey `p` and key image
    /// `image` over `msg`. Both base equations must close:
    /// `s' * G + T == R_g + e * P` and `s' * H(P) + T_h == R_h + e * I`.
    /// Completing with the true secret turns them into the full one-time
    /// signature verification (`s * G == R_g + e * P` and
    /// `s * H(P) == R_h + e * I`).
    pub fn verify(&self, msg: &[u8], p: &[u8; 32], image: &[u8; 32]) -> bool {
        let r_g = decompress(&self.r_g);
        let r_h = decompress(&self.r_h);
        let (Some(r_g), Some(r_h)) = (r_g, r_h) else {
            return false;
        };
        let Some(pk) = decompress(p) else {
            return false;
        };
        let Some(img) = decompress(image) else {
            return false;
        };
        let tp = decompress(&self.t_point);
        let tph = decompress(&self.t_point_h);
        let (Some(tp), Some(tph)) = (tp, tph) else {
            return false;
        };
        // WG-19 policy: degenerate (identity / small-order) points are
        // rejected before any group arithmetic runs.
        if img.is_small_order() || tp.is_small_order() || tph.is_small_order() {
            return false;
        }
        let Some(s) = canonical_scalar(&self.s_adaptor) else {
            return false;
        };
        let e = challenge(
            &self.r_g,
            &self.r_h,
            p,
            image,
            &self.t_point,
            &self.t_point_h,
            msg,
        );
        let hp_p = hp(p);
        if s * B + tp != r_g + e * pk {
            return false;
        }
        if s * hp_p + tph != r_h + e * img {
            return false;
        }
        true
    }

    /// Complete the adaptor with the swap secret: returns the full 96-byte
    /// one-time signature `(R_g, R_h, s)` with `s = s' + t`. A secret whose
    /// points differ from `t_point` / `t_point_h` yields a signature that
    /// fails [`verify_full`] (the equations only close for the true `t`).
    pub fn complete(&self, t: &SwapSecret) -> [u8; 96] {
        let s = Scalar::from_bytes_mod_order(self.s_adaptor) + Scalar::from_bytes_mod_order(t.t);
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(&self.r_g);
        out[32..64].copy_from_slice(&self.r_h);
        out[64..].copy_from_slice(&s.to_bytes());
        out
    }

    /// Recover the hidden swap secret from a completed signature: the
    /// scalar difference `t = s - s'` is checked against BOTH published
    /// points (`[t] * G == T` and `[t] * H(P) == T_h`) before it is
    /// returned, so a mismatched (adaptor, signature) pair yields `None`
    /// instead of a wrong secret.
    pub fn recover(full: &[u8; 96], adaptor: &ClsagAdaptor, p: &[u8; 32]) -> Option<SwapSecret> {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&full[64..]);
        let s = canonical_scalar(&s_bytes)?;
        let s_adaptor = canonical_scalar(&adaptor.s_adaptor)?;
        let t = s - s_adaptor;
        if (t * B).compress().to_bytes() != adaptor.t_point {
            return None;
        }
        // WG-21: the offer sidecar pre-binds (P, I) so the taker can
        // refuse mismatched locks before locking XMR; this check stays
        // the key-image leg of completed-signature recovery.
        if (t * hp(p)).compress().to_bytes() != adaptor.t_point_h {
            return None;
        }
        Some(SwapSecret { t: t.to_bytes() })
    }
}

/// Verify a completed (full) one-time signature `(R_g, R_h, s)` over `msg`
/// under the one-time pubkey `p` and key image `image`, against the
/// adaptor's published points `T` / `T_h`: `s * G == R_g + e * P` and
/// `s * H(P) == R_h + e * I`. This is the check the counterparty runs on
/// the completed signature that revealed the swap secret. The challenge is
/// recomputed from the FULL signature's nonce commitments, so a synthesized
/// `(R_g, R_h, s)` tuple cannot pass without solving a fixed-point of the
/// random oracle (Schnorr unforgeability).
pub fn verify_full(
    full: &[u8; 96],
    adaptor: &ClsagAdaptor,
    msg: &[u8],
    p: &[u8; 32],
    image: &[u8; 32],
) -> bool {
    let mut rg = [0u8; 32];
    rg.copy_from_slice(&full[..32]);
    let mut rh = [0u8; 32];
    rh.copy_from_slice(&full[32..64]);
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&full[64..]);
    let r_g = decompress(&rg);
    let r_h = decompress(&rh);
    let (Some(r_g), Some(r_h)) = (r_g, r_h) else {
        return false;
    };
    let Some(pk) = decompress(p) else {
        return false;
    };
    let Some(img) = decompress(image) else {
        return false;
    };
    let tp = decompress(&adaptor.t_point);
    let tph = decompress(&adaptor.t_point_h);
    let (Some(tp), Some(tph)) = (tp, tph) else {
        return false;
    };
    if img.is_small_order() || tp.is_small_order() || tph.is_small_order() {
        return false;
    }
    let Some(s) = canonical_scalar(&sb) else {
        return false;
    };
    let e = challenge(
        &rg,
        &rh,
        p,
        image,
        &adaptor.t_point,
        &adaptor.t_point_h,
        msg,
    );
    let hp_p = hp(p);
    if s * B != r_g + e * pk {
        return false;
    }
    if s * hp_p != r_h + e * img {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn keypair() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let sk = SwapSecret::generate(&mut OsRng).t;
        let keys = one_time_keys(&sk);
        (sk, keys.p, keys.image)
    }

    /// The group order l, as canonical little-endian bytes (WG-19 helper).
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

    fn identity_bytes() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    }

    const MSG: &[u8] = b"ghost-bridge: clsag claim xmr with preimage";

    #[test]
    #[allow(deprecated)]
    fn hp_is_deterministic_prime_order() {
        use curve25519_dalek::constants::BASEPOINT_ORDER;
        use curve25519_dalek::traits::Identity;
        let m1 = *blake3::hash(b"hp input one").as_bytes();
        let m2 = *blake3::hash(b"hp input two").as_bytes();
        let p1 = hp(&m1);
        assert_eq!(p1, hp(&m1));
        assert_ne!(p1, hp(&m2));
        // Cofactor-cleared output: prime-order subgroup member.
        assert_eq!(p1 * BASEPOINT_ORDER, EdwardsPoint::identity());
        assert_ne!(p1, EdwardsPoint::identity());
        // Try-and-increment terminates across a sample of inputs.
        for k in 0u8..64 {
            let m = *blake3::hash(&[k; 32]).as_bytes();
            assert_ne!(hp(&m), EdwardsPoint::identity());
        }
    }

    #[test]
    fn one_time_keys_deterministic_and_binding() {
        let (sk, p, image) = keypair();
        let keys = one_time_keys(&sk);
        assert_eq!(keys.p, p);
        assert_eq!(keys.image, image);
        // Key image = [x] * H(P): deterministic per key, distinct across
        // keys, never degenerate for honest keys.
        let (_sk2, p2, image2) = keypair();
        assert_ne!(p, p2);
        assert_ne!(image, image2);
        assert!(!decompress(&image).expect("image decodes").is_small_order());
    }

    #[test]
    fn sign_verify_adaptor_roundtrip() {
        let (sk, p, image) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        assert!(sig.verify(MSG, &p, &image));
        // The adaptor points must be the secret's points on both bases.
        let hp_p = hp(&p);
        let t_sc = Scalar::from_bytes_mod_order(t.t);
        assert_eq!(sig.t_point, (t_sc * B).compress().to_bytes());
        assert_eq!(sig.t_point_h, (t_sc * hp_p).compress().to_bytes());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (sk, p, image) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        assert!(!sig.verify(b"different message", &p, &image));
    }

    #[test]
    fn verify_rejects_wrong_pubkey_or_image() {
        let (sk, p, _) = keypair();
        let (_, p2, image2) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        assert!(!sig.verify(MSG, &p2, &image2));
        let (_, _, image3) = keypair();
        assert!(!sig.verify(MSG, &p, &image3));
    }

    #[test]
    fn verify_rejects_tampered_s() {
        let (sk, p, image) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let mut sig = ClsagAdaptor::sign(&sk, &t, MSG);
        sig.s_adaptor[0] ^= 0x01;
        assert!(!sig.verify(MSG, &p, &image));
    }

    #[test]
    fn verify_rejects_degenerate_points() {
        use curve25519_dalek::constants::EIGHT_TORSION;
        let (sk, p, image) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        // Identity key image (order 1).
        assert!(!sig.verify(MSG, &p, &identity_bytes()));
        // Order-8 torsion adaptor points: decompress fine, not the
        // identity, but outside the prime-order subgroup (WG-19 policy).
        let mut torsion_t = sig.clone();
        torsion_t.t_point = EIGHT_TORSION[1].compress().to_bytes();
        assert!(!torsion_t.verify(MSG, &p, &image));
        let mut torsion_th = sig.clone();
        torsion_th.t_point_h = EIGHT_TORSION[2].compress().to_bytes();
        assert!(!torsion_th.verify(MSG, &p, &image));
        // Non-decompressible nonce commitment.
        let mut garbage = sig.clone();
        garbage.r_g = [0xff; 32];
        assert!(!garbage.verify(MSG, &p, &image));
    }

    #[test]
    fn verify_rejects_non_canonical_s_adaptor() {
        let (sk, p, image) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let mut sig = ClsagAdaptor::sign(&sk, &t, MSG);
        // s' + l encodes the same scalar non-canonically: a verifier that
        // silently reduced would accept it (WG-19 malleability policy).
        let shifted = le_add(&sig.s_adaptor, &order_le());
        assert_ne!(shifted, sig.s_adaptor);
        sig.s_adaptor = shifted;
        assert!(!sig.verify(MSG, &p, &image));
    }

    #[test]
    fn complete_produces_valid_full_signature() {
        let (sk, p, image) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        let full = sig.complete(&t);
        assert!(verify_full(&full, &sig, MSG, &p, &image));
        assert!(!verify_full(&full, &sig, b"other", &p, &image));
    }

    #[test]
    fn complete_with_wrong_secret_fails_verification() {
        let (sk, p, image) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let wrong = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        let full = sig.complete(&wrong);
        assert!(!verify_full(&full, &sig, MSG, &p, &image));
    }

    #[test]
    fn recover_matches_original() {
        let (sk, p, _) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        let full = sig.complete(&t);
        let recovered = ClsagAdaptor::recover(&full, &sig, &p).expect("secret recovers");
        assert_eq!(recovered.t, t.t);
        // And the recovered secret reproduces both published points.
        let hp_p = hp(&p);
        let t_sc = Scalar::from_bytes_mod_order(recovered.t);
        assert_eq!((t_sc * B).compress().to_bytes(), sig.t_point);
        assert_eq!((t_sc * hp_p).compress().to_bytes(), sig.t_point_h);
    }

    #[test]
    fn recover_rejects_mismatched_pair() {
        let (sk, p, _) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let sig = ClsagAdaptor::sign(&sk, &t, MSG);
        // Completed with a DIFFERENT secret -> the difference fails the
        // dual [t]G == T / [t]H(P) == T_h binding.
        let wrong = SwapSecret::generate(&mut OsRng);
        let full = sig.complete(&wrong);
        assert!(ClsagAdaptor::recover(&full, &sig, &p).is_none());
        // Truncated/garbage full signature must not panic either.
        assert!(ClsagAdaptor::recover(&[0u8; 96], &sig, &p).is_none());
        // Non-canonical s in the completed signature: rejected, killing
        // the +(l) malleation of recovered secrets (WG-19 policy).
        let mut malleated = sig.complete(&t);
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&malleated[64..]);
        let shifted = le_add(&sb, &order_le());
        malleated[64..].copy_from_slice(&shifted);
        assert!(ClsagAdaptor::recover(&malleated, &sig, &p).is_none());
    }

    #[test]
    fn deterministic_nonce_repeats_only_for_identical_inputs() {
        let (sk, _, _) = keypair();
        let t = SwapSecret::generate(&mut OsRng);
        let s1 = ClsagAdaptor::sign(&sk, &t, MSG);
        let s2 = ClsagAdaptor::sign(&sk, &t, MSG);
        assert_eq!(s1.r_g, s2.r_g);
        assert_eq!(s1.s_adaptor, s2.s_adaptor);
        let s3 = ClsagAdaptor::sign(&sk, &t, b"another msg");
        assert_ne!(s1.r_g, s3.r_g);
        assert_ne!(s1.r_h, s3.r_h);
    }

    #[test]
    fn key_image_links_signatures() {
        // Two signatures under the same one-time key share the key image:
        // the linkability tag that makes a double-spend detectable.
        let (sk, _, image) = keypair();
        let t1 = SwapSecret::generate(&mut OsRng);
        let t2 = SwapSecret::generate(&mut OsRng);
        let sig1 = ClsagAdaptor::sign(&sk, &t1, MSG);
        let sig2 = ClsagAdaptor::sign(&sk, &t2, b"other msg");
        let keys = one_time_keys(&sk);
        assert!(sig1.verify(MSG, &keys.p, &image));
        assert!(sig2.verify(b"other msg", &keys.p, &image));
        assert_eq!(keys.image, image);
    }
}
