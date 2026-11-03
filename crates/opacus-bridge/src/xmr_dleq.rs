//! Cross-group DLEq proof: one secret scalar `x` is proven to control BOTH
//!
//! * an Ed25519/Monero key  `A1 = x * G1`  (EdwardsPoint, Monero basepoint), and
//! * a Ristretto key        `A2 = x * G2`  (RistrettoPoint, Ristretto basepoint).
//!
//! Both groups live on curve25519, so they share the same scalar field
//! (`l = 2^252 + 27742...`), which is what makes a Schnorr-style proof over
//! the pair sound:
//!
//! ```text
//!   commit:  R1 = r*G1 , R2 = r*G2
//!   chall:   c = H(R1 || R2 || A1 || A2) mod l
//!   respond: s = r + c*x
//!   verify:  s*G1 == R1 + c*A1   AND   s*G2 == R2 + c*A2
//! ```
//!
//! This is the primitive that lets a swap counterparty prove "the XMR
//! address and the OPACUS note key belong to the same owner" without
//! revealing `x`.

use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT as G1, RISTRETTO_BASEPOINT_POINT as G2};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

#[derive(Debug, PartialEq, Eq)]
pub enum DleqError {
    BadProof,
}

/// A cross-group DLEq proof.
#[derive(Clone, Debug)]
pub struct DleqProof {
    pub r1: CompressedEdwardsY,
    pub r2: CompressedRistretto,
    pub s: [u8; 32],
}

/// Wide scalar from bytes: 64-byte mod-l reduction (no digest dep needed).
fn scalar_wide(tag: &[u8], data: &[u8]) -> Scalar {
    let mut buf = Vec::with_capacity(tag.len() + data.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(data);
    let h1 = *blake3::hash(&buf).as_bytes();
    let h2 = *blake3::hash(&[b"wide", h1.as_slice()].concat()).as_bytes();
    let mut wide = [0u8; 64];
    wide[0..32].copy_from_slice(&h1);
    wide[32..64].copy_from_slice(&h2);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Domain-separated challenge hash.
fn challenge(
    r1: &CompressedEdwardsY,
    r2: &CompressedRistretto,
    a1: &CompressedEdwardsY,
    a2: &CompressedRistretto,
) -> Scalar {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"opacus-xmr-dleq-v1");
    buf.extend_from_slice(r1.as_bytes());
    buf.extend_from_slice(r2.as_bytes());
    buf.extend_from_slice(a1.as_bytes());
    buf.extend_from_slice(a2.as_bytes());
    scalar_wide(b"challenge", &buf)
}

/// Public key pair derived from one secret.
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub monero_pub: CompressedEdwardsY,
    pub ristretto_pub: CompressedRistretto,
}

pub fn keypair_from_secret(secret: &Scalar) -> KeyPair {
    KeyPair {
        monero_pub: (secret * G1).compress(),
        ristretto_pub: (secret * G2).compress(),
    }
}

/// Prove knowledge of `secret` such that it produces both public keys.
pub fn prove(secret: &Scalar) -> DleqProof {
    let kp = keypair_from_secret(secret);
    let r = scalar_wide(b"nonce", &rand_bytes());
    let r1 = (r * G1).compress();
    let r2 = (r * G2).compress();
    let c = challenge(&r1, &r2, &kp.monero_pub, &kp.ristretto_pub);
    let s = r + c * secret;
    DleqProof {
        r1,
        r2,
        s: s.to_bytes(),
    }
}

/// Verify the proof against both public keys.
pub fn verify(kp: &KeyPair, proof: &DleqProof) -> Result<(), DleqError> {
    let r1 = proof.r1.decompress().ok_or(DleqError::BadProof)?;
    let r2 = proof.r2.decompress().ok_or(DleqError::BadProof)?;
    let a1 = kp.monero_pub.decompress().ok_or(DleqError::BadProof)?;
    let a2 = kp.ristretto_pub.decompress().ok_or(DleqError::BadProof)?;
    let s = Scalar::from_canonical_bytes(proof.s)
        .into_option()
        .ok_or(DleqError::BadProof)?;
    let c = challenge(&proof.r1, &proof.r2, &kp.monero_pub, &kp.ristretto_pub);
    // s*G1 == R1 + c*A1
    if s * G1 != r1 + c * a1 {
        return Err(DleqError::BadProof);
    }
    // s*G2 == R2 + c*A2
    if s * G2 != r2 + c * a2 {
        return Err(DleqError::BadProof);
    }
    Ok(())
}

/// Cryptographically secure nonce source: 32 bytes from the OS CSPRNG.
/// A Schnorr nonce MUST be unpredictable and never repeated: with a
/// public proof (s, R1, R2, c) and a known nonce r the secret falls out
/// as x = (s - r) * c^-1. The previous blake3(nano-time + pid) source
/// was predictable within a brute-forced time window (audit C-01).
fn rand_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut out = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// Serialize a proof to 96 bytes (r1, r2, s).
pub fn proof_to_bytes(p: &DleqProof) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[0..32].copy_from_slice(p.r1.as_bytes());
    out[32..64].copy_from_slice(p.r2.as_bytes());
    out[64..96].copy_from_slice(&p.s);
    out
}

pub fn proof_from_bytes(b: &[u8; 96]) -> DleqProof {
    let mut y1 = [0u8; 32];
    y1.copy_from_slice(&b[0..32]);
    let mut y2 = [0u8; 32];
    y2.copy_from_slice(&b[32..64]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&b[64..96]);
    DleqProof {
        r1: CompressedEdwardsY(y1),
        r2: CompressedRistretto(y2),
        s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret(seed: u8) -> Scalar {
        scalar_wide(b"test", &[seed; 32])
    }

    #[test]
    fn prove_verify_roundtrip() {
        let secret = test_secret(1);
        let kp = keypair_from_secret(&secret);
        let proof = prove(&secret);
        verify(&kp, &proof).expect("valid proof must verify");

        // Serialization roundtrip.
        let bytes = proof_to_bytes(&proof);
        let proof2 = proof_from_bytes(&bytes);
        assert_eq!(proof2.r1, proof.r1);
        assert_eq!(proof2.r2, proof.r2);
        verify(&kp, &proof2).expect("serialized proof must verify");
    }

    #[test]
    fn wrong_secret_fails() {
        let kp = keypair_from_secret(&test_secret(2));
        let forged = prove(&test_secret(3)); // different secret
        assert_eq!(verify(&kp, &forged), Err(DleqError::BadProof));
    }

    #[test]
    fn tampered_key_fails() {
        let secret = test_secret(4);
        let mut kp = keypair_from_secret(&secret);
        // flip a bit in the ristretto key
        let mut y2 = kp.ristretto_pub.to_bytes();
        y2[0] ^= 0x01;
        kp.ristretto_pub = CompressedRistretto(y2);
        let proof = prove(&secret);
        assert_eq!(verify(&kp, &proof), Err(DleqError::BadProof));
    }

    #[test]
    fn nonce_source_is_csprng() {
        // Two raw draws from the nonce source must differ: the OS CSPRNG
        // does not repeat 32-byte outputs in practice (2^-256 collision).
        // A deterministic source (the old blake3(nanos + pid) bug, C-01)
        // would make the Schnorr nonce predictable and leak the secret
        // scalar via s = r + c*x.
        assert_ne!(rand_bytes(), rand_bytes());
        // Two proofs of the SAME secret must use different commitments:
        // with a fresh nonce each call, R1 = r*G1 differs. Identical R1
        // would mean nonce reuse - catastrophic for Schnorr signatures.
        let secret = test_secret(9);
        let p1 = prove(&secret);
        let p2 = prove(&secret);
        assert_ne!(p1.r1, p2.r1, "nonce must not repeat across proofs");
        assert_ne!(p1.s, p2.s, "response must not repeat across proofs");
    }

    #[test]
    fn same_secret_same_keys() {
        let s = test_secret(7);
        let a = keypair_from_secret(&s);
        let b = keypair_from_secret(&s);
        assert_eq!(a.monero_pub, b.monero_pub);
        assert_eq!(a.ristretto_pub, b.ristretto_pub);
        // and different secrets give different keys
        let c = keypair_from_secret(&test_secret(8));
        assert_ne!(a.monero_pub, c.monero_pub);
    }
}
