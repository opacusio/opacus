//! Stealth Addresses

use blake3::Hasher;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar};
use rand::{CryptoRng, RngCore};

#[derive(Debug, thiserror::Error)]
pub enum StealthError {
    #[error("Invalid address format")]
    InvalidAddress,
}

#[derive(Clone)]
pub struct RecipientKeys {
    pub view_key: [u8; 32],
    pub spend_key: [u8; 32],
}

#[derive(Clone)]
pub struct PublicAddress {
    pub view_pubkey: EdwardsPoint,
    pub spend_pubkey: EdwardsPoint,
}

impl PublicAddress {
    pub fn from_keys(keys: &RecipientKeys) -> Self {
        let v = Scalar::from_bytes_mod_order(keys.view_key);
        let s = Scalar::from_bytes_mod_order(keys.spend_key);
        Self {
            view_pubkey: v * ED25519_BASEPOINT_POINT,
            spend_pubkey: s * ED25519_BASEPOINT_POINT,
        }
    }

    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&self.view_pubkey.compress().to_bytes());
        payload.extend_from_slice(&self.spend_pubkey.compress().to_bytes());
        format!("opacus1{}", hex::encode(payload))
    }

    pub fn from_string(_s: &str) -> Result<Self, StealthError> {
        Err(StealthError::InvalidAddress) // TODO v0.3
    }
}

#[derive(Clone)]
pub struct StealthAddress {
    pub onetime_pubkey: EdwardsPoint,
    pub ephemeral_pubkey: EdwardsPoint,
}

impl StealthAddress {
    pub fn generate<R: RngCore + CryptoRng>(recipient: &PublicAddress, rng: &mut R) -> Self {
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order(r_bytes);
        let ephemeral = r * ED25519_BASEPOINT_POINT;
        let shared = r * recipient.view_pubkey;
        let mut h = Hasher::new();
        h.update(b"opacus_stealth_derive");
        h.update(shared.compress().as_bytes());
        let secret_bytes: [u8; 32] = h.finalize().into();
        let secret = Scalar::from_bytes_mod_order(secret_bytes);
        let onetime = secret * ED25519_BASEPOINT_POINT + recipient.spend_pubkey;
        Self {
            onetime_pubkey: onetime,
            ephemeral_pubkey: ephemeral,
        }
    }
}
