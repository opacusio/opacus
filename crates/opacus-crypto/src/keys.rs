//! Key management
//!
//! Wallet key material is derived from standard BIP-39 mnemonics
//! (English wordlist) per ADR docs/adr/r5-bip39-mnemonics.md (R5, WG-25):
//!
//! - `generate()`: 256-bit entropy from the injected `RngCore + CryptoRng`
//!   -> 24-word BIP-39 phrase.
//! - restore: strict BIP-39 validation (wordlist membership + checksum);
//!   `seed = PBKDF2-HMAC-SHA512(phrase, "mnemonic"+passphrase, 2048)`.
//! - spend/view: `blake3("ghost_spend_derive_v2" || seed)` and
//!   `blake3("ghost_view_derive_v2" || seed)`. v1 tags are retired and v1
//!   pseudo-mnemonics are rejected by the restore path.

use bip39::{Language, Mnemonic};
use blake3::Hasher;
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid BIP-39 mnemonic: {0}")]
    Invalid(#[from] bip39::Error),
}

/// Wallet spend/view keys derived from a BIP-39 mnemonic.
///
/// The phrase is kept verbatim (normalized by the `bip39` crate) and is
/// zeroized when the key is dropped. It MUST NOT be logged (ADR security
/// invariants); no `Debug`/`Display` impl exists on purpose.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SpendingKey {
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub mnemonic: String,
}

impl SpendingKey {
    /// Creates a new key: 256 bits from the injected CSPRNG -> 24 words.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .expect("32-byte entropy is always a valid BIP-39 length");
        Self::from_parts(mnemonic, "")
    }

    /// Strict BIP-39 restore path (empty passphrase). Rejects anything
    /// failing wordlist membership or checksum, including all v1
    /// pseudo-mnemonics ("ghost <hex chunks>").
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, KeyError> {
        Self::from_mnemonic_with_passphrase(mnemonic, "")
    }

    /// Strict BIP-39 restore with an optional passphrase ("25th word").
    pub fn from_mnemonic_with_passphrase(
        mnemonic: &str,
        passphrase: &str,
    ) -> Result<Self, KeyError> {
        let parsed = Mnemonic::parse_in(Language::English, mnemonic)?;
        Ok(Self::from_parts(parsed, passphrase))
    }

    fn from_parts(mnemonic: Mnemonic, passphrase: &str) -> Self {
        let mut seed: [u8; 64] = mnemonic.to_seed(passphrase);
        let mut h = Hasher::new();
        h.update(b"ghost_spend_derive_v2");
        h.update(&seed);
        let spend: [u8; 32] = h.finalize().into();
        let mut h = Hasher::new();
        h.update(b"ghost_view_derive_v2");
        h.update(&seed);
        let view: [u8; 32] = h.finalize().into();
        seed.zeroize();
        Self {
            spend_key: spend,
            view_key: view,
            mnemonic: mnemonic.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official BIP-39 English vectors (zero entropies; TREZOR passphrase row).
    // Computed independently per the BIP-39 spec (SHA256 checksum +
    // PBKDF2-HMAC-SHA512, 2048 iterations, salt "mnemonic"+passphrase) and
    // cross-checked against the published Trezor vector set.
    const V12_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const V12_SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    const V12_SPEND: &str = "0ce2839064712b672eb7bf66382ee6d07b3f5889079054d8f00843cd14653a0d";
    const V12_VIEW: &str = "2989d3395f72bca4a611ffa68ddf402120fb8bec4218641b35dd6912480e4773";

    const V12_TREZOR_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    const V12_TREZOR_SPEND: &str =
        "36d2e8e4bad52d1035681e13e293c0e12c9e4b2006df97df6eb5034d223eb9e9";
    const V12_TREZOR_VIEW: &str =
        "1f46e7582155d430365ed2ad3df6aa83ceff758c642138fc7fde2588f6a68acf";

    const V15_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address";
    const V18_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent";
    const V24_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const V24_SPEND: &str = "e50a17b0a81d06eb5157e28453465f944f2198cfbfe93e057414f43274ae9528";
    const V24_VIEW: &str = "aa282a13394f98ddf0940540fa67e656a41a2dabf4e5e9c98565065aff05c8e2";

    const V7F12_PHRASE: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn parse_ok(phrase: &str) -> SpendingKey {
        SpendingKey::from_mnemonic(phrase).expect("valid BIP-39 phrase")
    }

    #[test]
    fn official_vector_12_words() {
        let k = parse_ok(V12_PHRASE);
        assert_eq!(hex::encode(k.spend_key), V12_SPEND);
        assert_eq!(hex::encode(k.view_key), V12_VIEW);
        assert_eq!(k.mnemonic, V12_PHRASE);
    }

    #[test]
    fn official_vector_24_words() {
        let k = parse_ok(V24_PHRASE);
        assert_eq!(hex::encode(k.spend_key), V24_SPEND);
        assert_eq!(hex::encode(k.view_key), V24_VIEW);
    }

    #[test]
    fn seed_roundtrip_official_pbkdf2() {
        let m = Mnemonic::parse_in(Language::English, V12_PHRASE).expect("valid");
        assert_eq!(hex::encode(m.to_seed("")), V12_SEED);
        assert_eq!(hex::encode(m.to_seed("TREZOR")), V12_TREZOR_SEED);
        let m7 = Mnemonic::parse_in(Language::English, V7F12_PHRASE).expect("valid");
        assert_eq!(m7.to_seed("").len(), 64);
    }

    #[test]
    fn acceptance_matrix_12_15_18_24() {
        assert!(SpendingKey::from_mnemonic(V12_PHRASE).is_ok());
        assert!(SpendingKey::from_mnemonic(V15_PHRASE).is_ok());
        assert!(SpendingKey::from_mnemonic(V18_PHRASE).is_ok());
        assert!(SpendingKey::from_mnemonic(V24_PHRASE).is_ok());
        assert_eq!(V15_PHRASE.split_whitespace().count(), 15);
        assert_eq!(V18_PHRASE.split_whitespace().count(), 18);
        assert_eq!(V24_PHRASE.split_whitespace().count(), 24);
    }

    #[test]
    fn checksum_rejection() {
        // 12x "abandon": all words valid, checksum invalid
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(SpendingKey::from_mnemonic(bad).is_err());
        // valid words in wrong order: broken checksum
        let swapped = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon";
        assert!(SpendingKey::from_mnemonic(swapped).is_err());
    }

    #[test]
    fn wordlist_rejection_and_v1_rejected() {
        // v1-style pseudo-mnemonic: 11 hex-chunk tokens are not words ('ghost' itself is BIP-39 English word 780)
        let v1 =
            "ghost 0a1b2c 1b2c3d 2c3d4e 3d4e5f 4e5f60 5f6061 606162 616263 626364 636465 646566";
        assert!(SpendingKey::from_mnemonic(v1).is_err());
        assert!(SpendingKey::from_mnemonic("notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword notaword").is_err());
    }

    #[test]
    fn passphrase_changes_derivation() {
        let empty = parse_ok(V12_PHRASE);
        let trezor = SpendingKey::from_mnemonic_with_passphrase(V12_PHRASE, "TREZOR")
            .expect("valid with passphrase");
        assert_ne!(empty.spend_key, trezor.spend_key);
        assert_ne!(empty.view_key, trezor.view_key);
        assert_eq!(hex::encode(trezor.spend_key), V12_TREZOR_SPEND);
        assert_eq!(hex::encode(trezor.view_key), V12_TREZOR_VIEW);
    }

    #[test]
    fn derivation_is_stable() {
        let a = parse_ok(V24_PHRASE);
        let b = parse_ok(V24_PHRASE);
        assert_eq!(a.spend_key, b.spend_key);
        assert_eq!(a.view_key, b.view_key);
        assert_ne!(a.spend_key, a.view_key);
    }

    #[test]
    fn generate_uses_injected_csprng_and_yields_24_words() {
        let mut rng = FixedRng { byte: 0xa5 };
        let k = SpendingKey::generate(&mut rng);
        assert_eq!(k.mnemonic.split_whitespace().count(), 24);
        // the generated phrase must round-trip through the strict restore path
        let restored = SpendingKey::from_mnemonic(&k.mnemonic).expect("generated phrase is valid");
        assert_eq!(restored.spend_key, k.spend_key);
        assert_eq!(restored.view_key, k.view_key);
    }

    /// Deterministic stand-in for a CSPRNG (no real randomness in tests).
    struct FixedRng {
        byte: u8,
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for slot in dest.iter_mut() {
                *slot = self.byte;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}
}
