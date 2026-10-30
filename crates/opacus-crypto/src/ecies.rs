//! Reusable ristretto ECIES for sealed notes (WG-29 WP-B, D4/D5).
//!
//! Extracted byte-for-byte from the N3 note feed algebra in
//! crates/opacus-network/src/notes.rs (legacy notes.rs:233-277): one
//! ephemeral ristretto scalar, blake3::derive_key session keys over
//! (epk || pr || shared || nonce), a keyed-blake3 counter-mode keystream,
//! an encrypt-then-MAC tag, and a public id digest. All domain separation
//! lives in [`EciesTags`], so ONE algebra serves two instantiations:
//!
//! * the N3 wire (notes.rs): tags "opacus-note-v1 ..." - the N3 bytes
//!   stay byte-identical (the unchanged legacy notes.rs test suite is the
//!   regression gate);
//! * the WG-29 in-transaction enote: tags "ghost-encnote-v1 ...".
//!
//! The in-transaction enote wire form (D4) is BINARY and fixed size:
//! `epk 32 || nonce 16 || ct 137 || mac 32` = 217 B. It fits both caps:
//! N3 NOTE_PAYLOAD_MAX = 512 (backup delivery channel) and the tx-side
//! ENC_NOTE_MAX = 1024. The plaintext is [`EnoteV1`] (D1): the exact
//! field set the recipient needs to rebuild the accumulator leaf and the
//! later spend witness:
//! `version u8 = 1 || d 32 || a 32 || b 32 || rho 32 || v u64 LE` = 137 B.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Domain tags
// ---------------------------------------------------------------------------

/// Domain-separation parameters of one ECIES instantiation. Changing ANY
/// field changes every derived key and tag, so distinct instantiations
/// never cross-verify (tested: cross-tag isolation fails closed).
#[derive(Clone, Copy)]
pub struct EciesTags {
    /// blake3::derive_key context for the encryption (keystream) key.
    pub ks_context: &'static str,
    /// blake3::derive_key context for the MAC key.
    pub mac_context: &'static str,
    /// Prefix of every keystream block input.
    pub ks_block_tag: &'static [u8],
    /// Prefix of the keyed MAC input.
    pub mac_tag: &'static [u8],
    /// Prefix of the public id digest.
    pub id_tag: &'static [u8],
}

/// N3 note feed tags - the exact values the legacy notes.rs constants
/// carried (NOTE_ID_TAG / KS_TAG / MAC_TAG and the two derive_key
/// contexts). The N3 wire must stay byte-identical after the extraction.
pub const N3_NOTE_TAGS: EciesTags = EciesTags {
    ks_context: "opacus-note-v1 keystream",
    mac_context: "opacus-note-v1 mac",
    ks_block_tag: b"opacus-note-ks-v1",
    mac_tag: b"opacus-note-mac-v1",
    id_tag: b"opacus-note-id-v1",
};

/// WG-29 in-transaction enote tags (D4).
pub const ENOTE_TAGS: EciesTags = EciesTags {
    ks_context: "ghost-encnote-v1 keystream",
    mac_context: "ghost-encnote-v1 mac",
    ks_block_tag: b"ghost-encnote-ks-v1",
    mac_tag: b"ghost-encnote-mac-v1",
    id_tag: b"ghost-encnote-id-v1",
};

// ---------------------------------------------------------------------------
// Core algebra (byte-compatible with the legacy notes.rs construction)
// ---------------------------------------------------------------------------

/// Both session keys from one DH material blob (domain-separated).
/// Material: `epk || pr || shared || nonce`.
pub fn session_keys(
    tags: &EciesTags,
    epk: &[u8; 32],
    pr: &[u8; 32],
    shared: &[u8; 32],
    nonce: &[u8; 16],
) -> ([u8; 32], [u8; 32]) {
    let mut mat = Vec::with_capacity(32 + 32 + 32 + 16);
    mat.extend_from_slice(epk);
    mat.extend_from_slice(pr);
    mat.extend_from_slice(shared);
    mat.extend_from_slice(nonce);
    let k_enc = blake3::derive_key(tags.ks_context, &mat);
    let k_mac = blake3::derive_key(tags.mac_context, &mat);
    (k_enc, k_mac)
}

/// blake3 keyed-hash counter-mode keystream
/// (tags.ks_block_tag || nonce || le64(i)).
pub fn keystream(tags: &EciesTags, k_enc: &[u8; 32], nonce: &[u8; 16], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut ctr: u64 = 0;
    while out.len() < len {
        let mut input = Vec::with_capacity(tags.ks_block_tag.len() + 16 + 8);
        input.extend_from_slice(tags.ks_block_tag);
        input.extend_from_slice(nonce);
        input.extend_from_slice(&ctr.to_le_bytes());
        let block = blake3::keyed_hash(k_enc, &input);
        out.extend_from_slice(block.as_bytes());
        ctr += 1;
    }
    out.truncate(len);
    out
}

/// Encrypt-then-MAC tag over (version, epk, nonce, ct).
pub fn mac_of(
    tags: &EciesTags,
    k_mac: &[u8; 32],
    version: u32,
    epk: &[u8; 32],
    nonce: &[u8; 16],
    ct: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(k_mac);
    h.update(tags.mac_tag);
    h.update(&version.to_le_bytes());
    h.update(epk);
    h.update(nonce);
    h.update(ct);
    *h.finalize().as_bytes()
}

/// The PUBLIC id digest over (tag, version, hops, epk, nonce, ct) - no
/// key material. Relays verify and dedupe on it (N3 use).
pub fn id_digest(
    tags: &EciesTags,
    version: u32,
    hops: u32,
    epk: &[u8; 32],
    nonce: &[u8; 16],
    ct: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tags.id_tag);
    h.update(&version.to_le_bytes());
    h.update(&hops.to_le_bytes());
    h.update(epk);
    h.update(nonce);
    h.update(ct);
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Wallet note keys (D3)
// ---------------------------------------------------------------------------

/// Derivation tag of the wallet note key from the BIP-39 seed (D3).
pub const NOTE_DERIVE_TAG: &[u8] = b"ghost_note_derive_v1";

/// A zeroizing wrapper over the canonical 32-byte note secret scalar
/// (D3). No Debug/Display impl exists on purpose; the buffer is wiped on
/// drop (ZeroizeOnDrop) and can be wiped explicitly with [`wipe`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NoteSecret([u8; 32]);

impl NoteSecret {
    /// The scalar, reconstructed per use. Infallible: NoteSecret only
    /// ever holds the canonical output of `Scalar::to_bytes`.
    pub fn scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.0)
    }

    /// The matching ristretto public key: `[note_sk] * G_ri`.
    pub fn public(&self) -> CompressedRistretto {
        (self.scalar() * RISTRETTO_BASEPOINT_POINT).compress()
    }

    /// Explicit wipe (drop also wipes via ZeroizeOnDrop).
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }

    #[cfg(test)]
    fn is_zeroed(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// Derive the wallet note keypair from the 64-byte BIP-39 seed (D3):
/// `note_sk = scalar(blake3("ghost_note_derive_v1" || seed))` with the
/// canonical reduction (64-byte blake3 XOF squeeze -> mod l),
/// `note_pk = [note_sk] * RISTRETTO_BASEPOINT_POINT` (see
/// [`NoteSecret::public`]). Deterministic in the seed.
pub fn note_keypair_from_seed(seed: &[u8; 64]) -> NoteSecret {
    let mut h = blake3::Hasher::new();
    h.update(NOTE_DERIVE_TAG);
    h.update(seed);
    let mut squeeze = [0u8; 64];
    h.finalize_xof().fill(&mut squeeze);
    let scalar = Scalar::from_bytes_mod_order_wide(&squeeze);
    squeeze.zeroize();
    NoteSecret(scalar.to_bytes())
}

// ---------------------------------------------------------------------------
// ENoteV1 plaintext codec (D1)
// ---------------------------------------------------------------------------

/// Wire version of the ENoteV1 plaintext.
pub const ENOTE_VERSION: u8 = 1;
/// Fixed plaintext size (D1): 1 + 32*4 + 8 = 137 B.
pub const ENOTE_PLAINTEXT_LEN: usize = 137;
/// Fixed sealed-blob size (D4): 32 + 16 + 137 + 32 = 217 B.
pub const ENOTE_BLOB_LEN: usize = 217;

/// Errors from the ENoteV1 codec and the sealed-enote open path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnoteError {
    /// Input length is not the fixed codec length.
    BadLength { what: &'static str, got: usize },
    /// Plaintext version byte is not [`ENOTE_VERSION`].
    BadVersion(u8),
    /// The ephemeral key is not a valid ristretto point.
    BadEphemeralKey,
    /// The recipient key is not a valid ristretto point.
    BadRecipientKey,
    /// The MAC does not verify under the recipient key.
    MacMismatch,
}

impl std::fmt::Display for EnoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnoteError::BadLength { what, got } => write!(f, "enote {what}: bad length {got}"),
            EnoteError::BadVersion(v) => write!(f, "enote version {v} unsupported"),
            EnoteError::BadEphemeralKey => write!(f, "enote epk is not a valid ristretto point"),
            EnoteError::BadRecipientKey => {
                write!(f, "enote recipient key is not a valid ristretto point")
            }
            EnoteError::MacMismatch => write!(f, "enote MAC rejected"),
        }
    }
}

impl std::error::Error for EnoteError {}

/// One sealed output note (D1): the exact field set the recipient needs
/// to rebuild the accumulator leaf (WalletNoteV4::leaf_point over
/// (d, a, b, v, rho)) and the later spend witness (SpendNoteInput).
/// Canonical hand-rolled codec, no serde, fixed 137 B.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnoteV1 {
    /// Diversifier domain of the address [S4 3].
    pub d: [u8; 32],
    /// Owner key share a [S4 3].
    pub a: [u8; 32],
    /// Owner key share b [S4 3].
    pub b: [u8; 32],
    /// Per-note nullifier seed [S4 3].
    pub rho: [u8; 32],
    /// Amount, 0 <= v < 2^64, little-endian on the wire.
    pub v: u64,
}

impl EnoteV1 {
    /// Canonical wire encoding (D1):
    /// `version u8 = 1 || d 32 || a 32 || b 32 || rho 32 || v u64 LE`.
    pub fn encode(&self) -> [u8; ENOTE_PLAINTEXT_LEN] {
        let mut out = [0u8; ENOTE_PLAINTEXT_LEN];
        out[0] = ENOTE_VERSION;
        let mut o = 1;
        out[o..o + 32].copy_from_slice(&self.d);
        o += 32;
        out[o..o + 32].copy_from_slice(&self.a);
        o += 32;
        out[o..o + 32].copy_from_slice(&self.b);
        o += 32;
        out[o..o + 32].copy_from_slice(&self.rho);
        o += 32;
        out[o..o + 8].copy_from_slice(&self.v.to_le_bytes());
        out
    }

    /// Strict decode: exact length and the version byte MUST match.
    pub fn decode(bytes: &[u8]) -> Result<EnoteV1, EnoteError> {
        if bytes.len() != ENOTE_PLAINTEXT_LEN {
            return Err(EnoteError::BadLength {
                what: "plaintext",
                got: bytes.len(),
            });
        }
        if bytes[0] != ENOTE_VERSION {
            return Err(EnoteError::BadVersion(bytes[0]));
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&bytes[1..33]);
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes[33..65]);
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes[65..97]);
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[97..129]);
        let mut vle = [0u8; 8];
        vle.copy_from_slice(&bytes[129..137]);
        Ok(EnoteV1 {
            d,
            a,
            b,
            rho,
            v: u64::from_le_bytes(vle),
        })
    }
}

// ---------------------------------------------------------------------------
// Sealed enote wire (D4): epk 32 || nonce 16 || ct 137 || mac 32
// ---------------------------------------------------------------------------

/// Seal one enote to the recipient's note public key with fresh
/// randomness (D3, D4).
pub fn seal_enote(
    note: &EnoteV1,
    recipient_pk: &CompressedRistretto,
) -> Result<[u8; ENOTE_BLOB_LEN], EnoteError> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let e = Scalar::random(&mut OsRng);
    seal_enote_with(note, recipient_pk, &e, &nonce)
}

/// Deterministic seal with explicit ephemeral scalar and nonce (used by
/// tests and by callers that own the randomness).
pub fn seal_enote_with(
    note: &EnoteV1,
    recipient_pk: &CompressedRistretto,
    e: &Scalar,
    nonce: &[u8; 16],
) -> Result<[u8; ENOTE_BLOB_LEN], EnoteError> {
    let pt = recipient_pk
        .decompress()
        .ok_or(EnoteError::BadRecipientKey)?;
    let payload = note.encode();
    let epk = (e * RISTRETTO_BASEPOINT_POINT).compress();
    let shared = (e * pt).compress();
    let (k_enc, k_mac) = session_keys(
        &ENOTE_TAGS,
        epk.as_bytes(),
        recipient_pk.as_bytes(),
        shared.as_bytes(),
        nonce,
    );
    let ks = keystream(&ENOTE_TAGS, &k_enc, nonce, ENOTE_PLAINTEXT_LEN);
    let ct: Vec<u8> = payload.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mac = mac_of(
        &ENOTE_TAGS,
        &k_mac,
        u32::from(ENOTE_VERSION),
        epk.as_bytes(),
        nonce,
        &ct,
    );
    let mut out = [0u8; ENOTE_BLOB_LEN];
    let mut o = 0;
    out[o..o + 32].copy_from_slice(epk.as_bytes());
    o += 32;
    out[o..o + 16].copy_from_slice(nonce);
    o += 16;
    out[o..o + ENOTE_PLAINTEXT_LEN].copy_from_slice(&ct);
    o += ENOTE_PLAINTEXT_LEN;
    out[o..o + 32].copy_from_slice(&mac);
    Ok(out)
}

/// Open a sealed enote with the local note secret (D4). Order: exact
/// length, structural parse, MAC (constant-time blake3 Hash equality),
/// and only then decryption and the strict codec check.
pub fn open_enote(blob: &[u8], sk: &NoteSecret) -> Result<EnoteV1, EnoteError> {
    open_enote_with_tags(&ENOTE_TAGS, blob, sk)
}

/// Tag-parameterized open (the cross-tag isolation test proves the same
/// blob under different tags fails closed on the MAC).
pub fn open_enote_with_tags(
    tags: &EciesTags,
    blob: &[u8],
    sk: &NoteSecret,
) -> Result<EnoteV1, EnoteError> {
    if blob.len() != ENOTE_BLOB_LEN {
        return Err(EnoteError::BadLength {
            what: "sealed enote",
            got: blob.len(),
        });
    }
    let mut epk_b = [0u8; 32];
    epk_b.copy_from_slice(&blob[0..32]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&blob[32..48]);
    let ct = &blob[48..48 + ENOTE_PLAINTEXT_LEN];
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&blob[48 + ENOTE_PLAINTEXT_LEN..]);
    let epk_pt = CompressedRistretto(epk_b)
        .decompress()
        .ok_or(EnoteError::BadEphemeralKey)?;
    let shared = (sk.scalar() * epk_pt).compress();
    let (k_enc, k_mac) = session_keys(
        tags,
        &epk_b,
        sk.public().as_bytes(),
        shared.as_bytes(),
        &nonce,
    );
    let want = mac_of(tags, &k_mac, u32::from(ENOTE_VERSION), &epk_b, &nonce, ct);
    if blake3::Hash::from_bytes(want) != blake3::Hash::from_bytes(mac) {
        return Err(EnoteError::MacMismatch);
    }
    let ks = keystream(tags, &k_enc, &nonce, ENOTE_PLAINTEXT_LEN);
    let plain: Vec<u8> = ct.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    EnoteV1::decode(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seed(b: u8) -> [u8; 64] {
        [b; 64]
    }

    fn sample_note() -> EnoteV1 {
        let mut d = [0u8; 32];
        d[0] = 0x0d;
        let mut a = [0u8; 32];
        a[0] = 0x0a;
        let mut b = [0u8; 32];
        b[0] = 0x0b;
        let mut rho = [0u8; 32];
        rho[0] = 0x70;
        EnoteV1 {
            d,
            a,
            b,
            rho,
            v: 1_500_000_000,
        }
    }

    #[test]
    fn enote_codec_canonical_vector() {
        let note = sample_note();
        let enc = note.encode();
        assert_eq!(enc.len(), 137);
        assert_eq!(enc[0], 1);
        assert_eq!(&enc[1..33], &note.d);
        assert_eq!(&enc[33..65], &note.a);
        assert_eq!(&enc[65..97], &note.b);
        assert_eq!(&enc[97..129], &note.rho);
        assert_eq!(&enc[129..137], &note.v.to_le_bytes());
        assert_eq!(EnoteV1::decode(&enc).unwrap(), note);
    }

    #[test]
    fn enote_decode_rejects_len_and_version() {
        let enc = sample_note().encode();
        assert_eq!(
            EnoteV1::decode(&enc[..136]),
            Err(EnoteError::BadLength {
                what: "plaintext",
                got: 136
            })
        );
        let mut v2 = enc;
        v2[0] = 2;
        assert_eq!(EnoteV1::decode(&v2), Err(EnoteError::BadVersion(2)));
        assert!(EnoteV1::decode(&[]).is_err());
    }

    #[test]
    fn note_key_derivation_is_deterministic_and_seed_sensitive() {
        let k1 = note_keypair_from_seed(&fixed_seed(1));
        let k2 = note_keypair_from_seed(&fixed_seed(1));
        let k3 = note_keypair_from_seed(&fixed_seed(2));
        assert_eq!(k1.public(), k2.public());
        assert_ne!(k1.public(), k3.public());
    }

    #[test]
    fn enote_seal_open_roundtrip() {
        let sk = note_keypair_from_seed(&fixed_seed(7));
        let note = sample_note();
        let blob = seal_enote(&note, &sk.public()).unwrap();
        assert_eq!(blob.len(), ENOTE_BLOB_LEN);
        assert_eq!(blob.len(), 217);
        assert_eq!(open_enote(&blob, &sk).unwrap(), note);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sk_alice = note_keypair_from_seed(&fixed_seed(11));
        let sk_bob = note_keypair_from_seed(&fixed_seed(12));
        let blob = seal_enote(&sample_note(), &sk_alice.public()).unwrap();
        assert_eq!(open_enote(&blob, &sk_bob), Err(EnoteError::MacMismatch));
    }

    #[test]
    fn tampering_is_rejected() {
        let sk = note_keypair_from_seed(&fixed_seed(13));
        let blob = seal_enote(&sample_note(), &sk.public()).unwrap();
        // ct flip -> MAC mismatch
        let mut t = blob;
        t[48] ^= 1;
        assert_eq!(open_enote(&t, &sk), Err(EnoteError::MacMismatch));
        // nonce flip -> MAC mismatch
        let mut t = blob;
        t[40] ^= 1;
        assert_eq!(open_enote(&t, &sk), Err(EnoteError::MacMismatch));
        // mac flip -> MAC mismatch
        let mut t = blob;
        t[ENOTE_BLOB_LEN - 1] ^= 1;
        assert_eq!(open_enote(&t, &sk), Err(EnoteError::MacMismatch));
        // epk flip -> invalid point or MAC mismatch, but never a valid open
        let mut t = blob;
        t[0] ^= 1;
        assert!(open_enote(&t, &sk).is_err());
    }

    #[test]
    fn cross_tag_isolation_fails_closed() {
        let sk = note_keypair_from_seed(&fixed_seed(21));
        let blob = seal_enote(&sample_note(), &sk.public()).unwrap();
        // Same algebra, N3 tags: the MAC MUST reject (no cross-protocol use).
        assert_eq!(
            open_enote_with_tags(&N3_NOTE_TAGS, &blob, &sk),
            Err(EnoteError::MacMismatch)
        );
    }

    #[test]
    fn deterministic_seal_is_reproducible() {
        let sk = note_keypair_from_seed(&fixed_seed(31));
        let e = Scalar::from_bytes_mod_order_wide(&fixed_seed(32));
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&fixed_seed(33)[0..16]);
        let a = seal_enote_with(&sample_note(), &sk.public(), &e, &nonce).unwrap();
        let b = seal_enote_with(&sample_note(), &sk.public(), &e, &nonce).unwrap();
        assert_eq!(a, b);
        assert_eq!(open_enote(&a, &sk).unwrap(), sample_note());
    }

    #[test]
    fn note_secret_wipe_zeroes() {
        let mut sk = note_keypair_from_seed(&fixed_seed(41));
        assert!(!sk.is_zeroed());
        sk.wipe();
        assert!(sk.is_zeroed());
    }

    #[test]
    fn sealed_len_fits_network_and_tx_caps() {
        // D4/D7: 217 <= N3 NOTE_PAYLOAD_MAX 512 and <= ENC_NOTE_MAX 1024.
        const {
            assert!(ENOTE_BLOB_LEN <= 512);
            assert!(ENOTE_BLOB_LEN <= 1024);
        };
    }
}
