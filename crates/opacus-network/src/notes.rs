//! Encrypted note feed for the opacus P2P network (v0.6 networking, N3).
//!
//! This module closes the note-transport gap left open by the wallet phase:
//! `light_wallet.rs` documents that a recipient learns the one-time secret
//! of an outgoing note via the network note encryption "which arrives with
//! the networking phase", and `tx_v4.rs` ships `enc_notes` empty because
//! building plaintext payloads there would leak amounts and keys. The note
//! feed is that transport:
//!
//! * [`NoteBlob`] is the wire form: version, relay budget (hops), an
//!   ephemeral ristretto public key, a 16-byte nonce, the ciphertext, a
//!   MAC, and a PUBLIC blake3 `id` digest that any relay can recompute
//!   and verify without any secret material;
//! * [`seal_note`] seals an OPAQUE payload to the recipient ristretto
//!   identity key `pr` (the same DLEq-bound scalar that drives the N1
//!   handshake); [`open_note`] opens a blob with the local identity. The
//!   plaintext format is a wallet-layer concern - the network never
//!   interprets it;
//! * [`NoteInbox`] is the bounded per-node store of received blobs,
//!   deduped by id (mirroring the transcript replay window semantics);
//! * the net node accepts `Notes` frames after authentication, stores
//!   fresh blobs and relays them with a decremented hop budget to every
//!   OTHER connected peer, so a note reaches a recipient even when sender
//!   and recipient are not directly connected. Bounded: `NOTES_MAX_COUNT`
//!   blobs per frame, `NOTE_PAYLOAD_MAX` bytes per blob, `NOTES_MAX_HOPS`
//!   relay budget.
//!
//! Crypto construction (blake3-only ECIES, cofactor-free group):
//!
//! 1. the sender draws an ephemeral scalar `e`; `epk = e * G_ri`;
//! 2. `shared = e * pr_recipient` (ristretto, prime order);
//! 3. `k_enc = blake3::derive_key("opacus-note-v1 keystream",
//!    epk || pr || shared || nonce)` and the same material through the
//!    "opacus-note-v1 mac" context gives `k_mac`;
//! 4. ciphertext = payload XOR keystream, where the keystream is built
//!    from `blake3::keyed_hash(k_enc, ks_tag || nonce || le64(counter))`
//!    blocks; the ks/id/mac domain tags live in opacus_crypto::ecies
//!    (N3_NOTE_TAGS; WG-29 WP-B extraction, D5) - byte-identical wire.
//! 5. MAC = keyed blake3 over (version, epk, nonce, ciphertext) - NOT
//!    hops, so a relay can decrement the budget without the key -
//!    verified BEFORE any decryption; the comparison goes through
//!    `blake3::Hash` equality (constant-time per the blake3 crate).
//!
//! The `id` digest additionally covers (version, hops, epk, nonce,
//! ciphertext) WITHOUT any key: relays verify it, dedupe on it, and drop
//! anything that does not self-describe consistently.
//!
//! std-only; no new dependencies (curve25519-dalek, blake3, hex, rand and
//! serde are already in the handshake path).

use std::collections::{HashSet, VecDeque};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::handshake::HandshakeError;
use crate::identity::NodeIdentity;
use opacus_crypto::ecies;
// WG-29 WP-B (D5): the ECIES algebra (session keys, keystream, MAC, id
// digest) now lives in opacus_crypto::ecies, called with the N3 tags of
// ecies::N3_NOTE_TAGS; every derived byte is identical, so the N3 wire
// format is unchanged (the legacy tag constants moved with it).

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Wire version of the note blob format.
pub const NOTE_WIRE_VERSION: u32 = 1;
/// Hard cap on note blobs carried by one Notes frame.
pub const NOTES_MAX_COUNT: usize = 32;
/// Hard cap on one sealed note payload (bytes).
pub const NOTE_PAYLOAD_MAX: usize = 512;
/// Relay budget stamped into freshly sealed blobs; every relay decrements
/// it, a blob at zero is stored but no longer forwarded.
pub const NOTES_MAX_HOPS: u32 = 4;
/// Bounded note inbox size (blobs kept per node, also the dedupe window).
pub const NOTE_INBOX_CAP: usize = 1024;

// N3 domain tags (id / keystream block / MAC) moved to
// opacus_crypto::ecies::N3_NOTE_TAGS (WG-29 WP-B extraction, D5): same
// bytes, same wire - see the note next to the use statements above.

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from sealing, opening or validating note blobs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteError {
    /// Blob version is not [`NOTE_WIRE_VERSION`].
    BadVersion(u32),
    /// Relay budget above [`NOTES_MAX_HOPS`].
    BadHops(u32),
    /// A hex field is undecodable or has the wrong length.
    BadField(&'static str),
    /// The ephemeral key is not a valid ristretto point.
    BadEphemeralKey,
    /// The recipient key is not a valid ristretto point.
    BadRecipientKey,
    /// Payload length outside 1..=[`NOTE_PAYLOAD_MAX`].
    BadPayloadLen(usize),
    /// The MAC does not verify under the recipient key.
    MacMismatch,
    /// The public id digest does not match the blob contents.
    BadId,
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoteError::BadVersion(v) => write!(f, "unsupported note blob version: {v}"),
            NoteError::BadHops(h) => write!(f, "note hops {h} above cap {NOTES_MAX_HOPS}"),
            NoteError::BadField(w) => write!(f, "bad note blob field: {w}"),
            NoteError::BadEphemeralKey => write!(f, "note epk is not a valid ristretto point"),
            NoteError::BadRecipientKey => {
                write!(f, "note recipient key is not a valid ristretto point")
            }
            NoteError::BadPayloadLen(n) => {
                write!(
                    f,
                    "note payload must be 1..={NOTE_PAYLOAD_MAX} bytes, got {n}"
                )
            }
            NoteError::MacMismatch => write!(f, "note MAC rejected"),
            NoteError::BadId => write!(f, "note id digest mismatch"),
        }
    }
}

impl std::error::Error for NoteError {}

// ---------------------------------------------------------------------------
// Wire type
// ---------------------------------------------------------------------------

/// One sealed note blob on the wire. Every field is hex-encoded (the same
/// convention as the handshake frame fields).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NoteBlob {
    /// Blob format version ([`NOTE_WIRE_VERSION`]).
    pub version: u32,
    /// Remaining relay budget ([`NOTES_MAX_HOPS`] at seal time).
    pub hops: u32,
    /// hex(32) ephemeral ristretto public key `e * G_ri`.
    pub epk: String,
    /// hex(16) per-blob nonce.
    pub nonce: String,
    /// hex(1..=NOTE_PAYLOAD_MAX) ciphertext, same length as the plaintext.
    pub payload: String,
    /// hex(32) encrypt-then-MAC tag.
    pub mac: String,
    /// hex(32) PUBLIC blake3 digest over (version, hops, epk, nonce, ct);
    /// recomputed and enforced by every relay, used as the dedupe key.
    pub id: String,
}

fn dec_hex(s: &str, want: usize, what: &'static str) -> Result<Vec<u8>, NoteError> {
    let v = hex::decode(s).map_err(|_| NoteError::BadField(what))?;
    if v.len() != want {
        return Err(NoteError::BadField(what));
    }
    Ok(v)
}

fn fixed32(s: &str, what: &'static str) -> Result<[u8; 32], NoteError> {
    let v = dec_hex(s, 32, what)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn epk32(b: &NoteBlob) -> Result<[u8; 32], NoteError> {
    fixed32(&b.epk, "epk")
}

fn nonce16(b: &NoteBlob) -> Result<[u8; 16], NoteError> {
    let v = dec_hex(&b.nonce, 16, "nonce")?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    Ok(out)
}

fn mac32(b: &NoteBlob) -> Result<[u8; 32], NoteError> {
    fixed32(&b.mac, "mac")
}

fn id32(b: &NoteBlob) -> Result<[u8; 32], NoteError> {
    fixed32(&b.id, "id")
}

fn payload_bytes(b: &NoteBlob) -> Result<Vec<u8>, NoteError> {
    let v = hex::decode(&b.payload).map_err(|_| NoteError::BadField("payload"))?;
    if v.is_empty() || v.len() > NOTE_PAYLOAD_MAX {
        return Err(NoteError::BadPayloadLen(v.len()));
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Digests, keys, keystream
// ---------------------------------------------------------------------------

/// The PUBLIC blob id: blake3 over (tag, version, hops, epk, nonce, ct).
/// Relays verify and dedupe on it without any secret material.
fn id_digest(version: u32, hops: u32, epk: &[u8; 32], nonce: &[u8; 16], ct: &[u8]) -> [u8; 32] {
    ecies::id_digest(&ecies::N3_NOTE_TAGS, version, hops, epk, nonce, ct)
}

/// Recompute the public id of a blob (relay/test helper).
pub fn note_id_hex_of(blob: &NoteBlob) -> Result<String, NoteError> {
    let epk_b = epk32(blob)?;
    let nonce = nonce16(blob)?;
    let ct = payload_bytes(blob)?;
    Ok(hex::encode(id_digest(
        blob.version,
        blob.hops,
        &epk_b,
        &nonce,
        &ct,
    )))
}

/// Both session keys from one DH material blob (domain-separated).
fn session_keys(
    epk: &[u8; 32],
    pr: &[u8; 32],
    shared: &[u8; 32],
    nonce: &[u8; 16],
) -> ([u8; 32], [u8; 32]) {
    ecies::session_keys(&ecies::N3_NOTE_TAGS, epk, pr, shared, nonce)
}

/// blake3 keyed-hash counter-mode keystream over the N3 tags
/// (delegates to opacus_crypto::ecies::keystream; bytes unchanged).
fn keystream(k_enc: &[u8; 32], nonce: &[u8; 16], len: usize) -> Vec<u8> {
    ecies::keystream(&ecies::N3_NOTE_TAGS, k_enc, nonce, len)
}

/// Encrypt-then-MAC tag over (version, epk, nonce, ct) - deliberately
/// not hops: a relay must be able to decrement the budget without
/// knowing any key material.
fn mac_of(k_mac: &[u8; 32], version: u32, epk: &[u8; 32], nonce: &[u8; 16], ct: &[u8]) -> [u8; 32] {
    ecies::mac_of(&ecies::N3_NOTE_TAGS, k_mac, version, epk, nonce, ct)
}

// ---------------------------------------------------------------------------
// Structural validation (wire level, relay-safe)
// ---------------------------------------------------------------------------

/// Validate ONE blob: version, hops cap, hex fields with exact lengths,
/// the ephemeral key decompresses, the payload fits the cap, and the id
/// digest matches the contents. No secret material involved.
pub fn check_blob(b: &NoteBlob) -> Result<(), NoteError> {
    if b.version != NOTE_WIRE_VERSION {
        return Err(NoteError::BadVersion(b.version));
    }
    if b.hops > NOTES_MAX_HOPS {
        return Err(NoteError::BadHops(b.hops));
    }
    let epk_b = epk32(b)?;
    CompressedRistretto(epk_b)
        .decompress()
        .ok_or(NoteError::BadEphemeralKey)?;
    let nonce = nonce16(b)?;
    let ct = payload_bytes(b)?;
    let _ = mac32(b)?;
    let id = id32(b)?;
    if id != id_digest(b.version, b.hops, &epk_b, &nonce, &ct) {
        return Err(NoteError::BadId);
    }
    Ok(())
}

/// Validate a whole Notes batch (wire level, called by the frame decoder):
/// count cap first, then every blob structurally.
pub fn validate_note_blobs(notes: &[NoteBlob]) -> Result<(), HandshakeError> {
    if notes.len() > NOTES_MAX_COUNT {
        return Err(HandshakeError::NotesTooLarge(notes.len()));
    }
    for b in notes {
        check_blob(b).map_err(|e| HandshakeError::Malformed(format!("note blob: {e}")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Seal / open
// ---------------------------------------------------------------------------

/// Core seal with explicit ephemeral scalar and nonce (deterministic, used
/// by tests and by the public wrappers below).
pub(crate) fn seal_with(
    payload: &[u8],
    recipient_pr: &CompressedRistretto,
    hops: u32,
    e: &Scalar,
    nonce: &[u8; 16],
) -> Result<NoteBlob, NoteError> {
    if payload.is_empty() || payload.len() > NOTE_PAYLOAD_MAX {
        return Err(NoteError::BadPayloadLen(payload.len()));
    }
    if hops > NOTES_MAX_HOPS {
        return Err(NoteError::BadHops(hops));
    }
    let recip_pt = recipient_pr
        .decompress()
        .ok_or(NoteError::BadRecipientKey)?;
    let epk = (e * RISTRETTO_BASEPOINT_POINT).compress();
    let shared = (e * recip_pt).compress();
    let (k_enc, k_mac) = session_keys(
        epk.as_bytes(),
        recipient_pr.as_bytes(),
        shared.as_bytes(),
        nonce,
    );
    let ks = keystream(&k_enc, nonce, payload.len());
    let ct: Vec<u8> = payload.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mac = mac_of(&k_mac, NOTE_WIRE_VERSION, epk.as_bytes(), nonce, &ct);
    let id = id_digest(NOTE_WIRE_VERSION, hops, epk.as_bytes(), nonce, &ct);
    Ok(NoteBlob {
        version: NOTE_WIRE_VERSION,
        hops,
        epk: hex::encode(epk.as_bytes()),
        nonce: hex::encode(nonce),
        payload: hex::encode(ct),
        mac: hex::encode(mac),
        id: hex::encode(id),
    })
}

/// Seal an opaque payload to a recipient ristretto identity key with the
/// default relay budget and fresh randomness.
pub fn seal_note(
    payload: &[u8],
    recipient_pr: &CompressedRistretto,
) -> Result<NoteBlob, NoteError> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let e = Scalar::random(&mut OsRng);
    seal_with(payload, recipient_pr, NOTES_MAX_HOPS, &e, &nonce)
}

/// Seal with an explicit relay budget (e.g. 0 for a direct-delivery blob
/// that relays must store but never forward).
pub fn seal_note_with_hops(
    payload: &[u8],
    recipient_pr: &CompressedRistretto,
    hops: u32,
) -> Result<NoteBlob, NoteError> {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let e = Scalar::random(&mut OsRng);
    seal_with(payload, recipient_pr, hops, &e, &nonce)
}

/// Open a blob with the local identity. Order: full structural validation
/// (including the public id), then the MAC, and only then decryption.
pub fn open_note(blob: &NoteBlob, recipient: &NodeIdentity) -> Result<Vec<u8>, NoteError> {
    check_blob(blob)?;
    let epk_b = epk32(blob)?;
    let epk_pt = CompressedRistretto(epk_b)
        .decompress()
        .ok_or(NoteError::BadEphemeralKey)?;
    let shared = (recipient.secret() * epk_pt).compress();
    let nonce = nonce16(blob)?;
    let ct = payload_bytes(blob)?;
    let (k_enc, k_mac) = session_keys(&epk_b, recipient.pr.as_bytes(), shared.as_bytes(), &nonce);
    let want = mac_of(&k_mac, blob.version, &epk_b, &nonce, &ct);
    let got = mac32(blob)?;
    if blake3::Hash::from_bytes(want) != blake3::Hash::from_bytes(got) {
        return Err(NoteError::MacMismatch);
    }
    let ks = keystream(&k_enc, &nonce, ct.len());
    Ok(ct.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect())
}

// ---------------------------------------------------------------------------
// Note inbox (bounded, deduped)
// ---------------------------------------------------------------------------

/// Bounded per-node store of received note blobs. Deduped by the public id
/// with a sliding window of the same capacity (the ReplayCache pattern):
/// a blob that fell out of the window can be accepted again, which bounds
/// memory while tolerating slow relay loops.
pub struct NoteInbox {
    cap: usize,
    entries: Vec<NoteBlob>,
    seen_order: VecDeque<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
}

impl NoteInbox {
    pub fn new(cap: usize) -> NoteInbox {
        NoteInbox {
            cap: cap.max(1),
            entries: Vec::new(),
            seen_order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot of the stored blobs, oldest first.
    pub fn snapshot(&self) -> Vec<NoteBlob> {
        self.entries.clone()
    }

    /// Store one blob unless its id is inside the dedupe window. Returns
    /// true when the blob is new (and was stored).
    pub fn ingest(&mut self, blob: NoteBlob) -> bool {
        let id = match id32(&blob) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if self.seen.contains(&id) {
            return false;
        }
        self.seen.insert(id);
        self.seen_order.push_back(id);
        while self.seen_order.len() > self.cap {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.entries.push(blob);
        while self.entries.len() > self.cap {
            self.entries.remove(0);
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{decode_net_frame, encode_net_frame, NetMsg};
    use crate::net_node::{NetNode, NetNodeConfig};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn n3_scalar(seed: u8) -> Scalar {
        let mut buf = [0u8; 32];
        buf[0] = seed;
        buf[31] = seed.wrapping_add(3);
        Scalar::from_bytes_mod_order(buf)
    }

    fn n3_node(seed: u8) -> Arc<NetNode> {
        let cfg = NetNodeConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            advertise_addr: "127.0.0.1:65534".to_string(),
            ..Default::default()
        };
        NetNode::start(cfg, NodeIdentity::from_secret(n3_scalar(seed))).expect("node start")
    }

    fn n3_wait(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if cond() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn note_seal_open_roundtrip() {
        let id = NodeIdentity::from_secret(n3_scalar(21));
        let payload = b"opacus note payload v0.6".to_vec();
        let blob = seal_note(&payload, &id.pr).unwrap();
        assert_eq!(blob.version, NOTE_WIRE_VERSION);
        assert_eq!(blob.hops, NOTES_MAX_HOPS);
        assert_eq!(open_note(&blob, &id).unwrap(), payload);

        // max-size payload also roundtrips
        let big = vec![0x5au8; NOTE_PAYLOAD_MAX];
        let blob_big = seal_note(&big, &id.pr).unwrap();
        assert_eq!(open_note(&blob_big, &id).unwrap(), big);
    }

    #[test]
    fn note_seal_deterministic_and_distinct() {
        let id = NodeIdentity::from_secret(n3_scalar(22));
        let payload = b"determinism check";
        let e = n3_scalar(200);
        let nonce = [0x42u8; 16];
        let a = seal_with(payload, &id.pr, NOTES_MAX_HOPS, &e, &nonce).unwrap();
        let b = seal_with(payload, &id.pr, NOTES_MAX_HOPS, &e, &nonce).unwrap();
        assert_eq!(a, b);
        // same key material, different nonce: same epk, different ciphertext
        let mut nonce2 = nonce;
        nonce2[0] ^= 0x01;
        let c = seal_with(payload, &id.pr, NOTES_MAX_HOPS, &e, &nonce2).unwrap();
        assert_eq!(a.epk, c.epk);
        assert_ne!(a.payload, c.payload);
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn note_wrong_recipient_rejected() {
        let a = NodeIdentity::from_secret(n3_scalar(23));
        let b = NodeIdentity::from_secret(n3_scalar(24));
        let blob = seal_note(b"for a only", &a.pr).unwrap();
        assert!(matches!(open_note(&blob, &b), Err(NoteError::MacMismatch)));
    }

    #[test]
    fn note_tamper_detection_layers() {
        let id = NodeIdentity::from_secret(n3_scalar(25));
        let blob = seal_note(b"tamper target", &id.pr).unwrap();
        // flip one ciphertext byte WITHOUT fixing the public id: the id
        // digest mismatch must fire first
        let mut t1 = blob.clone();
        let mut ct = hex::decode(&t1.payload).unwrap();
        ct[0] ^= 0x01;
        t1.payload = hex::encode(&ct);
        assert!(matches!(open_note(&t1, &id), Err(NoteError::BadId)));
        // recompute the id over the tampered contents: now the sealed MAC
        // must fail (the MAC covers the ciphertext)
        t1.id = note_id_hex_of(&t1).unwrap();
        assert!(matches!(open_note(&t1, &id), Err(NoteError::MacMismatch)));
    }

    #[test]
    fn note_payload_caps() {
        let id = NodeIdentity::from_secret(n3_scalar(26));
        assert!(matches!(
            seal_note(b"", &id.pr),
            Err(NoteError::BadPayloadLen(0))
        ));
        assert_eq!(
            seal_note(&vec![0u8; NOTE_PAYLOAD_MAX + 1], &id.pr),
            Err(NoteError::BadPayloadLen(NOTE_PAYLOAD_MAX + 1))
        );
        assert!(seal_note(&vec![1u8; NOTE_PAYLOAD_MAX], &id.pr).is_ok());
    }

    #[test]
    fn note_validate_rejects_bad_fields() {
        let id = NodeIdentity::from_secret(n3_scalar(27));
        let blob = seal_note(b"validate me", &id.pr).unwrap();
        assert!(validate_note_blobs(&[]).is_ok());

        let many = vec![blob.clone(); NOTES_MAX_COUNT + 1];
        assert_eq!(
            validate_note_blobs(&many),
            Err(HandshakeError::NotesTooLarge(NOTES_MAX_COUNT + 1))
        );

        let mut hops = blob.clone();
        hops.hops = NOTES_MAX_HOPS + 1;
        assert!(matches!(
            validate_note_blobs(&[hops]),
            Err(HandshakeError::Malformed(_))
        ));

        let mut ver = blob.clone();
        ver.version = NOTE_WIRE_VERSION + 1;
        assert!(matches!(
            validate_note_blobs(&[ver]),
            Err(HandshakeError::Malformed(_))
        ));

        let mut epk = blob.clone();
        epk.epk = "zz".to_string();
        assert!(matches!(
            validate_note_blobs(&[epk]),
            Err(HandshakeError::Malformed(_))
        ));

        let mut idf = blob.clone();
        idf.id = hex::encode([0u8; 32]);
        assert!(matches!(
            validate_note_blobs(&[idf]),
            Err(HandshakeError::Malformed(_))
        ));
    }

    #[test]
    fn note_wire_roundtrip_and_negatives() {
        let id = NodeIdentity::from_secret(n3_scalar(28));
        let blob = seal_note(b"wire rt", &id.pr).unwrap();
        let msg = NetMsg::Notes {
            notes: vec![blob.clone()],
        };
        let wire = encode_net_frame(&msg).unwrap();
        assert_eq!(decode_net_frame(&wire).unwrap(), msg);

        // over-cap batch at the frame level
        let many = vec![blob.clone(); NOTES_MAX_COUNT + 1];
        let wire_big = encode_net_frame(&NetMsg::Notes { notes: many }).unwrap();
        assert!(matches!(
            decode_net_frame(&wire_big),
            Err(HandshakeError::NotesTooLarge(_))
        ));

        // wrong id digest
        let mut bad_id = blob.clone();
        bad_id.id = hex::encode([7u8; 32]);
        let wb = encode_net_frame(&NetMsg::Notes {
            notes: vec![bad_id],
        })
        .unwrap();
        assert!(matches!(
            decode_net_frame(&wb),
            Err(HandshakeError::Malformed(_))
        ));

        // oversize payload hex (id not fixed): structural cap fires first
        let mut over = blob;
        over.payload = hex::encode(vec![0u8; NOTE_PAYLOAD_MAX + 1]);
        let wo = encode_net_frame(&NetMsg::Notes { notes: vec![over] }).unwrap();
        assert!(matches!(
            decode_net_frame(&wo),
            Err(HandshakeError::Malformed(_))
        ));
    }

    #[test]
    fn note_inbox_dedupe_and_cap() {
        let id = NodeIdentity::from_secret(n3_scalar(29));
        let mut ib = NoteInbox::new(4);
        let blobs: Vec<NoteBlob> = (0..5)
            .map(|i| {
                let p = format!("inbox blob {i}").into_bytes();
                seal_note(&p, &id.pr).unwrap()
            })
            .collect();
        assert!(ib.ingest(blobs[0].clone()));
        assert!(!ib.ingest(blobs[0].clone()), "same id must dedupe");
        for b in &blobs[1..] {
            assert!(ib.ingest(b.clone()));
        }
        assert_eq!(ib.len(), 4, "cap must evict the oldest entry");
        let snap = ib.snapshot();
        assert_eq!(snap[0].id, blobs[1].id);
        assert_eq!(snap[3].id, blobs[4].id);
        // the evicted blob left the dedupe window: it is accepted again
        assert!(ib.ingest(blobs[0].clone()));
        assert_eq!(ib.len(), 4);
    }

    #[test]
    fn note_direct_delivery_two_nodes() {
        let a = n3_node(31);
        let c = n3_node(33);
        let c_addr = c.local_addr().unwrap().to_string();
        let c_hex = c.node_id_hex();
        let a_hex = a.node_id_hex();
        a.dial(&c_addr).unwrap();
        assert!(n3_wait(10, || {
            a.connected().contains(&c_hex) && c.connected().contains(&a_hex)
        }));

        let id_c = NodeIdentity::from_secret(n3_scalar(33));
        let payload = b"direct note v0.6".to_vec();
        let blob = seal_note(&payload, &id_c.pr).unwrap();
        a.send_notes(&c_hex, &[blob]).unwrap();
        assert!(n3_wait(10, || !c.inbox().is_empty()));
        let got = open_note(&c.inbox()[0], &id_c).unwrap();
        assert_eq!(got, payload);
        // the sender does not store its own outbound notes
        assert!(a.inbox().is_empty());
    }

    #[test]
    fn note_relay_through_common_peer() {
        let a = n3_node(41);
        let b = n3_node(42);
        let c = n3_node(43);
        let b_addr = b.local_addr().unwrap().to_string();
        let b_hex = b.node_id_hex();
        let a_hex = a.node_id_hex();
        let c_hex = c.node_id_hex();
        a.dial(&b_addr).unwrap();
        c.dial(&b_addr).unwrap();
        assert!(n3_wait(10, || {
            b.connected().contains(&a_hex)
                && b.connected().contains(&c_hex)
                && a.connected().contains(&b_hex)
                && c.connected().contains(&b_hex)
        }));

        let id_c = NodeIdentity::from_secret(n3_scalar(43));
        let payload = b"relayed note v0.6".to_vec();
        let blob = seal_note(&payload, &id_c.pr).unwrap();
        a.send_notes(&b_hex, &[blob]).unwrap();
        // B stores the blob and relays it (hops 4 -> 3) to C
        assert!(n3_wait(10, || !b.inbox().is_empty()));
        assert!(n3_wait(10, || !c.inbox().is_empty()));
        let got = open_note(&c.inbox()[0], &id_c).unwrap();
        assert_eq!(got, payload);
        // relayed blob kept a decremented budget
        assert_eq!(c.inbox()[0].hops, NOTES_MAX_HOPS - 1);
    }

    #[test]
    fn note_zero_hops_stored_not_relayed() {
        let a = n3_node(51);
        let b = n3_node(52);
        let c = n3_node(53);
        let b_addr = b.local_addr().unwrap().to_string();
        let b_hex = b.node_id_hex();
        let a_hex = a.node_id_hex();
        let c_hex = c.node_id_hex();
        a.dial(&b_addr).unwrap();
        c.dial(&b_addr).unwrap();
        assert!(n3_wait(10, || {
            b.connected().contains(&a_hex)
                && b.connected().contains(&c_hex)
                && a.connected().contains(&b_hex)
                && c.connected().contains(&b_hex)
        }));

        let id_c = NodeIdentity::from_secret(n3_scalar(53));
        let payload = b"no relay for this one".to_vec();
        let blob = seal_note_with_hops(&payload, &id_c.pr, 0).unwrap();
        a.send_notes(&b_hex, &[blob]).unwrap();
        // B stores it (hops == 0) but must NOT forward it to C
        assert!(n3_wait(10, || !b.inbox().is_empty()));
        assert!(!n3_wait(2, || !c.inbox().is_empty()));
        assert!(c.inbox().is_empty());
    }

    #[test]
    fn note_notes_frame_during_handshake_closes_conn() {
        let b = n3_node(61);
        let b_addr = b.local_addr().unwrap().to_string();
        let id_r = NodeIdentity::from_secret(n3_scalar(62));
        let blob = seal_note(b"handshake sneak", &id_r.pr).unwrap();
        let mut s = TcpStream::connect(&b_addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        // a structurally VALID Notes frame as the FIRST frame: the strict
        // single-shot handshake must reject it and close the connection
        let wire = encode_net_frame(&NetMsg::Notes { notes: vec![blob] }).unwrap();
        s.write_all(&wire).unwrap();
        s.flush().unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "node must close the connection with EOF");
        assert!(n3_wait(2, || b.connected().is_empty()));
    }
}
