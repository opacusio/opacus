//! Authenticated handshake for the opacus P2P network (v0.6 networking, N1).
//!
//! Wire: the same u32-LE length-prefixed JSON framing as the swap node, but
//! with its own protocol tag `opacus-net-v1` (the swap protocol keeps its
//! deliberate `ghost-swap-p2p-v1` tag - nothing is renamed).
//!
//! Flow (mutual authentication, 3 frames):
//!
//! ```text
//! Initiator                                       Responder
//!   | --- Hello{node_id,pe,pr,nonce_c} -----------> |
//!   | <-- Hello{node_id,pe,pr,nonce_s} -------------|
//!   | <-- Auth_r (DLEq + Schnorr over transcript) --|
//!   | --- Auth_c (DLEq + Schnorr over transcript) -> |
//! ```
//!
//! The transcript is canonical bytes over both nonces and all four public
//! keys; `tag = blake3(transcript)[0..32]`. Every AuthMsg carries TWO
//! proofs:
//!
//! 1. the cross-group DLEq (`opacus_bridge::xmr_dleq`): one scalar controls
//!    both `pe` and `pr` - this is the "DLEq-bound identity";
//! 2. a Schnorr signature over the transcript with the same scalar: it
//!    binds the proof to THIS exchange. Without (2) a captured (Hello,
//!    Auth) pair could be replayed verbatim against any responder; with it,
//!    any changed nonce or key breaks the signature.
//!
//! Replay protection: each host keeps a bounded window (default 1024) of
//! accepted transcript tags; a repeated tag is rejected. (A TTL-based
//! window is queued as hardening; the bounded window already bounds memory
//! and rejects in-practice replays.)
//!
//! Transport (Net-1): the handshake itself stays cleartext (only identity
//! keys and proofs cross it), but it now also derives the post-auth
//! transport keys: a static-static ECDH over the DLEq-bound identity keys,
//! bound to the verified transcript, with separate initiator->responder
//! and responder->initiator directions. Every post-auth frame is sealed
//! mac || ciphertext under the per-direction keys with a strictly
//! sequential per-direction counter (see `SessionKeys`).

use std::collections::{HashSet, VecDeque};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G1;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use opacus_bridge::xmr_dleq::{proof_from_bytes, proof_to_bytes, verify as dleq_verify, KeyPair};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::identity::{node_id_of, NodeIdentity};
use crate::notes::{validate_note_blobs, NoteBlob, NOTES_MAX_COUNT};

/// Protocol tag of the opacus network wire (v0.6).
pub const NET_PROTOCOL: &str = "opacus-net-v1";
/// Domain tag of the handshake transcript.
pub const NET_AUTH_TAG: &[u8] = b"opacus-net-auth-v1";
/// Domain tag of the transcript-binding Schnorr challenge.
const SIG_TAG: &[u8] = b"opacus-net-auth-sig-v1";
/// Current handshake version. v2 (Net-1): post-auth frames are
/// transport-encrypted, so a v1 peer is rejected right at Hello with a
/// clean BadVersion instead of failing on the first post-auth frame.
pub const HANDSHAKE_VERSION: u32 = 2;
/// Default replay-window size (accepted transcript tags per host).
pub const REPLAY_CACHE_CAP: usize = 1024;
/// Hard cap for one incoming network frame (prefix + body).
pub const MAX_NET_FRAME: usize = 1_048_576;
/// Hard cap on peer entries carried by one Disco frame.
pub const DISCO_MAX_PEERS: usize = 32;
/// Max length of one Disco addr string.
pub const MAX_ADDR_LEN: usize = 128;
/// Length of the hex-encoded node_id in Disco entries (16 bytes).
pub const PEER_ID_HEX_LEN: usize = 32;
/// The upgrade-plane name that hands a post-auth connection to the swap
/// node (N3b). The only plane served today.
pub const SWAP_UPGRADE_PLANE: &str = "swap";
/// Max length of one Upgrade plane string.
pub const MAX_UPGRADE_PLANE_LEN: usize = 16;

/// Handshake/wire errors. Any verification failure MUST close the
/// connection (and, at the node level, feed the ban policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    Malformed(String),
    BadVersion(u32),
    BadNodeId,
    BadProof,
    TagMismatch,
    BadSignature,
    Replay,
    Json(String),
    ProtocolMismatch(String),
    TooLarge(usize),
    DiscoTooLarge(usize),
    NotesTooLarge(usize),
    /// Post-auth transport failure (Net-1): MAC mismatch, a sealed body
    /// shorter than the MAC, or any other sealed-frame violation. The
    /// connection MUST be closed.
    BadTransport(String),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Malformed(m) => write!(f, "malformed: {m}"),
            HandshakeError::BadVersion(v) => write!(f, "bad version: {v}"),
            HandshakeError::BadNodeId => write!(f, "node_id does not hash the hello keys"),
            HandshakeError::BadProof => write!(f, "DLEq proof rejected"),
            HandshakeError::TagMismatch => write!(f, "transcript tag mismatch"),
            HandshakeError::BadSignature => write!(f, "transcript signature rejected"),
            HandshakeError::Replay => write!(f, "replayed transcript tag"),
            HandshakeError::Json(m) => write!(f, "json: {m}"),
            HandshakeError::ProtocolMismatch(p) => write!(f, "protocol mismatch: {p}"),
            HandshakeError::TooLarge(n) => write!(f, "frame too large: {n}"),
            HandshakeError::DiscoTooLarge(n) => {
                write!(f, "disco carries {n} peers, cap {}", DISCO_MAX_PEERS)
            }
            HandshakeError::NotesTooLarge(n) => {
                write!(f, "notes frame carries {n} blobs, cap {}", NOTES_MAX_COUNT)
            }
            HandshakeError::BadTransport(m) => write!(f, "transport: {m}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

// ---------------------------------------------------------------------------
// Wire types (hex strings for byte fields, like the swap protocol ids)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub version: u32,
    pub node_id: String,
    pub pe: String,
    pub pr: String,
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthMsg {
    pub dleq_proof: String,
    pub sig_r: String,
    pub sig_s: String,
    pub tag: String,
}

/// One peer entry in a Disco frame: identity (hex node_id) + dial addr.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DiscoPeer {
    pub peer_id: String,
    pub addr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum NetMsg {
    Hello {
        hello: Hello,
    },
    Auth {
        auth: AuthMsg,
    },
    /// Post-auth discovery gossip: a bounded batch of known peers.
    Disco {
        peers: Vec<DiscoPeer>,
    },
    /// Post-auth note feed: a bounded batch of sealed note blobs.
    Notes {
        notes: Vec<NoteBlob>,
    },
    /// Post-auth plane upgrade (N3b): the peer asks to hand this
    /// authenticated connection to the named plane ("swap" today).
    /// A struct variant: a unit variant does not survive the flattened
    /// NetFrame envelope.
    Upgrade {
        plane: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NetFrame {
    pub protocol: String,
    #[serde(flatten)]
    pub msg: NetMsg,
}

/// Encode one frame: u32-LE length prefix + JSON body (swap-node framing).
pub fn encode_net_frame(msg: &NetMsg) -> Result<Vec<u8>, HandshakeError> {
    let frame = NetFrame {
        protocol: NET_PROTOCOL.to_string(),
        msg: msg.clone(),
    };
    let body = serde_json::to_vec(&frame).map_err(|e| HandshakeError::Json(e.to_string()))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode one full frame (prefix + body).
pub fn decode_net_frame(buf: &[u8]) -> Result<NetMsg, HandshakeError> {
    if buf.len() < 4 {
        return Err(HandshakeError::Malformed(
            "frame shorter than 4 bytes".to_string(),
        ));
    }
    let declared = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() - 4 != declared {
        return Err(HandshakeError::Malformed(format!(
            "declared {declared} body bytes, got {}",
            buf.len() - 4
        )));
    }
    if buf.len() > MAX_NET_FRAME {
        return Err(HandshakeError::TooLarge(buf.len()));
    }
    let frame: NetFrame =
        serde_json::from_slice(&buf[4..]).map_err(|e| HandshakeError::Json(e.to_string()))?;
    if frame.protocol != NET_PROTOCOL {
        return Err(HandshakeError::ProtocolMismatch(frame.protocol));
    }
    if let NetMsg::Disco { peers } = &frame.msg {
        validate_disco(peers)?;
    }
    if let NetMsg::Notes { notes } = &frame.msg {
        validate_note_blobs(notes)?;
    }
    if let NetMsg::Upgrade { plane } = &frame.msg {
        validate_upgrade_plane(plane)?;
    }
    Ok(frame.msg)
}

/// Structural validation of one Upgrade payload (wire level): the plane
/// name is short, whitespace-free and names a plane this wire serves.
/// The only plane today is `swap`; whether the plane is AVAILABLE is a
/// node-level decision (the optional swap attachment), not a wire one.
pub fn validate_upgrade_plane(plane: &str) -> Result<(), HandshakeError> {
    if plane.is_empty()
        || plane.len() > MAX_UPGRADE_PLANE_LEN
        || plane.chars().any(char::is_whitespace)
    {
        return Err(HandshakeError::Malformed(format!(
            "upgrade plane must be 1..={MAX_UPGRADE_PLANE_LEN} chars, no whitespace"
        )));
    }
    if plane != SWAP_UPGRADE_PLANE {
        return Err(HandshakeError::Malformed(format!(
            "unknown upgrade plane {plane:?}, want \"swap\""
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
/// Structural validation of one Disco payload (wire level). Semantics
/// (canonical addr parsing, self/known filtering) are enforced by the
/// peer store on ingest.
pub fn validate_disco(peers: &[DiscoPeer]) -> Result<(), HandshakeError> {
    if peers.len() > DISCO_MAX_PEERS {
        return Err(HandshakeError::DiscoTooLarge(peers.len()));
    }
    for p in peers {
        if p.peer_id.len() != PEER_ID_HEX_LEN || !p.peer_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HandshakeError::Malformed(
                "disco peer_id must be 32 hex chars".to_string(),
            ));
        }
        if p.addr.is_empty()
            || p.addr.len() > MAX_ADDR_LEN
            || p.addr.chars().any(char::is_whitespace)
        {
            return Err(HandshakeError::Malformed(format!(
                "disco addr must be 1..={MAX_ADDR_LEN} chars, no whitespace"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transcript and crypto helpers
// ---------------------------------------------------------------------------

/// Canonical handshake transcript:
/// `b"opacus-net-auth-v1" || u32LE(1) || nonce_c || nonce_s || pr_c || pr_s || pe_c || pe_s`
pub fn transcript_of(
    nonce_c: &[u8; 32],
    nonce_s: &[u8; 32],
    pr_c: &CompressedRistretto,
    pr_s: &CompressedRistretto,
    pe_c: &CompressedEdwardsY,
    pe_s: &CompressedEdwardsY,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(8 + 32 * 6);
    t.extend_from_slice(NET_AUTH_TAG);
    t.extend_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    t.extend_from_slice(nonce_c);
    t.extend_from_slice(nonce_s);
    t.extend_from_slice(pr_c.as_bytes());
    t.extend_from_slice(pr_s.as_bytes());
    t.extend_from_slice(pe_c.as_bytes());
    t.extend_from_slice(pe_s.as_bytes());
    t
}

/// blake3(transcript)[0..32].
pub fn transcript_tag(transcript: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(blake3::hash(transcript).as_bytes());
    out
}

/// Wide scalar from bytes: 64-byte mod-l reduction (mirrors the bridge).
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

fn hex_dec32(s: &str) -> Result<[u8; 32], HandshakeError> {
    let v = hex::decode(s).map_err(|e| HandshakeError::Malformed(format!("hex: {e}")))?;
    if v.len() != 32 {
        return Err(HandshakeError::Malformed(format!(
            "want 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn hex_dec16(s: &str) -> Result<[u8; 16], HandshakeError> {
    let v = hex::decode(s).map_err(|e| HandshakeError::Malformed(format!("hex: {e}")))?;
    if v.len() != 16 {
        return Err(HandshakeError::Malformed(format!(
            "want 16 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    Ok(out)
}

fn hex_dec96(s: &str) -> Result<[u8; 96], HandshakeError> {
    let v = hex::decode(s).map_err(|e| HandshakeError::Malformed(format!("hex: {e}")))?;
    if v.len() != 96 {
        return Err(HandshakeError::Malformed(format!(
            "want 96 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 96];
    out.copy_from_slice(&v);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Hello / AuthMsg semantics
// ---------------------------------------------------------------------------

/// Parsed and consistency-checked hello contents.
pub struct HelloKeys {
    pub pe: CompressedEdwardsY,
    pub pr: CompressedRistretto,
    pub nonce: [u8; 32],
    pub node_id: [u8; 16],
}

impl Hello {
    pub fn build(id: &NodeIdentity, nonce: &[u8; 32]) -> Hello {
        Hello {
            version: HANDSHAKE_VERSION,
            node_id: hex::encode(id.node_id),
            pe: hex::encode(id.pe.as_bytes()),
            pr: hex::encode(id.pr.as_bytes()),
            nonce: hex::encode(nonce),
        }
    }

    /// Parse hex fields and enforce `node_id == blake3(tag || pe || pr)`.
    pub fn keys(&self) -> Result<HelloKeys, HandshakeError> {
        if self.version != HANDSHAKE_VERSION {
            return Err(HandshakeError::BadVersion(self.version));
        }
        let pe_b = hex_dec32(&self.pe)?;
        let pr_b = hex_dec32(&self.pr)?;
        let nonce = hex_dec32(&self.nonce)?;
        let node_id = hex_dec16(&self.node_id)?;
        let pe = CompressedEdwardsY(pe_b);
        let pr = CompressedRistretto(pr_b);
        if node_id_of(&pe, &pr) != node_id {
            return Err(HandshakeError::BadNodeId);
        }
        Ok(HelloKeys {
            pe,
            pr,
            nonce,
            node_id,
        })
    }
}

impl AuthMsg {
    /// Prove THIS identity over THIS transcript (DLEq + transcript Schnorr).
    pub fn produce(id: &NodeIdentity, transcript: &[u8]) -> AuthMsg {
        let proof = opacus_bridge::xmr_dleq::prove(id.secret());
        let dleq = proof_to_bytes(&proof);
        let r = Scalar::random(&mut OsRng);
        let big_r = (r * G1).compress();
        let mut buf = Vec::with_capacity(32 + transcript.len());
        buf.extend_from_slice(big_r.as_bytes());
        buf.extend_from_slice(transcript);
        let c = scalar_wide(SIG_TAG, &buf);
        let s = r + c * id.secret();
        AuthMsg {
            dleq_proof: hex::encode(dleq),
            sig_r: hex::encode(big_r.as_bytes()),
            sig_s: hex::encode(s.to_bytes()),
            tag: hex::encode(transcript_tag(transcript)),
        }
    }

    /// Verify against the claimed public keys and the locally rebuilt
    /// transcript. Order: tag -> DLEq -> transcript Schnorr.
    pub fn verify_against(
        &self,
        peer_pe: &CompressedEdwardsY,
        peer_pr: &CompressedRistretto,
        transcript: &[u8],
    ) -> Result<(), HandshakeError> {
        let want = transcript_tag(transcript);
        let got = hex_dec32(&self.tag)?;
        if got != want {
            return Err(HandshakeError::TagMismatch);
        }
        let dleq_b = hex_dec96(&self.dleq_proof)?;
        let proof = proof_from_bytes(&dleq_b);
        let kp = KeyPair {
            monero_pub: *peer_pe,
            ristretto_pub: *peer_pr,
        };
        dleq_verify(&kp, &proof).map_err(|_| HandshakeError::BadProof)?;

        let r_b = hex_dec32(&self.sig_r)?;
        let s_b = hex_dec32(&self.sig_s)?;
        let big_r = CompressedEdwardsY(r_b);
        let r_point = big_r.decompress().ok_or(HandshakeError::BadSignature)?;
        let s = Scalar::from_canonical_bytes(s_b)
            .into_option()
            .ok_or(HandshakeError::BadSignature)?;
        let mut buf = Vec::with_capacity(32 + transcript.len());
        buf.extend_from_slice(&r_b);
        buf.extend_from_slice(transcript);
        let c = scalar_wide(SIG_TAG, &buf);
        let a1 = peer_pe.decompress().ok_or(HandshakeError::BadSignature)?;
        if s * G1 != r_point + c * a1 {
            return Err(HandshakeError::BadSignature);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Post-auth transport keys (Net-1)
// ---------------------------------------------------------------------------

/// Domain tag of the per-direction encryption key derivation.
const TK_ENC_TAG: &str = "opacus-net-tk-v1 enc";
/// Domain tag of the per-direction MAC key derivation.
const TK_MAC_TAG: &str = "opacus-net-tk-v1 mac";
/// Domain tag of one keystream block.
const TK_KS_TAG: &[u8] = b"opacus-net-tk-v1 ks";
/// Domain tag of the frame MAC.
const TK_FRAME_MAC_TAG: &[u8] = b"opacus-net-tk-v1 frame-mac";
/// Length of one sealed frame's MAC (carried at the head of the body).
pub const TRANSPORT_MAC_LEN: usize = 32;

/// One direction's transport keys.
#[derive(Clone)]
pub struct DirKeys {
    enc: [u8; 32],
    mac: [u8; 32],
}

/// Post-auth transport keys (Net-1): the session secret is a
/// static-static ECDH over the DLEq-bound identity keys
/// (`sk_local * pr_peer` - only the two proven key holders can compute
/// it), bound to the verified handshake transcript. Each direction has
/// its own encryption + MAC keys. Construction family: the note ECIES
/// (keyed blake3 MAC verified BEFORE any decryption, blake3-keystream
/// encryption) - no new dependencies.
#[derive(Clone)]
pub struct SessionKeys {
    tx: DirKeys,
    rx: DirKeys,
}

impl SessionKeys {
    /// Derive both directions from the verified handshake. `role`
    /// selects which direction is ours; `peer` must be the VERIFIED
    /// peer (its `pr` was proven by the Auth proof).
    pub fn derive(
        role: Role,
        id: &NodeIdentity,
        peer: &VerifiedPeer,
        transcript: &[u8],
    ) -> Result<SessionKeys, HandshakeError> {
        let peer_point = peer.pr.decompress().ok_or(HandshakeError::BadProof)?;
        let shared = id.secret() * peer_point;
        let mut base = Vec::with_capacity(64 + transcript.len());
        base.extend_from_slice(NET_AUTH_TAG);
        base.extend_from_slice(shared.compress().as_bytes());
        base.extend_from_slice(transcript);
        let (tx, rx) = match role {
            Role::Initiator => (dir_keys(&base, "i2r"), dir_keys(&base, "r2i")),
            Role::Responder => (dir_keys(&base, "r2i"), dir_keys(&base, "i2r")),
        };
        Ok(SessionKeys { tx, rx })
    }

    /// Seal one outbound frame at the strictly increasing tx counter:
    /// body = mac(32) || ciphertext. The MAC covers the counter, so
    /// frames cannot be reordered, replayed or spliced across sequences.
    pub fn seal(&self, seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut ct = Vec::with_capacity(plaintext.len());
        for (i, chunk) in plaintext.chunks(32).enumerate() {
            let ks = keystream_block(&self.tx.enc, seq, i as u64);
            ct.extend(chunk.iter().zip(ks.iter()).map(|(p, k)| p ^ k));
        }
        let mac = blake3::keyed_hash(
            &self.tx.mac,
            &[TK_FRAME_MAC_TAG, &seq.to_le_bytes(), &ct].concat(),
        );
        let mut body = Vec::with_capacity(TRANSPORT_MAC_LEN + ct.len());
        body.extend_from_slice(mac.as_bytes());
        body.extend_from_slice(&ct);
        body
    }

    /// Open one inbound frame body at the expected rx counter. The MAC
    /// is verified (constant-time via blake3::Hash equality) BEFORE any
    /// decryption; a mismatch means tampering, reordering or replay -
    /// the connection must be closed.
    pub fn open(&self, seq: u64, body: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if body.len() < TRANSPORT_MAC_LEN {
            return Err(HandshakeError::BadTransport(format!(
                "sealed frame is {} bytes, shorter than the MAC",
                body.len()
            )));
        }
        let (mac_b, ct) = body.split_at(TRANSPORT_MAC_LEN);
        let want = blake3::keyed_hash(
            &self.rx.mac,
            &[TK_FRAME_MAC_TAG, &seq.to_le_bytes(), ct].concat(),
        );
        let got = blake3::Hash::from_bytes(mac_b.try_into().expect("32 bytes"));
        if got != want {
            return Err(HandshakeError::BadTransport(format!(
                "frame MAC mismatch at seq {seq}"
            )));
        }
        let mut pt = Vec::with_capacity(ct.len());
        for (i, chunk) in ct.chunks(32).enumerate() {
            let ks = keystream_block(&self.rx.enc, seq, i as u64);
            pt.extend(chunk.iter().zip(ks.iter()).map(|(c, k)| c ^ k));
        }
        Ok(pt)
    }
}

/// Per-direction keys: two independent blake3::derive_key expansions of
/// the shared base under direction-separated contexts.
fn dir_keys(base: &[u8], dir: &str) -> DirKeys {
    let enc = blake3::derive_key(&format!("{TK_ENC_TAG} {dir}"), base);
    let mac = blake3::derive_key(&format!("{TK_MAC_TAG} {dir}"), base);
    DirKeys { enc, mac }
}

/// One 32-byte keystream block: keyed hash over the tag, the sequence
/// and the block index (the same construction as the note keystream).
fn keystream_block(key: &[u8; 32], seq: u64, block: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(TK_KS_TAG.len() + 16);
    data.extend_from_slice(TK_KS_TAG);
    data.extend_from_slice(&seq.to_le_bytes());
    data.extend_from_slice(&block.to_le_bytes());
    *blake3::keyed_hash(key, &data).as_bytes()
}

// ---------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------

/// Bounded LRU window of accepted transcript tags (per host, not per peer).
pub struct ReplayCache {
    cap: usize,
    order: VecDeque<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
}

impl ReplayCache {
    pub fn new(cap: usize) -> ReplayCache {
        ReplayCache {
            cap: cap.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Ok(()) if the tag is fresh; Err(Replay) if seen inside the window.
    pub fn check_and_insert(&mut self, tag: &[u8; 32]) -> Result<(), HandshakeError> {
        if self.seen.contains(tag) {
            return Err(HandshakeError::Replay);
        }
        self.seen.insert(*tag);
        self.order.push_back(*tag);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Handshake state machines (one side of one connection)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// The outcome of a verified AuthMsg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedPeer {
    pub node_id: [u8; 16],
    pub pe: CompressedEdwardsY,
    pub pr: CompressedRistretto,
}

pub struct HandshakeSide {
    role: Role,
    id: NodeIdentity,
    nonce: [u8; 32],
    peer_pe: Option<CompressedEdwardsY>,
    peer_pr: Option<CompressedRistretto>,
    peer_node_id: Option<[u8; 16]>,
    transcript: Option<Vec<u8>>,
}

impl HandshakeSide {
    /// Start one side; returns the side and the Hello to send.
    pub fn start(role: Role, id: &NodeIdentity) -> (HandshakeSide, Hello) {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let side = HandshakeSide {
            role,
            id: id.clone(),
            nonce,
            peer_pe: None,
            peer_pr: None,
            peer_node_id: None,
            transcript: None,
        };
        (side, Hello::build(id, &nonce))
    }

    /// Ingest the peer Hello, rebuild the transcript locally.
    pub fn on_peer_hello(&mut self, hello: &Hello) -> Result<(), HandshakeError> {
        if hello.version != HANDSHAKE_VERSION {
            return Err(HandshakeError::BadVersion(hello.version));
        }
        let k = hello.keys()?;
        let transcript = match self.role {
            Role::Initiator => transcript_of(
                &self.nonce,
                &k.nonce,
                &self.id.pr,
                &k.pr,
                &self.id.pe,
                &k.pe,
            ),
            Role::Responder => transcript_of(
                &k.nonce,
                &self.nonce,
                &k.pr,
                &self.id.pr,
                &k.pe,
                &self.id.pe,
            ),
        };
        self.peer_pe = Some(k.pe);
        self.peer_pr = Some(k.pr);
        self.peer_node_id = Some(k.node_id);
        self.transcript = Some(transcript);
        Ok(())
    }

    /// Produce our AuthMsg (requires a peer hello first).
    pub fn produce_auth(&self) -> Result<AuthMsg, HandshakeError> {
        let t = self
            .transcript
            .as_ref()
            .ok_or_else(|| HandshakeError::Malformed("no peer hello yet".to_string()))?;
        Ok(AuthMsg::produce(&self.id, t))
    }

    /// Verify the peer AuthMsg, then record the tag in the replay window.
    /// The tag is recorded ONLY after a successful verification, so failed
    /// attempts cannot pollute the window.
    pub fn verify_auth(
        &self,
        auth: &AuthMsg,
        cache: &mut ReplayCache,
    ) -> Result<VerifiedPeer, HandshakeError> {
        let t = self
            .transcript
            .as_ref()
            .ok_or_else(|| HandshakeError::Malformed("no peer hello yet".to_string()))?;
        let pe = self
            .peer_pe
            .ok_or_else(|| HandshakeError::Malformed("no peer hello yet".to_string()))?;
        let pr = self
            .peer_pr
            .ok_or_else(|| HandshakeError::Malformed("no peer hello yet".to_string()))?;
        let node_id = self
            .peer_node_id
            .ok_or_else(|| HandshakeError::Malformed("no peer hello yet".to_string()))?;
        auth.verify_against(&pe, &pr, t)?;
        cache.check_and_insert(&transcript_tag(t))?;
        Ok(VerifiedPeer { node_id, pe, pr })
    }

    /// Net-1: derive the post-auth transport keys for THIS side. `peer`
    /// must be the value returned by verify_auth (the proven identity).
    pub fn session_keys(&self, peer: &VerifiedPeer) -> Result<SessionKeys, HandshakeError> {
        let t = self
            .transcript
            .as_ref()
            .ok_or_else(|| HandshakeError::Malformed("no peer hello yet".to_string()))?;
        SessionKeys::derive(self.role, &self.id, peer, t)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- N2-a: Disco wire + F6 negative decode tests ----

    fn disco_frame(peers: &[DiscoPeer]) -> Vec<u8> {
        encode_net_frame(&NetMsg::Disco {
            peers: peers.to_vec(),
        })
        .unwrap()
    }

    #[test]
    fn disco_roundtrip_and_accepts_cap() {
        let peers: Vec<DiscoPeer> = (0..DISCO_MAX_PEERS)
            .map(|i| DiscoPeer {
                peer_id: format!("{:032x}", i),
                addr: format!("127.0.0.1:{}", 10_000 + i),
            })
            .collect();
        let wire = disco_frame(&peers);
        match decode_net_frame(&wire).unwrap() {
            NetMsg::Disco { peers: got } => assert_eq!(got, peers),
            other => panic!("unexpected msg: {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_disco_over_cap() {
        let peers: Vec<DiscoPeer> = (0..=DISCO_MAX_PEERS)
            .map(|i| DiscoPeer {
                peer_id: format!("{:032x}", i),
                addr: format!("127.0.0.1:{}", 10_000 + i),
            })
            .collect();
        assert_eq!(peers.len(), DISCO_MAX_PEERS + 1);
        assert_eq!(
            decode_net_frame(&disco_frame(&peers)),
            Err(HandshakeError::DiscoTooLarge(DISCO_MAX_PEERS + 1))
        );
    }

    #[test]
    fn decode_rejects_disco_bad_peer_id() {
        let peers = vec![DiscoPeer {
            peer_id: "nothex".to_string(),
            addr: "127.0.0.1:10000".to_string(),
        }];
        assert!(matches!(
            decode_net_frame(&disco_frame(&peers)),
            Err(HandshakeError::Malformed(_))
        ));
    }

    #[test]
    fn decode_rejects_disco_bad_addr() {
        let cases = vec![
            String::new(),
            "has space:1".to_string(),
            "a".repeat(MAX_ADDR_LEN + 1),
        ];
        for addr in cases {
            let peers = vec![DiscoPeer {
                peer_id: format!("{:032x}", 1),
                addr,
            }];
            assert!(matches!(
                decode_net_frame(&disco_frame(&peers)),
                Err(HandshakeError::Malformed(_))
            ));
        }
    }

    #[test]
    fn decode_rejects_short_and_length_mismatch() {
        assert!(matches!(
            decode_net_frame(&[]),
            Err(HandshakeError::Malformed(_))
        ));
        let wire = disco_frame(&[]);
        assert!(matches!(
            decode_net_frame(&wire[..2]),
            Err(HandshakeError::Malformed(_))
        ));
        let mut bad = wire.clone();
        bad[0] = bad[0].wrapping_add(1); // declared != actual body length
        assert!(matches!(
            decode_net_frame(&bad),
            Err(HandshakeError::Malformed(_))
        ));
    }

    #[test]
    fn decode_rejects_oversize_frame() {
        let n = MAX_NET_FRAME + 1;
        let mut buf = vec![0u8; n];
        let declared = (n - 4) as u32;
        buf[0..4].copy_from_slice(&declared.to_le_bytes());
        assert_eq!(decode_net_frame(&buf), Err(HandshakeError::TooLarge(n)));
    }

    #[test]
    fn decode_rejects_wrong_protocol_and_garbage() {
        // well-formed envelope with a foreign protocol tag -> ProtocolMismatch
        // (minimal valid msg shape: an empty Disco batch; the protocol tag
        // check runs before validate_disco, so no peers are needed)
        let body = br#"{"protocol":"bogus","Disco":{"peers":[]}}"#;
        let mut wire = (body.len() as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(body);
        assert_eq!(
            decode_net_frame(&wire),
            Err(HandshakeError::ProtocolMismatch("bogus".to_string()))
        );

        // structurally invalid msg -> Json error wins over the protocol tag
        // check, because the envelope is parsed in a single serde pass
        let body3 =
            br#"{"protocol":"bogus","Hello":{"version":1,"node_id":"","pe":"","pr":"","nonce":""}}"#;
        let mut wire3 = (body3.len() as u32).to_le_bytes().to_vec();
        wire3.extend_from_slice(body3);
        assert!(matches!(
            decode_net_frame(&wire3),
            Err(HandshakeError::Json(_))
        ));

        let body2 = b"not json at all";
        let mut wire2 = (body2.len() as u32).to_le_bytes().to_vec();
        wire2.extend_from_slice(body2);
        assert!(matches!(
            decode_net_frame(&wire2),
            Err(HandshakeError::Json(_))
        ));
    }

    /// Both sides past the Hello exchange.
    fn pair() -> (HandshakeSide, HandshakeSide) {
        let ci = NodeIdentity::generate();
        let ri = NodeIdentity::generate();
        let (mut c, hello_c) = HandshakeSide::start(Role::Initiator, &ci);
        let (mut r, hello_r) = HandshakeSide::start(Role::Responder, &ri);
        c.on_peer_hello(&hello_r).unwrap();
        r.on_peer_hello(&hello_c).unwrap();
        (c, r)
    }

    #[test]
    fn handshake_mutual_happy_in_memory() {
        let (c, r) = pair();
        let mut cache_c = ReplayCache::new(REPLAY_CACHE_CAP);
        let mut cache_r = ReplayCache::new(REPLAY_CACHE_CAP);
        let auth_r = r.produce_auth().unwrap();
        let vp_at_c = c.verify_auth(&auth_r, &mut cache_c).unwrap();
        let auth_c = c.produce_auth().unwrap();
        let vp_at_r = r.verify_auth(&auth_c, &mut cache_r).unwrap();
        assert_ne!(vp_at_c.node_id, vp_at_r.node_id);
        // both sides committed to the same transcript
        assert_eq!(auth_r.tag, auth_c.tag);
    }

    #[test]
    fn handshake_loopback_tcp_completes() {
        use std::net::{TcpListener, TcpStream};

        fn read_frame(s: &mut std::net::TcpStream) -> Option<Vec<u8>> {
            use std::io::Read;
            let mut len_buf = [0u8; 4];
            s.read_exact(&mut len_buf).ok()?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf).ok()?;
            Some(buf)
        }

        fn write_frame(s: &mut std::net::TcpStream, wire: &[u8]) {
            use std::io::Write;
            s.write_all(&(wire.len() as u32).to_be_bytes()).unwrap();
            s.write_all(wire).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Responder on a real socket; returns the node_id it VERIFIED from
        // the initiator's Auth frame.
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let (mut r, hello_r) = HandshakeSide::start(Role::Responder, &NodeIdentity::generate());
            let wire = read_frame(&mut sock).unwrap();
            let hello_c = match decode_net_frame(&wire).unwrap() {
                NetMsg::Hello { hello } => hello,
                other => panic!("want hello, got {other:?}"),
            };
            r.on_peer_hello(&hello_c).unwrap();
            write_frame(
                &mut sock,
                &encode_net_frame(&NetMsg::Hello { hello: hello_r }).unwrap(),
            );
            write_frame(
                &mut sock,
                &encode_net_frame(&NetMsg::Auth {
                    auth: r.produce_auth().unwrap(),
                })
                .unwrap(),
            );
            let wire = read_frame(&mut sock).unwrap();
            let auth_c = match decode_net_frame(&wire).unwrap() {
                NetMsg::Auth { auth } => auth,
                other => panic!("want auth, got {other:?}"),
            };
            let mut cache = ReplayCache::new(REPLAY_CACHE_CAP);
            r.verify_auth(&auth_c, &mut cache).unwrap().node_id
        });

        // Initiator on the main thread: capture OUR node_id BEFORE hello_c
        // is moved into the outbound frame.
        let mut sock = TcpStream::connect(addr).unwrap();
        let (mut c, hello_c) = HandshakeSide::start(Role::Initiator, &NodeIdentity::generate());
        let mut client_nid = [0u8; 16];
        client_nid.copy_from_slice(&hex::decode(&hello_c.node_id).unwrap());
        write_frame(
            &mut sock,
            &encode_net_frame(&NetMsg::Hello { hello: hello_c }).unwrap(),
        );
        let wire = read_frame(&mut sock).unwrap();
        let hello_r = match decode_net_frame(&wire).unwrap() {
            NetMsg::Hello { hello } => hello,
            other => panic!("want hello, got {other:?}"),
        };
        c.on_peer_hello(&hello_r).unwrap();
        let wire = read_frame(&mut sock).unwrap();
        let auth_r = match decode_net_frame(&wire).unwrap() {
            NetMsg::Auth { auth } => auth,
            other => panic!("want auth, got {other:?}"),
        };
        let mut cache = ReplayCache::new(REPLAY_CACHE_CAP);
        let seen_r = c.verify_auth(&auth_r, &mut cache).unwrap().node_id;
        let mut declared_r = [0u8; 16];
        declared_r.copy_from_slice(&hex::decode(&hello_r.node_id).unwrap());
        // the client verified exactly the responder that said hello
        assert_eq!(seen_r, declared_r);
        let auth_c = c.produce_auth().unwrap();
        write_frame(
            &mut sock,
            &encode_net_frame(&NetMsg::Auth { auth: auth_c }).unwrap(),
        );

        // the server verified exactly the initiator that said hello
        let verified = server.join().unwrap();
        assert_eq!(verified, client_nid);
    }

    #[test]
    fn tampered_dleq_proof_rejected() {
        let (c, r) = pair();
        let mut cache = ReplayCache::new(REPLAY_CACHE_CAP);
        let mut auth = r.produce_auth().unwrap();
        let mut bytes = hex::decode(&auth.dleq_proof).unwrap();
        bytes[40] ^= 0x01;
        auth.dleq_proof = hex::encode(bytes);
        let err = c.verify_auth(&auth, &mut cache).unwrap_err();
        assert_eq!(err, HandshakeError::BadProof);
    }

    #[test]
    fn forged_transcript_rejected() {
        // session-1 hello (fixed nonce) + session-2 auth: tags differ
        let ci1 = NodeIdentity::generate();
        let ci2 = NodeIdentity::generate();
        let ri = NodeIdentity::generate();
        let (mut r, hello_r) = HandshakeSide::start(Role::Responder, &ri);
        let (mut c2, _hello_c2) = HandshakeSide::start(Role::Initiator, &ci2);
        let hello_c1 = Hello::build(&ci1, &[0x11u8; 32]);
        r.on_peer_hello(&hello_c1).unwrap();
        c2.on_peer_hello(&hello_r).unwrap();
        let auth2 = c2.produce_auth().unwrap();
        let mut cache = ReplayCache::new(REPLAY_CACHE_CAP);
        let err = r.verify_auth(&auth2, &mut cache).unwrap_err();
        assert_eq!(err, HandshakeError::TagMismatch);
    }

    #[test]
    fn auth_by_wrong_key_rejected() {
        // attacker signs the transcript but claims the victim's keys
        let victim = NodeIdentity::generate();
        let attacker = NodeIdentity::generate();
        let nonce_c = [5u8; 32];
        let nonce_s = [6u8; 32];
        let t = transcript_of(
            &nonce_c,
            &nonce_s,
            &attacker.pr,
            &victim.pr,
            &attacker.pe,
            &victim.pe,
        );
        let auth = AuthMsg::produce(&attacker, &t);
        let err = auth.verify_against(&victim.pe, &victim.pr, &t).unwrap_err();
        assert_eq!(err, HandshakeError::BadProof);
    }

    #[test]
    fn hello_node_id_mismatch_rejected() {
        let id = NodeIdentity::generate();
        let mut hello = Hello::build(&id, &[3u8; 32]);
        let mut nid = hex::decode(&hello.node_id).unwrap();
        nid[0] ^= 0x01;
        hello.node_id = hex::encode(nid);
        let err = hello.keys().err().unwrap();
        assert_eq!(err, HandshakeError::BadNodeId);
    }

    #[test]
    fn replayed_auth_rejected() {
        let (c, r) = pair();
        let auth_c = c.produce_auth().unwrap();
        let mut cache = ReplayCache::new(REPLAY_CACHE_CAP);
        r.verify_auth(&auth_c, &mut cache).unwrap();
        let err = r.verify_auth(&auth_c, &mut cache).unwrap_err();
        assert_eq!(err, HandshakeError::Replay);
    }

    #[test]
    fn wrong_version_rejected() {
        let (mut r, _) = HandshakeSide::start(Role::Responder, &NodeIdentity::generate());
        let id = NodeIdentity::generate();
        let mut hello = Hello::build(&id, &[4u8; 32]);
        hello.version = HANDSHAKE_VERSION + 1;
        assert_eq!(
            r.on_peer_hello(&hello).unwrap_err(),
            HandshakeError::BadVersion(HANDSHAKE_VERSION + 1)
        );
    }

    #[test]
    fn replay_cache_cap_evicts_oldest() {
        let mut cache = ReplayCache::new(4);
        for i in 0..8u8 {
            let mut tag = [0u8; 32];
            tag[0] = i;
            cache.check_and_insert(&tag).unwrap();
        }
        assert_eq!(cache.len(), 4);
        // oldest tags evicted
        let mut old = [0u8; 32];
        old[0] = 1;
        cache.check_and_insert(&old).unwrap();
        // newest still rejected
        let mut fresh = [0u8; 32];
        fresh[0] = 7;
        let err = cache.check_and_insert(&fresh).unwrap_err();
        assert_eq!(err, HandshakeError::Replay);
    }

    #[test]
    fn hundred_handshakes_no_state_leak() {
        let mut cache_c = ReplayCache::new(REPLAY_CACHE_CAP);
        let mut cache_r = ReplayCache::new(REPLAY_CACHE_CAP);
        for _ in 0..100 {
            let ci = NodeIdentity::generate();
            let ri = NodeIdentity::generate();
            let (mut c, hello_c) = HandshakeSide::start(Role::Initiator, &ci);
            let (mut r, hello_r) = HandshakeSide::start(Role::Responder, &ri);
            c.on_peer_hello(&hello_r).unwrap();
            r.on_peer_hello(&hello_c).unwrap();
            let auth_r = r.produce_auth().unwrap();
            c.verify_auth(&auth_r, &mut cache_c).unwrap();
            let auth_c = c.produce_auth().unwrap();
            r.verify_auth(&auth_c, &mut cache_r).unwrap();
            assert!(cache_c.len() <= REPLAY_CACHE_CAP);
            assert!(cache_r.len() <= REPLAY_CACHE_CAP);
        }
        assert_eq!(cache_c.len(), 100);
        assert_eq!(cache_r.len(), 100);
    }

    // ---- Net-1: post-auth transport keys -----------------------------

    #[test]
    fn transport_keys_cross_open() {
        let (c, r) = pair();
        let mut cache_c = ReplayCache::new(REPLAY_CACHE_CAP);
        let mut cache_r = ReplayCache::new(REPLAY_CACHE_CAP);
        let auth_r = r.produce_auth().unwrap();
        let vp_at_c = c.verify_auth(&auth_r, &mut cache_c).unwrap();
        let auth_c = c.produce_auth().unwrap();
        let vp_at_r = r.verify_auth(&auth_c, &mut cache_r).unwrap();

        let kc = c.session_keys(&vp_at_c).unwrap();
        let kr = r.session_keys(&vp_at_r).unwrap();

        // initiator -> responder at the same counter round-trips
        let pt = b"disco batch over the encrypted transport";
        let body = kc.seal(0, pt);
        assert_eq!(kr.open(0, &body).unwrap(), pt);
        // responder -> initiator likewise, at a different counter
        let body = kr.seal(7, pt);
        assert_eq!(kc.open(7, &body).unwrap(), pt);
        // directions are separated: the same (seq, plaintext) seals
        // differently per direction
        assert_ne!(kc.seal(0, pt), kr.seal(0, pt));
    }

    #[test]
    fn sealed_frame_binds_seq_and_content() {
        let (c, r) = pair();
        let mut cache_c = ReplayCache::new(REPLAY_CACHE_CAP);
        let mut cache_r = ReplayCache::new(REPLAY_CACHE_CAP);
        let auth_r = r.produce_auth().unwrap();
        let vp_at_c = c.verify_auth(&auth_r, &mut cache_c).unwrap();
        let auth_c = c.produce_auth().unwrap();
        let vp_at_r = r.verify_auth(&auth_c, &mut cache_r).unwrap();
        let kc = c.session_keys(&vp_at_c).unwrap();
        let kr = r.session_keys(&vp_at_r).unwrap();

        let pt: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        // multi-block round-trip
        let body = kc.seal(0, &pt);
        assert_eq!(kr.open(0, &body).unwrap(), pt);

        // the same plaintext under different counters seals differently
        let body1 = kc.seal(1, &pt);
        assert_ne!(body, body1);

        // a flipped ciphertext bit breaks the MAC (checked before any
        // decryption)
        let mut tampered = body.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let err = kr.open(0, &tampered).unwrap_err();
        assert!(matches!(err, HandshakeError::BadTransport(_)));

        // a flipped MAC bit is rejected as well
        let mut tampered_mac = body.clone();
        tampered_mac[0] ^= 0x01;
        assert!(matches!(
            kr.open(0, &tampered_mac).unwrap_err(),
            HandshakeError::BadTransport(_)
        ));

        // the counter is bound: opening at the wrong seq fails
        assert!(matches!(
            kr.open(1, &body).unwrap_err(),
            HandshakeError::BadTransport(_)
        ));

        // a body shorter than the MAC is rejected structurally
        assert!(matches!(
            kr.open(0, &[0u8; 8]).unwrap_err(),
            HandshakeError::BadTransport(_)
        ));
    }

    #[test]
    fn transport_keys_reject_invalid_peer_point() {
        // the Hello node_id check does not prove point validity; the
        // key derivation must fail cleanly on a non-ristretto peer key
        let id = NodeIdentity::generate();
        let vp = VerifiedPeer {
            node_id: [9u8; 16],
            pe: id.pe,
            pr: CompressedRistretto([0xffu8; 32]),
        };
        let err = match SessionKeys::derive(Role::Initiator, &id, &vp, &[0u8; 64]) {
            Err(e) => e,
            Ok(_) => panic!("a non-ristretto peer key must fail the derivation"),
        };
        assert_eq!(err, HandshakeError::BadProof);
    }
}
