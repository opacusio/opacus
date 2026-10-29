//! P2P message layer for XMR <-> GHOST atomic swaps (v0.1).
//!
//! Transport-agnostic coordination protocol on top of [`crate::xmr_swap`]:
//! peers exchange JSON frames over any byte pipe (the `u32`-LE length prefix
//! makes it stream-safe for TCP / libp2p / opacusd's transport later).
//!
//! Message flow (Maker sells GHOST, Taker sells XMR):
//!
//! ```text
//!  Maker                              Taker
//!  -----                              -----
//!  publish_offer  ->  Offer        ->
//!                                    (session Accepted, auto-reply)
//!                 <-  Accept       <-  receive(Offer)
//!  receive(Accept)                    publish_xmr_lock -> XmrLocked ->
//!  receive(XmrLocked)                 (XMR locked via wallet-rpc)
//!  publish_ghost_lock -> GhostLocked (carries the preimage!)
//!                 ->  GhostLocked  ->
//!                                    receive(GhostLocked) -> auto Claim
//!                 <-  Claim        <-
//!  receive(Claim): peer_claimed       claim GHOST on-chain with preimage
//!  -> claim XMR with revealed P
//! ```
//!
//! v0.1 limitations: Refund frames are notices; deadline enforcement is a
//! node-level sweep ([`SwapNet::expired_sessions`] feeding
//! [`SwapNode::enforce_deadlines`], WG-18) that auto-refunds expired
//! sessions on every height feed; offer ids bind the exact payload
//! bytes (blake3 over canonical JSON) so tampering is rejected.
//!
//! WG-22: the taker consumes the offer sidecar end-to-end - the
//! GhostLocked preimage must re-derive the announced one-time keys
//! (fail-closed in [`SwapNet::handle_message_with_otk`]) or the lock is
//! rejected before the session state moves.

use std::collections::HashMap;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::clsag::{one_time_keys, OneTimeKeys};
use crate::xmr_swap::{hashlock_of, Offer, Phase, Role, SwapError, SwapSession};

/// Wire protocol identifier; frames with a different tag are rejected.
pub const PROTOCOL: &str = "ghost-swap-p2p-v1";
const OFFER_ID_TAG: &[u8] = b"ghost-swap-offer-id-v1";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The offer fields exactly as hashed into the offer id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// WG-21: the payload fields are unchanged from v1 and still hash into
/// the offer id exactly as before; the one-time key binding travels as
/// an OPTIONAL Frame-level sidecar ([`OfferAdaptor`]) and is never
/// hashed into the id.
pub struct SwapOfferPayload {
    /// XMR amount in piconero (1e12).
    pub xmr_piconero: u64,
    /// GHOST amount in atoms.
    pub ghost_atoms: u64,
    /// blake3 hashlock, hex (64 chars).
    pub hashlock: String,
    pub fund_timeout_blocks: u64,
    pub claim_timeout_blocks: u64,
    pub maker_ghost_address: String,
    pub taker_xmr_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwapNetMessage {
    /// Maker -> network: a new swap offer.
    Offer {
        offer_id: String,
        #[serde(flatten)]
        payload: SwapOfferPayload,
    },
    /// Taker -> maker: offer accepted.
    Accept { offer_id: String },
    /// Taker -> maker: XMR locked on-chain (payment_id = hashlock).
    XmrLocked {
        offer_id: String,
        xmr_tx_hash: String,
        height: u64,
    },
    /// Maker -> taker: GHOST locked into the bridge pool AND the preimage
    /// revealed (safe: the taker is already committed by his XMR lock).
    GhostLocked {
        offer_id: String,
        ghost_tx_ref: String,
        height: u64,
        preimage: String,
    },
    /// Taker -> maker: claiming GHOST with the preimage (the revealed
    /// preimage is what lets the maker claim the XMR).
    Claim { offer_id: String, preimage: String },
    /// Either side: local refund executed (notice only in v0.1).
    Refund { offer_id: String, reason: String },
}

/// Envelope with a protocol tag; the unit that travels over the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// WG-21: optional offer-side one-time key binding. Present only on
    /// Offer frames from WG-21 makers; `serde(default)` keeps v1 frames
    /// decodable and `skip_serializing_if` keeps v1 bytes stable. NOT
    /// hashed into the offer id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptor: Option<OfferAdaptor>,
    pub protocol: String,
    #[serde(flatten)]
    pub msg: SwapNetMessage,
}

impl Frame {
    pub fn new(msg: SwapNetMessage) -> Self {
        Frame {
            adaptor: None,
            protocol: PROTOCOL.to_string(),
            msg,
        }
    }
}

// ---------------------------------------------------------------------------
// Byte framing: u32-LE length prefix + JSON body
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than 4 bytes of prefix.
    Truncated,
    /// Declared body length does not match the buffer.
    BadLength {
        declared: usize,
        available: usize,
    },
    Json(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Truncated => write!(f, "frame truncated (no length prefix)"),
            FrameError::BadLength {
                declared,
                available,
            } => {
                write!(
                    f,
                    "bad frame length: declared {declared}, available {available}"
                )
            }
            FrameError::Json(m) => write!(f, "frame json: {m}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode one frame: 4-byte little-endian body length + JSON body.
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(frame).map_err(|e| FrameError::Json(e.to_string()))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode exactly one frame from a complete buffer (trailing bytes = error).
pub fn decode_frame(buf: &[u8]) -> Result<Frame, FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Truncated);
    }
    let declared = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() - 4 != declared {
        return Err(FrameError::BadLength {
            declared,
            available: buf.len() - 4,
        });
    }
    serde_json::from_slice(&buf[4..]).map_err(|e| FrameError::Json(e.to_string()))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum SwapNetError {
    /// State machine violation delegated from [`SwapSession`].
    State(SwapError),
    /// Frame's protocol tag is not [`PROTOCOL`].
    ProtocolMismatch(String),
    /// No session for the referenced offer id.
    UnknownOffer,
    /// An offer with this id is already tracked.
    DuplicateOffer,
    /// Recomputed offer id does not match the announced one (tampering).
    OfferIdMismatch,
    BadHex(String),
    MalformedOffer(&'static str),
    /// Maker tried to publish the ghost lock without a stored preimage.
    MissingPreimage,

    /// WG-22: the taker's re-derivation of the offer-side one-time keys
    /// from the revealed preimage does not match the sidecar announced at
    /// offer time (fail-closed GhostLocked rejection).
    OneTimeKeyMismatch,
    Frame(String),
}

impl std::fmt::Display for SwapNetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapNetError::State(e) => write!(f, "swap state: {e:?}"),
            SwapNetError::ProtocolMismatch(p) => write!(f, "protocol mismatch: {p}"),
            SwapNetError::UnknownOffer => write!(f, "unknown offer id"),
            SwapNetError::DuplicateOffer => write!(f, "offer already tracked"),
            SwapNetError::OfferIdMismatch => write!(f, "offer id does not match payload"),
            SwapNetError::BadHex(m) => write!(f, "bad hex: {m}"),
            SwapNetError::MalformedOffer(m) => write!(f, "malformed offer: {m}"),
            SwapNetError::MissingPreimage => write!(f, "no preimage stored for this session"),

            SwapNetError::OneTimeKeyMismatch => {
                write!(f, "offer one-time key does not match the revealed preimage")
            }
            SwapNetError::Frame(m) => write!(f, "frame: {m}"),
        }
    }
}

impl std::error::Error for SwapNetError {}

impl From<SwapError> for SwapNetError {
    fn from(e: SwapError) -> Self {
        SwapNetError::State(e)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], SwapNetError> {
    let v = hex::decode(s).map_err(|e| SwapNetError::BadHex(e.to_string()))?;
    if v.len() != 32 {
        return Err(SwapNetError::BadHex("expected 32 bytes".to_string()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// WG-21: deterministic one-time spend key for the maker's GHOST lock,
/// derived from the swap preimage (domain-separated from the hashlock):
/// the taker re-derives the same key from the revealed preimage at
/// claim time; WG-22 enforces that re-derivation fail-closed at the
/// taker's GhostLocked step (see [`SwapNet::handle_message_with_otk`]).
fn otk_seed(preimage: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"ghost-bridge/offer-otk-v1");
    h.update(preimage);
    h.finalize().into()
}

/// Deterministic offer id: blake3(tag || canonical JSON of the payload).
/// serde_json serializes struct fields in declaration order, so equal
/// payloads always hash to the same id.
pub fn offer_id_of(payload: &SwapOfferPayload) -> [u8; 32] {
    // Serialization of a plain data struct cannot fail.
    let bytes = serde_json::to_vec(payload).expect("SwapOfferPayload serializes");
    let mut h = Hasher::new();
    h.update(OFFER_ID_TAG);
    h.update(&bytes);
    h.finalize().into()
}

/// WG-21: offer-side CLSAG one-time key binding, hex-encoded (64 chars).
/// It travels as an OPTIONAL Frame-level sidecar on Offer frames: the
/// maker's GHOST lock will use the one-time address `P = [x] * B` with
/// key image `I = [x] * H(P)`, so the taker can bind the future lock
/// before locking XMR. Deliberately NOT hashed into the offer id (v1
/// ids stay byte-stable); tampering is caught by the fail-closed
/// structural validation in [`SwapNet::receive_frame`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferAdaptor {
    /// One-time public key `P`, hex.
    pub p: String,
    /// Key image `I`, hex.
    pub image: String,
}

impl OfferAdaptor {
    /// Build the sidecar from derived one-time keys.
    pub fn from_keys(k: &OneTimeKeys) -> Self {
        OfferAdaptor {
            p: hex32(&k.p),
            image: hex32(&k.image),
        }
    }

    /// Structural validation (fail-closed): both fields must be canonical
    /// 32-byte hex; `P` must decompress to a non-degenerate point; `I`
    /// must decompress and differ from the identity and from `P`. The
    /// cryptographic key-image equation is checked at lock/claim time
    /// (WG-20 legs).
    pub fn validate(&self) -> Result<OneTimeKeys, SwapNetError> {
        let p = parse_hex32(&self.p)?;
        let image = parse_hex32(&self.image)?;
        if !crate::clsag::validate_one_time_binding(&p, &image) {
            return Err(SwapNetError::MalformedOffer("bad one-time key binding"));
        }
        Ok(OneTimeKeys { p, image })
    }
}

/// WG-21: unchanged - the payload still hashes into the offer id exactly
/// as in v1; the one-time key binding travels as a Frame sidecar and is
/// deliberately NOT part of the id (offer ids stay byte-stable).
fn payload_from_offer(offer: &Offer) -> SwapOfferPayload {
    SwapOfferPayload {
        xmr_piconero: offer.xmr_piconero,
        ghost_atoms: offer.ghost_atoms,
        hashlock: hex32(&offer.hashlock),
        fund_timeout_blocks: offer.fund_timeout_blocks,
        claim_timeout_blocks: offer.claim_timeout_blocks,
        maker_ghost_address: offer.maker_ghost_address.clone(),
        taker_xmr_address: offer.taker_xmr_address.clone(),
    }
}

/// WG-21: the wire payload carries no one-time key fields; the binding
/// arrives as the Frame sidecar and is validated fail-closed in
/// [`SwapNet::receive_frame`] before the state machine sees the offer.
fn offer_from_payload(p: &SwapOfferPayload) -> Result<Offer, SwapNetError> {
    if p.xmr_piconero == 0 || p.ghost_atoms == 0 {
        return Err(SwapNetError::MalformedOffer("zero amount"));
    }
    if p.fund_timeout_blocks == 0 || p.claim_timeout_blocks == 0 {
        return Err(SwapNetError::MalformedOffer("non-positive timeout"));
    }
    if p.fund_timeout_blocks > p.claim_timeout_blocks {
        return Err(SwapNetError::MalformedOffer(
            "fund timeout exceeds claim timeout",
        ));
    }
    if p.maker_ghost_address.is_empty() || p.taker_xmr_address.is_empty() {
        return Err(SwapNetError::MalformedOffer("empty address"));
    }
    Ok(Offer {
        xmr_piconero: p.xmr_piconero,
        ghost_atoms: p.ghost_atoms,
        hashlock: parse_hex32(&p.hashlock)?,
        fund_timeout_blocks: p.fund_timeout_blocks,
        claim_timeout_blocks: p.claim_timeout_blocks,
        maker_ghost_address: p.maker_ghost_address.clone(),
        taker_xmr_address: p.taker_xmr_address.clone(),
    })
}

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

/// One tracked swap: the [`SwapSession`] state machine plus P2P bookkeeping.
#[derive(Clone, Debug)]
pub struct TrackedSession {
    /// WG-21: the one-time key binding announced by the maker's offer
    /// sidecar (None for pre-WG-21 offers).
    pub offer_otk: Option<OneTimeKeys>,
    pub session: SwapSession,
    pub offer_id: [u8; 32],
    /// Peer confirmed acceptance (Accept frame received on maker side).
    pub accepted_by_peer: bool,
    /// Peer announced a refund (Refund frame; verify on-chain in v0.2).
    pub peer_refunded: bool,
    /// Maker: peer's Claim frame accepted (preimage verified).
    pub peer_claimed: bool,
    pub claimed_preimage: Option<[u8; 32]>,
    pub xmr_tx_hash: Option<String>,
    pub ghost_tx_ref: Option<String>,
}

/// One deadline-expired swap reported by [`SwapNet::expired_sessions`]
/// (WG-18). The reason is forwarded verbatim into the Refund notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiredSwap {
    pub offer_id: [u8; 32],
    pub reason: &'static str,
}

/// All swap sessions of this node, keyed by offer id.
#[derive(Default)]
pub struct SwapNet {
    sessions: HashMap<[u8; 32], TrackedSession>,
}

impl SwapNet {
    pub fn new() -> Self {
        SwapNet {
            sessions: HashMap::new(),
        }
    }

    pub fn session(&self, offer_id_hex: &str) -> Option<&TrackedSession> {
        let id = parse_hex32(offer_id_hex).ok()?;
        self.sessions.get(&id)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    // -- WG-18: deadline enforcement ----------------------------------------

    /// Sessions whose protocol deadline is reached at chain height `now`
    /// (WG-18). Exactly the two refund-eligible states of
    /// [`SwapSession::refund`]:
    ///
    /// * taker, still `Accepted` past the fund window;
    /// * maker, still `GhostLocked` at or past the claim window.
    ///
    /// Each reported session refunds successfully through
    /// [`SwapSession::refund`], so a sweep that calls `publish_refund`
    /// per entry cannot double-report: a refunded session leaves the
    /// eligible phase and later sweeps skip it. Timeouts arrive from
    /// peer payloads, so the deadlines are computed with saturating
    /// arithmetic (a malicious `u64` timeout must not panic the node).
    pub fn expired_sessions(&self, now: u64) -> Vec<ExpiredSwap> {
        let mut out = Vec::new();
        for (id, t) in self.sessions.iter() {
            let s = &t.session;
            match (s.phase, s.role) {
                (Phase::Accepted, Role::Taker) => {
                    let deadline = s
                        .accepted_height
                        .saturating_add(s.offer.fund_timeout_blocks);
                    if now > deadline {
                        out.push(ExpiredSwap {
                            offer_id: *id,
                            reason: "fund window expired",
                        });
                    }
                }
                (Phase::GhostLocked, Role::Maker) => {
                    let deadline = s
                        .both_locked_height
                        .unwrap_or(0)
                        .saturating_add(s.offer.claim_timeout_blocks);
                    if now >= deadline {
                        out.push(ExpiredSwap {
                            offer_id: *id,
                            reason: "claim window expired",
                        });
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn tracked_mut(&mut self, offer_id_hex: &str) -> Result<&mut TrackedSession, SwapNetError> {
        let id = parse_hex32(offer_id_hex)?;
        self.sessions.get_mut(&id).ok_or(SwapNetError::UnknownOffer)
    }

    // -- maker actions ------------------------------------------------------

    /// Maker: register a new offer (preimage is kept locally) and get the
    /// encoded Offer frame to broadcast.
    /// WG-21: the returned Offer frame embeds the one-time key binding
    /// derived from `preimage` (sidecar); the id and payload stay v1.
    pub fn publish_offer(
        &mut self,
        offer: Offer,
        preimage: [u8; 32],
    ) -> Result<(String, Vec<u8>), SwapNetError> {
        if hashlock_of(&preimage) != offer.hashlock {
            return Err(SwapNetError::State(SwapError::BadPreimage));
        }
        // WG-21: derive the one-time keys from the preimage and embed
        // them as the Frame sidecar (validated fail-closed by the taker).
        let otk = one_time_keys(&otk_seed(&preimage));
        let payload = payload_from_offer(&offer);
        let offer_id = offer_id_of(&payload);
        let mut session = SwapSession::make_offer(offer, 0);
        session.set_preimage(preimage)?;
        self.sessions.insert(
            offer_id,
            TrackedSession {
                session,
                offer_otk: Some(otk.clone()),
                offer_id,
                accepted_by_peer: false,
                peer_refunded: false,
                peer_claimed: false,
                claimed_preimage: None,
                xmr_tx_hash: None,
                ghost_tx_ref: None,
            },
        );
        let mut frame = Frame::new(SwapNetMessage::Offer {
            offer_id: hex32(&offer_id),
            payload,
        });
        frame.adaptor = Some(OfferAdaptor::from_keys(&otk));
        Ok((
            hex32(&offer_id),
            encode_frame(&frame).map_err(|e| SwapNetError::Frame(e.to_string()))?,
        ))
    }

    /// Maker: the GHOST lock is on-chain; announce it and reveal the
    /// preimage (the taker needs it to claim).
    pub fn publish_ghost_lock(
        &mut self,
        offer_id_hex: &str,
        ghost_tx_ref: &str,
        height: u64,
    ) -> Result<Vec<u8>, SwapNetError> {
        let id = parse_hex32(offer_id_hex)?;
        let t = self
            .sessions
            .get_mut(&id)
            .ok_or(SwapNetError::UnknownOffer)?;
        t.session.mark_ghost_locked(height)?;
        t.ghost_tx_ref = Some(ghost_tx_ref.to_string());
        let preimage = t.session.preimage.ok_or(SwapNetError::MissingPreimage)?;
        let frame = Frame::new(SwapNetMessage::GhostLocked {
            offer_id: offer_id_hex.to_string(),
            ghost_tx_ref: ghost_tx_ref.to_string(),
            height,
            preimage: hex32(&preimage),
        });
        encode_frame(&frame).map_err(|e| SwapNetError::Frame(e.to_string()))
    }

    // -- taker actions ------------------------------------------------------

    /// Taker: XMR lock tx is broadcast; announce it to the maker.
    pub fn publish_xmr_lock(
        &mut self,
        offer_id_hex: &str,
        xmr_tx_hash: &str,
        height: u64,
    ) -> Result<Vec<u8>, SwapNetError> {
        let id = parse_hex32(offer_id_hex)?;
        let t = self
            .sessions
            .get_mut(&id)
            .ok_or(SwapNetError::UnknownOffer)?;
        t.session.lock_xmr(height)?;
        t.xmr_tx_hash = Some(xmr_tx_hash.to_string());
        let frame = Frame::new(SwapNetMessage::XmrLocked {
            offer_id: offer_id_hex.to_string(),
            xmr_tx_hash: xmr_tx_hash.to_string(),
            height,
        });
        encode_frame(&frame).map_err(|e| SwapNetError::Frame(e.to_string()))
    }

    // -- both sides ---------------------------------------------------------

    /// Local refund executed; produce the notice frame.
    pub fn publish_refund(
        &mut self,
        offer_id_hex: &str,
        reason: &str,
        height: u64,
    ) -> Result<Vec<u8>, SwapNetError> {
        let id = parse_hex32(offer_id_hex)?;
        let t = self
            .sessions
            .get_mut(&id)
            .ok_or(SwapNetError::UnknownOffer)?;
        t.session.refund(height)?;
        let frame = Frame::new(SwapNetMessage::Refund {
            offer_id: offer_id_hex.to_string(),
            reason: reason.to_string(),
        });
        encode_frame(&frame).map_err(|e| SwapNetError::Frame(e.to_string()))
    }

    /// Decode a wire frame, apply it to the tracked session and return the
    /// encoded reply frames (possibly none).
    pub fn receive_frame(
        &mut self,
        wire: &[u8],
        current_height: u64,
    ) -> Result<Vec<Vec<u8>>, SwapNetError> {
        let frame = decode_frame(wire).map_err(|e| SwapNetError::Frame(e.to_string()))?;
        if frame.protocol != PROTOCOL {
            return Err(SwapNetError::ProtocolMismatch(frame.protocol));
        }
        // WG-21: validate the optional offer sidecar fail-closed before
        // the message reaches the state machine.
        let otk = match frame.adaptor.as_ref() {
            Some(a) => Some(a.validate()?),
            None => None,
        };
        let replies = self.handle_message_with_otk(frame.msg, otk.as_ref(), current_height)?;
        replies
            .iter()
            .map(|m| {
                encode_frame(&Frame::new(m.clone())).map_err(|e| SwapNetError::Frame(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// Core protocol transition. `current_height` is used for the taker's
    /// acceptance timestamp on new Offers; lock notifications carry their
    /// own heights.
    /// WG-21 compatibility shim: process a message with no sidecar OTK.
    /// Signature UNCHANGED from v1 (net_node-reachable surface).
    pub fn handle_message(
        &mut self,
        msg: SwapNetMessage,
        current_height: u64,
    ) -> Result<Vec<SwapNetMessage>, SwapNetError> {
        self.handle_message_with_otk(msg, None, current_height)
    }

    /// WG-21: as [`Self::handle_message`], with the offer-side one-time
    /// key binding decoded from the Frame sidecar (already validated by
    /// [`Self::receive_frame`]).
    pub fn handle_message_with_otk(
        &mut self,
        msg: SwapNetMessage,
        otk: Option<&OneTimeKeys>,
        current_height: u64,
    ) -> Result<Vec<SwapNetMessage>, SwapNetError> {
        match msg {
            SwapNetMessage::Offer { offer_id, payload } => {
                let id = parse_hex32(&offer_id)?;
                let offer = offer_from_payload(&payload)?;
                // WG-21: thread the validated sidecar (if any) into the
                // session record below.
                let wire_otk = otk.cloned();
                if offer_id_of(&payload) != id {
                    return Err(SwapNetError::OfferIdMismatch);
                }
                if self.sessions.contains_key(&id) {
                    return Err(SwapNetError::DuplicateOffer);
                }
                let session = SwapSession::accept(offer, current_height);
                self.sessions.insert(
                    id,
                    TrackedSession {
                        session,
                        offer_otk: wire_otk,
                        offer_id: id,
                        accepted_by_peer: false,
                        peer_refunded: false,
                        peer_claimed: false,
                        claimed_preimage: None,
                        xmr_tx_hash: None,
                        ghost_tx_ref: None,
                    },
                );
                Ok(vec![SwapNetMessage::Accept { offer_id }])
            }
            SwapNetMessage::Accept { offer_id } => {
                let t = self.tracked_mut(&offer_id)?;
                if t.session.role != Role::Maker {
                    return Err(SwapNetError::State(SwapError::WrongRole));
                }
                t.accepted_by_peer = true;
                Ok(vec![])
            }
            SwapNetMessage::XmrLocked {
                offer_id,
                xmr_tx_hash,
                height,
            } => {
                let t = self.tracked_mut(&offer_id)?;
                if t.session.role != Role::Maker {
                    return Err(SwapNetError::State(SwapError::WrongRole));
                }
                // Implicitly accepts an Offered maker session; checks the
                // fund deadline and moves to XmrLocked.
                t.session.mark_xmr_locked(height)?;
                t.xmr_tx_hash = Some(xmr_tx_hash);
                Ok(vec![])
            }
            SwapNetMessage::GhostLocked {
                offer_id,
                ghost_tx_ref,
                height,
                preimage,
            } => {
                let pre = parse_hex32(&preimage)?;
                let t = self.tracked_mut(&offer_id)?;
                if t.session.role != Role::Taker {
                    return Err(SwapNetError::State(SwapError::WrongRole));
                }
                if hashlock_of(&pre) != t.session.offer.hashlock {
                    return Err(SwapNetError::State(SwapError::BadPreimage));
                }
                // WG-22: the taker closes the WG-21 loop - the revealed
                // preimage must re-derive the one-time keys announced in
                // the offer sidecar. A maker whose announcement is not his
                // own deterministic derivation is rejected fail-closed
                // BEFORE any state transition, so no Claim auto-reply is
                // produced for a mismatched lock.
                if let Some(otk) = t.offer_otk.as_ref() {
                    let expected = one_time_keys(&otk_seed(&pre));
                    if *otk != expected {
                        return Err(SwapNetError::OneTimeKeyMismatch);
                    }
                }
                t.session.mark_ghost_locked(height)?;
                t.ghost_tx_ref = Some(ghost_tx_ref);
                Ok(vec![SwapNetMessage::Claim { offer_id, preimage }])
            }
            SwapNetMessage::Claim { offer_id, preimage } => {
                let pre = parse_hex32(&preimage)?;
                let t = self.tracked_mut(&offer_id)?;
                if t.session.role != Role::Maker {
                    return Err(SwapNetError::State(SwapError::WrongRole));
                }
                if t.session.phase != Phase::GhostLocked {
                    return Err(SwapNetError::State(SwapError::WrongPhase));
                }
                if hashlock_of(&pre) != t.session.offer.hashlock {
                    return Err(SwapNetError::State(SwapError::BadPreimage));
                }
                t.peer_claimed = true;
                t.claimed_preimage = Some(pre);
                Ok(vec![])
            }
            SwapNetMessage::Refund { offer_id, .. } => {
                let t = self.tracked_mut(&offer_id)?;
                t.peer_refunded = true;
                Ok(vec![])
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- WG-21: offer-side one-time key binding ------------------------------

    #[test]
    fn offer_wire_embeds_one_time_key_sidecar() {
        let mut maker = SwapNet::new();
        let (id_hex, wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let frame = decode_frame(&wire).unwrap();
        let otk = frame.adaptor.expect("WG-21 sidecar present");
        let want = one_time_keys(&otk_seed(&PREIMAGE));
        assert_eq!(otk.p, hex32(&want.p));
        assert_eq!(otk.image, hex32(&want.image));
        otk.validate().unwrap();
        // the sidecar must not shift the offer id (v1 ids stay stable)
        assert_eq!(id_hex, hex32(&offer_id_of(&payload())));
    }

    #[test]
    fn offer_sidecar_is_validated_fail_closed() {
        let mut maker = SwapNet::new();
        let (_, wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let mut frame = decode_frame(&wire).unwrap();
        let mut bad = frame.adaptor.clone().unwrap();
        bad.p = "zz".to_string(); // not hex
        frame.adaptor = Some(bad);
        let wire = encode_frame(&frame).unwrap();
        let mut taker = SwapNet::new();
        assert!(taker.receive_frame(&wire, 100).is_err());
    }

    #[test]
    fn pre_wg21_frames_without_sidecar_still_accepted() {
        // A v1 maker publishes no sidecar; the WG-21 taker must still
        // track the offer (offer_otk stays None).
        let mut maker = SwapNet::new();
        let (_, wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let mut frame = decode_frame(&wire).unwrap();
        frame.adaptor = None;
        let wire = encode_frame(&frame).unwrap();
        let mut taker = SwapNet::new();
        let replies = taker.receive_frame(&wire, 100).unwrap();
        assert_eq!(replies.len(), 1);
        let reply = decode_frame(&replies[0]).unwrap();
        assert!(matches!(reply.msg, SwapNetMessage::Accept { .. }));
        let t = taker.session(&hex32(&offer_id_of(&payload()))).unwrap();
        assert!(t.offer_otk.is_none());
    }

    #[test]
    fn offer_sidecar_is_stored_on_accept() {
        let mut maker = SwapNet::new();
        let (_, wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let mut taker = SwapNet::new();
        taker.receive_frame(&wire, 100).unwrap();
        let t = taker.session(&hex32(&offer_id_of(&payload()))).unwrap();
        let otk = t.offer_otk.as_ref().expect("sidecar stored");
        assert_eq!(otk.p, one_time_keys(&otk_seed(&PREIMAGE)).p);
    }

    // -- WG-22: taker-side sidecar consumption -------------------------------

    /// WG-22: the honest path still closes - the taker re-derives the
    /// sidecar one-time keys from the revealed preimage and auto-claims.
    #[test]
    fn ghost_lock_sidecar_binding_holds_on_honest_path() {
        let mut maker = SwapNet::new();
        let (id_hex, offer_wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let mut taker = SwapNet::new();
        taker.receive_frame(&offer_wire, 100).unwrap();
        let lock_wire = taker.publish_xmr_lock(&id_hex, "xmr-tx-wg22", 110).unwrap();
        // the maker must observe the taker's lock first: mark_ghost_locked
        // requires Phase::XmrLocked on the maker's side as well
        maker.receive_frame(&lock_wire, 0).unwrap();
        let ghost_wire = maker
            .publish_ghost_lock(&id_hex, "ghost-burn-wg22", 120)
            .unwrap();
        let replies = taker.receive_frame(&ghost_wire, 0).unwrap();
        assert_eq!(replies.len(), 1);
        assert!(matches!(
            decode_frame(&replies[0]).unwrap().msg,
            SwapNetMessage::Claim { .. }
        ));
    }

    /// WG-22: a valid-but-mismatched sidecar (a maker announcing one-time
    /// keys his own preimage derivation does not produce) is rejected
    /// fail-closed at the taker's GhostLocked step - no state transition,
    /// no Claim reply, the session stays XmrLocked.
    #[test]
    fn ghost_lock_sidecar_mismatch_rejected() {
        let mut maker = SwapNet::new();
        let (id_hex, offer_wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        // forge the sidecar: structurally valid, wrong derivation
        let mut frame = decode_frame(&offer_wire).unwrap();
        let mut forged = frame.adaptor.clone().unwrap();
        let impostor = one_time_keys(&[43u8; 32]);
        forged.p = hex32(&impostor.p);
        forged.image = hex32(&impostor.image);
        frame.adaptor = Some(forged);
        let offer_wire = encode_frame(&frame).unwrap();

        let mut taker = SwapNet::new();
        taker.receive_frame(&offer_wire, 100).unwrap();
        let lock_wire = taker.publish_xmr_lock(&id_hex, "xmr-tx-wg22", 110).unwrap();
        maker.receive_frame(&lock_wire, 0).unwrap();
        let ghost_wire = maker
            .publish_ghost_lock(&id_hex, "ghost-burn-wg22", 120)
            .unwrap();
        assert_eq!(
            taker.receive_frame(&ghost_wire, 0).unwrap_err(),
            SwapNetError::OneTimeKeyMismatch
        );
        let t = taker.session(&id_hex).unwrap();
        assert_eq!(t.session.phase, Phase::XmrLocked);
        assert!(t.offer_otk.is_some());
    }

    /// WG-22: pre-WG-21 offers carry no sidecar - the v1 wire shape keeps
    /// claiming exactly as before (no derivation to compare against).
    #[test]
    fn ghost_lock_without_sidecar_still_claims() {
        let mut maker = SwapNet::new();
        let (_, wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let mut frame = decode_frame(&wire).unwrap();
        frame.adaptor = None;
        let offer_wire = encode_frame(&frame).unwrap();
        let id_hex = hex32(&offer_id_of(&payload()));

        let mut taker = SwapNet::new();
        taker.receive_frame(&offer_wire, 100).unwrap();
        let lock_wire = taker.publish_xmr_lock(&id_hex, "xmr-tx-v1", 110).unwrap();
        maker.receive_frame(&lock_wire, 0).unwrap();
        let ghost_wire = maker
            .publish_ghost_lock(&id_hex, "ghost-burn-v1", 120)
            .unwrap();
        let replies = taker.receive_frame(&ghost_wire, 0).unwrap();
        assert_eq!(replies.len(), 1);
        assert!(matches!(
            decode_frame(&replies[0]).unwrap().msg,
            SwapNetMessage::Claim { .. }
        ));
    }

    const PREIMAGE: [u8; 32] = [42u8; 32];

    /// WG-18: the deadline sweep reports exactly the refund-eligible
    /// sessions and stops reporting them once refunded.
    #[test]
    fn expired_sessions_reports_refund_eligible_only() {
        // Maker registers the offer; a taker takes it via the wire frame.
        let mut maker = SwapNet::new();
        let (id_hex, offer_wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();

        let mut taker = SwapNet::new();
        taker.receive_frame(&offer_wire, 100).unwrap(); // taker Accepted @ 100
        assert_eq!(taker.session_count(), 1);

        // Maker still Offered, taker inside the fund window: nothing expired.
        assert!(maker.expired_sessions(1_000).is_empty());
        assert!(taker.expired_sessions(100).is_empty());
        assert!(taker.expired_sessions(200).is_empty()); // 100 + 100 fund timeout

        // Past the fund window the taker session expires.
        let expired = taker.expired_sessions(201);
        assert_eq!(expired.len(), 1);
        assert_eq!(hex32(&expired[0].offer_id), id_hex);
        assert_eq!(expired[0].reason, "fund window expired");

        // Refunding removes it from every later sweep.
        taker.publish_refund(&id_hex, "sweep test", 201).unwrap();
        assert!(taker.expired_sessions(9_999).is_empty());

        // Maker side: XmrLocked (implicit accept), GHOST lock, then the
        // claim window (both_locked 120 + 200) passes.
        let xmr_frame = Frame::new(SwapNetMessage::XmrLocked {
            offer_id: id_hex.clone(),
            xmr_tx_hash: "xmr-tx-sweep".to_string(),
            height: 110,
        });
        maker
            .receive_frame(&encode_frame(&xmr_frame).unwrap(), 110)
            .unwrap();
        let _lock_wire = maker
            .publish_ghost_lock(&id_hex, "ghost-burn-sweep", 120)
            .unwrap();
        assert!(maker.expired_sessions(319).is_empty());
        let expired = maker.expired_sessions(320);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].reason, "claim window expired");
        maker.publish_refund(&id_hex, "sweep test", 320).unwrap();
        assert!(maker.expired_sessions(9_999).is_empty());
    }

    /// WG-18: adversarial u64 timeouts saturate instead of panicking the
    /// sweep (timeouts arrive from peer-owned offer payloads).
    #[test]
    fn expired_sessions_saturates_hostile_timeouts() {
        let mut maker = SwapNet::new();
        let hostile = Offer::new(
            1_000_000_000_000,
            500_000_000,
            u64::MAX,
            u64::MAX,
            "ghost-maker",
            "xmr-taker",
            &PREIMAGE,
        )
        .unwrap();
        let (_id_hex, offer_wire) = maker.publish_offer(hostile, PREIMAGE).unwrap();

        let mut taker = SwapNet::new();
        taker.receive_frame(&offer_wire, 100).unwrap(); // Accepted @ 100
                                                        // accepted 100 + u64::MAX saturates; no height can exceed it and
                                                        // the sweep must neither panic nor report.
        assert!(taker.expired_sessions(u64::MAX).is_empty());
    }

    fn offer() -> Offer {
        Offer::new(
            2_000_000_000_000, // 2 XMR
            1_000_000_000,     // GHOST atoms
            100,               // fund timeout
            200,               // claim timeout (>= fund)
            "ghost-maker-addr",
            "xmr-taker-addr",
            &PREIMAGE,
        )
        .unwrap()
    }

    fn payload() -> SwapOfferPayload {
        payload_from_offer(&offer())
    }

    #[test]
    fn offer_id_deterministic_and_binding() {
        let a = offer_id_of(&payload());
        let b = offer_id_of(&payload_from_offer(&offer()));
        assert_eq!(a, b);
        let mut tampered = payload();
        tampered.ghost_atoms += 1;
        assert_ne!(offer_id_of(&tampered), a);
    }

    #[test]
    fn frame_roundtrip() {
        let frame = Frame::new(SwapNetMessage::Accept {
            offer_id: hex32(&[9u8; 32]),
        });
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
        assert_eq!(
            u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize,
            wire.len() - 4
        );
    }

    /// Full maker/taker choreography over actual wire bytes.
    #[test]
    fn full_choreography_over_wire() {
        let mut maker = SwapNet::new();
        let mut taker = SwapNet::new();

        let (id_hex, offer_wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();

        // taker receives the offer -> auto Accept
        let replies = taker.receive_frame(&offer_wire, 1005).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(taker.session_count(), 1);
        assert_eq!(
            taker.session(&id_hex).unwrap().session.phase,
            Phase::Accepted
        );

        // maker receives the Accept
        let replies = maker.receive_frame(&replies[0], 0).unwrap();
        assert!(replies.is_empty());
        assert!(maker.session(&id_hex).unwrap().accepted_by_peer);

        // taker locks XMR and announces it
        let lock_wire = taker.publish_xmr_lock(&id_hex, "xmr-tx-1", 1010).unwrap();
        assert_eq!(
            taker.session(&id_hex).unwrap().session.phase,
            Phase::XmrLocked
        );

        // maker observes the XMR lock (implicit accept), locks GHOST
        let replies = maker.receive_frame(&lock_wire, 0).unwrap();
        assert!(replies.is_empty());
        assert_eq!(
            maker.session(&id_hex).unwrap().session.phase,
            Phase::XmrLocked
        );
        let ghost_wire = maker
            .publish_ghost_lock(&id_hex, "ghost-burn-1", 1015)
            .unwrap();
        assert_eq!(
            maker.session(&id_hex).unwrap().session.phase,
            Phase::GhostLocked
        );

        // taker receives the ghost lock + preimage, auto-claims
        let replies = taker.receive_frame(&ghost_wire, 0).unwrap();
        assert_eq!(replies.len(), 1);
        let claim_msg = decode_frame(&replies[0]).unwrap().msg;
        match claim_msg {
            SwapNetMessage::Claim { offer_id, preimage } => {
                assert_eq!(offer_id, id_hex);
                assert_eq!(preimage, hex32(&PREIMAGE));
            }
            other => panic!("expected Claim, got {other:?}"),
        }
        assert_eq!(
            taker.session(&id_hex).unwrap().session.phase,
            Phase::GhostLocked
        );

        // maker receives the claim: preimage verified, XMR claim unlocked
        let replies = maker.receive_frame(&replies[0], 0).unwrap();
        assert!(replies.is_empty());
        let t = maker.session(&id_hex).unwrap();
        assert!(t.peer_claimed);
        assert_eq!(t.claimed_preimage, Some(PREIMAGE));

        // taker completes his local state machine with the on-chain claim
        assert_eq!(taker.session(&id_hex).unwrap().session.role, Role::Taker);
    }

    #[test]
    fn duplicate_offer_rejected() {
        let mut maker = SwapNet::new();
        let mut taker = SwapNet::new();
        let (_, wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        taker.receive_frame(&wire, 100).unwrap();
        assert_eq!(
            taker.receive_frame(&wire, 100).unwrap_err(),
            SwapNetError::DuplicateOffer
        );
    }

    #[test]
    fn tampered_offer_id_rejected() {
        let mut maker = SwapNet::new();
        let mut taker = SwapNet::new();
        let (_, wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let frame = decode_frame(&wire).unwrap();
        let mut frame = frame;
        if let SwapNetMessage::Offer { offer_id, .. } = &mut frame.msg {
            let first = offer_id.chars().next().unwrap();
            let flipped = if first == 'a' { 'b' } else { 'a' };
            offer_id.replace_range(0..1, &flipped.to_string());
        }
        let bad = encode_frame(&frame).unwrap();
        assert_eq!(
            taker.receive_frame(&bad, 100).unwrap_err(),
            SwapNetError::OfferIdMismatch
        );
    }

    #[test]
    fn malformed_offers_rejected() {
        let mut taker = SwapNet::new();
        // zero amount
        let mut p = payload();
        p.ghost_atoms = 0;
        let id = hex32(&offer_id_of(&p));
        let wire = encode_frame(&Frame::new(SwapNetMessage::Offer {
            offer_id: id,
            payload: p,
        }))
        .unwrap();
        assert_eq!(
            taker.receive_frame(&wire, 100).unwrap_err(),
            SwapNetError::MalformedOffer("zero amount")
        );

        // fund timeout > claim timeout
        let mut taker = SwapNet::new();
        let mut p = payload();
        p.fund_timeout_blocks = 300;
        p.claim_timeout_blocks = 200;
        let wire = encode_frame(&Frame::new(SwapNetMessage::Offer {
            offer_id: hex32(&offer_id_of(&p)),
            payload: p,
        }))
        .unwrap();
        assert_eq!(
            taker.receive_frame(&wire, 100).unwrap_err(),
            SwapNetError::MalformedOffer("fund timeout exceeds claim timeout")
        );

        // bad hashlock hex
        let mut taker = SwapNet::new();
        let mut p = payload();
        p.hashlock = "nothex".to_string();
        let wire = encode_frame(&Frame::new(SwapNetMessage::Offer {
            offer_id: hex32(&offer_id_of(&p)),
            payload: p,
        }))
        .unwrap();
        assert!(matches!(
            taker.receive_frame(&wire, 100).unwrap_err(),
            SwapNetError::BadHex(_)
        ));
    }

    #[test]
    fn wrong_protocol_rejected() {
        let mut taker = SwapNet::new();
        let frame = Frame {
            adaptor: None,
            protocol: "other-proto".to_string(),
            msg: SwapNetMessage::Accept {
                offer_id: hex32(&[1u8; 32]),
            },
        };
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(
            taker.receive_frame(&wire, 100).unwrap_err(),
            SwapNetError::ProtocolMismatch("other-proto".to_string())
        );
    }

    #[test]
    fn truncated_and_bad_length_frames_rejected() {
        assert_eq!(decode_frame(&[0u8; 3]), Err(FrameError::Truncated));
        let frame = Frame::new(SwapNetMessage::Accept {
            offer_id: hex32(&[1u8; 32]),
        });
        let wire = encode_frame(&frame).unwrap();
        let mut cut = wire.clone();
        cut.truncate(wire.len() - 3);
        assert!(matches!(
            decode_frame(&cut),
            Err(FrameError::BadLength { .. })
        ));
        // trailing garbage is rejected (strict one-frame decode)
        let mut extra = wire.clone();
        extra.push(0);
        assert!(matches!(
            decode_frame(&extra),
            Err(FrameError::BadLength { .. })
        ));
    }

    /// The fund-window expiry is enforced on the taker side (lock_xmr) and
    /// via local refund timers; a maker-side lock notice implicitly accepts
    /// the offer at its height by design (bridge-dex-1 semantics). What the
    /// P2P layer must guarantee instead: a notice cannot be REPLAYED to
    /// re-drive the state machine.
    #[test]
    fn xmr_locked_replay_rejected() {
        let mut maker = SwapNet::new();
        let (id_hex, _) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        let wire = encode_frame(&Frame::new(SwapNetMessage::XmrLocked {
            offer_id: id_hex.clone(),
            xmr_tx_hash: "tx".to_string(),
            height: 110,
        }))
        .unwrap();
        maker.receive_frame(&wire, 0).unwrap();
        assert_eq!(
            maker.session(&id_hex).unwrap().session.phase,
            Phase::XmrLocked
        );
        // same frame again -> session is already XmrLocked -> WrongPhase
        assert_eq!(
            maker.receive_frame(&wire, 0).unwrap_err(),
            SwapNetError::State(SwapError::WrongPhase)
        );
    }

    #[test]
    fn ghost_lock_before_xmr_lock_rejected() {
        let mut maker = SwapNet::new();
        let (id_hex, _) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        assert_eq!(
            maker.publish_ghost_lock(&id_hex, "ref", 100).unwrap_err(),
            SwapNetError::State(SwapError::WrongPhase)
        );
    }

    #[test]
    fn forged_claim_rejected() {
        let mut maker = SwapNet::new();
        let mut taker = SwapNet::new();
        let (id_hex, offer_wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        taker.receive_frame(&offer_wire, 100).unwrap();
        let lock_wire = taker.publish_xmr_lock(&id_hex, "tx", 110).unwrap();
        maker.receive_frame(&lock_wire, 0).unwrap();
        maker.publish_ghost_lock(&id_hex, "ref", 120).unwrap();

        let wire = encode_frame(&Frame::new(SwapNetMessage::Claim {
            offer_id: id_hex,
            preimage: hex32(&[7u8; 32]),
        }))
        .unwrap();
        assert_eq!(
            maker.receive_frame(&wire, 0).unwrap_err(),
            SwapNetError::State(SwapError::BadPreimage)
        );
    }

    #[test]
    fn refund_notice_flow() {
        let mut maker = SwapNet::new();
        let mut taker = SwapNet::new();
        let (id_hex, offer_wire) = maker.publish_offer(offer(), PREIMAGE).unwrap();
        // taker accepts at height 100 but never locks XMR
        taker.receive_frame(&offer_wire, 100).unwrap();
        // fund deadline = accepted_height(100) + fund_timeout(100) = 200
        let refund_wire = taker
            .publish_refund(&id_hex, "fund window expired", 201)
            .unwrap();
        let replies = maker.receive_frame(&refund_wire, 0).unwrap();
        assert!(replies.is_empty());
        assert!(maker.session(&id_hex).unwrap().peer_refunded);
        // refund too early is rejected by the state machine
        let mut taker2 = SwapNet::new();
        taker2.receive_frame(&offer_wire, 100).unwrap();
        assert_eq!(
            taker2
                .publish_refund(&id_hex, "too early", 150)
                .unwrap_err(),
            SwapNetError::State(SwapError::NotTimedOut)
        );
    }
}
