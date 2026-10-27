# add_swap_p2p.ps1
# Ghost project - P2P message layer for XMR<->GHOST atomic swaps
# (opacus-bridge/src/swap_p2p.rs: SwapNet, framed JSON wire protocol over
# xmr_swap state machine, offer/accept/lock/claim/refund) + foundry deploy
# kit for wGHOST (contracts/wGHOST.s.sol, contracts/foundry.toml).
# Additive only: 1 new module + idempotent 'pub mod swap_p2p;' registration.
# Generated 2026-10-18 - sandbox verified:
# opacus-bridge 27 passed / 0 failed (15 existing + 12 new), zero warnings.

$ErrorActionPreference = "Stop"

# ---- adjust if your project lives elsewhere ----
$ProjectRoot = "$PSScriptRoot"

Write-Host "=== Ghost: swap P2P layer + wGHOST deploy kit ===" -ForegroundColor Cyan

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found in PATH." -ForegroundColor Red
    exit 1
}
if (!(Test-Path (Join-Path $ProjectRoot "crates\opacus-bridge"))) {
    Write-Host "ERROR: crates\opacus-bridge not found." -ForegroundColor Red
    exit 1
}

function Write-Text([string]$Path, [string]$Content) {
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  wrote " + $Path)
}

# ---- 0) backups ----
$p = Join-Path $ProjectRoot "crates\opacus-bridge\src\lib.rs"
if (Test-Path $p) {
    Copy-Item $p "$p.bak-p2p" -Force
    Write-Host "  backup -> opacus-bridge\src\lib.rs.bak-p2p"
}
foreach ($f in @("contracts\wGHOST.s.sol", "contracts\foundry.toml")) {
    $p = Join-Path $ProjectRoot $f
    if (Test-Path $p) {
        Copy-Item $p "$p.bak-p2p" -Force
        Write-Host ("  backup -> " + $f + ".bak-p2p")
    }
}

# ---- crates\opacus-bridge\src\swap_p2p.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-bridge\src\swap_p2p.rs") @'
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
//! v0.1 limitations: Refund frames are notices (deadline enforcement stays
//! local via [`SwapSession::refund`]); offer ids bind the exact payload
//! bytes (blake3 over canonical JSON) so tampering is rejected.

use std::collections::HashMap;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use crate::xmr_swap::{hashlock_of, Offer, Phase, Role, SwapError, SwapSession};

/// Wire protocol identifier; frames with a different tag are rejected.
pub const PROTOCOL: &str = "ghost-swap-p2p-v1";
const OFFER_ID_TAG: &[u8] = b"ghost-swap-offer-id-v1";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The offer fields exactly as hashed into the offer id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub protocol: String,
    #[serde(flatten)]
    pub msg: SwapNetMessage,
}

impl Frame {
    pub fn new(msg: SwapNetMessage) -> Self {
        Frame {
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
    BadLength { declared: usize, available: usize },
    Json(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Truncated => write!(f, "frame truncated (no length prefix)"),
            FrameError::BadLength { declared, available } => {
                write!(f, "bad frame length: declared {declared}, available {available}")
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

fn offer_from_payload(p: &SwapOfferPayload) -> Result<Offer, SwapNetError> {
    if p.xmr_piconero == 0 || p.ghost_atoms == 0 {
        return Err(SwapNetError::MalformedOffer("zero amount"));
    }
    if p.fund_timeout_blocks == 0 || p.claim_timeout_blocks == 0 {
        return Err(SwapNetError::MalformedOffer("non-positive timeout"));
    }
    if p.fund_timeout_blocks > p.claim_timeout_blocks {
        return Err(SwapNetError::MalformedOffer("fund timeout exceeds claim timeout"));
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

    fn tracked_mut(&mut self, offer_id_hex: &str) -> Result<&mut TrackedSession, SwapNetError> {
        let id = parse_hex32(offer_id_hex)?;
        self.sessions
            .get_mut(&id)
            .ok_or(SwapNetError::UnknownOffer)
    }

    // -- maker actions ------------------------------------------------------

    /// Maker: register a new offer (preimage is kept locally) and get the
    /// encoded Offer frame to broadcast.
    pub fn publish_offer(
        &mut self,
        offer: Offer,
        preimage: [u8; 32],
    ) -> Result<(String, Vec<u8>), SwapNetError> {
        if hashlock_of(&preimage) != offer.hashlock {
            return Err(SwapNetError::State(SwapError::BadPreimage));
        }
        let payload = payload_from_offer(&offer);
        let offer_id = offer_id_of(&payload);
        let mut session = SwapSession::make_offer(offer, 0);
        session.set_preimage(preimage)?;
        self.sessions.insert(
            offer_id,
            TrackedSession {
                session,
                offer_id,
                accepted_by_peer: false,
                peer_refunded: false,
                peer_claimed: false,
                claimed_preimage: None,
                xmr_tx_hash: None,
                ghost_tx_ref: None,
            },
        );
        let frame = Frame::new(SwapNetMessage::Offer {
            offer_id: hex32(&offer_id),
            payload,
        });
        Ok((hex32(&offer_id), encode_frame(&frame).map_err(|e| SwapNetError::Frame(e.to_string()))?))
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
        let replies = self.handle_message(frame.msg, current_height)?;
        Ok(replies
            .iter()
            .map(|m| {
                encode_frame(&Frame::new(m.clone()))
                    .map_err(|e| SwapNetError::Frame(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Core protocol transition. `current_height` is used for the taker's
    /// acceptance timestamp on new Offers; lock notifications carry their
    /// own heights.
    pub fn handle_message(
        &mut self,
        msg: SwapNetMessage,
        current_height: u64,
    ) -> Result<Vec<SwapNetMessage>, SwapNetError> {
        match msg {
            SwapNetMessage::Offer { offer_id, payload } => {
                let id = parse_hex32(&offer_id)?;
                let offer = offer_from_payload(&payload)?;
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
                t.session.mark_ghost_locked(height)?;
                t.ghost_tx_ref = Some(ghost_tx_ref);
                Ok(vec![SwapNetMessage::Claim {
                    offer_id,
                    preimage,
                }])
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

    const PREIMAGE: [u8; 32] = [42u8; 32];

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
        assert_eq!(u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize, wire.len() - 4);
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
        assert_eq!(taker.session(&id_hex).unwrap().session.phase, Phase::Accepted);

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
            taker2.publish_refund(&id_hex, "too early", 150).unwrap_err(),
            SwapNetError::State(SwapError::NotTimedOut)
        );
    }
}

'@

# ---- contracts\wGHOST.s.sol ----
Write-Text (Join-Path $ProjectRoot "contracts\wGHOST.s.sol") @'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {WGHOST} from "./wGHOST.sol";

/// @notice Deploy the wGHOST bridge token with a 3-of-N quorum.
///
/// Local dev (anvil defaults, threshold 2):
///     cd contracts && forge install foundry-rs/forge-std
///     anvil &  forge script wGHOSTDeploy --broadcast
///
/// Sepolia:
///     export SIGNER_1=0xAAA... SIGNER_2=0xBBB... SIGNER_3=0xCCC...
///     export QUORUM_THRESHOLD=2
///     forge script wGHOSTDeploy --rpc-url $SEPOLIA_RPC_URL \
///         --private-key $DEPLOYER_KEY --broadcast --verify
///
/// After deployment call set_wghost(addr) on the opacus-dex side.
contract wGHOSTDeploy is Script {
    function run() external {
        // Anvil well-known accounts as defaults for local testing.
        address s1 = vm.envOr("SIGNER_1", 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
        address s2 = vm.envOr("SIGNER_2", 0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
        address s3 = vm.envOr("SIGNER_3", 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC);
        uint256 threshold = vm.envOr("QUORUM_THRESHOLD", uint256(2));

        address[] memory members = new address[](3);
        members[0] = s1;
        members[1] = s2;
        members[2] = s3;

        vm.startBroadcast();
        new WGHOST(members, threshold);
        vm.stopBroadcast();
    }
}

'@

# ---- contracts\foundry.toml ----
Write-Text (Join-Path $ProjectRoot "contracts\foundry.toml") @'
[profile.default]
src = "."
out = "out"
libs = ["lib"]
solc_version = "0.8.24"

'@

# ---- 1) opacus-bridge/src/lib.rs: declare the module (idempotent) ----
$libPath = Join-Path $ProjectRoot "crates\opacus-bridge\src\lib.rs"
$lib = [System.IO.File]::ReadAllText($libPath)
if ($lib -notmatch '(?m)^\s*(pub\s+)?mod\s+swap_p2p\s*;') {
    if (!$lib.EndsWith("`n")) { $lib += "`r`n" }
    $lib += "pub mod swap_p2p;`r`n"
    [System.IO.File]::WriteAllText($libPath, $lib, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  registered modules: swap_p2p"
} else {
    Write-Host "  swap_p2p already declared"
}

# ---- 2) tests ----
Write-Host ""
Push-Location $ProjectRoot
try {
    Write-Host "=== running: cargo test -p opacus-bridge --release ===" -ForegroundColor Cyan
    cargo test -p opacus-bridge --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "SWAP P2P TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "SWAP P2P TESTS PASSED (framing + offer/accept/lock/claim/refund)" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "What you got:" -ForegroundColor Cyan
Write-Host "  opacus-bridge/swap_p2p.rs: SwapNetMessage (Offer/Accept/XmrLocked/GhostLocked/Claim/Refund),"
Write-Host "    u32-LE framed JSON wire codec, offer_id = blake3(canonical payload JSON),"
Write-Host "    SwapNet session registry: tamper/duplicate/replay/preimage/deadline validation"
Write-Host "  contracts/wGHOST.s.sol + foundry.toml: forge script wGHOSTDeploy (anvil defaults / Sepolia env)"
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  - contracts: forge install foundry-rs/forge-std && forge build && forge test"
Write-Host "  - wire SwapNet::receive_frame into opacusd's P2P dispatch (adapter needs your msg enum)"
