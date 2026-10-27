# add_swap_node.ps1
# Ghost project - swap sessions on real TCP sockets (opacus-network).
# Adds crates\opacus-network\src\swap_node.rs: a SwapNode that runs the
# opacus-bridge "ghost-swap-p2p-v1" protocol (Offer/Accept/XmrLocked/
# GhostLocked/Claim/Refund) over full-duplex TCP connections.
# Self-contained: also installs opacus-bridge/src/swap_p2p.rs if it is not
# present yet (no need to run add_swap_p2p.ps1 first).
# Additive only; manifest patch checks the base key in ANY form
# (name.workspace or name = ...) before inserting - no TOML conflicts.
# Generated 2026-10-18 - sandbox verified:
# opacus-network 8 passed / 0 failed (incl. two-node swap e2e over TCP),
# opacus-bridge 27 passed / 0 failed, zero warnings.

$ErrorActionPreference = "Stop"

# ---- adjust if your project lives elsewhere ----
$ProjectRoot = "$PSScriptRoot"

Write-Host "=== Ghost: swap P2P node in opacus-network ===" -ForegroundColor Cyan

if (!(Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: cargo not found in PATH." -ForegroundColor Red
    exit 1
}
foreach ($d in @("crates\opacus-bridge", "crates\opacus-network")) {
    if (!(Test-Path (Join-Path $ProjectRoot $d))) {
        Write-Host ("ERROR: not found: " + $d) -ForegroundColor Red
        exit 1
    }
}

function Write-Text([string]$Path, [string]$Content) {
    $dir = Split-Path -Parent $Path
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  wrote " + $Path)
}

# ---- 0) backups ----
foreach ($f in @("crates\opacus-bridge\src\lib.rs", "crates\opacus-network\src\lib.rs", "crates\opacus-network\Cargo.toml")) {
    $p = Join-Path $ProjectRoot $f
    if (Test-Path $p) {
        Copy-Item $p "$p.bak-node" -Force
        Write-Host ("  backup -> " + $f + ".bak-node")
    }
}

# ---- 1) opacus-bridge/src/swap_p2p.rs (skipped when already installed) ----
$p2pPath = Join-Path $ProjectRoot "crates\opacus-bridge\src\swap_p2p.rs"
if ((Test-Path $p2pPath) -and (Select-String -Path $p2pPath -Pattern 'ghost-swap-p2p-v1' -Quiet)) {
    Write-Host "  opacus-bridge\src\swap_p2p.rs already present - skipped"
} else {
    if (Test-Path $p2pPath) { Copy-Item $p2pPath "$p2pPath.bak-node" -Force }
    Write-Text $p2pPath @'
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
}

# ---- 2) opacus-network/src/swap_node.rs ----
Write-Text (Join-Path $ProjectRoot "crates\opacus-network\src\swap_node.rs") @'
//! TCP node for the opacus-bridge swap P2P protocol (v0.1).
//!
//! Bridges [`SwapNet`] (opacus-bridge) onto real TCP sockets. Every
//! connection is full-duplex: frames read from a peer are applied to the
//! session registry and the auto-replies (Accept, Claim) are written back
//! on the same socket. The wire format is exactly the bridge's u32-LE
//! length-prefixed JSON frames (protocol tag "ghost-swap-p2p-v1").
//!
//! Layout:
//!
//! ```text
//!  SwapNode::start(cfg)     bind + listener thread + dial bootstrap peers
//!  node.broadcast_offer()   register Offer locally, push to all outbound
//!  node.send_wire()         push any encoded frame to all outbound peers
//!  conn_loop (per socket)   read frame -> SwapNet::receive_frame -> replies
//! ```
//!
//! Choreography (Maker sells GHOST, Taker sells XMR):
//!
//! ```text
//!  Maker (node A)                            Taker (node B)
//!  connect(A -> B) -- Offer -->              receive(Offer) -> auto Accept
//!               <-- Accept
//!               <-- XmrLocked                publish_xmr_lock + send_wire
//!  publish_ghost_lock -- GhostLocked (preimage!) -->
//!               <-- Claim                    receive(GhostLocked) -> auto Claim
//!  peer_claimed (preimage verified)          claim GHOST on-chain
//!  -> claim XMR with the revealed preimage
//! ```
//!
//! v0.1 limitations: direct 1:1 dials only (no gossip/discovery - the full
//! libp2p stack lands in v0.3); a protocol violation closes the connection
//! silently (the wire protocol has no Error frame yet); block heights for
//! incoming frames come from [`SwapNodeConfig`] (the opacusd wiring will
//! feed live heights); Refund frames are notices, deadline enforcement
//! stays local via the session state machine.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opacus_bridge::swap_p2p::{decode_frame, SwapNet, SwapNetError, SwapNetMessage};
use opacus_bridge::xmr_swap::Offer;

use crate::p2p::NetworkConfig;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum NetError {
    Io(std::io::Error),
    Frame(opacus_bridge::swap_p2p::FrameError),
    Protocol(SwapNetError),
    /// Peer declared a frame larger than the configured limit.
    TooLarge(usize),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "io: {e}"),
            NetError::Frame(e) => write!(f, "frame: {e}"),
            NetError::Protocol(e) => write!(f, "swap protocol: {e}"),
            NetError::TooLarge(n) => write!(f, "frame too large: {n} bytes"),
        }
    }
}

impl std::error::Error for NetError {}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e)
    }
}

impl From<SwapNetError> for NetError {
    fn from(e: SwapNetError) -> Self {
        NetError::Protocol(e)
    }
}

impl From<opacus_bridge::swap_p2p::FrameError> for NetError {
    fn from(e: opacus_bridge::swap_p2p::FrameError) -> Self {
        NetError::Frame(e)
    }
}

// ---------------------------------------------------------------------------
// Frame IO over sockets (u32-LE prefix + JSON body, as produced by
// opacus_bridge::swap_p2p::encode_frame)
// ---------------------------------------------------------------------------

fn read_full(stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize, NetError> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(NetError::Io(e)),
        }
    }
    Ok(off)
}

/// Read one wire frame (prefix + body, ready for `SwapNet::receive_frame`).
/// `Ok(None)` means the peer closed the connection cleanly between frames.
fn read_frame(stream: &mut TcpStream, max_frame_len: usize) -> Result<Option<Vec<u8>>, NetError> {
    let mut prefix = [0u8; 4];
    let got = read_full(stream, &mut prefix)?;
    if got == 0 {
        return Ok(None);
    }
    if got < 4 {
        return Err(NetError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed inside a frame prefix",
        )));
    }
    let len = u32::from_le_bytes(prefix) as usize;
    if len > max_frame_len {
        return Err(NetError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    read_full(stream, &mut body)?;
    let mut wire = Vec::with_capacity(4 + len);
    wire.extend_from_slice(&prefix);
    wire.extend_from_slice(&body);
    Ok(Some(wire))
}

fn write_frame(stream: &mut TcpStream, wire: &[u8]) -> Result<(), NetError> {
    stream.write_all(wire)?;
    stream.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SwapNodeConfig {
    /// Address to listen on ("ip:port"; port 0 = ephemeral).
    pub listen_addr: String,
    /// Peers to dial on start (v0.1: direct dials, no discovery).
    pub bootstrap_peers: Vec<String>,
    /// Per-read socket timeout; an idle peer is disconnected.
    pub read_timeout: Duration,
    /// Hard cap for one incoming frame (prefix + body).
    pub max_frame_len: usize,
    /// Block height fed to the session machine for incoming frames.
    pub current_height: u64,
}

impl Default for SwapNodeConfig {
    fn default() -> Self {
        SwapNodeConfig {
            listen_addr: "127.0.0.1:18081".to_string(),
            bootstrap_peers: Vec::new(),
            read_timeout: Duration::from_secs(30),
            max_frame_len: 1_048_576,
            current_height: 0,
        }
    }
}

impl SwapNodeConfig {
    /// Derive a swap node config from the shared network config: listen on
    /// loopback at the configured port (18080 by default) and dial the
    /// configured bootstrap nodes.
    pub fn from_network(cfg: &NetworkConfig) -> Self {
        let mut out = SwapNodeConfig::default();
        out.listen_addr = format!("127.0.0.1:{}", cfg.listen_port);
        out.bootstrap_peers = cfg.bootstrap_nodes.clone();
        out
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Bounded observability log (newest last). Tests and the opacusd wiring
/// read it; a real daemon will forward it to logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeEvent {
    PeerConnected(String),
    PeerDisconnected(String),
    /// Inbound frame kind ("Offer", "Accept", ...) or "Undecodable".
    Received(String),
    /// Auto-reply kind sent back on the same socket.
    Replied(String),
    /// Protocol or IO rejection; the connection is closed afterwards.
    Rejected(String),
}

const EVENT_CAP: usize = 1024;

fn msg_kind(m: &SwapNetMessage) -> &'static str {
    match m {
        SwapNetMessage::Offer { .. } => "Offer",
        SwapNetMessage::Accept { .. } => "Accept",
        SwapNetMessage::XmrLocked { .. } => "XmrLocked",
        SwapNetMessage::GhostLocked { .. } => "GhostLocked",
        SwapNetMessage::Claim { .. } => "Claim",
        SwapNetMessage::Refund { .. } => "Refund",
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

pub struct SwapNode {
    cfg: SwapNodeConfig,
    listener: TcpListener,
    net: Arc<Mutex<SwapNet>>,
    /// Write halves of all dialed peers (used by send_wire).
    outbound: Arc<Mutex<Vec<TcpStream>>>,
    events: Arc<Mutex<Vec<NodeEvent>>>,
}

impl SwapNode {
    /// Bind, spawn the listener thread and dial the bootstrap peers.
    /// Dial failures are logged (Rejected), not fatal.
    pub fn start(cfg: SwapNodeConfig) -> Result<Arc<Self>, NetError> {
        let listener = TcpListener::bind(&cfg.listen_addr)?;
        let node = Arc::new(SwapNode {
            cfg,
            listener,
            net: Arc::new(Mutex::new(SwapNet::new())),
            outbound: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(Vec::new())),
        });
        node.spawn_listener();
        let peers = node.cfg.bootstrap_peers.clone();
        for peer in peers {
            if let Err(e) = node.connect(&peer) {
                node.log(NodeEvent::Rejected(format!("dial {peer}: {e}")));
            }
        }
        Ok(node)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.listener.local_addr()?)
    }

    pub fn config(&self) -> &SwapNodeConfig {
        &self.cfg
    }

    /// Shared handle to the session registry (wallet / opacusd integration:
    /// publish_xmr_lock, publish_ghost_lock, session inspection).
    pub fn net(&self) -> Arc<Mutex<SwapNet>> {
        Arc::clone(&self.net)
    }

    /// Snapshot of recent events (bounded ring, newest last).
    pub fn events(&self) -> Vec<NodeEvent> {
        self.events.lock().unwrap().clone()
    }

    fn log(&self, ev: NodeEvent) {
        let mut evs = self.events.lock().unwrap();
        if evs.len() >= EVENT_CAP {
            evs.remove(0);
        }
        evs.push(ev);
    }

    /// Accept loop: one handler thread per inbound connection.
    fn spawn_listener(self: &Arc<Self>) {
        let node = Arc::clone(self);
        std::thread::spawn(move || {
            for conn in node.listener.incoming() {
                if let Ok(stream) = conn {
                    node.attach(stream);
                }
            }
        });
    }

    fn attach(self: &Arc<Self>, stream: TcpStream) {
        let node = Arc::clone(self);
        std::thread::spawn(move || Self::conn_loop(&node, stream));
    }

    /// Dial a peer, keep the write half for send_wire and attach a handler
    /// thread that reads everything coming back on this socket.
    pub fn connect(self: &Arc<Self>, addr: &str) -> Result<(), NetError> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        let write_half = stream.try_clone()?;
        self.outbound.lock().unwrap().push(write_half);
        self.attach(stream);
        Ok(())
    }

    /// Push a wire frame to every dialed peer; broken sockets are pruned.
    /// Returns how many peers received the frame.
    pub fn send_wire(&self, wire: &[u8]) -> Result<usize, NetError> {
        let mut outs = self.outbound.lock().unwrap();
        let mut sent = 0;
        outs.retain_mut(|s| match write_frame(s, wire) {
            Ok(()) => {
                sent += 1;
                true
            }
            Err(_) => false,
        });
        Ok(sent)
    }

    /// Register a local offer (preimage kept for the later XMR claim) and
    /// broadcast the Offer frame to all dialed peers. Returns the hex offer
    /// id. The offer is tracked even with zero peers connected.
    pub fn broadcast_offer(&self, offer: &Offer, preimage: &[u8; 32]) -> Result<String, NetError> {
        let (id, wire) = self.net.lock().unwrap().publish_offer(offer.clone(), *preimage)?;
        self.send_wire(&wire)?;
        Ok(id)
    }

    /// Process one inbound wire frame without any socket: the pure protocol
    /// step of conn_loop (handy for tests and embedded hosts). Returns the
    /// encoded auto-reply frames.
    pub fn process_wire(&self, wire: &[u8]) -> Result<Vec<Vec<u8>>, NetError> {
        Ok(self
            .net
            .lock()
            .unwrap()
            .receive_frame(wire, self.cfg.current_height)?)
    }

    /// Per-connection read loop: read -> apply -> reply on the same socket.
    /// Any protocol violation closes the connection (no Error frame in
    /// v0.1); an idle peer is disconnected after the read timeout.
    fn conn_loop(node: &SwapNode, mut io: TcpStream) {
        io.set_read_timeout(Some(node.cfg.read_timeout)).ok();
        io.set_nodelay(true).ok();
        let peer = io
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".to_string());
        node.log(NodeEvent::PeerConnected(peer.clone()));
        loop {
            match read_frame(&mut io, node.cfg.max_frame_len) {
                Ok(None) => {
                    node.log(NodeEvent::PeerDisconnected(peer));
                    return;
                }
                Ok(Some(wire)) => {
                    let kind = decode_frame(&wire)
                        .map(|f| msg_kind(&f.msg).to_string())
                        .unwrap_or_else(|_| "Undecodable".to_string());
                    node.log(NodeEvent::Received(kind));
                    match node.process_wire(&wire) {
                        Ok(replies) => {
                            for reply in replies {
                                let kind = decode_frame(&reply)
                                    .map(|f| msg_kind(&f.msg).to_string())
                                    .unwrap_or_else(|_| "?".to_string());
                                match write_frame(&mut io, &reply) {
                                    Ok(()) => node.log(NodeEvent::Replied(kind)),
                                    Err(e) => {
                                        node.log(NodeEvent::Rejected(e.to_string()));
                                        return;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            node.log(NodeEvent::Rejected(e.to_string()));
                            return;
                        }
                    }
                }
                Err(NetError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    node.log(NodeEvent::PeerDisconnected(peer));
                    return;
                }
                Err(e) => {
                    node.log(NodeEvent::Rejected(e.to_string()));
                    return;
                }
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
    use opacus_bridge::swap_p2p::{encode_frame, offer_id_of, Frame, SwapOfferPayload};
    use opacus_bridge::xmr_swap::{hashlock_of, Phase, Role};
    use std::time::Instant;

    const PREIMAGE: [u8; 32] = [7u8; 32];

    fn offer() -> Offer {
        Offer::new(
            2_000_000_000_000, // 2 XMR
            1_000_000_000,     // GHOST atoms
            100,               // fund timeout blocks
            200,               // claim timeout blocks
            "ghost-maker-addr",
            "xmr-taker-addr",
            &PREIMAGE,
        )
        .unwrap()
    }

    fn test_cfg() -> SwapNodeConfig {
        SwapNodeConfig {
            listen_addr: "127.0.0.1:0".to_string(), // ephemeral port
            current_height: 1000,
            read_timeout: Duration::from_secs(20),
            ..Default::default()
        }
    }

    fn wait_until(secs: u64, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if cond() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("condition not met within {secs}s");
    }

    fn hex_str(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// An Offer frame built the way an EXTERNAL peer would build it
    /// (nothing registered locally).
    fn external_offer_wire() -> (String, Vec<u8>) {
        let payload = SwapOfferPayload {
            xmr_piconero: 2_000_000_000_000,
            ghost_atoms: 1_000_000_000,
            hashlock: hex_str(&hashlock_of(&PREIMAGE)),
            fund_timeout_blocks: 100,
            claim_timeout_blocks: 200,
            maker_ghost_address: "ghost-maker-addr".to_string(),
            taker_xmr_address: "xmr-taker-addr".to_string(),
        };
        let id = offer_id_of(&payload);
        let frame = Frame::new(SwapNetMessage::Offer {
            offer_id: hex_str(&id),
            payload,
        });
        (hex_str(&id), encode_frame(&frame).unwrap())
    }

    #[test]
    fn config_from_network() {
        let nc = NetworkConfig {
            listen_port: 18099,
            ..Default::default()
        };
        let cfg = SwapNodeConfig::from_network(&nc);
        assert_eq!(cfg.listen_addr, "127.0.0.1:18099");
        assert_eq!(cfg.max_frame_len, 1_048_576);
        let d = SwapNodeConfig::default();
        assert_eq!(d.listen_addr, "127.0.0.1:18081");
        assert_eq!(d.current_height, 0);
    }

    #[test]
    fn frame_io_roundtrip_and_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let frame = Frame::new(SwapNetMessage::Accept {
            offer_id: hex_str(&[0xabu8; 32]),
        });
        let wire = encode_frame(&frame).unwrap();
        write_frame(&mut client, &wire).unwrap();
        let got = read_frame(&mut server, 1 << 20).unwrap().unwrap();
        assert_eq!(got, wire);
        assert_eq!(decode_frame(&got).unwrap(), frame);

        // clean EOF between frames
        drop(client);
        assert!(read_frame(&mut server, 1 << 20).unwrap().is_none());
    }

    #[test]
    fn process_wire_offer_yields_accept() {
        let node = SwapNode::start(test_cfg()).unwrap();
        let (_, wire) = external_offer_wire();
        let replies = node.process_wire(&wire).unwrap();
        assert_eq!(replies.len(), 1);
        let reply = decode_frame(&replies[0]).unwrap();
        match reply.msg {
            SwapNetMessage::Accept { offer_id } => {
                assert_eq!(offer_id.len(), 64);
            }
            other => panic!("expected Accept, got {other:?}"),
        }
        assert_eq!(node.net().lock().unwrap().session_count(), 1);
    }

    #[test]
    fn duplicate_offer_rejected_in_process() {
        let node = SwapNode::start(test_cfg()).unwrap();
        let (id, _) = external_offer_wire();
        // register locally first (maker side), then the same Offer arrives
        // over the wire -> replay rejected
        let (local_id, wire) = node
            .net()
            .lock()
            .unwrap()
            .publish_offer(offer(), PREIMAGE)
            .unwrap();
        assert_eq!(local_id, id);
        let err = node.process_wire(&wire).unwrap_err();
        assert!(matches!(err, NetError::Protocol(SwapNetError::DuplicateOffer)));
    }

    #[test]
    fn oversize_prefix_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap(); // 4 GiB
        let err = read_frame(&mut server, 1024).unwrap_err();
        assert!(matches!(err, NetError::TooLarge(_)));
    }

    #[test]
    fn node_survives_garbage_and_serves_next_peer() {
        let node = SwapNode::start(test_cfg()).unwrap();
        let addr = node.local_addr().unwrap().to_string();

        // peer 1: valid prefix, garbage JSON -> connection dropped, node alive
        let mut c1 = TcpStream::connect(&addr).unwrap();
        c1.write_all(&10u32.to_le_bytes()).unwrap();
        c1.write_all(b"garbage!!!").unwrap();
        wait_until(10, || {
            node.events()
                .iter()
                .any(|e| matches!(e, NodeEvent::Rejected(_)))
        });
        let mut buf = [0u8; 1];
        c1.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let closed = match c1.read(&mut buf) {
            Ok(0) => true,
            Err(_) => true,
            Ok(_) => false,
        };
        assert!(closed, "connection should be closed after protocol error");

        // peer 2: a real offer still gets served with an Accept reply
        let (_, wire) = external_offer_wire();
        let mut c2 = TcpStream::connect(&addr).unwrap();
        c2.write_all(&wire).unwrap();
        c2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut prefix = [0u8; 4];
        read_full(&mut c2, &mut prefix).unwrap();
        let len = u32::from_le_bytes(prefix) as usize;
        let mut body = vec![0u8; len];
        read_full(&mut c2, &mut body).unwrap();
        let mut full = Vec::with_capacity(4 + len);
        full.extend_from_slice(&prefix);
        full.extend_from_slice(&body);
        let reply = decode_frame(&full).unwrap();
        assert!(matches!(reply.msg, SwapNetMessage::Accept { .. }));
        assert_eq!(node.net().lock().unwrap().session_count(), 1);
    }

    /// THE e2e: two real nodes on two real TCP sockets, full swap
    /// choreography Offer -> Accept -> XmrLocked -> GhostLocked -> Claim.
    #[test]
    fn two_nodes_full_swap_over_tcp() {
        let maker = SwapNode::start(test_cfg()).unwrap();
        let taker = SwapNode::start(test_cfg()).unwrap();
        let taker_addr = taker.local_addr().unwrap().to_string();
        let maker_addr = maker.local_addr().unwrap().to_string();
        maker.connect(&taker_addr).unwrap();
        taker.connect(&maker_addr).unwrap();

        // maker publishes + broadcasts; taker auto-accepts; maker sees it
        let id = maker.broadcast_offer(&offer(), &PREIMAGE).unwrap();
        wait_until(10, || taker.net().lock().unwrap().session_count() == 1);
        wait_until(10, || {
            maker
                .net()
                .lock()
                .unwrap()
                .session(&id)
                .map(|t| t.accepted_by_peer)
                .unwrap_or(false)
        });

        // taker locks XMR and pushes the notice (height 1050 <= 1000+100)
        let lock = taker
            .net()
            .lock()
            .unwrap()
            .publish_xmr_lock(&id, "xmr-tx-e2e", 1050)
            .unwrap();
        assert_eq!(taker.send_wire(&lock).unwrap(), 1);
        wait_until(10, || {
            maker
                .net()
                .lock()
                .unwrap()
                .session(&id)
                .map(|t| t.session.phase == Phase::XmrLocked)
                .unwrap_or(false)
        });

        // maker locks GHOST, reveals the preimage; taker auto-claims
        let ghost = maker
            .net()
            .lock()
            .unwrap()
            .publish_ghost_lock(&id, "ghost-burn-e2e", 1060)
            .unwrap();
        assert_eq!(maker.send_wire(&ghost).unwrap(), 1);
        wait_until(10, || {
            taker
                .net()
                .lock()
                .unwrap()
                .session(&id)
                .map(|t| t.session.phase == Phase::GhostLocked)
                .unwrap_or(false)
        });

        // maker receives the Claim: preimage verified, XMR claim unlocked
        wait_until(10, || {
            maker
                .net()
                .lock()
                .unwrap()
                .session(&id)
                .map(|t| t.peer_claimed && t.claimed_preimage == Some(PREIMAGE))
                .unwrap_or(false)
        });

        let m = maker.net().lock().unwrap().session(&id).unwrap().clone();
        assert_eq!(m.xmr_tx_hash.as_deref(), Some("xmr-tx-e2e"));
        assert_eq!(m.session.role, Role::Maker);
        assert_eq!(m.session.phase, Phase::GhostLocked);
        let t = taker.net().lock().unwrap().session(&id).unwrap().clone();
        assert_eq!(t.ghost_tx_ref.as_deref(), Some("ghost-burn-e2e"));
        assert_eq!(t.session.phase, Phase::GhostLocked);

        // both directions actually saw traffic
        assert!(maker.events().iter().any(|e| matches!(e, NodeEvent::Received(ref k) if k == "Claim")));
        assert!(taker.events().iter().any(|e| matches!(e, NodeEvent::Replied(ref k) if k == "Claim")));
    }

    /// The offerId binding: a tampered payload (same offer_id) is rejected
    /// by the node's protocol step.
    #[test]
    fn tampered_offer_rejected_in_process() {
        let node = SwapNode::start(test_cfg()).unwrap();
        let (_, mut wire) = external_offer_wire();
        // flip one byte inside the JSON body (amount digit), keep prefix
        let last = wire.len() - 1;
        if wire[last] == b'0' {
            wire[last] = b'1';
        } else {
            wire[last] = b'0';
        }
        let err = node.process_wire(&wire).unwrap_err();
        // the bridge maps bad JSON to SwapNetError::Frame, a surviving
        // payload reaches the offer-id recomputation (OfferIdMismatch)
        assert!(
            matches!(err, NetError::Protocol(_) | NetError::Frame(_)),
            "tampered frame must be rejected, got {err:?}"
        );
    }
}

'@

# ---- 3) module registrations (idempotent) ----
$reg = @(
    @{ Path = (Join-Path $ProjectRoot "crates\opacus-bridge\src\lib.rs");  Mod = "swap_p2p"  },
    @{ Path = (Join-Path $ProjectRoot "crates\opacus-network\src\lib.rs"); Mod = "swap_node" }
)
foreach ($r in $reg) {
    $lib = [System.IO.File]::ReadAllText($r.Path)
    $pat = '(?m)^\s*(pub\s+)?mod\s+' + $r.Mod + '\s*;'
    if ($lib -notmatch $pat) {
        if (!$lib.EndsWith("`n")) { $lib += "`r`n" }
        $lib += ("pub mod " + $r.Mod + ";`r`n")
        [System.IO.File]::WriteAllText($r.Path, $lib, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host ("  registered modules: " + $r.Mod)
    } else {
        Write-Host ("  " + $r.Mod + " already declared")
    }
}

# ---- 4) crates\opacus-network\Cargo.toml: path dep on opacus-bridge ----
# Base-key presence check in ANY form (dotted inheritance OR plain value)
# before inserting a VALUE-style line: a value definition after a dotted
# key of a DIFFERENT name can never conflict (the v0.1 manifest lesson).
$tomlPath = Join-Path $ProjectRoot "crates\opacus-network\Cargo.toml"
$toml = [System.IO.File]::ReadAllText($tomlPath)
$lines = @($toml -split "`r?`n")

function Ensure-Dep([object[]]$Lines, [string]$Name, [string]$ValueLine) {
    $pat = '^\s*' + [regex]::Escape($Name) + '\s*(\.|=)'
    foreach ($l in $Lines) {
        if ($l -match $pat) {
            Write-Host ("  dep already present: " + $Name)
            return $Lines
        }
    }
    $idx = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i].Trim() -eq '[dependencies]') { $idx = $i; break }
    }
    if ($idx -lt 0) {
        Write-Host ("  no [dependencies] section - appending one with " + $Name)
        return @($Lines) + @('', '[dependencies]', $ValueLine)
    }
    $head = @($Lines[0..$idx])
    $tail = @()
    if (($idx + 1) -lt $Lines.Count) { $tail = @($Lines[($idx + 1)..($Lines.Count - 1)]) }
    Write-Host ("  added dep: " + $ValueLine)
    return @($head) + @($ValueLine) + @($tail)
}

$lines = @(Ensure-Dep $lines 'serde' 'serde = { version = "1", features = ["derive"] }')
$lines = @(Ensure-Dep $lines 'opacus-bridge' 'opacus-bridge = { path = "../opacus-bridge" }')
$joined = ($lines -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($tomlPath, $joined, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "  manifest patched: crates\opacus-network\Cargo.toml"

# ---- 5) tests ----
Write-Host ""
Push-Location $ProjectRoot
try {
    Write-Host "=== running: cargo test -p opacus-bridge --release ===" -ForegroundColor Cyan
    cargo test -p opacus-bridge --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BRIDGE TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "BRIDGE TESTS PASSED (DLEq + swap protocol + swap P2P + monero-rpc)" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== running: cargo test -p opacus-network --release ===" -ForegroundColor Cyan
    cargo test -p opacus-network --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "NETWORK SWAP TESTS FAILED - paste the output above back to the assistant" -ForegroundColor Red
        exit 1
    }
    Write-Host "NETWORK SWAP TESTS PASSED (TCP swap node: full offer/accept/lock/claim over sockets)" -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "What you got:" -ForegroundColor Cyan
Write-Host "  opacus-network/swap_node.rs: SwapNode - real TCP transport for swap sessions"
Write-Host "    SwapNode::start(cfg) / connect / broadcast_offer / send_wire / process_wire"
Write-Host "    full-duplex conn loop: inbound frames -> SwapNet::receive_frame -> auto-replies"
Write-Host "    (Accept, Claim) written back on the same socket; frame size cap; idle timeout;"
Write-Host "    SwapNodeConfig::from_network(&NetworkConfig) reuses your existing config"
Write-Host "  tests: two_nodes_full_swap_over_tcp - Offer -> Accept -> XmrLocked ->"
Write-Host "    GhostLocked (preimage) -> Claim across two live nodes on 127.0.0.1"
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  - opacusd wiring: SwapNodeConfig::from_network(&cfg), SwapNode::start(),"
Write-Host "    feed live block heights, drive lock/claim via node.net() from the wallet"
Write-Host "  - run integrate_wallet_tx.ps1 if not yet done (shielded tx flow)"
