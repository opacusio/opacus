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
//! v0.2 (opacusd wiring): the node holds a LIVE chain tip
//! ([`SwapNode::set_height`]) instead of a frozen config height - opacusd
//! feeds it on every accepted block and every protocol step reads the
//! fresh value.
//!
//! v0.1 limitations: direct 1:1 dials only (no gossip/discovery - the full
//! libp2p stack lands in v0.3); a protocol violation closes the connection
//! silently (the wire protocol has no Error frame yet); Refund frames are
//! notices, and the WG-18 deadline sweep ([`SwapNode::enforce_deadlines`])
//! auto-refunds expired sessions on every height feed.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::p2p::NetworkConfig;

// Re-exports for embedders (opacusd wiring): the swap service in opacus-node
// consumes the protocol types through opacus-network only, so opacus-node
// needs NO direct opacus-bridge dependency.
pub use opacus_bridge::swap_p2p::{
    decode_frame, encode_frame, offer_id_of, Frame, SwapNet, SwapNetError, SwapNetMessage,
    SwapOfferPayload, TrackedSession,
};
pub use opacus_bridge::xmr_swap::{hashlock_of, Offer, Phase, Role, SwapError, SwapSession};

pub use opacus_bridge::clsag::one_time_keys;
pub use opacus_bridge::swap_p2p::OfferAdaptor;

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
    /// Hard cap on concurrently tracked swap sessions (Net-2). A NEW
    /// inbound Offer arriving while the registry is at the cap is
    /// dropped before the state machine (Rejected event, no reply, the
    /// connection stays open); already-tracked offers keep their exact
    /// DuplicateOffer semantics and non-Offer frames keep flowing.
    /// v0.1 never evicts sessions, so the cap also bounds the
    /// registry's lifetime.
    pub max_sessions: usize,
    /// INITIAL block height; afterwards the live value is driven by
    /// [`SwapNode::set_height`] (opacusd feeds it per accepted block).
    pub current_height: u64,
}

impl Default for SwapNodeConfig {
    fn default() -> Self {
        SwapNodeConfig {
            listen_addr: "127.0.0.1:18081".to_string(),
            bootstrap_peers: Vec::new(),
            read_timeout: Duration::from_secs(30),
            max_frame_len: 1_048_576,
            max_sessions: 64,
            current_height: 0,
        }
    }
}

impl SwapNodeConfig {
    /// Derive a swap node config from the shared network config: listen on
    /// loopback at the configured port (18080 by default) and dial the
    /// configured bootstrap nodes.
    pub fn from_network(cfg: &NetworkConfig) -> Self {
        let out = SwapNodeConfig {
            listen_addr: format!("127.0.0.1:{}", cfg.listen_port),
            bootstrap_peers: cfg.bootstrap_nodes.clone(),
            ..Default::default()
        };
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
    /// Live chain tip; every protocol step reads it fresh.
    height: Arc<AtomicU64>,
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
        let height = Arc::new(AtomicU64::new(cfg.current_height));
        let node = Arc::new(SwapNode {
            cfg,
            height,
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

    /// Feed the live chain tip (opacusd calls this on every accepted block).
    /// Later protocol steps (inbound frame validation, acceptance
    /// timestamps, fund/claim deadlines) read the fresh value.
    pub fn set_height(&self, h: u64) {
        self.height.store(h, Ordering::Relaxed);
    }

    /// Current chain tip as seen by the session machine.
    pub fn height(&self) -> u64 {
        self.height.load(Ordering::Relaxed)
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
            for stream in node.listener.incoming().flatten() {
                node.attach(stream);
            }
        });
    }

    fn attach(self: &Arc<Self>, stream: TcpStream) {
        let node = Arc::clone(self);
        std::thread::spawn(move || Self::conn_loop(&node, stream));
    }

    /// Attach an EXTERNAL socket to this swap node. The N3b Upgrade
    /// frame hands an authenticated net connection over to the swap
    /// plane: the net node drops its bookkeeping and this conn_loop
    /// owns the socket from the clean frame boundary on.
    pub fn adopt_stream(self: &Arc<Self>, stream: TcpStream) {
        self.attach(stream);
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
    /// id. The offer is tracked even with zero peers connected. WG-21:
    /// the broadcast frame embeds the one-time key sidecar derived from
    /// the preimage (see `SwapNet::publish_offer`).
    pub fn broadcast_offer(&self, offer: &Offer, preimage: &[u8; 32]) -> Result<String, NetError> {
        let (id, wire) = self
            .net
            .lock()
            .unwrap()
            .publish_offer(offer.clone(), *preimage)?;
        self.send_wire(&wire)?;
        Ok(id)
    }

    /// Process one inbound wire frame without any socket: the pure protocol
    /// step of conn_loop (handy for tests and embedded hosts). Returns the
    /// encoded auto-reply frames. WG-21: Offer sidecars are validated
    /// fail-closed inside `SwapNet::receive_frame` before this returns.
    ///
    /// Net-2 admission cap: a NEW Offer arriving while the session
    /// registry is at `max_sessions` is dropped before it reaches the
    /// state machine - no reply, no error, the connection stays open
    /// (a Rejected event marks the drop). Offers already tracked keep
    /// their exact DuplicateOffer semantics; every non-Offer frame is
    /// unaffected. This bounds the registry against an Offer flood
    /// through the authenticated Upgrade plane.
    pub fn process_wire(&self, wire: &[u8]) -> Result<Vec<Vec<u8>>, NetError> {
        let offer_capped = match decode_frame(wire) {
            Ok(frame) => match frame.msg {
                SwapNetMessage::Offer { ref offer_id, .. } => {
                    let net = self.net.lock().unwrap();
                    net.session(offer_id).is_none() && net.session_count() >= self.cfg.max_sessions
                }
                _ => false,
            },
            Err(_) => false,
        };
        if offer_capped {
            self.log(NodeEvent::Rejected(format!(
                "offer cap reached ({} sessions)",
                self.cfg.max_sessions
            )));
            return Ok(Vec::new());
        }
        Ok(self
            .net
            .lock()
            .unwrap()
            .receive_frame(wire, self.height.load(Ordering::Relaxed))?)
    }

    /// WG-18 deadline sweep: refund every tracked session whose protocol
    /// deadline passed at the current node height and broadcast the Refund
    /// notice to all dialed peers. Returns the hex offer ids that were
    /// swept (each is also logged as a Rejected event with the reason).
    ///
    /// Sweeping is idempotent: a refunded session leaves the eligible
    /// phase, so later sweeps never re-report it. opacusd calls this on
    /// every accepted block through `feed_height`; it is also safe to
    /// call directly at any cadence. Deadline arithmetic saturates, so a
    /// hostile offer timeout can never panic the node here.
    pub fn enforce_deadlines(&self) -> Vec<String> {
        let now = self.height.load(Ordering::Relaxed);
        let expired = self.net.lock().unwrap().expired_sessions(now);
        let mut swept = Vec::new();
        for e in expired {
            let id_hex = hex::encode(e.offer_id);
            match self
                .net
                .lock()
                .unwrap()
                .publish_refund(&id_hex, e.reason, now)
            {
                Ok(wire) => {
                    let _ = self.send_wire(&wire);
                    self.log(NodeEvent::Rejected(format!(
                        "auto-refund {id_hex} ({})",
                        e.reason
                    )));
                    swept.push(id_hex);
                }
                Err(_) => {
                    // The state machine refused (a racing sweep or an
                    // inbound frame moved the session first); the next
                    // sweep re-evaluates from the fresh phase.
                }
            }
        }
        swept
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
    use std::time::Instant;

    const PREIMAGE: [u8; 32] = [7u8; 32];

    /// WG-18: the node deadline sweep refunds an expired taker session,
    /// logs the auto-refund and stays idempotent afterwards.
    #[test]
    fn deadline_sweep_refunds_expired_taker_session() {
        let node = SwapNode::start(test_cfg()).unwrap();
        let (id, wire) = external_offer_wire();
        node.process_wire(&wire).unwrap(); // taker Accepted @ cfg height 1000

        // Inside the fund window (1000 + 100): nothing to sweep.
        assert!(node.enforce_deadlines().is_empty());
        assert_eq!(node.net().lock().unwrap().session_count(), 1);

        // Past the fund window: sweep refunds + broadcasts the notice.
        node.set_height(1101);
        let swept = node.enforce_deadlines();
        assert_eq!(swept, vec![id.clone()]);
        let net = node.net();
        let t = net.lock().unwrap().session(&id).cloned().unwrap();
        assert_eq!(t.session.phase, Phase::Refunded);
        assert!(!t.peer_refunded); // local auto-refund, not a peer frame
        assert!(node
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Rejected(m) if m.contains("auto-refund"))));

        // Idempotent: the refunded session is never re-reported.
        assert!(node.enforce_deadlines().is_empty());
    }

    /// WG-18: a maker session left in GhostLocked past the claim window is
    /// swept exactly once the deadline passes.
    #[test]
    fn deadline_sweep_refunds_maker_after_claim_window() {
        let node = SwapNode::start(test_cfg()).unwrap();
        // The node is the MAKER here (locally registered offer).
        let id = node.broadcast_offer(&offer(), &PREIMAGE).unwrap();

        // The taker announces his XMR lock (implicit accept @ 1050), then
        // the maker locks GHOST locally and reveals the preimage.
        let xmr_frame = Frame::new(SwapNetMessage::XmrLocked {
            offer_id: id.clone(),
            xmr_tx_hash: "xmr-tx-sweep".to_string(),
            height: 1050,
        });
        node.process_wire(&encode_frame(&xmr_frame).unwrap())
            .unwrap();
        node.net()
            .lock()
            .unwrap()
            .publish_ghost_lock(&id, "ghost-burn-sweep", 1060)
            .unwrap();

        // claim window: both_locked 1060 + 200 -> deadline 1260
        node.set_height(1260);
        assert!(node.enforce_deadlines().is_empty());
        node.set_height(1261);
        let swept = node.enforce_deadlines();
        assert_eq!(swept, vec![id.clone()]);
        let net = node.net();
        assert_eq!(
            net.lock()
                .unwrap()
                .session(&id)
                .cloned()
                .unwrap()
                .session
                .phase,
            Phase::Refunded
        );
    }

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
    /// (nothing registered locally). WG-21: published without a one-time
    /// key sidecar - the v1 wire shape that WG-21 receivers still accept.
    fn external_offer_wire() -> (String, Vec<u8>) {
        external_offer_wire_with(PREIMAGE)
    }

    /// Same, for an arbitrary preimage - distinct offers need distinct
    /// payloads (the offer id is blake3 over the canonical payload).
    fn external_offer_wire_with(preimage: [u8; 32]) -> (String, Vec<u8>) {
        let payload = SwapOfferPayload {
            xmr_piconero: 2_000_000_000_000,
            ghost_atoms: 1_000_000_000,
            hashlock: hex_str(&hashlock_of(&preimage)),
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

    /// opacusd wiring: heights are fed LIVE via set_height; an inbound Offer
    /// is stamped with the fresh tip and the fund deadline is gated by it.
    #[test]
    fn live_height_feed_gates_incoming_swap() {
        let node = SwapNode::start(test_cfg()).unwrap();
        assert_eq!(node.height(), 1000);
        node.set_height(2000);
        assert_eq!(node.height(), 2000);

        let (id, wire) = external_offer_wire();
        node.process_wire(&wire).unwrap();
        let t = node.net().lock().unwrap().session(&id).unwrap().clone();
        assert_eq!(t.session.accepted_height, 2000);

        // 2500 > 2000 + 100 (fund timeout): past the deadline, rejected
        let err = node
            .net()
            .lock()
            .unwrap()
            .publish_xmr_lock(&id, "xmr-tx-late", 2500)
            .unwrap_err();
        assert!(matches!(err, SwapNetError::State(SwapError::NotTimedOut)));

        // fresh node + fresh offer: inside the window it passes
        let node2 = SwapNode::start(test_cfg()).unwrap();
        node2.set_height(2000);
        let (id2, wire2) = external_offer_wire();
        node2.process_wire(&wire2).unwrap();
        node2
            .net()
            .lock()
            .unwrap()
            .publish_xmr_lock(&id2, "xmr-tx-live", 2100)
            .unwrap();
        let t2 = node2.net().lock().unwrap().session(&id2).unwrap().clone();
        assert_eq!(t2.session.phase, Phase::XmrLocked);
    }

    /// opacusd scenario: both nodes start at height 0 (pre-sync) and get
    /// LIVE tips fed before the swap; the full TCP choreography completes.
    #[test]
    fn two_nodes_zero_start_live_heights_full_swap() {
        let mut maker_cfg = test_cfg();
        maker_cfg.current_height = 0;
        let mut taker_cfg = test_cfg();
        taker_cfg.current_height = 0;
        let maker = SwapNode::start(maker_cfg).unwrap();
        let taker = SwapNode::start(taker_cfg).unwrap();
        maker
            .connect(&taker.local_addr().unwrap().to_string())
            .unwrap();
        taker
            .connect(&maker.local_addr().unwrap().to_string())
            .unwrap();

        // opacusd feeds live tips before the swap starts
        maker.set_height(3000);
        taker.set_height(3000);

        let id = maker.broadcast_offer(&offer(), &PREIMAGE).unwrap();
        wait_until(10, || taker.net().lock().unwrap().session_count() == 1);
        let t0 = taker.net().lock().unwrap().session(&id).unwrap().clone();
        assert_eq!(t0.session.accepted_height, 3000);

        let lock = taker
            .net()
            .lock()
            .unwrap()
            .publish_xmr_lock(&id, "xmr-tx-live2", 3050)
            .unwrap();
        assert_eq!(taker.send_wire(&lock).unwrap(), 1);
        wait_until(10, || {
            maker
                .net()
                .lock()
                .unwrap()
                .session(&id)
                .map(|s| s.session.phase == Phase::XmrLocked)
                .unwrap_or(false)
        });

        let ghost = maker
            .net()
            .lock()
            .unwrap()
            .publish_ghost_lock(&id, "ghost-burn-live2", 3060)
            .unwrap();
        assert_eq!(maker.send_wire(&ghost).unwrap(), 1);
        wait_until(10, || {
            maker
                .net()
                .lock()
                .unwrap()
                .session(&id)
                .map(|s| s.peer_claimed && s.claimed_preimage == Some(PREIMAGE))
                .unwrap_or(false)
        });
        let m = maker.net().lock().unwrap().session(&id).unwrap().clone();
        assert_eq!(m.session.phase, Phase::GhostLocked);
        assert_eq!(m.xmr_tx_hash.as_deref(), Some("xmr-tx-live2"));
    }

    #[test]
    fn frame_io_roundtrip_and_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

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
        assert!(matches!(
            err,
            NetError::Protocol(SwapNetError::DuplicateOffer)
        ));
    }

    #[test]
    fn oversize_prefix_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
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
        assert!(maker
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Received(ref k) if k == "Claim")));
        assert!(taker
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Replied(ref k) if k == "Claim")));
    }

    /// Net-2: a NEW Offer arriving while the registry is at max_sessions
    /// is dropped - no reply, no session created, the connection stays
    /// alive (Rejected event) and the registry stays exactly at the cap;
    /// non-Offer frames keep flowing on the same node.
    #[test]
    fn offer_flood_capped_in_process() {
        let cfg = SwapNodeConfig {
            max_sessions: 2,
            ..test_cfg()
        };
        let node = SwapNode::start(cfg).unwrap();

        let (id1, w1) = external_offer_wire_with([1u8; 32]);
        let (_id2, w2) = external_offer_wire_with([2u8; 32]);
        let (_id3, w3) = external_offer_wire_with([3u8; 32]);

        assert_eq!(node.process_wire(&w1).unwrap().len(), 1); // Accept
        assert_eq!(node.process_wire(&w2).unwrap().len(), 1); // Accept
        assert_eq!(node.net().lock().unwrap().session_count(), 2);

        // the flood: a third NEW offer at cap -> dropped, not an error
        let replies = node.process_wire(&w3).unwrap();
        assert!(replies.is_empty());
        assert_eq!(node.net().lock().unwrap().session_count(), 2);
        assert!(node
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Rejected(m) if m.contains("offer cap"))));

        // non-Offer frames keep flowing: the taker-side session still
        // completes its GhostLocked -> Claim step after the cap drop
        // (the choreography needs XmrLocked before GhostLocked)
        node.net()
            .lock()
            .unwrap()
            .publish_xmr_lock(&id1, "xmr-tx-capped", 1020)
            .unwrap();
        let ghost = Frame::new(SwapNetMessage::GhostLocked {
            offer_id: id1,
            ghost_tx_ref: "ghost-burn-capped".to_string(),
            height: 1050,
            preimage: hex_str(&[1u8; 32]),
        });
        let replies = node.process_wire(&encode_frame(&ghost).unwrap()).unwrap();
        assert_eq!(replies.len(), 1);
        assert!(matches!(
            decode_frame(&replies[0]).unwrap().msg,
            SwapNetMessage::Claim { .. }
        ));
    }

    /// Net-2: an ALREADY tracked offer keeps its exact DuplicateOffer
    /// semantics even at cap (the cap only gates NEW sessions).
    #[test]
    fn offer_cap_keeps_duplicate_semantics() {
        let cfg = SwapNodeConfig {
            max_sessions: 1,
            ..test_cfg()
        };
        let node = SwapNode::start(cfg).unwrap();
        let (_id, wire) = external_offer_wire_with([9u8; 32]);
        node.process_wire(&wire).unwrap(); // registry now at cap (1/1)
        let err = node.process_wire(&wire).unwrap_err(); // retransmit
        assert!(matches!(
            err,
            NetError::Protocol(SwapNetError::DuplicateOffer)
        ));
        assert_eq!(node.net().lock().unwrap().session_count(), 1);
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

    /// WG-22: an Offer with a VALID but wrong one-time sidecar is tracked
    /// (fail-closed structural validation passes), but the later
    /// GhostLocked preimage fails the taker's re-derivation and the node
    /// rejects the frame (a protocol violation closes the connection).
    #[test]
    fn sidecar_mismatch_rejected_in_process() {
        let node = SwapNode::start(test_cfg()).unwrap();
        let (id, wire) = external_offer_wire();
        let mut frame = decode_frame(&wire).unwrap();
        let impostor = one_time_keys(&[0xAAu8; 32]);
        frame.adaptor = Some(OfferAdaptor::from_keys(&impostor));
        let wire = encode_frame(&frame).unwrap();
        node.process_wire(&wire).unwrap(); // taker Accepted (sidecar stored)

        node.net()
            .lock()
            .unwrap()
            .publish_xmr_lock(&id, "xmr-tx-wg22n", 1050)
            .unwrap();
        let ghost = Frame::new(SwapNetMessage::GhostLocked {
            offer_id: id,
            ghost_tx_ref: "ghost-burn-wg22n".to_string(),
            height: 1060,
            preimage: hex_str(&PREIMAGE),
        });
        let err = node
            .process_wire(&encode_frame(&ghost).unwrap())
            .unwrap_err();
        assert!(matches!(
            err,
            NetError::Protocol(SwapNetError::OneTimeKeyMismatch)
        ));
    }
}
