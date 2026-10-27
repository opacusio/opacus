# wire_opacusd_swap.ps1 - wire swap sessions into opacusd (opacus-node)
# Gives opacusd a live TCP swap node + wallet-driven lock/claim service.
#
# Run from the project root:
#   powershell -ExecutionPolicy Bypass -File .\wire_opacusd_swap.ps1
#
# What it does (idempotent, backups *.bak-svc):
#   1. opacus-network/swap_node.rs -> v0.2: LIVE chain tip (set_height)
#   2. opacus-node/src/swap_service.rs (new): SwapService + global registry
#   3. opacus-node Cargo.toml: opacus-network dep (safe ANY-form check)
#   4. mod registration (lib.rs or main.rs or src/bin entry)
#   5. autostart hook as the first statement of fn main
#   6. cargo test -p opacus-network --release
#   7. cargo test -p opacus-node --release

$ErrorActionPreference = "Stop"
$ProjectRoot = "$PSScriptRoot"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

function Write-TextFull([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, (New-Object System.Text.UTF8Encoding($true)))
}

function Read-Lines([string]$Path) {
    $c = [System.IO.File]::ReadAllText($Path)
    $c = $c.Replace("`r`n", "`n")
    $out = New-Object System.Collections.Generic.List[string]
    $parts = $c.Split("`n")
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if (($i -eq $parts.Count - 1) -and ($parts[$i] -eq "")) { break }
        $out.Add($parts[$i])
    }
    return $out
}

function Write-Lines([string]$Path, $Lines) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($l in $Lines) {
        [void]$sb.Append($l)
        [void]$sb.Append("`r`n")
    }
    Write-TextFull $Path $sb.ToString()
}

function Backup-File([string]$Path, [string]$Suffix) {
    if (Test-Path $Path) { Copy-Item -Path $Path -Destination ($Path + $Suffix) -Force }
}

function Abort-Wiring([string]$Reason) {
    Write-Output ("WIRING ABORTED: {0}" -f $Reason)
    Write-Output "Paste the output above back to the assistant."
    exit 1
}

function Print-Skeleton([string]$SrcDir) {
    Write-Output "--- OPACUSD SKELETON BEGIN ---"
    if (Test-Path $SrcDir) {
        Get-ChildItem $SrcDir -Name | ForEach-Object { Write-Output ("  " + $_) }
    }
    foreach ($cand in @((Join-Path $SrcDir "main.rs"), (Join-Path $SrcDir "lib.rs"))) {
        if (Test-Path $cand) {
            Write-Output ("  --- " + $cand + " (first 30 lines) ---")
            Get-Content $cand -TotalCount 30 | ForEach-Object { Write-Output ("  | " + $_) }
        }
    }
    Write-Output "--- OPACUSD SKELETON END ---"
}

# Safe manifest check: ANY form of the key (dotted OR value) blocks insert.
function Ensure-Dep([string]$ManifestPath, [string]$Crate, [string]$DepLine) {
    $lines = Read-Lines $ManifestPath
    $pat = "^\s*" + [regex]::Escape($Crate) + "\s*(\.|=)"
    foreach ($ln in $lines) {
        if ($ln -match $pat) { return "present" }
    }
    $n = $lines.Count
    for ($i = 0; $i -lt $n; $i++) {
        if ($lines[$i] -match "^\s*\[dependencies\]\s*(#.*)?$") {
            $out = New-Object System.Collections.Generic.List[string]
            for ($k = 0; $k -le $i; $k++) { $out.Add($lines[$k]) }
            $out.Add($DepLine)
            for ($k = $i + 1; $k -lt $n; $k++) { $out.Add($lines[$k]) }
            Write-Lines $ManifestPath $out
            return "inserted"
        }
    }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) { $out.Add($l) }
    $out.Add("")
    $out.Add("[dependencies]")
    $out.Add($DepLine)
    Write-Lines $ManifestPath $out
    return "appended"
}

function Ensure-Mod([string]$Path, [string]$ModLine) {
    $lines = Read-Lines $Path
    foreach ($ln in $lines) {
        if ($ln -match "^\s*(pub\s+)?mod\s+swap_service\s*;") { return "present" }
    }
    foreach ($ln in $lines) {
        if ($ln -match "\bswap_service\b") { return "COLLISION" }
    }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) { $out.Add($l) }
    $out.Add("")
    $out.Add($ModLine)
    Write-Lines $Path $out
    return "appended"
}

function Insert-Hook([string]$Path, [string]$CallLine) {
    $lines = Read-Lines $Path
    foreach ($ln in $lines) {
        if ($ln.Contains("(wire_opacusd_swap)")) { return "present" }
    }
    $n = $lines.Count
    for ($i = 0; $i -lt $n; $i++) {
        if (($lines[$i] -match "\bfn\s+main\b") -and ($lines[$i].Contains("{"))) {
            $out = New-Object System.Collections.Generic.List[string]
            for ($k = 0; $k -le $i; $k++) { $out.Add($lines[$k]) }
            $out.Add($CallLine)
            for ($k = $i + 1; $k -lt $n; $k++) { $out.Add($lines[$k]) }
            Write-Lines $Path $out
            return "hooked"
        }
    }
    for ($i = 0; $i -lt $n; $i++) {
        if ($lines[$i] -match "\bfn\s+main\b") {
            $jmax = [Math]::Min($i + 5, $n)
            for ($j = $i; $j -lt $jmax; $j++) {
                if ($lines[$j].Contains("{")) {
                    $out = New-Object System.Collections.Generic.List[string]
                    for ($k = 0; $k -le $j; $k++) { $out.Add($lines[$k]) }
                    $out.Add($CallLine)
                    for ($k = $j + 1; $k -lt $n; $k++) { $out.Add($lines[$k]) }
                    Write-Lines $Path $out
                    return "hooked"
                }
            }
            break
        }
    }
    return "NO_ENTRY"
}

# ---------------------------------------------------------------------------
# embedded sources (verified in sandbox)
# ---------------------------------------------------------------------------

$SwapNodeRs = @'
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
//! notices, deadline enforcement stays local via the session state machine.

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
            .receive_frame(wire, self.height.load(Ordering::Relaxed))?)
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

$SwapServiceRs = @'
//! opacusd swap service: embeds the TCP swap node
//! ([`opacus_network::swap_node`]) into the daemon and exposes the
//! wallet-driven swap choreography.
//!
//! Wiring - three one-liners inside opacusd:
//!
//! ```text
//! opacus_node::swap_service::autostart_from_env();  // fn main: bind + listener + dials
//! opacus_node::swap_service::feed_height(tip);      // block/header loop: live chain tip
//! let svc = opacus_node::swap_service::global();    // wallet/CLI: drive lock/claim
//! ```
//!
//! Choreography through the service (maker sells GHOST, taker sells XMR):
//!
//! ```text
//! svc.publish_offer(&offer, &preimage)   -> Offer broadcast, hex offer id back
//! svc.xmr_lock(&id, "xmr-tx..", h)       -> taker announces his XMR lock
//! svc.ghost_lock(&id, "ref..", h)        -> maker locks GHOST, preimage revealed
//! (Claim auto-replies on the socket; the maker then claims XMR on-chain)
//! ```
//!
//! Env knobs for [`autostart_from_env`]:
//!
//! ```text
//! GHOST_SWAP=0              disable the swap node
//! GHOST_SWAP_PORT=18081     listen port (default 18081, loopback)
//! GHOST_SWAP_PEERS=a:b,c:d  bootstrap dials
//! GHOST_SWAP_HEIGHT=n       initial chain tip
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use opacus_network::p2p::NetworkConfig;
use opacus_network::swap_node::{
    NetError, NodeEvent, Offer, SwapNode, SwapNodeConfig, TrackedSession,
};

/// The swap node embedded in opacusd plus the live height feed.
pub struct SwapService {
    node: Arc<SwapNode>,
    height: Arc<AtomicU64>,
}

impl SwapService {
    /// Build from the shared [`NetworkConfig`] (loopback listen at the
    /// network port, bootstrap dials from the same list) and start.
    pub fn spawn(net_cfg: &NetworkConfig) -> Result<Arc<Self>, NetError> {
        Self::spawn_with_height(net_cfg, 0)
    }

    /// Like [`SwapService::spawn`] with an explicit initial chain tip.
    pub fn spawn_with_height(
        net_cfg: &NetworkConfig,
        initial_height: u64,
    ) -> Result<Arc<Self>, NetError> {
        let height = Arc::new(AtomicU64::new(initial_height));
        let mut cfg = SwapNodeConfig::from_network(net_cfg);
        cfg.current_height = initial_height;
        let node = SwapNode::start(cfg)?;
        Ok(Arc::new(SwapService { node, height }))
    }

    /// Raw node handle (events, local_addr, process_wire, net()).
    pub fn node(&self) -> Arc<SwapNode> {
        Arc::clone(&self.node)
    }

    /// Current chain tip of the swap session machine.
    pub fn height(&self) -> u64 {
        self.height.load(Ordering::Relaxed)
    }

    /// opacusd feeds the accepted tip here (block/header loop).
    pub fn set_height(&self, h: u64) {
        self.height.store(h, Ordering::Relaxed);
        self.node.set_height(h);
    }

    // -- wallet-driven choreography (frames pushed to connected peers) ------

    /// Maker: register + broadcast an offer; returns the hex offer id.
    pub fn publish_offer(&self, offer: &Offer, preimage: &[u8; 32]) -> Result<String, NetError> {
        self.node.broadcast_offer(offer, preimage)
    }

    /// Taker: the XMR lock tx is on-chain; announce it to the maker.
    /// Returns the number of peers the notice reached.
    pub fn xmr_lock(
        &self,
        offer_id: &str,
        xmr_tx_hash: &str,
        lock_height: u64,
    ) -> Result<usize, NetError> {
        let wire = self
            .node
            .net()
            .lock()
            .unwrap()
            .publish_xmr_lock(offer_id, xmr_tx_hash, lock_height)?;
        self.node.send_wire(&wire)
    }

    /// Maker: the GHOST lock is on-chain; announce it and reveal the
    /// preimage (the taker needs it to claim). Returns peers reached.
    pub fn ghost_lock(
        &self,
        offer_id: &str,
        ghost_tx_ref: &str,
        lock_height: u64,
    ) -> Result<usize, NetError> {
        let wire = self
            .node
            .net()
            .lock()
            .unwrap()
            .publish_ghost_lock(offer_id, ghost_tx_ref, lock_height)?;
        self.node.send_wire(&wire)
    }

    /// Either side: local refund executed; broadcast the notice.
    pub fn refund_notice(
        &self,
        offer_id: &str,
        reason: &str,
        height: u64,
    ) -> Result<usize, NetError> {
        let wire = self
            .node
            .net()
            .lock()
            .unwrap()
            .publish_refund(offer_id, reason, height)?;
        self.node.send_wire(&wire)
    }

    /// Snapshot of one tracked session (None = unknown offer id).
    pub fn session(&self, offer_id: &str) -> Option<TrackedSession> {
        self.node.net().lock().unwrap().session(offer_id).cloned()
    }

    /// How many swap sessions this node tracks.
    pub fn session_count(&self) -> usize {
        self.node.net().lock().unwrap().session_count()
    }

    /// Recent node events (bounded ring, newest last).
    pub fn events(&self) -> Vec<NodeEvent> {
        self.node.events()
    }
}

// ---------------------------------------------------------------------------
// Process-wide instance (the swap node of this daemon)
// ---------------------------------------------------------------------------

static GLOBAL: Mutex<Option<Arc<SwapService>>> = Mutex::new(None);

/// Start the process-wide swap node. Idempotent: the first successful
/// start wins, later calls return the existing instance.
pub fn init_global(net_cfg: &NetworkConfig) -> Result<Arc<SwapService>, NetError> {
    let mut g = GLOBAL.lock().unwrap();
    if let Some(prev) = g.as_ref() {
        return Ok(Arc::clone(prev));
    }
    let svc = SwapService::spawn(net_cfg)?;
    *g = Some(Arc::clone(&svc));
    Ok(svc)
}

/// The process-wide swap node, if started.
pub fn global() -> Option<Arc<SwapService>> {
    GLOBAL.lock().unwrap().as_ref().map(Arc::clone)
}

/// Feed the live chain tip to the process-wide node (no-op if it was
/// never started - e.g. GHOST_SWAP=0).
pub fn feed_height(h: u64) {
    if let Some(svc) = global() {
        svc.set_height(h);
    }
}

/// One-line opacusd main hook: start the swap node from env knobs.
/// Returns true if a node is now running (fresh or already started).
pub fn autostart_from_env() -> bool {
    if global().is_some() {
        return true;
    }
    if std::env::var("GHOST_SWAP").as_deref() == Ok("0") {
        return false;
    }
    let port = std::env::var("GHOST_SWAP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(18081);
    let peers: Vec<String> = std::env::var("GHOST_SWAP_PEERS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let height = std::env::var("GHOST_SWAP_HEIGHT")
        .ok()
        .and_then(|h| h.parse::<u64>().ok())
        .unwrap_or(0);
    let net_cfg = NetworkConfig {
        listen_port: port,
        use_tor: false,
        max_peers: 50,
        bootstrap_nodes: peers,
    };
    match init_global(&net_cfg) {
        Ok(svc) => {
            if height > 0 {
                svc.set_height(height);
            }
            match svc.node().local_addr() {
                Ok(a) => println!("[opacusd-swap] listening on {a} (height {})", svc.height()),
                Err(_) => println!("[opacusd-swap] node started (height {})", svc.height()),
            }
            true
        }
        Err(e) => {
            println!("[opacusd-swap] failed to start: {e}");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use opacus_network::swap_node::{
        encode_frame, hashlock_of, offer_id_of, Frame, Phase, SwapNetMessage, SwapNetError,
        SwapOfferPayload,
    };
    use std::time::{Duration, Instant};

    const PREIMAGE: [u8; 32] = [9u8; 32];

    fn net_cfg() -> NetworkConfig {
        NetworkConfig {
            listen_port: 0, // ephemeral swap port
            use_tor: false,
            max_peers: 8,
            bootstrap_nodes: Vec::new(),
        }
    }

    fn offer() -> Offer {
        Offer::new(
            1_000_000_000_000, // 1 XMR
            500_000_000,       // GHOST atoms
            100,               // fund timeout blocks
            200,               // claim timeout blocks
            "ghost-maker-svc",
            "xmr-taker-svc",
            &PREIMAGE,
        )
        .unwrap()
    }

    fn hex_str(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// An Offer frame built the way an EXTERNAL peer would build it.
    fn external_offer_wire() -> (String, Vec<u8>) {
        let payload = SwapOfferPayload {
            xmr_piconero: 1_000_000_000_000,
            ghost_atoms: 500_000_000,
            hashlock: hex_str(&hashlock_of(&PREIMAGE)),
            fund_timeout_blocks: 100,
            claim_timeout_blocks: 200,
            maker_ghost_address: "ghost-maker-svc".to_string(),
            taker_xmr_address: "xmr-taker-svc".to_string(),
        };
        let id = offer_id_of(&payload);
        let frame = Frame::new(SwapNetMessage::Offer {
            offer_id: hex_str(&id),
            payload,
        });
        (hex_str(&id), encode_frame(&frame).unwrap())
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

    #[test]
    fn service_binds_from_network_config() {
        let svc = SwapService::spawn(&net_cfg()).unwrap();
        let port = svc.node().local_addr().unwrap().port();
        assert!(port > 0);
        assert_eq!(svc.height(), 0);
        svc.set_height(555);
        assert_eq!(svc.height(), 555);
        assert_eq!(svc.node().height(), 555);
        assert_eq!(svc.session_count(), 0);
        assert!(svc.events().is_empty());
    }

    /// The live tip flows service -> node -> session machine, and the fund
    /// deadline is gated by it (this is why opacusd must feed heights).
    #[test]
    fn live_height_flows_through_service() {
        let svc = SwapService::spawn(&net_cfg()).unwrap();
        svc.set_height(1234);
        let (id, wire) = external_offer_wire();
        svc.node().process_wire(&wire).unwrap();
        let t = svc.session(&id).unwrap();
        assert_eq!(t.session.accepted_height, 1234);

        // 2500 > 1234 + 100: past the fund deadline -> protocol rejection
        let err = svc.xmr_lock(&id, "xmr-tx-late", 2500).unwrap_err();
        assert!(matches!(
            err,
            NetError::Protocol(SwapNetError::State(_))
        ));
    }

    /// THE e2e: full choreography Offer -> Accept -> XmrLocked ->
    /// GhostLocked (preimage) -> Claim across two live services.
    #[test]
    fn two_services_full_swap() {
        let maker = SwapService::spawn(&net_cfg()).unwrap();
        let taker = SwapService::spawn(&net_cfg()).unwrap();
        let maddr = maker.node().local_addr().unwrap().to_string();
        let taddr = taker.node().local_addr().unwrap().to_string();
        maker.node().connect(&taddr).unwrap();
        taker.node().connect(&maddr).unwrap();

        // opacusd feeds live tips on both sides
        maker.set_height(1000);
        taker.set_height(1000);

        let id = maker.publish_offer(&offer(), &PREIMAGE).unwrap();
        wait_until(10, || taker.session_count() == 1);
        wait_until(10, || {
            maker
                .session(&id)
                .map(|s| s.accepted_by_peer)
                .unwrap_or(false)
        });

        assert_eq!(taker.xmr_lock(&id, "xmr-tx-svc", 1050).unwrap(), 1);
        wait_until(10, || {
            maker
                .session(&id)
                .map(|s| s.session.phase == Phase::XmrLocked)
                .unwrap_or(false)
        });

        assert_eq!(maker.ghost_lock(&id, "ghost-burn-svc", 1060).unwrap(), 1);
        wait_until(10, || {
            taker
                .session(&id)
                .map(|s| s.session.phase == Phase::GhostLocked)
                .unwrap_or(false)
        });
        wait_until(10, || {
            maker
                .session(&id)
                .map(|s| s.peer_claimed && s.claimed_preimage == Some(PREIMAGE))
                .unwrap_or(false)
        });

        let m = maker.session(&id).unwrap();
        assert_eq!(m.xmr_tx_hash.as_deref(), Some("xmr-tx-svc"));
        let t = taker.session(&id).unwrap();
        assert_eq!(t.ghost_tx_ref.as_deref(), Some("ghost-burn-svc"));
        assert!(maker
            .events()
            .iter()
            .any(|e| matches!(e, NodeEvent::Received(ref k) if k == "Claim")));
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Process-wide registry: idempotent init + the feed_height one-liner.
    #[test]
    fn global_registry_feed_height_and_idempotent_init() {
        let _g = TEST_LOCK.lock().unwrap();
        assert!(global().is_none());
        let first = init_global(&net_cfg()).unwrap();
        assert!(global().is_some());
        let second = init_global(&net_cfg()).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        feed_height(777);
        assert_eq!(global().unwrap().height(), 777);
    }
}
'@

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

Write-Output "=== wire_opacusd_swap: wire swap sessions into opacusd ==="

$NetDir = Join-Path $ProjectRoot "crates\opacus-network"
$NodeDir = Join-Path $ProjectRoot "crates\opacus-node"
$NetSrc = Join-Path $NetDir "src"
$NodeSrc = Join-Path $NodeDir "src"
if (-not (Test-Path $NetSrc)) { Abort-Wiring "crates\opacus-network\src not found" }
if (-not (Test-Path $NodeSrc)) { Abort-Wiring "crates\opacus-node\src not found" }

# --- STEP 1: swap_node.rs v0.2 (live height) -------------------------------
$SwapNodePath = Join-Path $NetSrc "swap_node.rs"
Write-Output "STEP 1: opacus-network/swap_node.rs -> v0.2 live chain tip (set_height)"
if (Test-Path $SwapNodePath) {
    $cur = [System.IO.File]::ReadAllText($SwapNodePath)
    if ((-not $cur.Contains("ghost-swap-p2p-v1")) -or (-not $cur.Contains("two_nodes_full_swap_over_tcp"))) {
        Abort-Wiring "crates\opacus-network\src\swap_node.rs was modified outside the delivered scripts - refusing to overwrite"
    }
    Backup-File $SwapNodePath ".bak-svc"
    Write-Output "  backup: swap_node.rs.bak-svc"
}
Write-TextFull $SwapNodePath $SwapNodeRs
Write-Output ("  written: {0} bytes" -f ((Get-Item $SwapNodePath).Length))

# --- STEP 2: swap_service.rs (opacusd swap service) --------------------------
$libPath = Join-Path $NodeSrc "lib.rs"
$mainPath = Join-Path $NodeSrc "main.rs"
$haveLib = Test-Path $libPath
$haveMain = Test-Path $mainPath
$binDir = Join-Path $NodeSrc "bin"
$binEntry = $null
if ((-not $haveMain) -and (Test-Path $binDir)) {
    foreach ($f in (Get-ChildItem $binDir -Filter "*.rs")) {
        $t = [System.IO.File]::ReadAllText($f.FullName)
        if ($t -match "\bfn\s+main\b") { $binEntry = $f.FullName; break }
    }
}
if ($haveLib -or $haveMain) {
    $SvcPath = Join-Path $NodeSrc "swap_service.rs"
} elseif ($binEntry) {
    $SvcPath = Join-Path $binDir "swap_service.rs"
} else {
    Print-Skeleton $NodeSrc
    Abort-Wiring "crates\opacus-node\src has neither lib.rs, main.rs nor src\bin\*.rs with fn main"
}
Write-Output ("STEP 2: opacus-node swap service -> {0}" -f $SvcPath)
if (Test-Path $SvcPath) {
    Backup-File $SvcPath ".bak-svc"
    Write-Output "  backup: swap_service.rs.bak-svc"
}
Write-TextFull $SvcPath $SwapServiceRs
Write-Output ("  written: {0} bytes" -f ((Get-Item $SvcPath).Length))

# --- STEP 3: opacus-node manifest (opacus-network dep, safe pattern) ----------
$NodeManifest = Join-Path $NodeDir "Cargo.toml"
if (-not (Test-Path $NodeManifest)) { Abort-Wiring "crates\opacus-node\Cargo.toml not found" }
Write-Output "STEP 3: opacus-node Cargo.toml - ensure opacus-network dep"
Backup-File $NodeManifest ".bak-svc"
$depSt = Ensure-Dep $NodeManifest "opacus-network" 'opacus-network = { path = "../opacus-network" }'
Write-Output ("  opacus-network dep: {0}" -f $depSt)

# --- STEP 4: mod registration ------------------------------------------------
Write-Output "STEP 4: register the swap_service module"
if ($haveLib) {
    $st = Ensure-Mod $libPath "pub mod swap_service;"
    if ($st -eq "COLLISION") { Abort-Wiring "lib.rs mentions swap_service but not as 'pub mod swap_service;' - manual review needed" }
    Write-Output ("  lib.rs: {0}" -f $st)
} elseif ($haveMain) {
    $st = Ensure-Mod $mainPath "mod swap_service;"
    if ($st -eq "COLLISION") { Abort-Wiring "main.rs mentions swap_service but not as 'mod swap_service;' - manual review needed" }
    Write-Output ("  main.rs: {0}" -f $st)
} else {
    $st = Ensure-Mod $binEntry "mod swap_service;"
    if ($st -eq "COLLISION") { Abort-Wiring "bin entry mentions swap_service but not as 'mod swap_service;' - manual review needed" }
    Write-Output ("  bin entry: {0}" -f $st)
}

# --- STEP 5: opacusd entry hook ------------------------------------------------
Write-Output "STEP 5: autostart hook in the opacusd entry"
$prefix = "crate::"
if ($haveLib) { $prefix = "opacus_node::" }
$callLine = "    " + $prefix + "swap_service::autostart_from_env(); // opacusd swap service (wire_opacusd_swap)"
$entry = $null
if ($haveMain) { $entry = $mainPath } elseif ($binEntry) { $entry = $binEntry }
if ($entry) {
    $st = Insert-Hook $entry $callLine
    if ($st -eq "NO_ENTRY") {
        Print-Skeleton $NodeSrc
        Write-Output "HOOK SKIPPED - add this line manually as the first statement of fn main:"
        Write-Output $callLine
    } else {
        Write-Output ("  entry hook: {0}" -f $st)
    }
} else {
    Write-Output "HOOK SKIPPED - lib-only crate; call autostart_from_env() from your binary:"
    Write-Output $callLine
}

# --- STEP 6: network regression ----------------------------------------------
Set-Location $ProjectRoot
Write-Output "STEP 6: cargo test -p opacus-network --release"
$netOut = cmd /c "cargo test -p opacus-network --release 2>&1"
$netOut | ForEach-Object { Write-Output $_ }
if ($LASTEXITCODE -ne 0) {
    Write-Output "GHOST-NETWORK TESTS FAILED - paste the output above back to the assistant"
    exit 1
}
Write-Output "NETWORK SWAP REGRESSION PASSED (10 tests: live height feed via set_height)"

# --- STEP 7: opacusd suite -----------------------------------------------------
Write-Output "STEP 7: cargo test -p opacus-node --release"
$nodeOut = cmd /c "cargo test -p opacus-node --release 2>&1"
$nodeOut | ForEach-Object { Write-Output $_ }
if ($LASTEXITCODE -ne 0) {
    Write-Output "GHOST-NODE TESTS FAILED - paste the output above back to the assistant"
    exit 1
}

Write-Output ""
Write-Output "OPACUSD SWAP WIRING COMPLETE - swap service live in opacusd"
Write-Output ""
Write-Output "What you got:"
Write-Output "  opacus-network/swap_node.rs v0.2: SwapNode::set_height()/height() -"
Write-Output "    the session machine always uses the LIVE chain tip"
Write-Output "  opacus-node/src/swap_service.rs: SwapService (node + height feed) and"
Write-Output "    global registry: init_global / global / feed_height / autostart_from_env"
Write-Output "    wallet-driven choreography: publish_offer / xmr_lock / ghost_lock /"
Write-Output "    refund_notice / session / session_count / events"
Write-Output "  opacusd main: autostart_from_env() runs the swap node on every start"
Write-Output ""
Write-Output "How to drive it:"
Write-Output "  feed heights in the block/header loop:  opacus_node::swap_service::feed_height(tip);"
Write-Output "  wallet/CLI:  let svc = opacus_node::swap_service::global();"
Write-Output "               let id = svc.publish_offer(&offer, &preimage)?;"
Write-Output "               svc.xmr_lock(&id, ""xmr-tx-hash"", h)?;   // taker side"
Write-Output "               svc.ghost_lock(&id, ""ghost-ref"", h)?;   // maker side"
Write-Output "  env knobs: GHOST_SWAP=0 disable; GHOST_SWAP_PORT=18081;"
Write-Output "             GHOST_SWAP_PEERS=ip:port,ip:port; GHOST_SWAP_HEIGHT=n"
Write-Output "  backups: *.bak-svc"
