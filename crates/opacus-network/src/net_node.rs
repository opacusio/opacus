//! Authenticated network node (v0.6 networking, phase N2-b).
//!
//! [`NetNode`] glues the N1 handshake onto real TCP sockets and the N2-a
//! peer store into one control-plane node:
//!
//! * every connection runs the mutual DLEq handshake in both roles (the
//!   dialer is the Initiator, the listener is the Responder);
//! * a connection is STRICTLY single-shot (audit F5): exactly one Hello
//!   and one Auth per direction in the fixed frame order; after the
//!   handshake only Disco | Notes | Upgrade frames are accepted - any
//!   other frame (including a second handshake) closes the connection;
//! * right after the handshake both sides exchange one bounded Disco
//!   batch. The batch leads with a SELF-entry (our advertised dialable
//!   address), so the receiving store always gains an address worth
//!   dialing; the responder never records the raw inbound source address
//!   (that is the initiator's ephemeral port, not a dial address) - the
//!   initiator records the address it actually dialed;
//! * contacts land in the persistent `PeerStore` (`insert_or_touch` for
//!   direct dials, `merge_remote` for gossip, explicit save after every
//!   change);
//! * the transcript replay window is per node (shared `ReplayCache`),
//!   so a captured (Hello, Auth) pair cannot be replayed on a new
//!   connection;
//! * the declared frame length is checked BEFORE the body is allocated,
//!   so a lying prefix cannot force a huge allocation (default cap:
//!   `MAX_NET_FRAME`, closing the N1 backlog item on read_frame caps);
//! * the swap plane (N3b): a post-auth `Upgrade` frame hands the raw
//!   connection to the attached swap node; without an attachment every
//!   Upgrade is rejected and the connection closed;
//! * post-auth frames are transport-encrypted (Net-1): the handshake
//!   derives per-direction keys from a static-static ECDH over the
//!   DLEq-bound identity keys bound to the transcript; every sealed
//!   frame is mac(32) || ciphertext with a strictly sequential
//!   per-direction counter - tampering, replay and reordering close
//!   the connection. The Upgrade handover is the boundary: the net
//!   plane's last frame (Upgrade) is sealed, the adopted raw socket
//!   then speaks the swap protocol as before.
//!
//! std-only, thread-per-connection, mirroring `swap_node.rs` (opacusd
//! embeds this node through `opacus_node::net_service`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::handshake::{
    decode_net_frame, encode_net_frame, DiscoPeer, HandshakeError, HandshakeSide, NetMsg,
    ReplayCache, Role, SessionKeys, VerifiedPeer, DISCO_MAX_PEERS, MAX_NET_FRAME, REPLAY_CACHE_CAP,
    TRANSPORT_MAC_LEN,
};
use crate::identity::NodeIdentity;
use crate::notes::{note_id_hex_of, NoteBlob, NoteInbox, NOTES_MAX_COUNT, NOTE_INBOX_CAP};
use crate::p2p::PeerInfo;
use crate::peers::{PeerStore, PeerStoreError};
use crate::swap_node::SwapNode;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Net node errors (socket, handshake, peer store).
#[derive(Debug)]
pub enum NetNodeError {
    Io(std::io::Error),
    Handshake(HandshakeError),
    PeerStore(PeerStoreError),
}

impl std::fmt::Display for NetNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetNodeError::Io(e) => write!(f, "io: {e}"),
            NetNodeError::Handshake(e) => write!(f, "handshake: {e}"),
            NetNodeError::PeerStore(e) => write!(f, "peer store: {e}"),
        }
    }
}

impl std::error::Error for NetNodeError {}

impl From<std::io::Error> for NetNodeError {
    fn from(e: std::io::Error) -> Self {
        NetNodeError::Io(e)
    }
}

impl From<HandshakeError> for NetNodeError {
    fn from(e: HandshakeError) -> Self {
        NetNodeError::Handshake(e)
    }
}

impl From<PeerStoreError> for NetNodeError {
    fn from(e: PeerStoreError) -> Self {
        NetNodeError::PeerStore(e)
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Net node configuration.
#[derive(Clone, Debug)]
pub struct NetNodeConfig {
    /// Address to listen on ("ip:port"; port 0 = ephemeral).
    pub listen_addr: String,
    /// The dialable address advertised to peers as the Disco self-entry.
    /// Must parse as a `SocketAddr`. Loopback testing: any parseable
    /// ip:port; real deployments: the public ip:port of this node.
    pub advertise_addr: String,
    /// Peers to dial (and run the handshake with) on start.
    pub bootstrap_peers: Vec<String>,
    /// Per-read socket timeout; an idle authenticated peer is disconnected.
    pub read_timeout: Duration,
    /// Hard cap for one incoming frame (prefix + body); enforced BEFORE
    /// the body is allocated.
    pub max_frame_len: usize,
    /// Persistent peer store path; `None` = in-memory store.
    pub peers_path: Option<PathBuf>,
    /// Peer store capacity.
    pub max_peers: usize,
    /// Known peers per outbound Disco batch (self-entry excluded,
    /// capped at `DISCO_MAX_PEERS - 1`).
    pub disco_batch: usize,
    /// Hard cap on ESTABLISHED authenticated connections (audit Net-3):
    /// the H-01 half-open cap bounds only the handshake phase, so the
    /// authenticated pool itself must be bounded too - a mass dial that
    /// completes handshakes would otherwise grow the conns map (and the
    /// one-handler-thread-per-connection pool) without limit.
    pub max_conns: usize,
}

impl Default for NetNodeConfig {
    fn default() -> Self {
        NetNodeConfig {
            listen_addr: "0.0.0.0:18080".to_string(),
            advertise_addr: "127.0.0.1:18080".to_string(),
            bootstrap_peers: Vec::new(),
            read_timeout: Duration::from_secs(30),
            max_frame_len: MAX_NET_FRAME,
            peers_path: None,
            max_peers: 512,
            disco_batch: 16,
            max_conns: 128,
        }
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Bounded observability log (newest last).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetEvent {
    /// Mutual handshake completed; the connection is now authenticated.
    Authenticated {
        node_id: String,
        addr: String,
        inbound: bool,
    },
    /// Handshake or post-auth protocol failure; the connection is closed.
    Rejected { addr: String, reason: String },
    /// A Disco batch was merged into the peer store.
    DiscoMerged { node_id: String, added: usize },
    /// Note blobs arrived from an authenticated peer (kept = newly
    /// stored, relayed = blob deliveries forwarded to other peers).
    NotesObserved {
        node_id: String,
        kept: usize,
        relayed: usize,
    },
    /// The authenticated connection was handed over to the requested
    /// plane (N3b); the raw stream now belongs to that plane node.
    Upgraded { node_id: String, plane: String },
    /// The authenticated peer disconnected (clean EOF or idle timeout).
    Disconnected { node_id: String },
}

const EVENT_CAP: usize = 1024;

/// Maximum number of inbound connections that may sit mid-handshake
/// (half-open) at the same time (audit H-01). A rolling pool of stalled
/// dials must not be able to occupy every handshake slot.
const MAX_HALF_OPEN: usize = 64;

/// Hard wall-clock read budget for the whole handshake phase. With the
/// replay-cache lock no longer held across socket reads (audit H-01) a
/// stalled handshake only burns its own thread; this timeout reclaims
/// it quickly. The keep-alive loop restores the regular idle timeout.
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(10);

fn kind_of(m: &NetMsg) -> &'static str {
    match m {
        NetMsg::Hello { .. } => "Hello",
        NetMsg::Auth { .. } => "Auth",
        NetMsg::Disco { .. } => "Disco",
        NetMsg::Notes { .. } => "Notes",
        NetMsg::Upgrade { .. } => "Upgrade",
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// Authenticated P2P control-plane node: handshake + disco + peer store.
pub struct NetNode {
    cfg: NetNodeConfig,
    identity: NodeIdentity,
    /// Canonical advertised dial address (parsed once at start).
    advert: String,
    listener: TcpListener,
    store: Arc<Mutex<PeerStore>>,
    cache: Arc<Mutex<ReplayCache>>,
    /// Authenticated connections: hex node_id -> outbound state
    /// (write half + tx transport keys + counter, Net-1).
    conns: Arc<Mutex<HashMap<String, Arc<Mutex<ConnOut>>>>>,
    /// Received (still sealed) note blobs, bounded and deduped by id.
    notes: Arc<Mutex<NoteInbox>>,
    /// Optional swap-plane target of Upgrade handovers (N3b). `None`
    /// until attach_swap is called; every Upgrade is rejected before.
    swap: Arc<Mutex<Option<Arc<SwapNode>>>>,
    /// Inbound connections currently mid-handshake (half-open). Bounded
    /// by MAX_HALF_OPEN (audit H-01).
    half_open: Arc<std::sync::atomic::AtomicUsize>,
    events: Arc<Mutex<Vec<NetEvent>>>,
}

/// Post-auth outbound state of one connection (Net-1): the write half,
/// OUR tx-direction transport keys and the strictly increasing tx
/// counter. The mutex serializes concurrent writers (send_notes,
/// relay_notes, the conn thread's own frames) so sealed frames never
/// interleave mid-write and both rx counters stay in lockstep.
struct ConnOut {
    stream: TcpStream,
    keys: SessionKeys,
    tx_seq: u64,
}

impl NetNode {
    /// Validate the config, bind, spawn the accept loop and dial the
    /// bootstrap peers (dial failures are logged, not fatal).
    pub fn start(cfg: NetNodeConfig, identity: NodeIdentity) -> Result<Arc<Self>, NetNodeError> {
        let advert_sock: SocketAddr = cfg.advertise_addr.parse().map_err(|e| {
            NetNodeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("bad advertise_addr {}: {e}", cfg.advertise_addr),
            ))
        })?;
        let store = match &cfg.peers_path {
            Some(p) => PeerStore::load_or_new(p, cfg.max_peers)?.0,
            None => PeerStore::in_memory(cfg.max_peers),
        };
        let listener = TcpListener::bind(&cfg.listen_addr)?;
        let node = Arc::new(NetNode {
            cfg,
            identity,
            advert: advert_sock.to_string(),
            listener,
            store: Arc::new(Mutex::new(store)),
            cache: Arc::new(Mutex::new(ReplayCache::new(REPLAY_CACHE_CAP))),
            conns: Arc::new(Mutex::new(HashMap::new())),
            notes: Arc::new(Mutex::new(NoteInbox::new(NOTE_INBOX_CAP))),
            swap: Arc::new(Mutex::new(None)),
            half_open: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            events: Arc::new(Mutex::new(Vec::new())),
        });
        node.spawn_listener();
        let boot = node.cfg.bootstrap_peers.clone();
        for peer in boot {
            if let Err(e) = node.dial(&peer) {
                node.log(NetEvent::Rejected {
                    addr: peer,
                    reason: format!("dial: {e}"),
                });
            }
        }
        Ok(node)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetNodeError> {
        Ok(self.listener.local_addr()?)
    }

    /// Our hex node_id (the Disco self-entry peer_id).
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.identity.node_id)
    }

    /// The canonical advertised dial address.
    pub fn advertise_addr(&self) -> &str {
        &self.advert
    }

    /// Snapshot of the peer store (sorted by address).
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.store.lock().unwrap().list()
    }

    /// Hex node_ids of currently authenticated connections (sorted).
    pub fn connected(&self) -> Vec<String> {
        let mut v: Vec<String> = self.conns.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }

    /// Snapshot of recent events (bounded ring, newest last).
    pub fn events(&self) -> Vec<NetEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Snapshot of the received (still sealed) note inbox, oldest first.
    pub fn inbox(&self) -> Vec<NoteBlob> {
        self.notes.lock().unwrap().snapshot()
    }

    /// Attach the swap plane (N3b): authenticated peers may hand their
    /// connection over to this swap node with a post-auth Upgrade frame.
    /// The first attachment wins for the lifetime of the node.
    pub fn attach_swap(&self, swap: Arc<SwapNode>) {
        *self.swap.lock().unwrap() = Some(swap);
    }

    /// Send sealed note blobs to ONE authenticated peer (by hex node_id).
    /// The batch must respect the wire cap; the peer must be connected.
    pub fn send_notes(&self, node_id_hex: &str, notes: &[NoteBlob]) -> Result<(), NetNodeError> {
        if notes.len() > NOTES_MAX_COUNT {
            return Err(NetNodeError::Handshake(HandshakeError::NotesTooLarge(
                notes.len(),
            )));
        }
        self.send_frame(
            node_id_hex,
            &NetMsg::Notes {
                notes: notes.to_vec(),
            },
        )
    }

    /// Net-1: seal + send one frame to an authenticated peer through
    /// its conns entry (the entry carries the tx keys and the counter).
    fn send_frame(&self, peer_hex: &str, msg: &NetMsg) -> Result<(), NetNodeError> {
        let out = {
            let conns = self.conns.lock().unwrap();
            conns.get(peer_hex).cloned()
        }
        .ok_or_else(|| {
            NetNodeError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("peer {peer_hex} is not connected"),
            ))
        })?;
        write_conn_frame(&out, msg)
    }

    /// Relay a batch of note blobs to every authenticated peer except the
    /// sender. Delivery failures never fail the caller (they only drop
    /// the dead connection).
    fn relay_notes(&self, from_hex: &str, notes: &[NoteBlob]) -> usize {
        let targets: Vec<(String, Arc<Mutex<ConnOut>>)> = {
            let conns = self.conns.lock().unwrap();
            conns
                .iter()
                .filter(|(id, _)| id.as_str() != from_hex)
                .map(|(id, o)| (id.clone(), Arc::clone(o)))
                .collect()
        };
        let mut ok = 0usize;
        for (id, out) in &targets {
            match write_conn_frame(
                out,
                &NetMsg::Notes {
                    notes: notes.to_vec(),
                },
            ) {
                Ok(()) => ok += 1,
                Err(_) => self.drop_conn(id),
            }
        }
        ok * notes.len()
    }

    fn log(&self, ev: NetEvent) {
        let mut evs = self.events.lock().unwrap();
        if evs.len() >= EVENT_CAP {
            evs.remove(0);
        }
        evs.push(ev);
    }

    fn drop_conn(&self, peer_hex: &str) {
        self.conns.lock().unwrap().remove(peer_hex);
    }

    /// Dial a peer and run the authenticated handshake as Initiator; the
    /// whole connection flow (handshake + disco + keep-alive loop) runs on
    /// its own thread. Dial errors are returned; later failures land in
    /// events.
    pub fn dial(self: &Arc<Self>, addr: &str) -> Result<(), NetNodeError> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        let node = Arc::clone(self);
        let addr = addr.to_string();
        std::thread::spawn(move || node.conn_run(stream, Role::Initiator, addr));
        Ok(())
    }

    /// Accept loop: one handler thread per inbound connection.
    fn spawn_listener(self: &Arc<Self>) {
        let node = Arc::clone(self);
        std::thread::spawn(move || {
            for stream in node.listener.incoming().flatten() {
                let node = Arc::clone(&node);
                let addr = stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".to_string());
                std::thread::spawn(move || node.conn_run(stream, Role::Responder, addr));
            }
        });
    }

    /// Our outbound Disco batch: the self-entry (advertised dial address)
    /// followed by the most recently seen known peers, capped at
    /// `DISCO_MAX_PEERS` entries in total.
    fn our_batch(&self) -> Vec<DiscoPeer> {
        let self_entry = DiscoPeer {
            peer_id: self.node_id_hex(),
            addr: self.advert.clone(),
        };
        let rest = self
            .store
            .lock()
            .unwrap()
            .to_disco_batch(self.cfg.disco_batch.min(DISCO_MAX_PEERS - 1));
        let mut batch = Vec::with_capacity(1 + rest.len());
        batch.push(self_entry);
        batch.extend(rest);
        batch.truncate(DISCO_MAX_PEERS);
        batch
    }
}

// ---------------------------------------------------------------------------
// Frame IO over sockets (u32-LE prefix + JSON body, net framing)
// ---------------------------------------------------------------------------

fn read_full(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(off)
}

/// Read one full net frame (prefix + body). `Ok(None)` means the peer
/// closed the connection cleanly between frames. The declared length is
/// checked BEFORE the body is allocated.
fn read_net_frame(
    stream: &mut TcpStream,
    max_frame_len: usize,
) -> Result<Option<Vec<u8>>, NetNodeError> {
    let mut prefix = [0u8; 4];
    let got = read_full(stream, &mut prefix)?;
    if got == 0 {
        return Ok(None);
    }
    if got < 4 {
        return Err(NetNodeError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed inside a frame prefix",
        )));
    }
    let len = u32::from_le_bytes(prefix) as usize;
    if len > max_frame_len {
        return Err(NetNodeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        )));
    }
    let mut body = vec![0u8; len];
    read_full(stream, &mut body)?;
    let mut wire = Vec::with_capacity(4 + len);
    wire.extend_from_slice(&prefix);
    wire.extend_from_slice(&body);
    Ok(Some(wire))
}

fn write_net_frame(stream: &mut TcpStream, msg: &NetMsg) -> Result<(), NetNodeError> {
    let wire = encode_net_frame(msg)?;
    stream.write_all(&wire)?;
    stream.flush()?;
    Ok(())
}

/// Net-1: read one sealed post-auth frame ([u32-LE body_len]
/// [mac(32) || ct]) and open it under the rx direction at the strictly
/// sequential rx counter, then decode the plaintext net frame. The
/// counter advances only on a fully verified frame, so tampering,
/// replay and reordering all surface as transport rejections.
fn read_sealed_frame(
    stream: &mut TcpStream,
    keys: &SessionKeys,
    rx_seq: &mut u64,
    max_body: usize,
) -> Result<Option<NetMsg>, NetNodeError> {
    let wire = match read_net_frame(stream, max_body)? {
        Some(w) => w,
        None => return Ok(None),
    };
    let plain = keys.open(*rx_seq, &wire[4..])?;
    *rx_seq += 1;
    Ok(Some(decode_net_frame(&plain)?))
}

/// Net-1: seal + write one post-auth frame under the connection's tx
/// direction at the connection's strictly increasing tx counter (the
/// per-connection mutex keeps concurrent writers ordered).
fn write_conn_frame(out: &Mutex<ConnOut>, msg: &NetMsg) -> Result<(), NetNodeError> {
    let mut c = out.lock().unwrap();
    let pt = encode_net_frame(msg)?;
    let body = c.keys.seal(c.tx_seq, &pt);
    let mut wire = Vec::with_capacity(4 + body.len());
    wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
    wire.extend_from_slice(&body);
    c.stream.write_all(&wire)?;
    c.stream.flush()?;
    c.tx_seq += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-connection flow: handshake (strict single-shot) -> disco -> keep-alive
// ---------------------------------------------------------------------------

impl NetNode {
    fn conn_run(self: &Arc<Self>, mut stream: TcpStream, role: Role, peer_addr: String) {
        // Audit H-01: the handshake phase runs under a short dedicated
        // read budget; the keep-alive loop below restores the regular
        // idle timeout.
        stream.set_read_timeout(Some(HANDSHAKE_READ_TIMEOUT)).ok();
        stream.set_nodelay(true).ok();

        // Audit H-01: inbound connections are gated by a half-open cap
        // BEFORE entering the handshake, so a rolling pool of stalled
        // dials cannot occupy every handshake slot.
        let handshake_result = if role == Role::Responder {
            let cur = self
                .half_open
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if cur >= MAX_HALF_OPEN {
                self.half_open
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                self.log(NetEvent::Rejected {
                    addr: peer_addr,
                    reason: format!("too many half-open connections ({cur})"),
                });
                return;
            }
            let outcome = self.handshake_phase(&mut stream, role);
            self.half_open
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            outcome
        } else {
            self.handshake_phase(&mut stream, role)
        };
        let (vp, batch, keys) = match handshake_result {
            Ok(ok) => ok,
            Err(e) => {
                self.log(NetEvent::Rejected {
                    addr: peer_addr,
                    reason: e.to_string(),
                });
                return;
            }
        };

        // Audit H-01: back to the regular idle timeout for keep-alive.
        stream.set_read_timeout(Some(self.cfg.read_timeout)).ok();

        let peer_hex = hex::encode(vp.node_id);
        // Audit Net-3: bound the ESTABLISHED connection pool (the
        // half-open cap bounds only the handshake phase) and reject a
        // duplicate connection for an already-connected peer - two live
        // handler threads for one node_id would race the idle-timeout
        // cleanup against the fresh entry. try_clone + check-and-insert
        // run under one lock acquisition, so the admission decision is
        // atomic.
        let half = match stream.try_clone() {
            Ok(h) => h,
            Err(e) => {
                self.log(NetEvent::Rejected {
                    addr: peer_addr,
                    reason: format!("try_clone: {e}"),
                });
                return;
            }
        };
        let out = {
            let mut conns = self.conns.lock().unwrap();
            let established = conns.len();
            if established >= self.cfg.max_conns {
                drop(conns);
                self.log(NetEvent::Rejected {
                    addr: peer_addr,
                    reason: format!("too many established connections ({established})"),
                });
                return;
            }
            if conns.contains_key(&peer_hex) {
                drop(conns);
                self.log(NetEvent::Rejected {
                    addr: peer_addr,
                    reason: format!("peer {peer_hex} already connected"),
                });
                return;
            }
            let out = Arc::new(Mutex::new(ConnOut {
                stream: half,
                keys: keys.clone(),
                tx_seq: 0,
            }));
            conns.insert(peer_hex.clone(), Arc::clone(&out));
            out
        };
        self.log(NetEvent::Authenticated {
            node_id: peer_hex.clone(),
            addr: peer_addr.clone(),
            inbound: role == Role::Responder,
        });
        // The initiator records the address it actually dialed; the
        // responder waits for the peer's advertised self-entry instead
        // (the inbound source address is an ephemeral port, not dialable).
        if role == Role::Initiator {
            let mut st = self.store.lock().unwrap();
            let _ = st.insert_or_touch(&peer_addr, &peer_hex);
            let _ = st.save();
        }

        // Disco exchange (Net-1: sealed): both sides push one bounded
        // batch, then read the peer's batch in the keep-alive loop below.
        if let Err(e) = write_conn_frame(&out, &NetMsg::Disco { peers: batch }) {
            self.drop_conn(&peer_hex);
            self.log(NetEvent::Rejected {
                addr: peer_addr,
                reason: e.to_string(),
            });
            return;
        }
        // Net-1: rx side of the transport - frames arrive as
        // [u32-LE body_len][mac(32) || ct]; the rx counter is implicit
        // and strictly sequential, so replay, reordering and drops are
        // all transport failures and close the connection.
        let mut rx_seq: u64 = 0;
        loop {
            match read_sealed_frame(
                &mut stream,
                &keys,
                &mut rx_seq,
                self.cfg.max_frame_len + TRANSPORT_MAC_LEN,
            ) {
                Ok(None) => break,
                Ok(Some(msg)) => match msg {
                    NetMsg::Disco { peers } => {
                        let added = {
                            let mut st = self.store.lock().unwrap();
                            let added =
                                st.merge_remote(&peers, &self.node_id_hex(), Some(&self.advert));
                            let _ = st.save();
                            added
                        };
                        self.log(NetEvent::DiscoMerged {
                            node_id: peer_hex.clone(),
                            added,
                        });
                    }
                    NetMsg::Notes { notes } => {
                        let (kept, fresh) = {
                            let mut inbox = self.notes.lock().unwrap();
                            let mut fresh: Vec<NoteBlob> = Vec::new();
                            for b in notes {
                                if inbox.ingest(b.clone()) {
                                    fresh.push(b);
                                }
                            }
                            (fresh.len(), fresh)
                        };
                        let mut relayed = 0usize;
                        let mut out: Vec<NoteBlob> = Vec::new();
                        for mut b in fresh {
                            if b.hops > 0 {
                                b.hops -= 1;
                                // the public id covers hops: recompute
                                // it for the decremented budget or the
                                // next hop rejects the blob as BadId
                                if let Ok(new_id) = note_id_hex_of(&b) {
                                    b.id = new_id;
                                    out.push(b);
                                }
                            }
                        }
                        if !out.is_empty() {
                            relayed = self.relay_notes(&peer_hex, &out);
                        }
                        self.log(NetEvent::NotesObserved {
                            node_id: peer_hex.clone(),
                            kept,
                            relayed,
                        });
                    }
                    NetMsg::Upgrade { plane } => {
                        // N3b swap-plane handover: the authenticated
                        // peer asks to move this raw connection to the
                        // attached swap node. Without an attachment
                        // every Upgrade is rejected and the connection
                        // closed.
                        let swap = self.swap.lock().unwrap().clone();
                        match swap {
                            Some(swap) => {
                                // the conns write-half is a try_clone,
                                // so dropping the bookkeeping keeps the
                                // socket alive; adopt_stream takes the
                                // original stream at a clean frame
                                // boundary
                                self.drop_conn(&peer_hex);
                                self.log(NetEvent::Upgraded {
                                    node_id: peer_hex.clone(),
                                    plane,
                                });
                                swap.adopt_stream(stream);
                            }
                            None => {
                                self.drop_conn(&peer_hex);
                                self.log(NetEvent::Rejected {
                                    addr: peer_addr,
                                    reason: "upgrade plane not available".to_string(),
                                });
                            }
                        }
                        return;
                    }
                    other => {
                        // strict single-shot (audit F5): after the
                        // handshake only Disco, Notes and the N3b
                        // Upgrade handover are accepted
                        self.drop_conn(&peer_hex);
                        self.log(NetEvent::Rejected {
                            addr: peer_addr,
                            reason: format!("unexpected {} frame after handshake", kind_of(&other)),
                        });
                        return;
                    }
                },
                Err(NetNodeError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    self.drop_conn(&peer_hex);
                    self.log(NetEvent::Disconnected { node_id: peer_hex });
                    return;
                }
                Err(e) => {
                    self.drop_conn(&peer_hex);
                    self.log(NetEvent::Rejected {
                        addr: peer_addr,
                        reason: e.to_string(),
                    });
                    return;
                }
            }
        }
        self.drop_conn(&peer_hex);
        self.log(NetEvent::Disconnected { node_id: peer_hex });
    }

    /// Strict single-shot handshake phase (audit F5): exactly one Hello and
    /// one Auth per direction, in the fixed frame order. The responder
    /// pushes its Hello and Auth back-to-back; the initiator verifies the
    /// responder Auth before answering with its own. Returns the verified
    /// peer and OUR Disco batch.
    fn handshake_phase(
        &self,
        stream: &mut TcpStream,
        role: Role,
    ) -> Result<(VerifiedPeer, Vec<DiscoPeer>, SessionKeys), NetNodeError> {
        let (mut side, hello) = HandshakeSide::start(role, &self.identity);

        let read_msg = |stream: &mut TcpStream| -> Result<NetMsg, NetNodeError> {
            let wire = read_net_frame(stream, self.cfg.max_frame_len)?.ok_or_else(|| {
                NetNodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during handshake",
                ))
            })?;
            Ok(decode_net_frame(&wire)?)
        };

        match role {
            Role::Initiator => {
                write_net_frame(stream, &NetMsg::Hello { hello })?;
                let peer_hello = match read_msg(stream)? {
                    NetMsg::Hello { hello } => hello,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Hello frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                side.on_peer_hello(&peer_hello)?;
                let peer_auth = match read_msg(stream)? {
                    NetMsg::Auth { auth } => auth,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Auth frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                let vp = {
                    // Audit H-01: the replay-cache lock is taken ONLY
                    // for the check-and-insert, never across the
                    // blocking socket reads above.
                    let mut cache = self.cache.lock().unwrap();
                    side.verify_auth(&peer_auth, &mut cache)?
                };
                let my_auth = side.produce_auth()?;
                write_net_frame(stream, &NetMsg::Auth { auth: my_auth })?;
                let keys = side.session_keys(&vp)?;
                Ok((vp, self.our_batch(), keys))
            }
            Role::Responder => {
                let peer_hello = match read_msg(stream)? {
                    NetMsg::Hello { hello } => hello,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Hello frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                side.on_peer_hello(&peer_hello)?;
                let my_auth = side.produce_auth()?;
                write_net_frame(stream, &NetMsg::Hello { hello })?;
                write_net_frame(stream, &NetMsg::Auth { auth: my_auth })?;
                let peer_auth = match read_msg(stream)? {
                    NetMsg::Auth { auth } => auth,
                    other => {
                        return Err(NetNodeError::Handshake(HandshakeError::Malformed(format!(
                            "expected Auth frame, got {}",
                            kind_of(&other)
                        ))))
                    }
                };
                let vp = {
                    // Audit H-01: same narrowed critical section as the
                    // initiator role above.
                    let mut cache = self.cache.lock().unwrap();
                    side.verify_auth(&peer_auth, &mut cache)?
                };
                let keys = side.session_keys(&vp)?;
                Ok((vp, self.our_batch(), keys))
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
    use crate::handshake::{Hello, SWAP_UPGRADE_PLANE};
    use crate::p2p::NetworkConfig;
    use crate::swap_node::{
        decode_frame, encode_frame, hashlock_of, offer_id_of, Frame, NodeEvent, SwapNetMessage,
        SwapNodeConfig, SwapOfferPayload,
    };
    use std::time::Instant;

    fn start_node(n: u8, peers_path: Option<PathBuf>) -> Arc<NetNode> {
        let cfg = NetNodeConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            advertise_addr: format!("127.0.0.1:{}", 46_000 + n as u16),
            bootstrap_peers: Vec::new(),
            read_timeout: Duration::from_secs(20),
            max_frame_len: MAX_NET_FRAME,
            peers_path,
            max_peers: 64,
            disco_batch: 16,
            max_conns: 64,
        };
        NetNode::start(cfg, NodeIdentity::generate()).unwrap()
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

    /// Manually run the initiator flow on a raw stream (test helper): the
    /// responder completes its handshake, but this stream sends no Disco
    /// batch, so the caller stays in full control of what is written next.
    fn raw_dial_handshake_only(addr: &str) -> (TcpStream, SessionKeys) {
        let id = NodeIdentity::generate();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).ok();
        let (mut side, hello) = HandshakeSide::start(Role::Initiator, &id);
        write_net_frame(&mut stream, &NetMsg::Hello { hello }).unwrap();
        let wire = read_net_frame(&mut stream, MAX_NET_FRAME).unwrap().unwrap();
        let peer_hello = match decode_net_frame(&wire).unwrap() {
            NetMsg::Hello { hello } => hello,
            other => panic!("expected Hello, got {}", kind_of(&other)),
        };
        side.on_peer_hello(&peer_hello).unwrap();
        let wire = read_net_frame(&mut stream, MAX_NET_FRAME).unwrap().unwrap();
        let peer_auth = match decode_net_frame(&wire).unwrap() {
            NetMsg::Auth { auth } => auth,
            other => panic!("expected Auth, got {}", kind_of(&other)),
        };
        let mut cache = ReplayCache::new(16);
        let vp = side.verify_auth(&peer_auth, &mut cache).unwrap();
        let my_auth = side.produce_auth().unwrap();
        write_net_frame(&mut stream, &NetMsg::Auth { auth: my_auth }).unwrap();
        let keys = side.session_keys(&vp).unwrap();
        (stream, keys)
    }

    /// Net-1 test helper: seal + write one frame at the given test-side
    /// counter (mirrors what the real initiator thread does).
    fn write_sealed_test_frame(s: &mut TcpStream, keys: &SessionKeys, seq: u64, msg: &NetMsg) {
        let body = keys.seal(seq, &encode_net_frame(msg).unwrap());
        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&(body.len() as u32).to_le_bytes());
        wire.extend_from_slice(&body);
        s.write_all(&wire).unwrap();
        s.flush().unwrap();
    }

    #[test]
    fn two_nodes_handshake_disco_and_store() {
        let a = start_node(1, None);
        let b = start_node(2, None);
        a.dial(&b.local_addr().unwrap().to_string()).unwrap();
        let a_id = a.node_id_hex();
        let b_id = b.node_id_hex();

        wait_until(10, || a.connected().contains(&b_id));
        wait_until(10, || b.connected().contains(&a_id));

        // A's store gains B both from the dialed address and from the
        // disco self-entry; B's store gains A from the self-entry only.
        wait_until(10, || a.peers().iter().any(|p| p.peer_id == b_id));
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == a_id));

        assert!(a
            .events()
            .iter()
            .any(|e| matches!(e, NetEvent::Authenticated { inbound: false, .. })));
        assert!(b.events().iter().any(|e| matches!(
            e,
            NetEvent::Authenticated { ref node_id, inbound: true, .. } if *node_id == a_id
        )));
        // both sides merged exactly one NEW peer (the self-entry of the
        // other side; the entry carrying the recipient's own identity is
        // skipped as self)
        assert!(b
            .events()
            .iter()
            .any(|e| matches!(e, NetEvent::DiscoMerged { added: 1, .. })));
        assert!(a
            .events()
            .iter()
            .any(|e| matches!(e, NetEvent::DiscoMerged { added: 1, .. })));
    }

    #[test]
    fn disco_gossip_propagates_through_common_peer() {
        let a = start_node(1, None);
        let b = start_node(2, None);
        let c = start_node(3, None);
        let a_id = a.node_id_hex();
        let c_id = c.node_id_hex();

        b.dial(&a.local_addr().unwrap().to_string()).unwrap();
        // B must have merged A's self-entry before C connects, so B's
        // batch to C already carries A
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == a_id));

        c.dial(&b.local_addr().unwrap().to_string()).unwrap();
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == c_id));
        // C learns A purely from B's gossip
        wait_until(10, || c.peers().iter().any(|p| p.peer_id == a_id));
    }

    #[test]
    fn stalled_handshake_does_not_block_other_handshakes() {
        // Audit H-01 regression: the replay-cache lock must not be held
        // across blocking socket reads. A stalled inbound connection
        // (open, silent) must not delay a concurrent handshake.
        let b = start_node(4, None);
        let addr = b.local_addr().unwrap().to_string();
        let stalled = TcpStream::connect(&addr).unwrap();
        stalled.set_nodelay(true).ok();
        // give the accept loop time to pick the stalled conn up first
        std::thread::sleep(Duration::from_millis(100));
        // a full handshake must complete promptly DESPITE the stalled
        // connection; under the old lock placement this blocked for the
        // whole read timeout (20 s in tests)
        let t0 = Instant::now();
        let (s2, _keys) = raw_dial_handshake_only(&addr);
        let elapsed = t0.elapsed();
        drop(s2);
        drop(stalled);
        assert!(
            elapsed < Duration::from_secs(8),
            "handshake blocked for {elapsed:?} - replay-cache lock is held across reads"
        );
    }

    fn start_node_cap(n: u8, max_conns: usize, peers_path: Option<PathBuf>) -> Arc<NetNode> {
        let cfg = NetNodeConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            advertise_addr: format!("127.0.0.1:{}", 46_000 + n as u16),
            bootstrap_peers: Vec::new(),
            read_timeout: Duration::from_secs(20),
            max_frame_len: MAX_NET_FRAME,
            peers_path,
            max_peers: 64,
            disco_batch: 16,
            max_conns,
        };
        NetNode::start(cfg, NodeIdentity::generate()).unwrap()
    }

    #[test]
    fn established_cap_rejects_excess_connections() {
        // Audit Net-3 regression: connections beyond the established cap
        // are closed right after a successful handshake and never enter
        // the conns map.
        let b = start_node_cap(6, 1, None);
        let addr = b.local_addr().unwrap().to_string();
        let a = start_node(1, None);
        a.dial(&addr).unwrap();
        let a_id = a.node_id_hex();
        wait_until(10, || b.connected().contains(&a_id));
        let c = start_node(2, None);
        c.dial(&addr).unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. }
                        if reason.contains("too many established connections")
                )
            })
        });
        assert_eq!(
            b.connected().len(),
            1,
            "only the first peer stays connected"
        );
    }

    #[test]
    fn duplicate_connection_rejected() {
        // Audit Net-3 regression: a second connection from an
        // already-connected peer is rejected instead of replacing (and
        // racing) the live entry.
        let b = start_node(2, None);
        let addr = b.local_addr().unwrap().to_string();
        let a = start_node(1, None);
        a.dial(&addr).unwrap();
        let a_id = a.node_id_hex();
        wait_until(10, || b.connected().contains(&a_id));
        a.dial(&addr).unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("already connected")
                )
            })
        });
        assert_eq!(
            b.connected().len(),
            1,
            "the live entry survives the duplicate dial"
        );
    }
    #[test]
    fn half_open_cap_rejects_excess_inbound() {
        // Audit H-01 regression: inbound connections beyond the
        // half-open cap are rejected immediately (closed without a
        // handshake) instead of piling up unbounded.
        let b = start_node(5, None);
        let addr = b.local_addr().unwrap().to_string();
        let mut held: Vec<TcpStream> = Vec::new();
        for _ in 0..MAX_HALF_OPEN {
            held.push(TcpStream::connect(&addr).unwrap());
        }
        // keep probing until the cap rejection shows up in the event
        // log (self-calibrating against accept-loop timing races)
        let mut rejected = false;
        for _ in 0..(MAX_HALF_OPEN * 4) {
            let mut probe = TcpStream::connect(&addr).unwrap();
            probe
                .set_read_timeout(Some(Duration::from_millis(100)))
                .ok();
            let mut buf = [0u8; 1];
            let _ = probe.read(&mut buf); // rejected conns see EOF/reset fast
            held.push(probe);
            if b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("half-open")
                )
            }) {
                rejected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(rejected, "no half-open cap rejection observed");
    }
    #[test]
    fn second_hello_after_auth_rejected() {
        let b = start_node(2, None);
        let addr = b.local_addr().unwrap().to_string();
        let (mut stream, keys) = raw_dial_handshake_only(&addr);
        // post-handshake: a second Hello frame (properly sealed, so it
        // clears the transport) must still kill the connection
        let hello = Hello::build(&NodeIdentity::generate(), &[7u8; 32]);
        write_sealed_test_frame(&mut stream, &keys, 0, &NetMsg::Hello { hello });
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("unexpected")
                )
            })
        });
    }

    #[test]
    fn garbage_first_frame_rejected() {
        let b = start_node(2, None);
        let mut s = TcpStream::connect(b.local_addr().unwrap().to_string()).unwrap();
        s.write_all(b"not json at all").unwrap();
        s.flush().unwrap();
        wait_until(10, || {
            b.events()
                .iter()
                .any(|e| matches!(e, NetEvent::Rejected { .. }))
        });
    }

    #[test]
    fn wrong_protocol_frame_rejected() {
        let b = start_node(2, None);
        let mut s = TcpStream::connect(b.local_addr().unwrap().to_string()).unwrap();
        // well-formed envelope carrying the SWAP protocol tag: the net
        // node must reject it as a protocol mismatch
        let body = br#"{"protocol":"ghost-swap-p2p-v1","Hello":{"hello":{"version":1,"node_id":"aa","pe":"","pr":"","nonce":""}}}"#;
        s.write_all(&(body.len() as u32).to_le_bytes()).unwrap();
        s.write_all(body).unwrap();
        s.flush().unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("protocol mismatch")
                )
            })
        });
    }

    #[test]
    fn oversized_declared_frame_rejected_before_allocation() {
        let b = start_node(2, None);
        let mut s = TcpStream::connect(b.local_addr().unwrap().to_string()).unwrap();
        let n = (MAX_NET_FRAME + 1) as u32;
        s.write_all(&n.to_le_bytes()).unwrap();
        s.flush().unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("too large")
                )
            })
        });
    }

    #[test]
    fn bootstrap_dial_persists_peer_store() {
        let dir = std::env::temp_dir().join(format!(
            "opacus-net-persist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.json");

        let a = start_node(1, None);
        let b = start_node(2, Some(path.clone()));
        a.dial(&b.local_addr().unwrap().to_string()).unwrap();
        let a_id = a.node_id_hex();
        wait_until(10, || b.peers().iter().any(|p| p.peer_id == a_id));

        // merged contacts are persisted (atomic save after every change)
        wait_until(10, || {
            let (st, _) = PeerStore::load_or_new(&path, 64).unwrap();
            st.list().iter().any(|p| p.peer_id == a_id)
        });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ---- N3b: swap upgrade frame ------------------------------------

    fn hex_str(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// An Offer frame built the way an EXTERNAL peer would build it
    /// (ghost-swap-p2p-v1 wire bytes).
    fn external_offer_wire() -> (String, Vec<u8>) {
        let preimage = [9u8; 32];
        let payload = SwapOfferPayload {
            xmr_piconero: 1_000_000_000_000,
            ghost_atoms: 500_000_000,
            hashlock: hex_str(&hashlock_of(&preimage)),
            fund_timeout_blocks: 100,
            claim_timeout_blocks: 200,
            maker_ghost_address: "ghost-maker-n3b".to_string(),
            taker_xmr_address: "xmr-taker-n3b".to_string(),
        };
        let id = offer_id_of(&payload);
        let frame = Frame::new(SwapNetMessage::Offer {
            offer_id: hex_str(&id),
            payload,
        });
        (hex_str(&id), encode_frame(&frame).unwrap())
    }

    /// Read one raw u32-LE length-prefixed frame (the swap framing is
    /// byte-identical to the net framing).
    fn read_swap_reply(s: &mut TcpStream) -> Option<Vec<u8>> {
        let mut prefix = [0u8; 4];
        s.read_exact(&mut prefix).ok()?;
        let len = u32::from_le_bytes(prefix) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).ok()?;
        let mut wire = Vec::with_capacity(4 + len);
        wire.extend_from_slice(&prefix);
        wire.extend_from_slice(&body);
        Some(wire)
    }

    #[test]
    fn upgrade_wire_roundtrip_and_bad_plane_rejected() {
        let wire = encode_net_frame(&NetMsg::Upgrade {
            plane: SWAP_UPGRADE_PLANE.to_string(),
        })
        .unwrap();
        assert_eq!(
            decode_net_frame(&wire).unwrap(),
            NetMsg::Upgrade {
                plane: "swap".to_string()
            }
        );
        // empty, whitespace, unknown plane, over the length cap
        for bad in ["", "swap x", "eth", "aaaaaaaaaaaaaaaaa"] {
            let wire = encode_net_frame(&NetMsg::Upgrade {
                plane: bad.to_string(),
            })
            .unwrap();
            assert!(
                decode_net_frame(&wire).is_err(),
                "plane {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn post_auth_cleartext_frame_rejected() {
        // Net-1 regression: after the handshake the transport is
        // encrypted - a cleartext frame fails the MAC and closes the
        // connection.
        let b = start_node(6, None);
        let (mut s, keys) = raw_dial_handshake_only(&b.local_addr().unwrap().to_string());
        // drain the responder's sealed Disco batch (rx counter 0)
        let wire = read_net_frame(&mut s, MAX_NET_FRAME + TRANSPORT_MAC_LEN)
            .unwrap()
            .unwrap();
        keys.open(0, &wire[4..]).unwrap();
        // a CLEARTEXT Disco now: the MAC check must reject it
        let clear = encode_net_frame(&NetMsg::Disco { peers: vec![] }).unwrap();
        s.write_all(&(clear.len() as u32).to_le_bytes()).unwrap();
        s.write_all(&clear).unwrap();
        s.flush().unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. } if reason.contains("transport")
                )
            })
        });
    }

    #[test]
    fn upgrade_during_handshake_rejected() {
        let b = start_node(2, None);
        let mut s = TcpStream::connect(b.local_addr().unwrap().to_string()).unwrap();
        // the FIRST frame on a fresh connection must be Hello
        write_net_frame(
            &mut s,
            &NetMsg::Upgrade {
                plane: SWAP_UPGRADE_PLANE.to_string(),
            },
        )
        .unwrap();
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. }
                        if reason.contains("expected Hello frame, got Upgrade")
                )
            })
        });
    }

    #[test]
    fn upgrade_without_swap_plane_rejected() {
        let b = start_node(3, None);
        let (mut s, keys) = raw_dial_handshake_only(&b.local_addr().unwrap().to_string());
        write_sealed_test_frame(
            &mut s,
            &keys,
            0,
            &NetMsg::Upgrade {
                plane: SWAP_UPGRADE_PLANE.to_string(),
            },
        );
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Rejected { reason, .. }
                        if reason.contains("upgrade plane not available")
                )
            })
        });
    }

    /// THE N3b e2e: after the Upgrade handover the raw socket speaks the
    /// swap protocol - an external Offer is tracked and auto-accepted on
    /// the very same connection.
    #[test]
    fn upgrade_hands_connection_to_swap_plane() {
        let b = start_node(4, None);
        let swap = SwapNode::start(SwapNodeConfig::from_network(&NetworkConfig {
            listen_port: 0,
            use_tor: false,
            max_peers: 8,
            bootstrap_nodes: Vec::new(),
        }))
        .unwrap();
        b.attach_swap(Arc::clone(&swap));

        let (mut s, keys) = raw_dial_handshake_only(&b.local_addr().unwrap().to_string());
        // drain the responder Disco batch BEFORE the upgrade (it arrives
        // sealed): once the swap conn_loop owns the socket, a stale
        // control-plane frame would be read as swap-protocol garbage
        let wire = read_net_frame(&mut s, MAX_NET_FRAME + TRANSPORT_MAC_LEN)
            .unwrap()
            .unwrap();
        let plain = keys.open(0, &wire[4..]).unwrap();
        match decode_net_frame(&plain).unwrap() {
            NetMsg::Disco { .. } => {}
            other => panic!(
                "expected the responder Disco batch, got {}",
                kind_of(&other)
            ),
        }

        write_sealed_test_frame(
            &mut s,
            &keys,
            0,
            &NetMsg::Upgrade {
                plane: SWAP_UPGRADE_PLANE.to_string(),
            },
        );
        wait_until(10, || {
            b.events().iter().any(|e| {
                matches!(
                    e,
                    NetEvent::Upgraded { plane, .. } if plane == SWAP_UPGRADE_PLANE
                )
            })
        });
        wait_until(10, || {
            swap.events()
                .iter()
                .any(|e| matches!(e, NodeEvent::PeerConnected(_)))
        });

        // the adopted socket now speaks the swap protocol end to end
        let (id, wire) = external_offer_wire();
        s.write_all(&wire).unwrap();
        s.flush().unwrap();
        wait_until(10, || swap.net().lock().unwrap().session_count() == 1);
        assert!(
            swap.net().lock().unwrap().session(&id).is_some(),
            "the offered session must be tracked by the swap plane"
        );
        // the auto-Accept travels back over the very same socket
        let reply = read_swap_reply(&mut s).unwrap();
        let frame = decode_frame(&reply).unwrap();
        assert!(matches!(frame.msg, SwapNetMessage::Accept { .. }));
    }
}
