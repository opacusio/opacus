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
        let wire =
            self.node
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
        let wire = self.node.net().lock().unwrap().publish_ghost_lock(
            offer_id,
            ghost_tx_ref,
            lock_height,
        )?;
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

    /// WG-18: deadline sweep passthrough - refund every session whose
    /// protocol deadline passed at the current height and broadcast the
    /// Refund notices. Returns the hex offer ids that were swept.
    pub fn enforce_deadlines(&self) -> Vec<String> {
        self.node.enforce_deadlines()
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
/// never started - e.g. GHOST_SWAP=0). Every feed also runs the WG-18
/// deadline sweep, so an accepted block that closes a swap's fund or
/// claim window auto-refunds the session and notifies the peers.
pub fn feed_height(h: u64) {
    if let Some(svc) = global() {
        svc.set_height(h);
        for id in svc.enforce_deadlines() {
            println!("[opacusd-swap] auto-refunded expired swap {id}");
        }
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
        encode_frame, hashlock_of, offer_id_of, Frame, Phase, SwapNetError, SwapNetMessage,
        SwapOfferPayload,
    };
    use std::time::{Duration, Instant};

    const PREIMAGE: [u8; 32] = [9u8; 32];

    /// WG-18: the service-level sweep refunds an expired taker session at
    /// the live height and stays idempotent afterwards.
    #[test]
    fn service_deadline_sweep_refunds_expired_session() {
        let svc = SwapService::spawn(&net_cfg()).unwrap();
        svc.set_height(1000);
        let (id, wire) = external_offer_wire();
        svc.node().process_wire(&wire).unwrap(); // taker Accepted @ 1000

        // Inside the fund window (1000 + 100): nothing to sweep.
        assert!(svc.enforce_deadlines().is_empty());

        // Past the fund window: swept exactly once.
        svc.set_height(1101);
        assert_eq!(svc.enforce_deadlines(), vec![id.clone()]);
        let t = svc.session(&id).unwrap();
        assert_eq!(t.session.phase, Phase::Refunded);
        assert!(svc.enforce_deadlines().is_empty());
    }

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
        assert!(matches!(err, NetError::Protocol(SwapNetError::State(_))));
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
    /// (WG-18 note: the sweep test below may have started the global node
    /// first - the registry has no teardown - so this test pins only what
    /// it owns: init is idempotent and feed_height flows through.)
    #[test]
    fn global_registry_feed_height_and_idempotent_init() {
        let _g = TEST_LOCK.lock().unwrap();
        let first = init_global(&net_cfg()).unwrap();
        assert!(global().is_some());
        let second = init_global(&net_cfg()).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        feed_height(777);
        assert_eq!(global().unwrap().height(), 777);
    }

    /// WG-18: feeding a height that closes the fund window auto-refunds
    /// the expired session (the opacusd block loop enforces deadlines).
    #[test]
    fn feed_height_runs_deadline_sweep() {
        let _g = TEST_LOCK.lock().unwrap();
        if global().is_none() {
            init_global(&net_cfg()).unwrap();
        }
        let svc = global().unwrap();
        svc.set_height(2000);
        let (id, wire) = external_offer_wire();
        svc.node().process_wire(&wire).unwrap(); // taker Accepted @ 2000
        assert!(svc.session(&id).is_some());

        // 2000 + 100 = 2100 fund window; feeding 2101 sweeps it inline.
        feed_height(2101);
        assert_eq!(svc.session(&id).unwrap().session.phase, Phase::Refunded);
    }
}
