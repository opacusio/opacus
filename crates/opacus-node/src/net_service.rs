//! opacusd network service: embeds the authenticated net node
//! ([`opacus_network::net_node::NetNode`]) into the daemon.
//!
//! One-liner inside opacusd main (after the config is built):
//!
//! ```text
//! opacus_node::net_service::autostart(&config);
//! ```
//!
//! The node identity and the persistent peer store live in the daemon
//! data dir (`network-identity.json`, `peers.json`). Env knobs:
//!
//! ```text
//! OPACUS_NET=0                  disable the net node
//! OPACUS_NET_PORT=n             listen port (default: daemon p2p_port, 18080)
//! OPACUS_NET_ADDR=ip:port       full listen addr override (default 0.0.0.0:port)
//! OPACUS_NET_PEERS=a:b,c:d      bootstrap dials
//! OPACUS_NET_ADVERTISE=ip:port  advertised dial addr (default 127.0.0.1:port)
//! ```

use std::path::Path;
use std::sync::{Arc, Mutex};

use opacus_network::identity::NodeIdentity;
use opacus_network::net_node::{NetNode, NetNodeConfig, NetNodeError};

use crate::daemon::DaemonConfig;

static NET_GLOBAL: Mutex<Option<Arc<NetNode>>> = Mutex::new(None);

/// The process-wide net node, if started.
pub fn global() -> Option<Arc<NetNode>> {
    NET_GLOBAL.lock().unwrap().as_ref().map(Arc::clone)
}

/// Register the process-wide net node (first start wins); returns the
/// active instance.
pub fn init_global(node: Arc<NetNode>) -> Arc<NetNode> {
    let mut g = NET_GLOBAL.lock().unwrap();
    match g.as_ref() {
        Some(prev) => Arc::clone(prev),
        None => {
            *g = Some(Arc::clone(&node));
            node
        }
    }
}

/// Spawn a net node from explicit parameters (opacusd main + tests). The
/// identity is loaded or created under `data_dir`; the peer store is
/// persisted as `data_dir/peers.json`.
pub fn spawn_with(
    data_dir: &Path,
    listen_addr: String,
    advertise_addr: String,
    bootstrap_peers: Vec<String>,
) -> Result<Arc<NetNode>, NetNodeError> {
    let (identity, _) = NodeIdentity::load_or_generate(&data_dir.join("network-identity.json"))?;
    let cfg = NetNodeConfig {
        listen_addr,
        advertise_addr,
        bootstrap_peers,
        peers_path: Some(data_dir.join("peers.json")),
        ..Default::default()
    };
    NetNode::start(cfg, identity)
}

/// One-line opacusd main hook: start the authenticated net node from the
/// daemon config + env knobs. Returns true if a node is now running.
pub fn autostart(config: &DaemonConfig) -> bool {
    if global().is_some() {
        return true;
    }
    if std::env::var("OPACUS_NET").as_deref() == Ok("0") {
        return false;
    }
    let port = std::env::var("OPACUS_NET_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(config.p2p_port);
    let listen = std::env::var("OPACUS_NET_ADDR").unwrap_or_else(|_| format!("0.0.0.0:{port}"));
    let advertise =
        std::env::var("OPACUS_NET_ADVERTISE").unwrap_or_else(|_| format!("127.0.0.1:{port}"));
    let bootstrap: Vec<String> = std::env::var("OPACUS_NET_PEERS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    match spawn_with(&config.data_dir, listen, advertise, bootstrap) {
        Ok(node) => {
            let node = init_global(node);
            match node.local_addr() {
                Ok(a) => println!(
                    "[opacusd-net] node {} listening on {a} (advertise {}, peers {})",
                    &node.node_id_hex()[..16],
                    node.advertise_addr(),
                    node.peers().len()
                ),
                Err(_) => println!("[opacusd-net] node started"),
            }
            true
        }
        Err(e) => {
            println!("[opacusd-net] failed to start: {e}");
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

    #[test]
    fn spawn_with_binds_and_persists_identity() {
        let dir = std::env::temp_dir().join(format!(
            "opacus-net-svc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let node = spawn_with(
            &dir,
            "127.0.0.1:0".to_string(),
            "127.0.0.1:0".to_string(),
            Vec::new(),
        )
        .unwrap();
        let port = node.local_addr().unwrap().port();
        assert!(port > 0);
        assert_eq!(node.node_id_hex().len(), 32);
        assert!(dir.join("network-identity.json").exists());
        // load_or_new persists the fresh empty store immediately
        assert!(dir.join("peers.json").exists());
        assert_eq!(node.connected().len(), 0);
        drop(node);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
