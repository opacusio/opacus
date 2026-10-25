//! Node daemon

use std::path::PathBuf;

use opacus_consensus::v4::{accept_transaction, ConsensusParams, ConsensusState};

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("Initialization failed: {0}")]
    InitFailed(String),
    #[error("Transaction rejected by consensus: {0}")]
    TxRejected(String),
}

#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub data_dir: PathBuf,
    pub network: String,
    pub use_tor: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            p2p_port: 18080,
            rpc_port: 18081,
            data_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".ghost"),
            network: "mainnet".to_string(),
            use_tor: false,
        }
    }
}

/// The consensus bundle a daemon runs, selected from the configured
/// network (Node-1). Pre-mainnet the codebase defines exactly one
/// parameter set - the testnet set (v4 active from genesis, zero fee
/// floor [S4 9]) - and one normative accumulator shape (the sparse
/// 2^32-slot frontier), so both networks resolve to the same
/// construction today; this match is the single place to extend when
/// mainnet parameters land. The network string is validated strictly:
/// an unknown value refuses startup instead of being silently ignored
/// (case and surrounding whitespace are normalized).
fn select_consensus(network: &str) -> Result<(ConsensusState, ConsensusParams), DaemonError> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "testnet" => Ok((ConsensusState::mainnet(), ConsensusParams::testnet())),
        other => Err(DaemonError::InitFailed(format!(
            "unknown network \"{other}\" (expected \"mainnet\" or \"testnet\")"
        ))),
    }
}

pub struct OpacusDaemon {
    config: DaemonConfig,
    height: u64,
    consensus: ConsensusState,
    params: ConsensusParams,
}

impl OpacusDaemon {
    pub fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        // Node-1: validate the network BEFORE any side effect - an
        // unknown value fails fast and leaves no data dir behind.
        let (consensus, params) = select_consensus(&config.network)?;
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
        tracing::info!("Ghost daemon initialized at {:?}", config.data_dir);
        tracing::info!(
            "consensus: net={} | v4_activation_height={} | fee_floor={}",
            config.network,
            params.v4_activation_height,
            params.fee_floor
        );
        Ok(Self {
            config,
            height: 0,
            consensus,
            params,
        })
    }

    /// Submit a raw transaction payload to the node's consensus gate.
    ///
    /// Phase 4 [S4 9, S4 9 activation]: the payload runs through the
    /// normative v4 validation order and the activation height gate; on
    /// success the daemon's frontier and seen-set are updated, on failure
    /// the state is untouched and the reason is reported. The full v0.4
    /// wire acceptance path lives in `opacus-consensus::v4`; the daemon is
    /// the node-facing wrapper.
    pub fn submit_transaction(&mut self, height: u64, raw: &[u8]) -> Result<(), DaemonError> {
        accept_transaction::<32>(&self.params, height, raw, &mut self.consensus)
            .map_err(|e| DaemonError::TxRejected(e.to_string()))?;
        tracing::info!("tx accepted at height {height}");
        Ok(())
    }

    /// Read-only view of the node's shielded-pool state (frontier root,
    /// leaf and seen-set counters).
    pub fn consensus(&self) -> &ConsensusState {
        &self.consensus
    }

    pub fn params(&self) -> &ConsensusParams {
        &self.params
    }

    pub async fn run(&mut self) -> Result<(), DaemonError> {
        tracing::info!(
            "Ghost node running | P2P: {} | RPC: {} | net: {}",
            self.config.p2p_port,
            self.config.rpc_port,
            self.config.network
        );
        tracing::info!("Press Ctrl+C to stop");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            self.height += 1;
            tracing::debug!("heartbeat, height={}", self.height);
        }
    }

    pub fn height(&self) -> u64 {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_daemon() -> OpacusDaemon {
        let dir = std::env::temp_dir().join(format!(
            "ghost-daemon-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        OpacusDaemon::new(DaemonConfig {
            data_dir: dir,
            ..DaemonConfig::default()
        })
        .expect("daemon init")
    }

    #[test]
    fn submit_rejects_non_v4_after_activation() {
        // Testnet params: activation height 0, so every height is at-or-
        // after activation and only version-4 wire is accepted [S4 9
        // activation].
        let mut d = tmp_daemon();
        let err = d
            .submit_transaction(7, &[3, 1, 0, 0, 1, 2, 3])
            .expect_err("v3-style payload must be rejected after activation");
        assert!(err.to_string().contains("only version 4"), "{err}");
        assert!(matches!(err, DaemonError::TxRejected(_)));
    }

    #[test]
    fn submit_rejects_garbage_and_keeps_state_clean() {
        let mut d = tmp_daemon();
        let before = d.consensus().leaf_count();
        let err = d
            .submit_transaction(0, b"not a transaction at all")
            .expect_err("garbage must be rejected");
        assert!(matches!(err, DaemonError::TxRejected(_)));
        assert_eq!(d.consensus().leaf_count(), before, "state untouched");
        assert_eq!(d.consensus().seen_count(), 0);
    }

    #[test]
    fn daemon_state_starts_fresh_mainnet_shape() {
        let d = tmp_daemon();
        assert_eq!(d.consensus().leaf_count(), 0);
        assert_eq!(d.consensus().seen_count(), 0);
        assert_eq!(d.params().fee_floor, 0);
        assert_eq!(d.params().v4_activation_height, 0);
    }

    fn tmp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ghost-daemon-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    /// Node-1: the configured network is honored - "testnet" constructs
    /// the daemon over the testnet parameter set.
    #[test]
    fn daemon_honors_configured_network_testnet() {
        let d = OpacusDaemon::new(DaemonConfig {
            data_dir: tmp_dir(),
            network: "testnet".to_string(),
            ..DaemonConfig::default()
        })
        .expect("testnet daemon init");
        assert_eq!(d.params().v4_activation_height, 0);
        assert_eq!(d.params().fee_floor, 0);
        assert_eq!(d.consensus().leaf_count(), 0);
        assert_eq!(d.consensus().seen_count(), 0);
    }

    /// Node-1: an unknown network value refuses startup (InitFailed) and
    /// leaves no side effects - the data dir is not even created.
    #[test]
    fn daemon_refuses_unknown_network() {
        let dir = tmp_dir();
        let res = OpacusDaemon::new(DaemonConfig {
            data_dir: dir.clone(),
            network: "mainet".to_string(),
            ..DaemonConfig::default()
        });
        // Result::expect_err would need OpacusDaemon: Debug; the match
        // keeps the production type untouched.
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("a typo'd network must refuse startup"),
        };
        assert!(matches!(err, DaemonError::InitFailed(_)));
        assert!(err.to_string().contains("unknown network"), "{err}");
        assert!(!dir.exists(), "no side effects before validation");
    }

    /// Node-1: the network string is normalized (case + surrounding
    /// whitespace) instead of compared verbatim.
    #[test]
    fn daemon_network_is_normalized() {
        let d = OpacusDaemon::new(DaemonConfig {
            data_dir: tmp_dir(),
            network: "  TestNet  ".to_string(),
            ..DaemonConfig::default()
        })
        .expect("normalized network must be accepted");
        assert_eq!(d.params().fee_floor, 0);
    }
}
