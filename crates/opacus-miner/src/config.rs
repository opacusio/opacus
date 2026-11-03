//! Miner config

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MiningMode {
    Pool,
    Solo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinerConfig {
    pub mode: MiningMode,
    pub pool_url: Option<String>,
    pub pool_login: Option<String>,
    pub pool_password: String,
    pub node_rpc_url: String,
    pub threads: Option<usize>,
    pub reward_address: String,
    pub stats_interval_secs: u64,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            mode: MiningMode::Solo,
            pool_url: Some("pool.opacus.network:3333".to_string()),
            pool_login: None,
            pool_password: "x".to_string(),
            node_rpc_url: "http://localhost:18081".to_string(),
            threads: None,
            reward_address: String::new(),
            stats_interval_secs: 60,
        }
    }
}

impl MinerConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn effective_threads(&self) -> usize {
        self.threads
            .unwrap_or_else(|| num_cpus::get().saturating_sub(1).max(1))
    }
}
