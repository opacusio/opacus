//! Opacus Miner

pub mod config;
pub mod engine;
pub mod opacushash;
pub mod stats;

pub use config::{MinerConfig, MiningMode};
pub use engine::MinerEngine;
pub use opacushash::OpacusHashContext;
pub use stats::MinerStats;

pub const MINER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn user_agent() -> String {
    format!("opacus-miner/{}", MINER_VERSION)
}
