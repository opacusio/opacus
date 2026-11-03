//! Opacus Light Client

pub mod compact_state;

pub use compact_state::{CompactBlock, CompactOutput, CompactState};

#[derive(Debug, thiserror::Error)]
pub enum LightClientError {
    #[error("Sync failed: {0}")]
    SyncFailed(String),
    #[error("Out of sync")]
    OutOfSync,
}
