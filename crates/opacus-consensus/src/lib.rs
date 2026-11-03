//! Opacus Consensus Layer
pub mod block;
pub mod transaction;
pub mod v4;

pub use block::{block_reward, Block, BlockHeader};
pub use transaction::{Transaction, TxOutput};

pub const BLOCK_TIME_SECONDS: u64 = 120;
pub const MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
