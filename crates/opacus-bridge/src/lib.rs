//! Ghost Bridge - Monero <-> Ghost atomic swaps

pub mod adaptor;
pub mod clsag;
pub mod swap;

pub use adaptor::{AdaptorSignature, SwapSecret};
pub use clsag::{one_time_keys, ClsagAdaptor, OneTimeKeys};
pub use swap::{SwapEngine, SwapId, SwapState};

pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;
pub const MAX_RELAYER_FEE_BPS: u64 = 100;
pub mod swap_p2p;
pub mod xmr_dleq;
pub mod xmr_rpc;
pub mod xmr_swap;
