//! Opacus Bridge - Monero <-> Opacus atomic swaps

pub mod adaptor;
pub mod clsag;
pub mod clsag_adaptor;
pub mod clsag_verify;
pub mod swap;

pub use adaptor::{AdaptorSignature, SwapSecret};
pub use clsag::{one_time_keys, ClsagAdaptor, OneTimeKeys};
pub use clsag_verify::{
    pre_mlsag_hash, verify_clsag, verify_tx, ClsagSig, MoneroTx, ParseError, RingMember,
    RCT_TYPE_BULLETPROOF_PLUS, RCT_TYPE_CLSAG,
};
pub use swap::{SwapEngine, SwapId, SwapState};
pub use swap_p2p::{OfferAdaptor, XmrClaimSidecar};
pub use xmr_swap::{swap_claim_message, swap_secret, XmrClaimAdaptor};

pub const BRIDGE_PROTOCOL_VERSION: u32 = 2;
pub const MAX_RELAYER_FEE_BPS: u64 = 100;
pub mod swap_p2p;
pub mod xmr_dleq;
pub mod xmr_rpc;
pub mod xmr_swap;
