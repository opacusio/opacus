//! # opacus-dex
//!
//! Uniswap (Ethereum) integration for Opacus.
//!
//! Layered pipeline:
//! 1. [`rlp`] / [`abi`] - minimal RLP + ABI encoders (no codegen).
//! 2. [`tx`] - legacy EIP-155 transaction signing with k256.
//! 3. [`uniswap`] - Uniswap V2 Router02 calldata: quotes, token/ETH swaps,
//!    ERC20 approve/transfer/balance, WETH wrapping.
//! 4. [`rpc`] - Ethereum JSON-RPC client (eth_call / gas / nonce /
//!    sendRawTransaction) over any [`rpc::Transport`].
//!
//! wOPACUS flow (see `contracts/wOPACUS.sol` in the repo):
//! 1. Lock native GHOST with the bridge (opacus-bridge).
//! 2. Bridge quorum attests; wOPACUS is minted to your EVM address.
//! 3. `approve(wOPACUS, Router)` then `swap_exact_tokens_for_tokens(...)`.
//! 4. To return: swap back to wOPACUS, `burn` via the bridge, unlock native.

pub mod abi;
pub mod rlp;
pub mod rpc;
pub mod tx;
pub mod uniswap;
pub mod wopacus;

pub use tx::{Address, TxParams};
