//! wOPACUS helpers: the ERC20 side of the Opacus bridge on Ethereum.
//!
//! The token contract lives in `contracts/wOPACUS.sol`. Until it is
//! deployed, set the address with [`set_wopacus`] at startup (or persist
//! it in config). The legacy wGHOST deployment keeps its env fallback so
//! pre-rename configs keep working until the redeploy round completes.

use crate::abi::{encode_call, AbiArg};
use crate::tx::Address;
use std::sync::OnceLock;

static WOPACUS: OnceLock<Address> = OnceLock::new();

/// Configure the deployed wOPACUS address (call once at startup).
pub fn set_wopacus(addr: Address) -> bool {
    WOPACUS.set(addr).is_ok()
}

/// Current wOPACUS address or the zero address placeholder.
///
/// Resolution order:
/// 1. an address already set via [`set_wopacus`]
/// 2. the `WOPACUS_ADDRESS` environment variable (0x-prefixed 20-byte hex);
///    a successfully parsed value is cached into the same slot, as if
///    [`set_wopacus`] had been called
/// 3. the legacy `WGHOST_ADDRESS` variable (pre-rename configs)
/// 4. the zero address placeholder
pub fn wopacus() -> Address {
    if let Some(addr) = WOPACUS.get() {
        return *addr;
    }
    if let Some(addr) = env_address("WOPACUS_ADDRESS") {
        let _ = WOPACUS.set(addr);
        return addr;
    }
    if let Some(addr) = env_address("WGHOST_ADDRESS") {
        let _ = WOPACUS.set(addr);
        return addr;
    }
    Address([0u8; 20])
}

fn env_address(name: &str) -> Option<Address> {
    let raw = std::env::var(name).ok()?;
    parse_address(&raw)
}

/// Parse a 0x-prefixed (or bare) 20-byte hex EVM address.
pub fn parse_address(raw: &str) -> Option<Address> {
    let s = raw.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(Address(out))
}

/// burn(amount, recipient): destroy wOPACUS to trigger native Opacus
/// release on the Opacus side (bridge relayers watch the Burned event).
/// The wrapper exposes burn(uint256,string), so the recipient rides in
/// the calldata instead of a side channel.
pub fn burn(amount: u128, recipient: &str) -> crate::uniswap::Call {
    crate::uniswap::Call {
        to: wopacus(),
        data: encode_call(
            "burn(uint256,string)",
            &[
                AbiArg::uint_u128(amount),
                AbiArg::Str(recipient.to_string()),
            ],
        ),
        value_wei: [0u8; 32],
    }
}

/// Burned event topic: keccak256("Burned(address,uint256,string)")
/// = 0x0bd10d08cdd688ae27d8149d34aea2ddb78c6e0116355640cf1af79a2c9ab394.
pub fn burn_event_topic() -> [u8; 32] {
    crate::abi::keccak256(b"Burned(address,uint256,string)")
}

/// Minted event topic: keccak256("Minted(address,uint256,bytes32)")
/// = 0xc263b302aec62d29105026245f19e16f8e0137066ccd4a8bd941f716bd4096bb.
pub fn mint_event_topic() -> [u8; 32] {
    crate::abi::keccak256(b"Minted(address,uint256,bytes32)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::selector;

    #[test]
    fn burn_calldata_and_topics() {
        set_wopacus(Address([0xab; 20]));
        let call = burn(1_000, "opacus-recipient");
        assert_eq!(call.to, Address([0xab; 20]));
        assert_eq!(&call.data[0..4], &selector("burn(uint256,string)"));
        // amount word: 1000 = 0x03E8 in the last two bytes
        assert_eq!(call.data[4 + 30], 0x03);
        assert_eq!(call.data[4 + 31], 0xe8);
        // string tail offset = 2 head words = 64
        assert_eq!(call.data[4 + 63], 64);
        // string length word (16 = "opacus-recipient".len())
        assert_eq!(call.data[4 + 64 + 31], 16);
        // keccak topics are pinned to the renamed events
        assert_eq!(
            hex::encode(burn_event_topic()),
            "0bd10d08cdd688ae27d8149d34aea2ddb78c6e0116355640cf1af79a2c9ab394"
        );
        assert_eq!(
            hex::encode(mint_event_topic()),
            "c263b302aec62d29105026245f19e16f8e0137066ccd4a8bd941f716bd4096bb"
        );
        assert_ne!(burn_event_topic(), mint_event_topic());
    }

    #[test]
    fn parse_address_shapes() {
        let ok = "0x1111111111111111111111111111111111111111";
        let a = parse_address(ok).expect("valid");
        assert_eq!(a.0[0], 0x11);
        assert_eq!(a.0[19], 0x11);
        assert_eq!(parse_address(&ok.to_uppercase()).expect("valid").0[0], 0x11);
        assert_eq!(parse_address(&ok[2..]).expect("bare").0[5], 0x11);
        assert!(parse_address("0x1234").is_none());
        assert!(parse_address("0xzz11111111111111111111111111111111111111").is_none());
        assert!(parse_address("").is_none());
        assert!(parse_address("0x11111111111111111111111111111111111111").is_none());
    }
}
