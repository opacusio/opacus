//! Minimal Ethereum ABI encoding for the subset Uniswap integration needs:
//! uint256, address, bool, dynamic address[]/string and function selectors.

use crate::rlp::u256_from_u128;
use tiny_keccak::{Hasher, Keccak};

pub const SELECTOR_LEN: usize = 4;

/// keccak256 of arbitrary bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Function selector: first 4 bytes of keccak256("name(types...)").
pub fn selector(signature: &str) -> [u8; SELECTOR_LEN] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// One head-slot word (32 bytes, left-padded).
fn word(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() <= 32, "word overflow");
    let mut w = [0u8; 32];
    w[32 - bytes.len()..].copy_from_slice(bytes);
    w.to_vec()
}

/// An ABI argument (already encoded to its 32-byte head or a tail segment).
pub enum AbiArg {
    /// uint256 / int256 / bool / bytes32
    Word([u8; 32]),
    /// address (20 bytes, left-padded)
    Address([u8; 20]),
    /// dynamic address[] (encoded as offset + length + words)
    AddressArray(Vec<[u8; 20]>),
    /// dynamic UTF-8 string (offset + length + bytes + padding)
    Str(String),
}

impl AbiArg {
    pub fn uint_u128(v: u128) -> Self {
        AbiArg::Word(u256_from_u128(v))
    }

    pub fn uint_u64(v: u64) -> Self {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        AbiArg::Word(w)
    }

    pub fn boolean(b: bool) -> Self {
        let mut w = [0u8; 32];
        if b {
            w[31] = 1;
        }
        AbiArg::Word(w)
    }
}

/// Encode a function call: selector + head/tail encoded arguments.
///
/// Two-pass layout: all head words are emitted first, then all dynamic
/// tails. Appending a dynamic arg's tail inline interleaves it between
/// the head words of the static args that follow - a payload no contract
/// can decode.
pub fn encode_call(sig: &str, args: &[AbiArg]) -> Vec<u8> {
    let mut out = selector(sig).to_vec();

    // static head words; dynamic args place an offset into their tail
    let static_heads: Vec<Vec<u8>> = args
        .iter()
        .map(|a| match a {
            AbiArg::Word(w) => word(w),
            AbiArg::Address(a) => word(a),
            AbiArg::AddressArray(_) | AbiArg::Str(_) => word(&[]), // placeholder, fixed below
        })
        .collect();

    let dynamic_count = args
        .iter()
        .filter(|a| matches!(a, AbiArg::AddressArray(_) | AbiArg::Str(_)))
        .count();
    if dynamic_count == 0 {
        for h in static_heads {
            out.extend_from_slice(&h);
        }
        return out;
    }

    // head size = one word per argument; the tail area starts after that
    let head_words = args.len();
    let mut tails: Vec<Vec<u8>> = Vec::new();
    for a in args {
        match a {
            AbiArg::AddressArray(items) => {
                // length word + one 32-byte word per address
                tails.push(encode_address_array(items));
            }
            AbiArg::Str(s) => {
                // length word + bytes + zero padding to a word
                tails.push(encode_string(s));
            }
            _ => {}
        }
    }
    // assign tail offsets in argument order
    let mut offsets = Vec::with_capacity(args.len());
    let mut running = head_words * 32;
    let mut dyn_idx = 0usize;
    for a in args {
        if matches!(a, AbiArg::AddressArray(_) | AbiArg::Str(_)) {
            offsets.push(running);
            running += tails[dyn_idx].len();
            dyn_idx += 1;
        } else {
            offsets.push(0);
        }
    }

    // pass 1: all head words (static value or tail offset) ...
    for (i, a) in args.iter().enumerate() {
        match a {
            AbiArg::AddressArray(_) | AbiArg::Str(_) => {
                out.extend_from_slice(&word(&u128_to_be32(offsets[i])));
            }
            _ => out.extend_from_slice(&static_heads[i]),
        }
    }
    // pass 2: ... then all dynamic tails in argument order
    for t in &tails {
        out.extend_from_slice(t);
    }
    out
}

fn u128_to_be32(v: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(v as u64).to_be_bytes());
    w
}

fn encode_address_array(items: &[[u8; 20]]) -> Vec<u8> {
    let mut out = word(&(items.len() as u128).to_be_bytes());
    for a in items {
        out.extend_from_slice(&word(a));
    }
    out
}

fn encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = word(&(bytes.len() as u128).to_be_bytes());
    out.extend_from_slice(bytes);
    let pad = (32 - bytes.len() % 32) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_selectors() {
        // Uniswap V2 Router02 selectors (well-known).
        assert_eq!(
            selector("getAmountsOut(uint256,address[])"),
            [0xd0, 0x6c, 0xa6, 0x1f]
        );
        assert_eq!(
            selector("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
            [0x38, 0xed, 0x17, 0x39]
        );
        assert_eq!(
            selector("swapExactETHForTokens(uint256,address[],address,uint256)"),
            [0x7f, 0xf3, 0x6a, 0xb5]
        );
        assert_eq!(
            selector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)"),
            [0x18, 0xcb, 0xaf, 0xe5]
        );
        // ERC20
        assert_eq!(
            selector("approve(address,uint256)"),
            [0x09, 0x5e, 0xa7, 0xb3]
        );
        assert_eq!(selector("deposit()"), [0xd0, 0xe3, 0x0d, 0xb0]);
    }

    #[test]
    fn approve_encoding() {
        // approve(spender=0x1111..11, amount=1000)
        let mut spender = [0x11u8; 20];
        spender[19] = 0x11;
        let data = encode_call(
            "approve(address,uint256)",
            &[AbiArg::Address(spender), AbiArg::uint_u128(1000)],
        );
        assert_eq!(&data[0..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(data.len(), 4 + 64);
        // address word: 12 zero bytes then 20 address bytes
        assert_eq!(&data[4..16], &[0u8; 12]);
        assert_eq!(&data[16..36], &spender);
        // amount word: 1000 = 0x03E8 -> last two bytes
        assert_eq!(data[4 + 62], 0x03);
        assert_eq!(data[4 + 63], 0xe8);
    }

    #[test]
    fn address_array_offsets() {
        let a = [1u8; 20];
        let b = [2u8; 20];
        let data = encode_call(
            "getAmountsOut(uint256,address[])",
            &[AbiArg::uint_u128(1234), AbiArg::AddressArray(vec![a, b])],
        );
        assert_eq!(&data[0..4], &[0xd0, 0x6c, 0xa6, 0x1f]);
        assert_eq!(data.len(), 4 + 64 + 32 * 3);
        // offset of array tail = 2 words = 64 (second head slot)
        assert_eq!(data[4 + 31], 0xd2); // uint 1234 = 0x04d2 last byte
        assert_eq!(data[4 + 63], 64); // offset word
                                      // length
        let tail = &data[4 + 64..];
        assert_eq!(tail[31], 2);
        // first address starts after 32 zero-padding bytes
        assert_eq!(&tail[32 + 12..32 + 32], &a);
        assert_eq!(&tail[64 + 12..64 + 32], &b);
    }

    #[test]
    fn string_encoding() {
        // burn(uint256,string): amount 1000, "opacus-recipient" (16 bytes)
        let data = encode_call(
            "burn(uint256,string)",
            &[
                AbiArg::uint_u128(1000),
                AbiArg::Str("opacus-recipient".into()),
            ],
        );
        assert_eq!(data.len(), 4 + 32 + 32 + 32 + 32);
        // offset of the string tail = 2 head words = 64
        assert_eq!(data[4 + 63], 64);
        // amount word: 1000 = 0x03E8
        assert_eq!(data[4 + 30], 0x03);
        assert_eq!(data[4 + 31], 0xe8);
        // tail: length word = 16, then the UTF-8 bytes, zero padding
        let tail = &data[4 + 64..];
        assert_eq!(tail[31], 16);
        assert_eq!(&tail[32..48], b"opacus-recipient");
        assert_eq!(&tail[48..64], &[0u8; 16]);
    }

    #[test]
    fn string_first_offset_order() {
        // a dynamic arg FIRST must not interleave its tail between the
        // head words of the static args that follow (regression: the
        // single-pass emitter did exactly that)
        let data = encode_call(
            "burn(string,uint256)",
            &[AbiArg::Str("ab".into()), AbiArg::uint_u128(7)],
        );
        assert_eq!(data.len(), 4 + 32 + 32 + 32 + 32);
        // head 0: offset of the string tail = 2 words = 64
        assert_eq!(data[4 + 31], 64);
        // head 1: the uint256 7 (static head must follow the offset)
        assert_eq!(data[4 + 63], 7);
        // tail: length 2, "ab", 30 zero pad bytes
        let tail = &data[4 + 64..];
        assert_eq!(tail[31], 2);
        assert_eq!(&tail[32..34], b"ab");
        assert_eq!(&tail[34..64], &[0u8; 30]);
    }
}
