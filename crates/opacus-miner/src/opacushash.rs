// opacus audit (v3): OpacusHash round loop is consensus-critical; the indexed form
// mirrors the reference spec 1:1, iteration-by-reference would obscure it.
#![allow(clippy::needless_range_loop)]
//! OpacusHash PoW core

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

pub const SCRATCHPAD_SIZE: usize = 256 * 1024;
pub const NUM_ITERATIONS: u32 = 128;

pub struct OpacusHashContext {
    scratchpad: Vec<u8>,
}

impl Default for OpacusHashContext {
    fn default() -> Self {
        Self::new()
    }
}

impl OpacusHashContext {
    pub fn new() -> Self {
        Self {
            scratchpad: vec![0u8; SCRATCHPAD_SIZE],
        }
    }

    pub fn hash(&mut self, input: &[u8]) -> [u8; 32] {
        let seed = blake3::hash(input);
        let mut seed_bytes: [u8; 32] = *seed.as_bytes();
        let mut offset = 0usize;
        while offset < SCRATCHPAD_SIZE {
            let chunk = blake3::hash(&seed_bytes);
            let copy_len = 32.min(SCRATCHPAD_SIZE - offset);
            self.scratchpad[offset..offset + copy_len]
                .copy_from_slice(&chunk.as_bytes()[..copy_len]);
            offset += copy_len;
            seed_bytes = *chunk.as_bytes();
        }

        let mut state = [0u8; 32];
        for i in 0..NUM_ITERATIONS as usize {
            let idx = (i.wrapping_mul(37).wrapping_mul(64)) % (SCRATCHPAD_SIZE - 32);
            for j in 0..32 {
                state[j] ^= self.scratchpad[idx + j];
            }
            let mixed = blake3::hash(&state);
            self.scratchpad[idx..idx + 32].copy_from_slice(mixed.as_bytes());
        }

        let mut h = blake3::Hasher::new();
        h.update(b"opacus_final_v1");
        h.update(input);
        h.update(&state);
        h.update(&self.scratchpad[..4096]);
        h.finalize().into()
    }
}

fn target_for(difficulty: u64) -> u64 {
    u64::MAX / difficulty.max(1)
}

pub fn verify(header_hash: &[u8; 32], nonce: u64, difficulty: u64) -> bool {
    let mut input = Vec::with_capacity(40);
    input.extend_from_slice(header_hash);
    input.extend_from_slice(&nonce.to_le_bytes());
    let mut ctx = OpacusHashContext::new();
    let hash = ctx.hash(&input);
    let prefix = u64::from_le_bytes(hash[..8].try_into().unwrap());
    prefix < target_for(difficulty)
}

pub fn mine(
    header_hash: &[u8; 32],
    difficulty: u64,
    start_nonce: u64,
    stop_flag: &AtomicBool,
    deadline: Option<Instant>,
    hashes_counter: &AtomicU64,
) -> Option<u64> {
    let mut ctx = OpacusHashContext::new();
    let mut nonce = start_nonce;
    let mut since_report = 0u64;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            return None;
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return None;
            }
        }

        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(header_hash);
        input.extend_from_slice(&nonce.to_le_bytes());
        let hash = ctx.hash(&input);

        since_report += 1;
        if since_report >= 64 {
            hashes_counter.fetch_add(since_report, Ordering::Relaxed);
            since_report = 0;
        }

        let prefix = u64::from_le_bytes(hash[..8].try_into().unwrap());
        if prefix < target_for(difficulty) {
            hashes_counter.fetch_add(since_report, Ordering::Relaxed);
            return Some(nonce);
        }
        nonce = nonce.wrapping_add(1);
    }
}
