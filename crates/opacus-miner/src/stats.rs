//! Miner stats

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::info;

struct Sample {
    at: Instant,
    hashes: u64,
}

pub struct MinerStats {
    samples: Mutex<Vec<Sample>>,
    started_at: Instant,
    shares_accepted: AtomicU64,
    shares_rejected: AtomicU64,
    blocks_found: AtomicU64,
}

impl MinerStats {
    pub fn new() -> Self {
        Self {
            samples: Mutex::new(Vec::new()),
            started_at: Instant::now(),
            shares_accepted: AtomicU64::new(0),
            shares_rejected: AtomicU64::new(0),
            blocks_found: AtomicU64::new(0),
        }
    }

    pub fn add_hashes(&self, count: u64) {
        let mut samples = self.samples.lock();
        samples.push(Sample {
            at: Instant::now(),
            hashes: count,
        });
        if samples.len() > 600 {
            samples.remove(0);
        }
    }

    pub fn hashrate(&self) -> f64 {
        let cutoff = Instant::now() - Duration::from_secs(60);
        let recent: u64 = self
            .samples
            .lock()
            .iter()
            .filter(|s| s.at > cutoff)
            .map(|s| s.hashes)
            .sum();
        if recent == 0 {
            return 0.0;
        }
        let window = self.started_at.elapsed().as_secs_f64().clamp(1.0, 60.0);
        recent as f64 / window
    }

    pub fn share_accepted(&self) {
        self.shares_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn share_rejected(&self) {
        self.shares_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn block_found(&self) {
        let n = self.blocks_found.fetch_add(1, Ordering::Relaxed) + 1;
        info!("BLOCK FOUND! Total: {}", n);
    }

    pub fn print_summary(&self) {
        let uptime = self.started_at.elapsed().as_secs();
        info!(
            "Opacus Miner | Hashrate: {:.1} H/s | Uptime: {}h {}m {}s | Shares: {} ok / {} rej | Blocks: {}",
            self.hashrate(),
            uptime / 3600,
            (uptime % 3600) / 60,
            uptime % 60,
            self.shares_accepted.load(Ordering::Relaxed),
            self.shares_rejected.load(Ordering::Relaxed),
            self.blocks_found.load(Ordering::Relaxed),
        );
    }
}

impl Default for MinerStats {
    fn default() -> Self {
        Self::new()
    }
}
