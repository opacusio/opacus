//! Miner engine

use crate::{opacushash, MinerConfig, MinerStats, MiningMode};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub struct MinerEngine {
    config: MinerConfig,
    stats: Arc<MinerStats>,
    stop_flag: Arc<AtomicBool>,
}

impl MinerEngine {
    pub fn new(config: MinerConfig) -> Self {
        Self {
            stats: Arc::new(MinerStats::new()),
            stop_flag: Arc::new(AtomicBool::new(false)),
            config,
        }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_flag)
    }

    /// Blocking run (call from spawn_blocking)
    pub fn run_blocking(&self, duration: Option<Duration>) -> anyhow::Result<()> {
        let threads = self.config.effective_threads();
        info!(
            "Opacus Miner v{} | threads: {} | mode: {:?}",
            crate::MINER_VERSION,
            threads,
            self.config.mode
        );
        if self.config.reward_address.is_empty() {
            warn!("No reward address set!");
        }

        let deadline = duration.map(|d| Instant::now() + d);
        let difficulty = match self.config.mode {
            MiningMode::Solo => 1000,
            MiningMode::Pool => 100,
        };

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let header = format!("opacus_block_{}", ts);
        let mut header_hash = [0u8; 32];
        header_hash.copy_from_slice(blake3::hash(header.as_bytes()).as_bytes());

        info!("Mining started (difficulty: {})", difficulty);

        let hashes_total = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for thread_id in 0..threads {
            let hh = header_hash;
            let stop = Arc::clone(&self.stop_flag);
            let counter = Arc::clone(&hashes_total);
            let start = (thread_id as u64) << 40;

            let handle = std::thread::Builder::new()
                .name(format!("opacus-miner-{}", thread_id))
                .spawn(move || opacushash::mine(&hh, difficulty, start, &stop, deadline, &counter))
                .expect("failed to spawn miner thread");
            handles.push(handle);
        }

        let stats = Arc::clone(&self.stats);
        let counter = Arc::clone(&hashes_total);
        let progress_stop = Arc::clone(&self.stop_flag);
        let reporter = std::thread::spawn(move || {
            let mut last = 0u64;
            loop {
                if progress_stop.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_secs(5));
                let total = counter.load(Ordering::Relaxed);
                let delta = total - last;
                last = total;
                if delta > 0 {
                    stats.add_hashes(delta);
                }
                if let Some(d) = deadline {
                    if Instant::now() >= d {
                        break;
                    }
                }
            }
        });

        let mut found = false;
        for (id, h) in handles.into_iter().enumerate() {
            if let Ok(Some(nonce)) = h.join() {
                info!("Thread {} found nonce {}", id, nonce);
                found = true;
            }
        }
        self.stop_flag.store(true, Ordering::Relaxed);
        let _ = reporter.join();

        if found {
            self.stats.block_found();
        }
        self.stats.print_summary();
        Ok(())
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    pub fn stats(&self) -> Arc<MinerStats> {
        Arc::clone(&self.stats)
    }
}
