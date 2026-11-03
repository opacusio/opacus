//! Opacus CLI

use clap::{Parser, Subcommand};
use opacus_crypto::keys::SpendingKey;
use opacus_miner::{MinerConfig, MinerEngine, MiningMode};
use opacus_node::{DaemonConfig, OpacusDaemon};
use opacus_wallet::LightWallet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// R2 (WP-D2a): the default launch network. Pre-mainnet
/// `select_consensus` maps BOTH strings to the single testnet
/// parameter set (v4 active from genesis, zero fee floor), but the
/// value is still validated strictly by the daemon (Node-1): an
/// unknown name refuses startup before any socket or data dir exists.
const DEFAULT_NETWORK: &str = "mainnet";

#[derive(Parser)]
#[command(
    name = "opacus",
    version,
    about = "Opacus: Private. Instant. Bridgeable."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start full node
    Start {
        #[arg(long)]
        tor: bool,
        /// Chain to run: "mainnet" | "testnet" (validated by the daemon
        /// - Node-1; an unknown value refuses startup).
        #[arg(long, default_value = DEFAULT_NETWORK)]
        network: String,
        /// Node data dir (default ~/.opacus). Pass a fresh path for a
        /// clean-boot smoke run.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Mine Opacus
    Mine {
        #[arg(long)]
        pool: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        threads: Option<usize>,
        #[arg(long)]
        solo: bool,
        #[arg(long, default_value_t = 60)]
        duration_secs: u64,
    },
    /// Create new wallet
    CreateWallet,
    /// Restore wallet from seed
    RestoreWallet {
        #[arg(short, long)]
        seed: String,
    },
    /// Show address
    Address,
    /// Show balance
    Balance,
    /// Send (requires node)
    Send {
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        amount: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Commands::Start {
            tor,
            network,
            data_dir,
        } => start_node(tor, network, data_dir).await?,
        Commands::Mine {
            pool,
            address,
            threads,
            solo,
            duration_secs,
        } => run_miner(pool, address, threads, solo, duration_secs).await?,
        Commands::CreateWallet => create_wallet()?,
        Commands::RestoreWallet { seed } => restore_wallet(&seed)?,
        Commands::Address => show_address()?,
        Commands::Balance => show_balance()?,
        Commands::Send { to, amount } => send(&to, amount)?,
    }
    Ok(())
}

fn default_data_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".opacus")
}

/// The daemon launch surface (WP-D2a): the network string and the data
/// dir flow from the CLI flags into `DaemonConfig` verbatim; the
/// p2p/rpc ports and every unset knob keep the daemon defaults.
fn daemon_config(network: String, data_dir: Option<PathBuf>, tor: bool) -> DaemonConfig {
    DaemonConfig {
        network,
        use_tor: tor,
        data_dir: data_dir.unwrap_or_else(default_data_dir),
        ..Default::default()
    }
}

async fn start_node(tor: bool, network: String, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let config = daemon_config(network, data_dir, tor);
    println!("Starting Opacus Node... (Ctrl+C to stop)");
    println!("  network:  {}", config.network);
    println!("  data dir: {}", config.data_dir.display());
    // Node-1: construct the daemon FIRST - an unknown network refuses
    // startup here, before any socket is bound or any file is written.
    let mut daemon = OpacusDaemon::new(config.clone())?;
    // R2 (WP-D2a): bind the authenticated p2p listener exactly like
    // opacusd does. OPACUS_NET=0 disables; OPACUS_NET_PORT / OPACUS_NET_ADDR
    // / OPACUS_NET_PEERS / OPACUS_NET_ADVERTISE override the defaults
    // (documented in opacus_node::net_service).
    if !opacus_node::net_service::autostart(&config) {
        println!("p2p listener not started (disabled or failed to bind)");
    }
    daemon.run().await?;
    Ok(())
}

async fn run_miner(
    pool: Option<String>,
    address: Option<String>,
    threads: Option<usize>,
    solo: bool,
    duration_secs: u64,
) -> anyhow::Result<()> {
    let mut config = MinerConfig {
        mode: if solo {
            MiningMode::Solo
        } else {
            MiningMode::Pool
        },
        ..Default::default()
    };
    if let Some(p) = pool {
        config.pool_url = Some(p);
    }
    config.reward_address = match address {
        Some(a) => a,
        None => {
            let dir = wallet_dir()?;
            let path = dir.join("mnemonic.txt");
            if path.exists() {
                let mnemonic = std::fs::read_to_string(&path)?;
                let key = SpendingKey::from_mnemonic(mnemonic.trim())?;
                LightWallet::new(&key).get_address().to_string()
            } else {
                println!("WARNING: no wallet found - empty address. Run: opacus create-wallet");
                String::new()
            }
        }
    };
    config.threads = threads;

    println!("Opacus Miner");
    println!("  Mode:     {:?}", config.mode);
    println!("  Threads:  {}", config.effective_threads());
    println!(
        "  Address:  {}",
        if config.reward_address.is_empty() {
            "(not set)"
        } else {
            &config.reward_address
        }
    );
    println!("  Duration: {}s (Ctrl+C to stop early)", duration_secs);
    println!();

    let engine = MinerEngine::new(config);
    let stop_flag = engine.stop_flag();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!();
            println!("Stopping...");
            stop_flag.store(true, Ordering::Relaxed);
        }
    });

    tokio::task::spawn_blocking(move || {
        engine.run_blocking(Some(Duration::from_secs(duration_secs)))
    })
    .await
    .map_err(|e| anyhow::anyhow!("task error: {e}"))??;

    println!();
    println!("Mining session complete!");
    Ok(())
}

fn create_wallet() -> anyhow::Result<()> {
    use rand::rngs::OsRng;
    let key = SpendingKey::generate(&mut OsRng);

    let dir = wallet_dir()?;
    std::fs::create_dir_all(&dir)?;

    let mnemonic_path = dir.join("mnemonic.txt");
    std::fs::write(&mnemonic_path, &key.mnemonic)?;

    let wallet = LightWallet::new(&key);
    std::fs::write(dir.join("address.txt"), wallet.get_address())?;

    println!("Wallet created!");
    println!();
    println!("SEED PHRASE (keep it safe!):");
    println!("=============================================");
    println!("{}", key.mnemonic);
    println!("=============================================");
    println!();
    println!("WARNING: anyone with this phrase can steal your funds!");
    println!("Address: {}", wallet.get_address());
    println!("Wallet:  {}", dir.display());
    Ok(())
}

fn restore_wallet(seed: &str) -> anyhow::Result<()> {
    let key = SpendingKey::from_mnemonic(seed)?;
    let wallet = LightWallet::new(&key);

    let dir = wallet_dir()?;
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("mnemonic.txt"), seed)?;
    std::fs::write(dir.join("address.txt"), wallet.get_address())?;

    println!("Wallet restored!");
    println!("Address: {}", wallet.get_address());
    Ok(())
}

fn show_address() -> anyhow::Result<()> {
    let path = wallet_dir()?.join("address.txt");
    if path.exists() {
        println!("Address: {}", std::fs::read_to_string(&path)?.trim());
    } else {
        println!("No wallet found. Run: opacus create-wallet");
    }
    Ok(())
}

fn show_balance() -> anyhow::Result<()> {
    println!("Balance: 0.000000000 OPACUS");
    println!("  (node connection in v0.3)");
    Ok(())
}

fn send(to: &str, amount: u64) -> anyhow::Result<()> {
    println!("Sending {} atoms to {} ...", amount, to);
    println!("  (send via node in v0.3)");
    Ok(())
}

fn wallet_dir() -> anyhow::Result<PathBuf> {
    Ok(dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("no home dir"))?
        .join(".opacus")
        .join("wallet"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "opacus-cli-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    /// WP-D2a: the launch default stays "mainnet" (the pre-flag
    /// behavior) and no data-dir override is set.
    #[test]
    fn start_defaults_to_mainnet() {
        let cli = Cli::parse_from(["opacus", "start"]);
        match cli.command {
            Commands::Start {
                tor,
                network,
                data_dir,
            } => {
                assert!(!tor);
                assert_eq!(network, "mainnet");
                assert!(data_dir.is_none());
            }
            _ => panic!("expected the start subcommand"),
        }
    }

    /// WP-D2a: `opacus start --network testnet --data-dir <fresh>` parses
    /// both flags - the runbook R2 smoke command is a real surface.
    #[test]
    fn start_parses_network_and_data_dir() {
        let cli = Cli::parse_from([
            "opacus",
            "start",
            "--network",
            "testnet",
            "--data-dir",
            "/tmp/r2-fresh",
        ]);
        match cli.command {
            Commands::Start {
                network, data_dir, ..
            } => {
                assert_eq!(network, "testnet");
                assert_eq!(data_dir, Some(PathBuf::from("/tmp/r2-fresh")));
            }
            _ => panic!("expected the start subcommand"),
        }
    }

    /// WP-D2a: the flags land in the daemon config verbatim; the ports
    /// keep the daemon defaults (p2p 18080 per the runbook stage).
    #[test]
    fn daemon_config_carries_flags_and_keeps_defaults() {
        let cfg = daemon_config("testnet".into(), Some(tmp_dir("cfg")), true);
        assert_eq!(cfg.network, "testnet");
        assert!(cfg.use_tor);
        assert_eq!(cfg.p2p_port, 18080);
        assert_eq!(cfg.rpc_port, 18081);
    }

    /// WP-D2a: without --data-dir the node still targets ~/.opacus.
    #[test]
    fn daemon_config_defaults_to_home_dot_opacus() {
        let cfg = daemon_config("mainnet".into(), None, false);
        assert_eq!(
            cfg.data_dir,
            dirs::home_dir().expect("home dir").join(".opacus")
        );
        assert_eq!(cfg.network, "mainnet");
        assert!(!cfg.use_tor);
    }

    /// Node-1 through the CLI surface: a typo'd network fails inside
    /// `OpacusDaemon::new` - which `start_node` calls BEFORE the net
    /// service could bind anything - and leaves no data dir behind.
    #[test]
    fn unknown_network_refuses_before_sockets() {
        let dir = tmp_dir("badnet");
        let cfg = daemon_config("mainet".into(), Some(dir.clone()), false);
        let res = OpacusDaemon::new(cfg);
        assert!(res.is_err(), "a typo'd network must refuse startup");
        assert!(!dir.exists(), "no side effects before validation");
    }

    /// The accepted networks construct cleanly over a fresh data dir
    /// (the exact shape of the R2 smoke boot).
    #[test]
    fn testnet_boots_over_fresh_data_dir() {
        let dir = tmp_dir("boot");
        let cfg = daemon_config("testnet".into(), Some(dir.clone()), false);
        let daemon = OpacusDaemon::new(cfg).expect("testnet boot");
        assert_eq!(daemon.params().v4_activation_height, 0);
        assert_eq!(daemon.params().fee_floor, 0);
        assert!(dir.exists(), "data dir created on boot");
        std::fs::remove_dir_all(&dir).ok();
    }
}
