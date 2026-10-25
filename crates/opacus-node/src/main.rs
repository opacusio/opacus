//! opacusd - node daemon

use clap::Parser;
use opacus_node::{DaemonConfig, OpacusDaemon};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "opacusd", about = "Ghost full node daemon", version)]
struct Args {
    #[arg(short, long, default_value = "~/.ghost")]
    data_dir: String,
    #[arg(short, long, default_value_t = 18080)]
    p2p_port: u16,
    #[arg(short, long, default_value_t = 18081)]
    rpc_port: u16,
    /// Chain to run: "mainnet" | "testnet" (validated by the daemon -
    /// Node-1; an unknown value refuses startup).
    #[arg(short = 'n', long, default_value = "mainnet")]
    network: String,
    #[arg(long)]
    tor: bool,
}

#[tokio::main]
async fn main() {
    opacus_node::swap_service::autostart_from_env(); // opacusd swap service (wire_opacusd_swap)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let expanded = args
        .data_dir
        .replace('~', &std::env::var("USERPROFILE").unwrap_or_default());

    let config = DaemonConfig {
        p2p_port: args.p2p_port,
        rpc_port: args.rpc_port,
        data_dir: PathBuf::from(expanded),
        network: args.network,
        use_tor: args.tor,
    };

    // v0.6 N2b: authenticated net node + peer discovery. The node identity
    // and the persistent peer store live in data_dir; GHOST_NET=0 disables,
    // GHOST_NET_PORT / GHOST_NET_ADDR / GHOST_NET_PEERS / GHOST_NET_ADVERTISE
    // override the defaults.
    opacus_node::net_service::autostart(&config);

    // v0.6 N3b: when both planes are up, authenticated peers can hand
    // their connection to the swap plane with a post-auth Upgrade frame.
    if let (Some(net), Some(swap)) = (
        opacus_node::net_service::global(),
        opacus_node::swap_service::global(),
    ) {
        net.attach_swap(swap.node());
        println!("[opacusd] swap plane attached to the net node");
    }

    let mut daemon = OpacusDaemon::new(config).expect("failed to start daemon");
    daemon.run().await.expect("daemon crashed");
}
