use std::net::SocketAddr;

use clap::Parser;
use tracing_subscriber::EnvFilter;
use yaco_agent::gossip;

#[derive(Parser)]
#[command(version, about = "YACO node agent")]
struct Args {
    /// Unique ID of this node in the cluster.
    #[arg(long, env = "YACO_NODE_ID")]
    node_id: String,

    /// UDP address for gossip.
    #[arg(long, env = "YACO_LISTEN", default_value = "127.0.0.1:7280")]
    listen: SocketAddr,

    /// Gossip address of an existing node. Repeat for more seeds.
    #[arg(long = "seed", env = "YACO_SEEDS", value_delimiter = ',')]
    seeds: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = gossip::config(
        &args.node_id,
        args.listen,
        &args.seeds,
        gossip::DEFAULT_GOSSIP_INTERVAL,
    );
    let handle = gossip::start(config).await?;
    tracing::info!(node_id = %args.node_id, listen = %args.listen, seeds = ?args.seeds, "agent started");

    tokio::select! {
        _ = gossip::log_membership(&handle) => {
            tracing::error!("chitchat stopped");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }

    handle.shutdown().await
}
