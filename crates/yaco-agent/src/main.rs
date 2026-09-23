use std::net::SocketAddr;

use clap::Parser;
use defguard_wireguard_rs::key::Key;
use tracing_subscriber::EnvFilter;
use yaco_agent::gossip;
use yaco_agent::mesh::{self, Mesh, MeshPeer};

#[derive(Parser)]
#[command(version, about = "YACO node agent")]
struct Args {
    /// Unique ID of this node in the cluster.
    #[arg(long, env = "YACO_NODE_ID")]
    node_id: String,

    /// UDP address for gossip.
    /// Its IP is also the public IP of the WireGuard endpoint.
    #[arg(long, env = "YACO_LISTEN", default_value = "127.0.0.1:7280")]
    listen: SocketAddr,

    /// Gossip address of an existing node. Repeat for more seeds.
    #[arg(long = "seed", env = "YACO_SEEDS", value_delimiter = ',')]
    seeds: Vec<SocketAddr>,

    /// UDP port of the mesh WireGuard interface.
    #[arg(long, env = "YACO_WG_PORT", default_value_t = 7281)]
    wg_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // A new key on every start. Storing it on disk comes with the join step.
    let private_key = Key::generate();
    let own_facts = MeshPeer {
        public_key: private_key.public_key().to_string(),
        mesh_ip: mesh::mesh_ip(&args.node_id, 0),
        endpoint: SocketAddr::new(args.listen.ip(), args.wg_port),
    };
    let mut mesh = Mesh::create(&private_key, own_facts.mesh_ip, args.wg_port)?;

    let config = gossip::config(
        &args.node_id,
        args.listen,
        &args.seeds,
        gossip::DEFAULT_GOSSIP_INTERVAL,
    );
    let handle = gossip::start(config, own_facts.to_facts()).await?;
    tracing::info!(
        node_id = %args.node_id,
        listen = %args.listen,
        seeds = ?args.seeds,
        mesh_ip = %own_facts.mesh_ip,
        wg_endpoint = %own_facts.endpoint,
        "agent started"
    );

    let result = tokio::select! {
        _ = async {
            tokio::join!(gossip::log_membership(&handle), mesh::sync_peers(&handle, &mut mesh))
        } => {
            tracing::error!("chitchat stopped");
            handle.shutdown().await
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("leaving the cluster");
            gossip::leave(handle, gossip::DEFAULT_GOSSIP_INTERVAL).await
        }
    };

    mesh.remove();
    result
}
