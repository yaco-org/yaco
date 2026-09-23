use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use defguard_wireguard_rs::key::Key;
use tracing_subscriber::EnvFilter;
use yaco_agent::gossip;
use yaco_agent::join::{self, Bootstrap, JoinServer};
use yaco_agent::keys::ClusterKeys;
use yaco_agent::mesh::{self, Mesh, MeshPeer, PendingPeers};

#[derive(Parser)]
#[command(version, about = "YACO node agent")]
struct Args {
    /// Unique ID of this node in the cluster.
    #[arg(long, env = "YACO_NODE_ID")]
    node_id: String,

    /// The cluster secret. Every node of the cluster has the same token.
    /// Prefer the environment variable: command line arguments are visible to other users.
    #[arg(long, env = "YACO_TOKEN", hide_env_values = true)]
    token: String,

    /// UDP address for gossip.
    /// Its IP is also the public IP of both WireGuard endpoints.
    #[arg(long, env = "YACO_LISTEN", default_value = "127.0.0.1:7280")]
    listen: SocketAddr,

    /// Public bootstrap address (IP and bootstrap port) of an existing node.
    /// Repeat for more seeds. Without seeds, the node starts a new cluster.
    #[arg(long = "seed", env = "YACO_SEEDS", value_delimiter = ',')]
    seeds: Vec<SocketAddr>,

    /// UDP port of the mesh WireGuard interface.
    #[arg(long, env = "YACO_WG_PORT", default_value_t = 7281)]
    wg_port: u16,

    /// UDP port of the bootstrap WireGuard interface.
    #[arg(long, env = "YACO_BOOT_PORT", default_value_t = 7282)]
    boot_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let keys = ClusterKeys::derive(&args.token)?;

    // A new key on every start. Storing it on disk is a later step.
    let private_key = Key::generate();
    let public_key = private_key.public_key().to_string();
    let endpoint = SocketAddr::new(args.listen.ip(), args.wg_port);
    let boot = Bootstrap::create(args.boot_port)?;
    let pending = Arc::new(PendingPeers::default());

    let (own_facts, gossip_seeds) = if args.seeds.is_empty() {
        tracing::info!("no seeds, starting a new cluster");
        let own_facts = MeshPeer {
            public_key,
            mesh_ip: mesh::mesh_ip(&args.node_id, 0),
            endpoint,
        };
        (own_facts, Vec::new())
    } else {
        let (own_facts, response) = join::join(
            &boot,
            &keys,
            &args.seeds,
            &args.node_id,
            &public_key,
            endpoint,
        )
        .await?;
        // The members are mesh peers before gossip has them.
        pending.add(response.members);
        (own_facts, vec![response.gossip_seed])
    };

    let mut mesh = Mesh::create(
        &private_key,
        &keys.mesh_psk,
        own_facts.mesh_ip,
        args.wg_port,
    )?;

    let config = gossip::config(
        &args.node_id,
        args.listen,
        &gossip_seeds,
        gossip::DEFAULT_GOSSIP_INTERVAL,
    );
    let handle = gossip::start(config, own_facts.to_facts()).await?;

    // From now on, this node is a seed for other nodes.
    boot.set_server(&keys)?;
    let join_server = JoinServer {
        chitchat: handle.chitchat(),
        self_id: handle.chitchat_id().clone(),
        own: own_facts.clone(),
        pending: pending.clone(),
    };

    tracing::info!(
        node_id = %args.node_id,
        listen = %args.listen,
        mesh_ip = %own_facts.mesh_ip,
        wg_endpoint = %own_facts.endpoint,
        boot_port = args.boot_port,
        "agent started"
    );

    let result = tokio::select! {
        _ = async {
            tokio::join!(
                gossip::log_membership(&handle),
                mesh::sync_peers(&handle, &mut mesh, &pending),
            )
        } => {
            tracing::error!("chitchat stopped");
            handle.shutdown().await
        }
        result = join::serve(join_server) => {
            tracing::error!("join endpoint stopped: {result:?}");
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
