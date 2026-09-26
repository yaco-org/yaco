use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use defguard_wireguard_rs::key::Key;
use tracing_subscriber::EnvFilter;
use yaco_agent::config::Config;
use yaco_agent::gossip;
use yaco_agent::join::{self, Bootstrap, JoinServer};
use yaco_agent::keys::ClusterKeys;
use yaco_agent::mesh::{self, Mesh, MeshPeer, PendingPeers};

#[derive(Parser)]
#[command(version, about = "YACO node agent")]
struct Args {
    /// Path of the config file. See `yaco.example.toml`.
    #[arg(long, env = "YACO_CONFIG", default_value = "/etc/yaco/yaco.toml")]
    config: PathBuf,

    /// The cluster secret. Every node of the cluster has the same token.
    /// Prefer the environment variable: command line arguments are visible to other users.
    #[arg(long, env = "YACO_TOKEN", hide_env_values = true)]
    token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // No color codes in files and in the journal.
        .with_ansi(std::io::stdout().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let keys = ClusterKeys::derive(&args.token)?;

    // A new key on every start. Storing it on disk is a later step.
    let private_key = Key::generate();
    let public_key = private_key.public_key().to_string();
    let endpoint = SocketAddr::new(config.node.public_ip, config.node.mesh_port);
    let boot = Bootstrap::create(&config)?;
    let pending = Arc::new(PendingPeers::new(config.cluster.pending_peer_ttl));

    let (own_facts, gossip_seeds) = if config.node.seeds.is_empty() {
        tracing::info!("no seeds, starting a new cluster");
        let own_facts = MeshPeer {
            public_key,
            mesh_ip: mesh::mesh_ip(config.cluster.mesh_subnet, &config.node.id, 0),
            endpoint,
        };
        (own_facts, Vec::new())
    } else {
        let (own_facts, response) =
            join::join(&boot, &keys, &config, &public_key, endpoint).await?;
        // The members are mesh peers before gossip has them.
        pending.add(response.members);
        // The gossip seed is the mesh address of the seed.
        (own_facts, vec![response.gossip_seed])
    };

    let mut mesh = Mesh::create(&config, &private_key, &keys.mesh_psk, own_facts.mesh_ip)?;

    // chitchat sends its first gossip to the seed over the mesh,
    // so the peers from the join must be configured before it starts.
    mesh.set_peers(mesh::desired_peers(
        Vec::new(),
        pending.current(&[]),
        &own_facts.public_key,
    ));

    let gossip_addr = SocketAddr::new(IpAddr::V4(own_facts.mesh_ip), config.cluster.gossip_port);
    let chitchat_config =
        gossip::config(&config.node.id, gossip_addr, &gossip_seeds, &config.cluster);
    let handle = gossip::start(chitchat_config, own_facts.to_facts()).await?;

    // From now on, this node is a seed for other nodes.
    boot.set_server(&keys)?;
    let join_server = JoinServer {
        config: config.clone(),
        chitchat: handle.chitchat(),
        self_id: handle.chitchat_id().clone(),
        own: own_facts.clone(),
        pending: pending.clone(),
    };

    tracing::info!(
        node_id = %config.node.id,
        public_ip = %config.node.public_ip,
        gossip = %gossip_addr,
        mesh_ip = %own_facts.mesh_ip,
        wg_endpoint = %own_facts.endpoint,
        boot_port = config.node.boot_port,
        config_fingerprint = %config.cluster.fingerprint(),
        "agent started"
    );

    let result = tokio::select! {
        _ = async {
            tokio::join!(
                gossip::log_membership(&handle),
                mesh::sync_peers(&handle, &mut mesh, &pending, config.cluster.peer_resync_interval),
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
            gossip::leave(handle, &config.cluster).await
        }
    };

    mesh.remove();
    result
}
