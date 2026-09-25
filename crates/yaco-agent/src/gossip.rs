//! Membership and state replication with chitchat.
//!
//! The agent runs chitchat on its mesh IP only,
//! so gossip is encrypted and only nodes with the join token take part.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chitchat::transport::UdpTransport;
use chitchat::{
    ChitchatConfig, ChitchatHandle, ChitchatId, FailureDetectorConfig, ProtocolVersion,
    spawn_chitchat,
};

pub const CLUSTER_ID: &str = "yaco";
pub const DEFAULT_GOSSIP_INTERVAL: Duration = Duration::from_secs(1);

/// UDP port of chitchat, on the mesh IP.
pub const GOSSIP_PORT: u16 = 7280;

/// A node sets this key just before it shuts down.
/// Other nodes then remove it from the live set at once,
/// instead of after the failure detector timeout.
pub const LEAVING_KEY: &str = "leaving";

/// Gossip rounds to wait after setting `LEAVING_KEY`,
/// so that the key reaches the other nodes.
pub const LEAVE_ROUNDS: u32 = 3;

/// How long to wait before chitchat removes a dead node.
/// We wait so that nodes that got disconnected
/// because of network issues can seamlessly join back.
/// Once the node is deleted, it will have to be restarted
/// to execute the regular join procedure again.
pub const DEAD_NODE_GRACE_PERIOD: u64 = 24;

/// Builds a chitchat config with the chitchat default values.
///
/// `seeds` are gossip addresses of other nodes.
/// An empty list starts a new cluster.
pub fn config(
    node_id: &str,
    listen_addr: SocketAddr,
    seeds: &[SocketAddr],
    gossip_interval: Duration,
) -> ChitchatConfig {
    ChitchatConfig {
        chitchat_id: ChitchatId::new(node_id, generation_id(), listen_addr),
        cluster_id: CLUSTER_ID.to_string(),
        gossip_interval,
        listen_addr,
        seed_nodes: seeds.iter().map(|addr| addr.to_string()).collect(),
        failure_detector_config: FailureDetectorConfig {
            dead_node_grace_period: Duration::from_hours(DEAD_NODE_GRACE_PERIOD),
            ..FailureDetectorConfig::default()
        },
        marked_for_deletion_grace_period: Duration::from_secs(60 * 60),
        catchup_callback: None,
        extra_liveness_predicate: Some(Box::new(|node_state| {
            node_state.get(LEAVING_KEY).is_none()
        })),
        // Every node is new, so all nodes understand V1.
        protocol_version: ProtocolVersion::V1,
    }
}

/// Starts chitchat in a background tokio task.
/// `key_values` are published in the own namespace from the start.
pub async fn start(
    config: ChitchatConfig,
    key_values: Vec<(String, String)>,
) -> anyhow::Result<ChitchatHandle> {
    spawn_chitchat(config, key_values, &UdpTransport).await
}

/// Leaves the cluster gracefully and stops chitchat.
pub async fn leave(handle: ChitchatHandle, gossip_interval: Duration) -> anyhow::Result<()> {
    handle
        .with_chitchat(|chitchat| chitchat.self_node_state().set(LEAVING_KEY, "true"))
        .await;
    tokio::time::sleep(gossip_interval * LEAVE_ROUNDS).await;
    handle.shutdown().await
}

/// Returns the sorted node IDs of all live nodes, self included.
///
/// Reads the live-nodes watcher, not `Chitchat::live_nodes()`,
/// because only the watcher applies `extra_liveness_predicate`.
/// The watcher is updated once per gossip round.
pub async fn live_node_ids(handle: &ChitchatHandle) -> Vec<String> {
    let watcher = handle.chitchat().lock().await.live_nodes_watcher();
    watcher
        .borrow()
        .keys()
        .map(|id| id.node_id.to_string())
        .collect()
}

/// Logs the live node set every time it changes.
/// Returns when chitchat stops.
pub async fn log_membership(handle: &ChitchatHandle) {
    let mut watcher = handle.chitchat().lock().await.live_nodes_watcher();
    loop {
        let ids: Vec<String> = watcher
            .borrow_and_update()
            .keys()
            .map(|id| id.node_id.to_string())
            .collect();
        tracing::info!(live = ?ids, "membership changed");
        if watcher.changed().await.is_err() {
            return;
        }
    }
}

/// chitchat uses the generation ID to detect a restarted node.
/// It must increase on every start,
/// so use the start time, as chitchat recommends.
fn generation_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
