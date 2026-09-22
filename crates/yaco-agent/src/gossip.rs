//! Membership and state replication with chitchat.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chitchat::transport::UdpTransport;
use chitchat::{
    ChitchatConfig, ChitchatHandle, ChitchatId, FailureDetectorConfig, ProtocolVersion,
    spawn_chitchat,
};

pub const CLUSTER_ID: &str = "yaco";
pub const DEFAULT_GOSSIP_INTERVAL: Duration = Duration::from_secs(1);

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
        failure_detector_config: FailureDetectorConfig::default(),
        marked_for_deletion_grace_period: Duration::from_secs(60 * 60),
        catchup_callback: None,
        extra_liveness_predicate: None,
        // Every node is new, so all nodes understand V1.
        protocol_version: ProtocolVersion::V1,
    }
}

/// Starts chitchat in a background tokio task.
pub async fn start(config: ChitchatConfig) -> anyhow::Result<ChitchatHandle> {
    spawn_chitchat(config, Vec::new(), &UdpTransport).await
}

/// Returns the sorted node IDs of all live nodes, self included.
pub async fn live_node_ids(handle: &ChitchatHandle) -> Vec<String> {
    let chitchat = handle.chitchat();
    let chitchat = chitchat.lock().await;
    let mut ids: Vec<String> = chitchat
        .live_nodes()
        .map(|id| id.node_id.to_string())
        .collect();
    ids.sort();
    ids
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
