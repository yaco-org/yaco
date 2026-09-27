//! Agent configuration, read from one TOML file.
//!
//! The file has two tables:
//!
//! - `[node]`: values of this node only, for example its ID and public IP.
//! - `[cluster]`: values that must be the same on every node.
//!   A joining node sends the fingerprint of its `[cluster]` table,
//!   and the seed refuses the join if the fingerprint differs from its own.
//!
//! Every value except `node.id` and `node.public_ip` has a default.
//! Unknown keys are errors, so a typo does not silently fall back to a default.
//! Durations are strings like "500ms", "30s" or "24h".
//!
//! The join token is not in the file. It comes from `YACO_TOKEN`.

mod tests;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::join::{BOOT_CLIENT_IP, BOOT_SERVER_IP};
use crate::mesh::MeshSubnet;

/// Linux limits interface names to 15 bytes.
const MAX_INTERFACE_NAME_LEN: usize = 15;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
}

/// Values of this node only. Not part of the cluster fingerprint.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Unique ID of this node in the cluster.
    pub id: String,
    /// Public IP of this node, for both WireGuard endpoints.
    pub public_ip: IpAddr,
    /// Public bootstrap addresses (IP and bootstrap port) of existing nodes.
    /// Empty: the node starts a new cluster.
    #[serde(default)]
    pub seeds: Vec<SocketAddr>,
    /// UDP port of the mesh WireGuard interface.
    #[serde(default = "default_mesh_port")]
    pub mesh_port: u16,
    /// UDP port of the bootstrap WireGuard interface.
    #[serde(default = "default_boot_port")]
    pub boot_port: u16,
    /// Name of the mesh WireGuard interface.
    #[serde(default = "default_mesh_interface")]
    pub mesh_interface: String,
    /// Name of the bootstrap WireGuard interface.
    #[serde(default = "default_boot_interface")]
    pub boot_interface: String,
}

fn default_mesh_port() -> u16 {
    7281
}

fn default_boot_port() -> u16 {
    7282
}

fn default_mesh_interface() -> String {
    "yaco-mesh".to_string()
}

fn default_boot_interface() -> String {
    "yaco-boot".to_string()
}

/// Values that must be the same on every node.
///
/// Cluster fingerprint is built out of the values of these fields.
/// Changing the fields changes the fingerprint,
/// so nodes of the old and the new version cannot join each other.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterConfig {
    // Mesh.
    /// Subnet of the mesh IPs.
    pub mesh_subnet: MeshSubnet,
    /// MTU of both WireGuard interfaces.
    pub mtu: u32,
    /// How often the peer list is synchronized without a membership change.
    #[serde(with = "humantime_serde")]
    pub peer_resync_interval: Duration,

    // Gossip.
    /// chitchat ignores messages with another cluster ID.
    pub cluster_id: String,
    /// UDP port of chitchat, on the mesh IP.
    pub gossip_port: u16,
    #[serde(with = "humantime_serde")]
    pub gossip_interval: Duration,
    /// Gossip rounds to wait after a node marks itself as leaving,
    /// so that the mark reaches the other nodes.
    pub leave_rounds: u32,
    /// How long chitchat keeps a dead node, and so its WireGuard peer.
    /// A node that comes back later must restart and join again.
    #[serde(with = "humantime_serde")]
    pub dead_node_grace_period: Duration,
    /// How long chitchat keeps deleted keys.
    #[serde(with = "humantime_serde")]
    pub tombstone_grace_period: Duration,
    /// Failure detector: phi value above which a node is dead.
    pub phi_threshold: f64,
    /// Failure detector: number of heartbeat intervals to keep.
    pub sampling_window_size: usize,
    /// Failure detector: a longer heartbeat interval is not sampled.
    #[serde(with = "humantime_serde")]
    pub max_heartbeat_interval: Duration,
    /// Failure detector: interval to assume before the first heartbeat.
    #[serde(with = "humantime_serde")]
    pub initial_heartbeat_interval: Duration,

    // Join.
    /// TCP port of the join endpoint, inside the bootstrap tunnel.
    pub join_port: u16,
    /// Timeout of one join request, WireGuard handshake included.
    #[serde(with = "humantime_serde")]
    pub join_request_timeout: Duration,
    /// How often a joining node tries all seeds before it gives up.
    pub join_rounds: u32,
    /// Pause between two join rounds.
    /// A random part of up to the same length is added,
    /// so that two nodes that join through the same seed do not collide again.
    #[serde(with = "humantime_serde")]
    pub join_retry_delay: Duration,
    /// How many mesh IPs a joining node proposes to one seed before it gives up.
    pub max_mesh_ip_attempts: u32,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        ClusterConfig {
            mesh_subnet: "10.42.0.0/16".parse().unwrap(),
            mtu: 1420,
            peer_resync_interval: Duration::from_secs(30),

            cluster_id: "yaco".to_string(),
            gossip_port: 7280,
            gossip_interval: Duration::from_secs(1),
            leave_rounds: 3,
            dead_node_grace_period: Duration::from_secs(24 * 60 * 60),
            tombstone_grace_period: Duration::from_secs(60 * 60),
            // The chitchat defaults.
            phi_threshold: 8.0,
            sampling_window_size: 1000,
            max_heartbeat_interval: Duration::from_secs(10),
            initial_heartbeat_interval: Duration::from_secs(5),

            join_port: 7283,
            join_request_timeout: Duration::from_secs(5),
            join_rounds: 5,
            join_retry_delay: Duration::from_secs(5),
            max_mesh_ip_attempts: 16,
        }
    }
}

impl Config {
    /// Reads, parses and validates the config file.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("bad config file {}", path.display()))
    }

    /// Parses and validates the text of a config file.
    pub fn parse(text: &str) -> anyhow::Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let node = &self.node;
        let cluster = &self.cluster;

        anyhow::ensure!(!node.id.is_empty(), "node.id is empty");
        for (key, name) in [
            ("node.mesh_interface", &node.mesh_interface),
            ("node.boot_interface", &node.boot_interface),
        ] {
            anyhow::ensure!(
                !name.is_empty() && name.len() <= MAX_INTERFACE_NAME_LEN,
                "{key} must have 1 to {MAX_INTERFACE_NAME_LEN} characters"
            );
        }
        anyhow::ensure!(
            node.mesh_interface != node.boot_interface,
            "node.mesh_interface and node.boot_interface are the same"
        );

        // `MeshSubnet` checks its own size and host bits when it is parsed.
        // A mesh node must never get a bootstrap address.
        let mesh_subnet = cluster.mesh_subnet;
        anyhow::ensure!(
            !mesh_subnet.is_host(BOOT_SERVER_IP) && !mesh_subnet.is_host(BOOT_CLIENT_IP),
            "cluster.mesh_subnet {mesh_subnet} contains the bootstrap addresses \
             {BOOT_SERVER_IP} and {BOOT_CLIENT_IP}"
        );

        anyhow::ensure!(
            !cluster.cluster_id.is_empty(),
            "cluster.cluster_id is empty"
        );
        anyhow::ensure!(
            !cluster.gossip_interval.is_zero(),
            "cluster.gossip_interval must be more than zero"
        );
        anyhow::ensure!(
            cluster.join_rounds > 0,
            "cluster.join_rounds must be more than zero"
        );
        anyhow::ensure!(
            cluster.max_mesh_ip_attempts > 0,
            "cluster.max_mesh_ip_attempts must be more than zero"
        );
        Ok(())
    }
}

/// Fingerprint of a `[cluster]` table: SHA-256 over its values, as lowercase hex.
/// Two nodes can join each other only if their fingerprints are equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigFingerprint(String);

impl fmt::Display for ConfigFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ClusterConfig {
    /// Returns the fingerprint of the values, not of the file text,
    /// so comments, blank lines and the order of keys do not change it.
    ///
    /// This is not `std::hash::Hash` on purpose:
    /// the std docs say that the data `Hash` gives to a hasher is not portable
    /// across platforms (endianness, type sizes) or stable across compiler versions.
    /// Nodes built for other CPUs or with other compilers must get the same fingerprint.
    /// Also, serde visits every field, so a new field cannot be forgotten.
    pub fn fingerprint(&self) -> ConfigFingerprint {
        // serde_json writes the fields in declaration order, so the bytes are stable.
        let json = serde_json::to_vec(self).expect("a cluster config always serializes");
        let hex = Sha256::digest(&json)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        ConfigFingerprint(hex)
    }
}
