//! WireGuard mesh between the live nodes.
//!
//! chitchat runs over the mesh.
//!
//! Every node publishes its WireGuard facts in its own chitchat namespace.
//!
//! `sync_peers` configures new peers from two sources:
//!
//! - gossip: the nodes that are new or changed since the last gossip view;
//! - a channel: on a joining node, the members from the join response;
//!   on a seed, the node that just joined (see `join`).
//!   These nodes are not in gossip yet.
//!
//! Both sources put the peers into one queue, and `sync_peers` configures them one by one.
//! Only a node that disappears from gossip removes a peer,
//! so a peer from the channel stays until gossip has it.
//!
//! A dead node keeps its peer so that if it came back
//! (after network connection is restored, for example),
//! it would be able to continue communication with the rest of the cluster.
//! chitchat gossips with dead nodes from time to time, for this reason.
//!
//! A peer is removed only when its node leaves gracefully,
//! or when chitchat forgets the dead node (`dead_node_grace_period`).

mod tests;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};

use yaco_api::{Liveness, Node};

use crate::config::Config;
use crate::view::{ClusterView, FACTS_PREFIX};

/// Names of the facts that the mesh needs.
/// In chitchat, the keys have the prefix `view::FACTS_PREFIX`.
pub const WG_PUBLIC_KEY_FACT: &str = "wg_public_key";
pub const MESH_IP_FACT: &str = "mesh_ip";
pub const ENDPOINT_FACT: &str = "endpoint";

/// One node of the mesh, as the WireGuard peer list needs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPeer {
    /// The chitchat node ID.
    pub node_id: String,
    /// Base64 in JSON and in the facts, as `wg` prints it.
    pub public_key: Key,
    pub mesh_ip: Ipv4Addr,
    pub endpoint: SocketAddr,
}

impl MeshPeer {
    /// The facts of this node, with the mesh IP of `attempt` (see `MeshSubnet::mesh_ip`).
    pub fn own(config: &Config, public_key: &Key, attempt: u32) -> Self {
        Self {
            node_id: config.node.id.clone(),
            public_key: public_key.clone(),
            mesh_ip: config.cluster.mesh_subnet.mesh_ip(&config.node.id, attempt),
            endpoint: SocketAddr::new(config.node.public_ip, config.node.mesh_port),
        }
    }

    /// Parses the facts of one node of the cluster view.
    /// Received data can be malformed, so this never panics.
    pub fn from_node(node: &Node) -> anyhow::Result<Self> {
        let fact = |name: &str| {
            node.facts
                .get(name)
                .with_context(|| format!("missing {name}"))
        };
        let public_key = fact(WG_PUBLIC_KEY_FACT)?;
        let public_key = Key::try_from(public_key.as_str())
            .map_err(|err| anyhow::anyhow!("bad {WG_PUBLIC_KEY_FACT}: {err}"))?;
        let mesh_ip = fact(MESH_IP_FACT)?
            .parse()
            .with_context(|| format!("bad {MESH_IP_FACT}"))?;
        let endpoint = fact(ENDPOINT_FACT)?
            .parse()
            .with_context(|| format!("bad {ENDPOINT_FACT}"))?;
        Ok(Self {
            node_id: node.id.clone(),
            public_key,
            mesh_ip,
            endpoint,
        })
    }

    /// Returns the facts to publish for this node.
    /// The node ID is not a fact: chitchat has it in the node's `ChitchatId`.
    pub fn to_facts(&self) -> Vec<(String, String)> {
        [
            (WG_PUBLIC_KEY_FACT, self.public_key.to_string()),
            (MESH_IP_FACT, self.mesh_ip.to_string()),
            (ENDPOINT_FACT, self.endpoint.to_string()),
        ]
        .into_iter()
        .map(|(name, value)| (format!("{FACTS_PREFIX}{name}"), value))
        .collect()
    }
}

/// Subnet of the mesh IPs.
///
/// It is a /30 or larger and has no host bits set,
/// so it always has room for two or more hosts, as `mesh_ip` needs.
/// In the config file and in JSON it is a string like "10.42.0.0/16".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Ipv4Net", into = "Ipv4Net")]
pub struct MeshSubnet(Ipv4Net);

impl TryFrom<Ipv4Net> for MeshSubnet {
    type Error = anyhow::Error;

    fn try_from(net: Ipv4Net) -> anyhow::Result<Self> {
        // A /31 or /32 has no room for host addresses.
        anyhow::ensure!(
            net.prefix_len() <= 30,
            "mesh subnet {net} is too small, the longest prefix is /30"
        );
        anyhow::ensure!(
            net == net.trunc(),
            "mesh subnet {net} has host bits set, write {}",
            net.trunc()
        );
        Ok(Self(net))
    }
}

impl From<MeshSubnet> for Ipv4Net {
    fn from(subnet: MeshSubnet) -> Self {
        subnet.0
    }
}

impl FromStr for MeshSubnet {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        let net: Ipv4Net = text.parse()?;
        Self::try_from(net)
    }
}

impl fmt::Display for MeshSubnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl MeshSubnet {
    pub fn prefix_len(&self) -> u8 {
        self.0.prefix_len()
    }

    /// Returns true if `ip` is a host address in the subnet:
    /// in the subnet, and neither the subnet address nor the broadcast address.
    pub fn is_host(&self, ip: Ipv4Addr) -> bool {
        self.0.contains(&ip) && ip != self.0.network() && ip != self.0.broadcast()
    }

    /// Proposes a mesh IP for a node.
    ///
    /// SHA-256 keeps the result stable across versions and platforms.
    pub fn mesh_ip(&self, node_id: &str, attempt: u32) -> Ipv4Addr {
        let mut hasher = Sha256::new();
        hasher.update(node_id.as_bytes());
        hasher.update(attempt.to_be_bytes());
        let hash = hasher.finalize();
        let value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
        // All addresses of the subnet, minus the subnet address and the broadcast address.
        let host_count = (1u64 << (32 - self.0.prefix_len())) - 2;
        let host = 1 + u64::from(value) % host_count;
        Ipv4Addr::from(u32::from(self.0.network()) + host as u32)
    }
}

/// Returns the peers of all other nodes of the view, live or dead.
/// Skips the nodes that left gracefully,
/// and skips (with a warning) nodes with bad or missing facts.
fn good_known_peers(view: &ClusterView) -> Vec<MeshPeer> {
    let mut peers = Vec::new();
    for node in view.nodes.values() {
        if node.id == view.self_id || node.liveness == Liveness::Leaving {
            continue;
        }
        match MeshPeer::from_node(node) {
            Ok(peer) => peers.push(peer),
            Err(err) => tracing::warn!(node_id = %node.id, "skipping node with bad facts: {err:#}"),
        }
    }
    peers
}

/// Adds a peer to the queue of peers to configure.
/// Replaces an older queued peer of the same node.
fn add_pending(pending: &mut Vec<MeshPeer>, peer: MeshPeer) {
    pending.retain(|p| p.node_id != peer.node_id);
    pending.push(peer);
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PeersDiff {
    changed: Vec<MeshPeer>,
    gone: Vec<MeshPeer>,
}

/// Compares two gossip views.
/// Returns the peers that are new or changed in `new`,
/// and the peers of `old` whose node is not in `new`:
/// the node left gracefully, or chitchat forgot it.
fn get_gossip_changes(old: &[MeshPeer], new: &[MeshPeer]) -> PeersDiff {
    let changed = new
        .iter()
        .filter(|peer| !old.contains(peer))
        .cloned()
        .collect();
    let gone = old
        .iter()
        .filter(|peer| !new.iter().any(|p| p.node_id == peer.node_id))
        .cloned()
        .collect();
    PeersDiff { changed, gone }
}

/// The mesh interface of this node.
pub struct Mesh {
    api: WGApi<Kernel>,
    interface: String,
    psk: Key,
    peers: Vec<MeshPeer>,
}

impl Mesh {
    /// Creates and configures the mesh interface, with no peers.
    /// `psk` is the pre-shared key for all peers, from the join token.
    pub fn create(
        config: &Config,
        private_key: &Key,
        psk: &Key,
        mesh_ip: Ipv4Addr,
    ) -> anyhow::Result<Mesh> {
        let interface = config.node.mesh_interface.clone();
        let mut api = WGApi::<Kernel>::new(interface.clone())?;

        // An interface left behind by a crashed agent is not a problem:
        // `create_interface` reuses an existing interface,
        // and `configure_interface` replaces its addresses, key and peers.
        api.create_interface()
            .with_context(|| format!("cannot create interface {interface}"))?;
        api.configure_interface(&InterfaceConfiguration {
            name: interface.clone(),
            prvkey: private_key.to_string(),
            // The subnet prefix makes the kernel route the whole subnet into the interface.
            addresses: vec![IpAddrMask::new(
                IpAddr::V4(mesh_ip),
                config.cluster.mesh_subnet.prefix_len(),
            )],
            port: config.node.mesh_port,
            peers: Vec::new(),
            mtu: Some(config.cluster.mtu),
            fwmark: None,
        })
        .with_context(|| format!("cannot configure interface {interface}"))?;

        Ok(Mesh {
            api,
            interface,
            psk: psk.clone(),
            peers: Vec::new(),
        })
    }

    /// The configured peers.
    pub fn peers(&self) -> &[MeshPeer] {
        &self.peers
    }

    /// Configures `peer`.
    /// Removes the old peer of the same node if its key is different,
    /// for example after a restart.
    pub fn add_peer(&mut self, peer: &MeshPeer) -> anyhow::Result<()> {
        if self.peers.contains(peer) {
            return Ok(());
        }
        self.configure_peer(peer)?;
        tracing::info!(node_id = %peer.node_id, mesh_ip = %peer.mesh_ip, endpoint = %peer.endpoint, "configured mesh peer");

        let old = self
            .peers
            .iter()
            .find(|p| p.node_id == peer.node_id && p.public_key != peer.public_key)
            .cloned();
        if let Some(old) = old {
            self.remove_peer(&old);
        }
        self.peers.retain(|p| p.node_id != peer.node_id);
        self.peers.push(peer.clone());
        Ok(())
    }

    fn configure_peer(&self, peer: &MeshPeer) -> anyhow::Result<()> {
        let mut wg_peer = Peer::new(peer.public_key.clone());
        wg_peer.preshared_key = Some(self.psk.clone());
        wg_peer.endpoint = Some(peer.endpoint);
        wg_peer.allowed_ips = vec![IpAddrMask::host(IpAddr::V4(peer.mesh_ip))];
        self.api.configure_peer(&wg_peer)?;
        Ok(())
    }

    /// Removes `peer` if it is configured with the same key.
    /// A failure is only logged.
    pub fn remove_peer(&mut self, peer: &MeshPeer) {
        if !self.peers.iter().any(|p| p.public_key == peer.public_key) {
            return;
        }
        match self.api.remove_peer(&peer.public_key) {
            Ok(()) => {
                tracing::info!(node_id = %peer.node_id, public_key = %peer.public_key, "removed mesh peer")
            }
            Err(err) => {
                tracing::error!(node_id = %peer.node_id, "cannot remove mesh peer: {err:#}")
            }
        }
        self.peers.retain(|p| p.public_key != peer.public_key);
    }

    /// Removes the mesh interface.
    ///
    /// Only logs a failure: the agent stops anyway,
    /// and the next start reuses a leftover interface.
    /// Known failure: `remove_interface` also clears DNS settings of the interface,
    /// and fails on hosts with neither systemd-resolved nor resolvconf.
    /// Then the kernel interface stays.
    pub fn remove(self) {
        match self.api.remove_interface() {
            Ok(()) => tracing::info!("removed interface {}", self.interface),
            Err(err) => tracing::warn!("cannot remove interface {}: {err}", self.interface),
        }
    }
}

/// Configures the peers from the cluster view and from the channel `new_peers`,
/// and removes the peers of nodes that disappear from the view.
///
/// `new_peers` brings the peers that are not in gossip yet:
/// from `main` after a join, and from the join server for every accepted node.
/// After every update, `peers` gets all peers of this node, queued ones included,
/// for the mesh IP check and the response of the join server.
///
/// Updates on every change of the view, on every new peer from the channel,
/// and also every `resync_interval`, to retry failed peers.
/// Returns when the view task stops.
pub async fn sync_peers(
    mut view: watch::Receiver<ClusterView>,
    mesh: &mut Mesh,
    mut new_peers: mpsc::UnboundedReceiver<MeshPeer>,
    peers: watch::Sender<Vec<MeshPeer>>,
    resync_interval: Duration,
) {
    // Peers to configure.
    let mut pending: Vec<MeshPeer> = Vec::new();
    // The gossip view of the last update.
    let mut last_known: Vec<MeshPeer> = Vec::new();
    loop {
        let known = good_known_peers(&view.borrow_and_update());
        let peers_diff = get_gossip_changes(&last_known, &known);
        for peer in peers_diff.changed {
            add_pending(&mut pending, peer);
        }
        for peer in &peers_diff.gone {
            pending.retain(|p| p.public_key != peer.public_key);
            mesh.remove_peer(peer);
        }
        last_known = known;

        // Configure the queue one by one. A failed peer stays for the next update.
        let mut failed = Vec::new();
        for peer in pending.drain(..) {
            if let Err(err) = mesh.add_peer(&peer) {
                tracing::error!(node_id = %peer.node_id, mesh_ip = %peer.mesh_ip, "cannot configure mesh peer: {err:#}");
                failed.push(peer);
            }
        }
        pending = failed;

        // The join server must also see the queued peers.
        peers.send_replace(mesh.peers().iter().chain(&pending).cloned().collect());

        tokio::select! {
            changed = view.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            // No branch when all senders are gone: then only gossip and the timer wake the loop.
            Some(peer) = new_peers.recv() => add_pending(&mut pending, peer),
            _ = tokio::time::sleep(resync_interval) => {}
        }
    }
}
