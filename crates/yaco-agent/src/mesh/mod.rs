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

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context;
use chitchat::{Chitchat, ChitchatHandle, ChitchatId, NodeState};
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::gossip::LEAVING_KEY;

/// Fact keys in the own chitchat namespace.
pub const WG_PUBLIC_KEY_KEY: &str = "facts/wg_public_key";
pub const MESH_IP_KEY: &str = "facts/mesh_ip";
pub const ENDPOINT_KEY: &str = "facts/endpoint";

/// One node of the mesh, as the WireGuard peer list needs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPeer {
    /// The chitchat node ID.
    pub node_id: String,
    /// Base64, as `wg` prints it.
    pub public_key: String,
    pub mesh_ip: Ipv4Addr,
    pub endpoint: SocketAddr,
}

impl MeshPeer {
    /// Parses the facts of one node from its chitchat state.
    /// Received data can be malformed, so this never panics.
    pub fn from_node_state(state: &NodeState) -> anyhow::Result<MeshPeer> {
        let public_key = state
            .get(WG_PUBLIC_KEY_KEY)
            .context("missing wg_public_key")?;
        check_public_key(public_key)?;
        let mesh_ip = state
            .get(MESH_IP_KEY)
            .context("missing mesh_ip")?
            .parse()
            .context("bad mesh_ip")?;
        let endpoint = state
            .get(ENDPOINT_KEY)
            .context("missing endpoint")?
            .parse()
            .context("bad endpoint")?;
        Ok(MeshPeer {
            node_id: state.chitchat_id().node_id.to_string(),
            public_key: public_key.to_string(),
            mesh_ip,
            endpoint,
        })
    }

    /// Returns the facts to publish for this node.
    /// The node ID is not a fact: chitchat has it in the node's `ChitchatId`.
    pub fn to_facts(&self) -> Vec<(String, String)> {
        vec![
            (WG_PUBLIC_KEY_KEY.to_string(), self.public_key.clone()),
            (MESH_IP_KEY.to_string(), self.mesh_ip.to_string()),
            (ENDPOINT_KEY.to_string(), self.endpoint.to_string()),
        ]
    }
}

/// Checks that `public_key` is a base64 WireGuard key.
pub fn check_public_key(public_key: &str) -> anyhow::Result<()> {
    Key::try_from(public_key).map_err(|err| anyhow::anyhow!("bad wg_public_key: {err}"))?;
    Ok(())
}

/// Returns true if `ip` is a host address in `subnet`:
/// in the subnet, and neither the subnet address nor the broadcast address.
pub fn is_mesh_ip(subnet: Ipv4Net, ip: Ipv4Addr) -> bool {
    subnet.contains(&ip) && ip != subnet.network() && ip != subnet.broadcast()
}

/// Proposes a mesh IP for a node, in `subnet`.
///
/// SHA-256 keeps the result stable across versions and platforms.
/// The result is a host address: never the subnet address or the broadcast address.
/// `subnet` must be a /30 or larger, as `Config` makes sure.
pub fn mesh_ip(subnet: Ipv4Net, node_id: &str, attempt: u32) -> Ipv4Addr {
    let mut hasher = Sha256::new();
    hasher.update(node_id.as_bytes());
    hasher.update(attempt.to_be_bytes());
    let hash = hasher.finalize();
    let value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    // All addresses of the subnet, minus the subnet address and the broadcast address.
    let host_count = (1u64 << (32 - subnet.prefix_len())) - 2;
    let host = 1 + u64::from(value) % host_count;
    Ipv4Addr::from(u32::from(subnet.network()) + host as u32)
}

/// Keeps only the latest generation of every node ID.
/// A restarted node has a new generation (and a new key),
/// and chitchat keeps the old generation as a dead node for a while.
fn latest_generations<'a, T>(
    nodes: impl IntoIterator<Item = (&'a ChitchatId, T)>,
) -> BTreeMap<String, T> {
    let mut latest: BTreeMap<String, (u64, T)> = BTreeMap::new();
    for (id, value) in nodes {
        let is_newer = match latest.get(&*id.node_id) {
            Some((generation, _)) => id.generation_id > *generation,
            None => true,
        };
        if is_newer {
            latest.insert(id.node_id.to_string(), (id.generation_id, value));
        }
    }
    latest
        .into_iter()
        .map(|(node_id, (_, value))| (node_id, value))
        .collect()
}

/// Returns the peers of all other nodes that chitchat knows, live or dead.
/// Takes the latest generation of every node, skips the own node and nodes that left gracefully,
/// and skips (with a warning) nodes with bad or missing facts.
fn good_known_peers(chitchat: &Chitchat) -> Vec<MeshPeer> {
    let own_node_id = &chitchat.self_chitchat_id().node_id;
    let mut peers = Vec::new();
    for (node_id, state) in latest_generations(chitchat.node_states()) {
        // Also skips older generations of this node.
        if *node_id == **own_node_id || state.get(LEAVING_KEY).is_some() {
            continue;
        }
        match MeshPeer::from_node_state(state) {
            Ok(peer) => peers.push(peer),
            Err(err) => tracing::warn!(%node_id, "skipping node with bad facts: {err:#}"),
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
fn gossip_changes(old: &[MeshPeer], new: &[MeshPeer]) -> PeersDiff {
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
        let key = Key::try_from(peer.public_key.as_str())
            .map_err(|err| anyhow::anyhow!("bad public key: {err}"))?;
        let mut wg_peer = Peer::new(key);
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
        match self.remove_key(&peer.public_key) {
            Ok(()) => {
                tracing::info!(node_id = %peer.node_id, public_key = %peer.public_key, "removed mesh peer")
            }
            Err(err) => {
                tracing::error!(node_id = %peer.node_id, "cannot remove mesh peer: {err:#}")
            }
        }
        self.peers.retain(|p| p.public_key != peer.public_key);
    }

    fn remove_key(&self, public_key: &str) -> anyhow::Result<()> {
        let key =
            Key::try_from(public_key).map_err(|err| anyhow::anyhow!("bad public key: {err}"))?;
        self.api.remove_peer(&key)?;
        Ok(())
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

/// Configures the peers from gossip and from the channel `new_peers`,
/// and removes the peers of nodes that disappear from gossip.
///
/// `new_peers` brings the peers that are not in gossip yet:
/// from `main` after a join, and from the join server for every accepted node.
/// After every update, `peers` gets all peers of this node, queued ones included,
/// for the mesh IP check and the response of the join server.
///
/// Updates on every change of the live set, on every new peer from the channel,
/// and also every `resync_interval`: to retry failed peers,
/// and to remove dead nodes that chitchat forgot.
/// Returns when chitchat stops.
pub async fn sync_peers(
    handle: &ChitchatHandle,
    mesh: &mut Mesh,
    mut new_peers: mpsc::UnboundedReceiver<MeshPeer>,
    peers: watch::Sender<Vec<MeshPeer>>,
    resync_interval: Duration,
) {
    // Peers to configure.
    let mut pending: Vec<MeshPeer> = Vec::new();
    // The gossip view of the last update.
    let mut last_known: Vec<MeshPeer> = Vec::new();
    let mut watcher = handle.chitchat().lock().await.live_nodes_watcher();
    loop {
        // The live set is only the trigger. Mark it as seen.
        watcher.borrow_and_update();
        let known = good_known_peers(&*handle.chitchat().lock().await);
        let peers_diff = gossip_changes(&last_known, &known);
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
            changed = watcher.changed() => {
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
