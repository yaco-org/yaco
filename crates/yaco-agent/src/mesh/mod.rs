//! WireGuard mesh between the live nodes.
//!
//! chitchat runs over the mesh.
//!
//! Every node publishes its WireGuard facts in its own chitchat namespace.
//! Every node makes its peer list from the facts of all nodes that chitchat knows.
//!
//! A node that joins gets its first peers from the join response (see `join`),
//! before gossip has them. `PendingPeers` keeps those peers configured
//! until they appear in gossip.
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
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context;
use chitchat::{ChitchatHandle, ChitchatId, NodeState};
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use crate::gossip::LEAVING_KEY;

/// Name of the main mesh interface.
/// The `yaco-` prefix keeps it apart from interfaces of other tools,
/// for example `wg0` of wg-quick.
/// Linux limits interface names to 15 characters.
pub const INTERFACE: &str = "yaco-mesh";

/// Mesh subnet: 10.42.0.0/16.
pub const SUBNET: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 0);
pub const SUBNET_PREFIX_LEN: u8 = 16;

/// Interface MTU.
pub const MTU: u32 = 1420;

/// Fact keys in the own chitchat namespace.
pub const WG_PUBLIC_KEY_KEY: &str = "facts/wg_public_key";
pub const MESH_IP_KEY: &str = "facts/mesh_ip";
pub const ENDPOINT_KEY: &str = "facts/endpoint";

/// How often `sync_peers` retries without a membership change.
pub const RESYNC_INTERVAL: Duration = Duration::from_secs(30);

/// How long a pending peer stays configured without appearing in gossip.
pub const PENDING_TTL: Duration = Duration::from_secs(60);

/// One remote node, as the WireGuard peer list needs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPeer {
    /// Base64, as `wg` prints it.
    pub public_key: String,
    pub mesh_ip: Ipv4Addr,
    pub endpoint: SocketAddr,
}

impl MeshPeer {
    /// Parses the facts of one node.
    /// Received data can be malformed, so this never panics.
    pub fn from_facts(
        public_key: Option<&str>,
        mesh_ip: Option<&str>,
        endpoint: Option<&str>,
    ) -> anyhow::Result<MeshPeer> {
        let public_key = public_key.context("missing wg_public_key")?;
        check_public_key(public_key)?;
        let mesh_ip = mesh_ip
            .context("missing mesh_ip")?
            .parse()
            .context("bad mesh_ip")?;
        let endpoint = endpoint
            .context("missing endpoint")?
            .parse()
            .context("bad endpoint")?;
        Ok(MeshPeer {
            public_key: public_key.to_string(),
            mesh_ip,
            endpoint,
        })
    }

    /// Returns the facts to publish for this node.
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

/// Returns true if `ip` is a host address in the mesh subnet.
pub fn is_mesh_ip(ip: Ipv4Addr) -> bool {
    let host = u32::from(ip).wrapping_sub(u32::from(SUBNET));
    (1..=65534).contains(&host)
}

/// Proposes a mesh IP for a node.
///
/// SHA-256 keeps the result stable across versions and platforms.
/// The host part is in 1..=65534,
/// so the result is never the subnet address or the broadcast address.
pub fn mesh_ip(node_id: &str, attempt: u32) -> Ipv4Addr {
    let mut hasher = Sha256::new();
    hasher.update(node_id.as_bytes());
    hasher.update(attempt.to_be_bytes());
    let hash = hasher.finalize();
    let value = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    let host = 1 + value % 65534;
    Ipv4Addr::from(u32::from(SUBNET) + host)
}

/// Keeps only the latest generation of every node ID.
/// A restarted node has a new generation (and a new key),
/// and chitchat keeps the old generation as a dead node for a while.
pub fn latest_generations<'a, T>(
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

/// Returns the peers of all nodes that chitchat knows, live or dead, by node ID.
/// Takes the latest generation of every node, skips nodes that left gracefully,
/// and skips (with a warning) nodes with bad or missing facts.
pub fn known_peers(nodes: &BTreeMap<ChitchatId, NodeState>) -> BTreeMap<String, MeshPeer> {
    let mut peers = BTreeMap::new();
    for (node_id, state) in latest_generations(nodes) {
        if state.get(LEAVING_KEY).is_some() {
            continue;
        }
        let peer = MeshPeer::from_facts(
            state.get(WG_PUBLIC_KEY_KEY),
            state.get(MESH_IP_KEY),
            state.get(ENDPOINT_KEY),
        );
        match peer {
            Ok(peer) => {
                peers.insert(node_id, peer);
            }
            Err(err) => tracing::warn!(%node_id, "skipping node with bad facts: {err:#}"),
        }
    }
    peers
}

/// Returns the known peers, plus the pending peers that gossip does not have yet.
/// Skips the own node, which can be in a join response.
pub fn desired_peers(
    known: Vec<MeshPeer>,
    pending: Vec<MeshPeer>,
    own_public_key: &str,
) -> Vec<MeshPeer> {
    let mut peers = known;
    for peer in pending {
        let known = peers.iter().any(|p| p.public_key == peer.public_key);
        if !known && peer.public_key != own_public_key {
            peers.push(peer);
        }
    }
    peers
}

/// Peers that are not in gossip yet:
/// on a seed, the node that just joined;
/// on a joining node, the members from the join response.
/// A peer is forgotten when it appears in gossip, or after `PENDING_TTL`.
/// From then on, gossip alone decides, so a node that leaves is removed at once.
#[derive(Default)]
pub struct PendingPeers {
    peers: Mutex<Vec<(MeshPeer, Instant)>>,
    /// Wakes `sync_peers` after `add`.
    changed: Notify,
}

impl PendingPeers {
    pub fn add(&self, peers: Vec<MeshPeer>) {
        let now = Instant::now();
        {
            let mut pending = self.peers.lock().unwrap();
            for peer in peers {
                pending.retain(|(p, _)| p.public_key != peer.public_key);
                pending.push((peer, now));
            }
        }
        self.changed.notify_one();
    }

    /// Forgets the expired peers and the peers in `known`, and returns the others.
    pub fn current(&self, known: &[MeshPeer]) -> Vec<MeshPeer> {
        let mut pending = self.peers.lock().unwrap();
        pending.retain(|(peer, added)| {
            let is_known = known.iter().any(|k| k.public_key == peer.public_key);
            added.elapsed() < PENDING_TTL && !is_known
        });
        pending.iter().map(|(peer, _)| peer.clone()).collect()
    }
}

/// Compares the configured peers with the desired peers.
/// Returns the peers to add or update, and the public keys to remove.
pub fn diff_peers<'a>(
    current: &[MeshPeer],
    desired: &'a [MeshPeer],
) -> (Vec<&'a MeshPeer>, Vec<String>) {
    let to_configure = desired
        .iter()
        .filter(|peer| !current.contains(peer))
        .collect();
    let to_remove = current
        .iter()
        .filter(|old| !desired.iter().any(|new| new.public_key == old.public_key))
        .map(|old| old.public_key.clone())
        .collect();
    (to_configure, to_remove)
}

/// The mesh interface of this node.
pub struct Mesh {
    api: WGApi<Kernel>,
    psk: Key,
    public_key: String,
    peers: Vec<MeshPeer>,
}

impl Mesh {
    /// Creates and configures the mesh interface, with no peers.
    /// `psk` is the pre-shared key for all peers, from the join token.
    pub fn create(
        private_key: &Key,
        psk: &Key,
        mesh_ip: Ipv4Addr,
        port: u16,
    ) -> anyhow::Result<Mesh> {
        let mut api = WGApi::<Kernel>::new(INTERFACE)?;

        // An interface left behind by a crashed agent is not a problem:
        // `create_interface` reuses an existing interface,
        // and `configure_interface` replaces its addresses, key and peers.
        api.create_interface()
            .with_context(|| format!("cannot create interface {INTERFACE}"))?;
        api.configure_interface(&InterfaceConfiguration {
            name: INTERFACE.to_string(),
            prvkey: private_key.to_string(),
            // The /16 prefix makes the kernel route the whole subnet into the interface.
            addresses: vec![IpAddrMask::new(IpAddr::V4(mesh_ip), SUBNET_PREFIX_LEN)],
            port,
            peers: Vec::new(),
            mtu: Some(MTU),
            fwmark: None,
        })
        .with_context(|| format!("cannot configure interface {INTERFACE}"))?;

        Ok(Mesh {
            api,
            psk: psk.clone(),
            public_key: private_key.public_key().to_string(),
            peers: Vec::new(),
        })
    }

    /// Makes the WireGuard peers equal to `desired`.
    ///
    /// A failed change is logged and not recorded,
    /// so the next call tries it again.
    pub fn set_peers(&mut self, desired: Vec<MeshPeer>) {
        let (to_configure, to_remove) = diff_peers(&self.peers, &desired);
        let mut applied = Vec::new();

        for public_key in &to_remove {
            match self.remove_peer(public_key) {
                Ok(()) => tracing::info!(%public_key, "removed mesh peer"),
                Err(err) => {
                    tracing::error!(%public_key, "cannot remove mesh peer: {err:#}");
                    let old = self.peers.iter().find(|p| &p.public_key == public_key);
                    applied.extend(old.cloned());
                }
            }
        }

        // Building a new list of current peers from current peers and new peers
        for peer in &desired {
            if !to_configure.contains(&peer) {
                // If a peer is already present just add it to the list
                applied.push(peer.clone());
                continue;
            }
            // Otherwise, configure
            match self.configure_peer(peer) {
                Ok(()) => {
                    tracing::info!(mesh_ip = %peer.mesh_ip, endpoint = %peer.endpoint, "configured mesh peer");
                    applied.push(peer.clone());
                }
                Err(err) => {
                    tracing::error!(mesh_ip = %peer.mesh_ip, "cannot configure mesh peer: {err:#}")
                }
            }
        }

        self.peers = applied;
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

    fn remove_peer(&self, public_key: &str) -> anyhow::Result<()> {
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
            Ok(()) => tracing::info!("removed interface {INTERFACE}"),
            Err(err) => tracing::warn!("cannot remove interface {INTERFACE}: {err}"),
        }
    }
}

/// Keeps the WireGuard peers equal to the known nodes plus the pending peers.
/// Updates on every change of the live set, on every new pending peer,
/// and also every `RESYNC_INTERVAL`: to retry failed changes,
/// to drop expired pending peers, and to drop dead nodes that chitchat forgot.
/// Returns when chitchat stops.
pub async fn sync_peers(handle: &ChitchatHandle, mesh: &mut Mesh, pending: &PendingPeers) {
    let own_node_id = handle.chitchat_id().node_id.to_string();
    let mut watcher = handle.chitchat().lock().await.live_nodes_watcher();
    loop {
        // The live set is only the trigger. Mark it as seen.
        watcher.borrow_and_update();
        let nodes = handle.chitchat().lock().await.node_states().clone();
        let mut known = known_peers(&nodes);
        // Also removes older generations of this node.
        known.remove(&own_node_id);
        let known: Vec<MeshPeer> = known.into_values().collect();
        let not_known = pending.current(&known);
        mesh.set_peers(desired_peers(known, not_known, &mesh.public_key));
        tokio::select! {
            changed = watcher.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            // Wakes up the loop on changes to pending peers
            // from `handle_join` of the join server
            _ = pending.changed.notified() => {}
            _ = tokio::time::sleep(RESYNC_INTERVAL) => {}
        }
    }
}
