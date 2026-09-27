//! Secure join through a bootstrap WireGuard tunnel.
//!
//! Every node has one bootstrap interface (`node.boot_interface`) in one of two roles:
//!
//! - Server role, on every member:
//!   the key is `boot_server` from the join token,
//!   and the only peer is the `boot_client` public key, with no endpoint.
//!   The join endpoint listens on this interface only.
//! - Client role, on a joining node, only during the join:
//!   the key is `boot_client`,
//!   and the only peer is the seed, with the `boot_server` public key.
//!
//! After the join, the joining node reconfigures the same interface to the server role,
//! so it can be a seed for other nodes.

mod tests;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};

use crate::config::{ClusterConfig, Config, ConfigFingerprint};
use crate::keys::ClusterKeys;
use crate::mesh::MeshPeer;

/// Addresses inside the bootstrap tunnel. They are not configurable.
/// They are link-local, so they are never routed,
/// and a /30 has room for exactly these two hosts.
/// Every member has the same server address which don't conflict
/// because each member has its own tunnel to the joining node.
pub const BOOT_SERVER_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 42, 1);
pub const BOOT_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 42, 2);
pub const BOOT_PREFIX_LEN: u8 = 30;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    /// `[cluster]` config fingerprint of the joining node.
    /// The seed refuses the join if it differs from its own.
    pub config_fingerprint: ConfigFingerprint,
    /// The node ID, the main WireGuard key, the proposed mesh IP and the public endpoint.
    pub peer: MeshPeer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    /// The seed and all its peers: the nodes that it knows, live or dead,
    /// and the nodes that joined but are not in gossip yet.
    pub members: Vec<MeshPeer>,
    /// Gossip address of the seed, inside the mesh.
    pub gossip_seed: SocketAddr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JoinRefusal {
    /// The request is malformed. HTTP 400.
    BadRequest(String),
    /// The `[cluster]` config of the joining node differs from the seed's. HTTP 400.
    ConfigMismatch,
    /// Another node has the proposed mesh IP. HTTP 409.
    MeshIpInUse,
}

/// Checks a join request against the config and the known members of the seed.
/// `members` must include the seed itself and the pending peers.
pub fn check_join(
    request: &JoinRequest,
    cluster: &ClusterConfig,
    members: &[MeshPeer],
) -> Result<(), JoinRefusal> {
    if request.config_fingerprint != cluster.fingerprint() {
        return Err(JoinRefusal::ConfigMismatch);
    }
    if request.peer.node_id.is_empty() {
        return Err(JoinRefusal::BadRequest("empty node_id".to_string()));
    }
    if !cluster.mesh_subnet.is_host(request.peer.mesh_ip) {
        return Err(JoinRefusal::BadRequest(format!(
            "{} is not in the mesh subnet",
            request.peer.mesh_ip
        )));
    }
    // The same key is the same node, for example a retried request.
    let in_use = members
        .iter()
        .any(|m| m.mesh_ip == request.peer.mesh_ip && m.public_key != request.peer.public_key);
    if in_use {
        return Err(JoinRefusal::MeshIpInUse);
    }
    Ok(())
}

/// The bootstrap interface of this node.
pub struct Bootstrap {
    api: WGApi<Kernel>,
    interface: String,
    port: u16,
    cluster: ClusterConfig,
}

impl Bootstrap {
    /// Creates the bootstrap interface, or reuses a leftover one.
    /// Call `set_client` or `set_server` next.
    pub fn create(config: &Config) -> anyhow::Result<Bootstrap> {
        let interface = config.node.boot_interface.clone();
        let mut api = WGApi::<Kernel>::new(interface.clone())?;
        api.create_interface()
            .with_context(|| format!("cannot create interface {interface}"))?;
        Ok(Bootstrap {
            api,
            interface,
            port: config.node.boot_port,
            cluster: config.cluster.clone(),
        })
    }

    /// Client role: the only peer is the seed at `seed`.
    pub fn set_client(&self, keys: &ClusterKeys, seed: SocketAddr) -> anyhow::Result<()> {
        let mut server = Peer::new(keys.boot_server.public_key());
        server.endpoint = Some(seed);
        server.allowed_ips = vec![IpAddrMask::host(IpAddr::V4(BOOT_SERVER_IP))];
        self.configure(&keys.boot_client, BOOT_CLIENT_IP, server)
    }

    /// Server role: the only peer is any joining node.
    pub fn set_server(&self, keys: &ClusterKeys) -> anyhow::Result<()> {
        let mut client = Peer::new(keys.boot_client.public_key());
        client.allowed_ips = vec![IpAddrMask::host(IpAddr::V4(BOOT_CLIENT_IP))];
        self.configure(&keys.boot_server, BOOT_SERVER_IP, client)
    }

    /// Replaces the key, the address and the peers of the interface.
    fn configure(&self, private_key: &Key, ip: Ipv4Addr, peer: Peer) -> anyhow::Result<()> {
        self.api
            .configure_interface(&InterfaceConfiguration {
                name: self.interface.clone(),
                prvkey: private_key.to_string(),
                // The subnet prefix gives the kernel a route to the other end of the tunnel.
                addresses: vec![IpAddrMask::new(IpAddr::V4(ip), BOOT_PREFIX_LEN)],
                port: self.port,
                peers: vec![peer],
                mtu: Some(self.cluster.mtu),
                fwmark: None,
            })
            .with_context(|| format!("cannot configure interface {}", self.interface))
    }
}

/// Shared state of the join endpoint.
pub struct JoinServer {
    config: Config,
    /// Facts of this node.
    own: MeshPeer,
    /// Gossip address of this node, inside the mesh.
    gossip_addr: SocketAddr,
    /// Sends the peer of every accepted node to `mesh::sync_peers`.
    new_peers: mpsc::UnboundedSender<MeshPeer>,
    /// All peers of this node, from `mesh::sync_peers`.
    peers: watch::Receiver<Vec<MeshPeer>>,
}

impl JoinServer {
    pub fn new(
        config: Config,
        own: MeshPeer,
        gossip_addr: SocketAddr,
        new_peers: mpsc::UnboundedSender<MeshPeer>,
        peers: watch::Receiver<Vec<MeshPeer>>,
    ) -> JoinServer {
        JoinServer {
            config,
            own,
            gossip_addr,
            new_peers,
            peers,
        }
    }
}

/// Serves `POST /join` on the bootstrap interface only.
/// Call it after `Bootstrap::set_server`, when the server address exists.
pub async fn serve(server: JoinServer) -> anyhow::Result<()> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    // Without this, the kernel also accepts connections to the server address
    // that arrive on another interface, outside the tunnel.
    socket.bind_device(Some(server.config.node.boot_interface.as_bytes()))?;
    socket.set_reuseaddr(true)?;
    let cluster = &server.config.cluster;
    socket
        .bind(SocketAddr::new(
            IpAddr::V4(BOOT_SERVER_IP),
            cluster.join_port,
        ))
        .context("cannot bind the join endpoint")?;
    let listener = socket.listen(16)?;

    let app = Router::new()
        .route("/join", post(handle_join))
        .with_state(Arc::new(server));
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_join(
    State(server): State<Arc<JoinServer>>,
    Json(request): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, (StatusCode, String)> {
    let node_id = &request.peer.node_id;

    // The peers include dead nodes, because a dead node can come back and still have its mesh IP,
    // and the nodes that joined but are not in gossip yet.
    // An earlier generation of the joining node gives its mesh IP free.
    let mut members = vec![server.own.clone()];
    members.extend(
        server
            .peers
            .borrow()
            .iter()
            .filter(|peer| peer.node_id != *node_id)
            .cloned(),
    );

    match check_join(&request, &server.config.cluster, &members) {
        Ok(()) => {
            tracing::info!(%node_id, mesh_ip = %request.peer.mesh_ip, endpoint = %request.peer.endpoint, "accepted join");
            // Add the new node as a mesh peer now, not after gossip.
            if server.new_peers.send(request.peer.clone()).is_err() {
                tracing::error!(%node_id, "cannot add the mesh peer: peer sync stopped");
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "peer sync stopped".to_string(),
                ));
            }
            Ok(Json(JoinResponse {
                members,
                gossip_seed: server.gossip_addr,
            }))
        }
        Err(JoinRefusal::ConfigMismatch) => {
            let reason = format!(
                "the [cluster] config differs: the seed has fingerprint {}, the joining node has fingerprint {}",
                server.config.cluster.fingerprint(),
                request.config_fingerprint
            );
            tracing::warn!(%node_id, "refused join: {reason}");
            Err((StatusCode::BAD_REQUEST, reason))
        }
        Err(JoinRefusal::BadRequest(reason)) => {
            tracing::warn!(%node_id, "refused join: {reason}");
            Err((StatusCode::BAD_REQUEST, reason))
        }
        Err(JoinRefusal::MeshIpInUse) => {
            tracing::info!(%node_id, mesh_ip = %request.peer.mesh_ip, "refused join: mesh IP in use");
            Err((StatusCode::CONFLICT, "mesh IP in use".to_string()))
        }
    }
}

/// Joins the cluster through one of the seeds in `node.seeds`.
///
/// The seeds are public bootstrap endpoints (IP and bootstrap port) of members.
/// Proposes `mesh_subnet.mesh_ip(node.id, attempt)` and takes the next attempt on HTTP 409.
/// Returns the accepted facts of this node and the join response.
pub async fn join(
    boot: &Bootstrap,
    keys: &ClusterKeys,
    config: &Config,
    public_key: &Key,
) -> anyhow::Result<(MeshPeer, JoinResponse)> {
    let cluster = &config.cluster;
    let config_fingerprint = cluster.fingerprint();
    let client = reqwest::Client::builder()
        .timeout(cluster.join_request_timeout)
        // So that we don't proxy join requests through an unrelated proxy.
        .no_proxy()
        .build()?;
    let url = format!("http://{BOOT_SERVER_IP}:{}/join", cluster.join_port);

    for round in 0..cluster.join_rounds {
        if round > 0 {
            tokio::time::sleep(with_jitter(cluster.join_retry_delay)).await;
        }
        for &seed in &config.node.seeds {
            boot.set_client(keys, seed)?;
            let mut attempt = 0;
            while attempt < cluster.max_mesh_ip_attempts {
                let peer = MeshPeer::own(config, public_key, attempt);
                let request = JoinRequest {
                    config_fingerprint: config_fingerprint.clone(),
                    peer: peer.clone(),
                };
                let result = client.post(&url).json(&request).send().await;
                match result {
                    Ok(response) if response.status() == StatusCode::CONFLICT => {
                        tracing::info!(%seed, mesh_ip = %peer.mesh_ip, "mesh IP in use, trying the next one");
                        attempt += 1;
                    }
                    Ok(response) if response.status().is_success() => {
                        let response: JoinResponse = response
                            .json()
                            .await
                            .context("bad join response from the seed")?;
                        tracing::info!(%seed, mesh_ip = %peer.mesh_ip, members = response.members.len(), "joined the cluster");
                        return Ok((peer, response));
                    }
                    Ok(response) => {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        tracing::warn!(%seed, %status, "seed refused the join: {body}");
                        break;
                    }
                    Err(err) => {
                        let err = anyhow::Error::from(err);
                        tracing::warn!(%seed, "cannot reach the seed: {err:#}");
                        break;
                    }
                }
            }
        }
    }
    anyhow::bail!("cannot join through any seed. Check the seed addresses and the join token")
}

/// Returns `delay` plus a random part of up to `delay`.
///
/// All joining nodes share one bootstrap client key,
/// so a seed sees two nodes that join at the same moment as one WireGuard peer,
/// and at least one of the two requests times out.
/// Without the random part, both nodes would retry at the same moment and collide again.
pub fn with_jitter(delay: Duration) -> Duration {
    delay + delay.mul_f64(rand::random::<f64>())
}
