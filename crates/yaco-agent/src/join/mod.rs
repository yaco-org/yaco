//! Secure join through a bootstrap WireGuard tunnel.
//!
//! Every node has one bootstrap interface, `yaco-boot`, in one of two roles:
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
use chitchat::{Chitchat, ChitchatId};
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::keys::ClusterKeys;
use crate::mesh::{self, MeshPeer, PendingPeers};

/// Name of the bootstrap interface.
pub const INTERFACE: &str = "yaco-boot";

/// Addresses inside the bootstrap tunnel.
/// They are link-local (169.254.0.0/16), so they are never routed,
/// and they do not overlap the mesh subnet or the Docker address pools.
/// Every member has the same server address.
/// Because each member has its own tunnel to the joining node
/// this should not conflict.
pub const SERVER_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 42, 1);
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 42, 2);
/// The /30 prefix gives only two usable IPs (above).
pub const PREFIX_LEN: u8 = 30;

/// TCP port of the join endpoint, inside the tunnel.
pub const HTTP_PORT: u16 = 7283;

/// Timeout for one join request, WireGuard handshake included.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the joining node tries all seeds before it gives up.
pub const JOIN_ROUNDS: u32 = 5;
/// Pause between two rounds.
pub const RETRY_DELAY: Duration = Duration::from_secs(1);
/// How many mesh IPs the joining node proposes before it gives up.
pub const MAX_IP_ATTEMPTS: u32 = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub node_id: String,
    /// The main WireGuard key, the proposed mesh IP and the public endpoint.
    pub peer: MeshPeer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinResponse {
    /// The seed and all nodes that the seed knows, live or dead.
    pub members: Vec<MeshPeer>,
    /// Gossip address of the seed, inside the mesh.
    pub gossip_seed: SocketAddr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JoinRefusal {
    /// The request is malformed. HTTP 400.
    BadRequest(String),
    /// Another node has the proposed mesh IP. HTTP 409.
    MeshIpInUse,
}

/// Checks a join request against the known members.
/// `members` must include the seed itself and the pending peers.
pub fn check_join(request: &JoinRequest, members: &[MeshPeer]) -> Result<(), JoinRefusal> {
    if request.node_id.is_empty() {
        return Err(JoinRefusal::BadRequest("empty node_id".to_string()));
    }
    mesh::check_public_key(&request.peer.public_key)
        .map_err(|err| JoinRefusal::BadRequest(err.to_string()))?;
    if !mesh::is_mesh_ip(request.peer.mesh_ip) {
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
    port: u16,
}

impl Bootstrap {
    /// Creates the bootstrap interface, or reuses a leftover one.
    /// Call `set_client` or `set_server` next.
    pub fn create(port: u16) -> anyhow::Result<Bootstrap> {
        let mut api = WGApi::<Kernel>::new(INTERFACE)?;
        api.create_interface()
            .with_context(|| format!("cannot create interface {INTERFACE}"))?;
        Ok(Bootstrap { api, port })
    }

    /// Client role: the only peer is the seed at `seed`.
    pub fn set_client(&self, keys: &ClusterKeys, seed: SocketAddr) -> anyhow::Result<()> {
        let mut server = Peer::new(keys.boot_server.public_key());
        server.endpoint = Some(seed);
        server.allowed_ips = vec![IpAddrMask::host(IpAddr::V4(SERVER_IP))];
        self.configure(&keys.boot_client, CLIENT_IP, server)
    }

    /// Server role: the only peer is any joining node.
    pub fn set_server(&self, keys: &ClusterKeys) -> anyhow::Result<()> {
        let mut client = Peer::new(keys.boot_client.public_key());
        client.allowed_ips = vec![IpAddrMask::host(IpAddr::V4(CLIENT_IP))];
        self.configure(&keys.boot_server, SERVER_IP, client)
    }

    /// Replaces the key, the address and the peers of the interface.
    fn configure(&self, private_key: &Key, ip: Ipv4Addr, peer: Peer) -> anyhow::Result<()> {
        self.api
            .configure_interface(&InterfaceConfiguration {
                name: INTERFACE.to_string(),
                prvkey: private_key.to_string(),
                addresses: vec![IpAddrMask::new(IpAddr::V4(ip), PREFIX_LEN)],
                port: self.port,
                peers: vec![peer],
                mtu: Some(mesh::MTU),
                fwmark: None,
            })
            .with_context(|| format!("cannot configure interface {INTERFACE}"))
    }
}

/// Shared state of the join endpoint.
pub struct JoinServer {
    pub chitchat: Arc<Mutex<Chitchat>>,
    pub self_id: ChitchatId,
    /// Facts of this node.
    pub own: MeshPeer,
    pub pending: Arc<PendingPeers>,
}

/// Serves `POST /join` on the bootstrap interface only.
/// Call it after `Bootstrap::set_server`, when the server address exists.
pub async fn serve(server: JoinServer) -> anyhow::Result<()> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    // Without this, the kernel also accepts connections to SERVER_IP
    // that arrive on another interface, outside the tunnel.
    socket.bind_device(Some(INTERFACE.as_bytes()))?;
    socket.set_reuseaddr(true)?;
    socket
        .bind(SocketAddr::new(IpAddr::V4(SERVER_IP), HTTP_PORT))
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
    let (gossip_seed, nodes) = {
        let chitchat = server.chitchat.lock().await;
        let nodes = chitchat.node_states().clone();
        let addr = chitchat.self_chitchat_id().gossip_advertise_addr;
        (addr, nodes)
    };

    // All nodes that chitchat knows, dead ones included:
    // a dead node can come back and still have its mesh IP.
    let mut known = mesh::known_peers(&nodes);
    known.remove(&*server.self_id.node_id);
    // An earlier generation of the joining node gives its mesh IP free.
    known.remove(&request.node_id);
    let mut members = vec![server.own.clone()];
    members.extend(known.into_values());

    // Mesh IPs in use: the members and the nodes that joined but are not in gossip yet.
    let mut taken = members.clone();
    taken.extend(server.pending.current(&members));

    match check_join(&request, &taken) {
        Ok(()) => {
            tracing::info!(node_id = %request.node_id, mesh_ip = %request.peer.mesh_ip, endpoint = %request.peer.endpoint, "accepted join");
            // Add the new node as a mesh peer now, not after gossip.
            server.pending.add(vec![request.peer]);
            Ok(Json(JoinResponse {
                members,
                gossip_seed,
            }))
        }
        Err(JoinRefusal::BadRequest(reason)) => {
            tracing::warn!(node_id = %request.node_id, "refused join: {reason}");
            Err((StatusCode::BAD_REQUEST, reason))
        }
        Err(JoinRefusal::MeshIpInUse) => {
            tracing::info!(node_id = %request.node_id, mesh_ip = %request.peer.mesh_ip, "refused join: mesh IP in use");
            Err((StatusCode::CONFLICT, "mesh IP in use".to_string()))
        }
    }
}

/// Joins the cluster through one of `seeds`.
///
/// `seeds` are public bootstrap endpoints (IP and bootstrap port) of members.
/// Proposes `mesh_ip(node_id, attempt)` and takes the next attempt on HTTP 409.
/// Returns the accepted facts of this node and the join response.
pub async fn join(
    boot: &Bootstrap,
    keys: &ClusterKeys,
    seeds: &[SocketAddr],
    node_id: &str,
    public_key: &str,
    endpoint: SocketAddr,
) -> anyhow::Result<(MeshPeer, JoinResponse)> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        // So that we don't proxy join requests through an unrelated proxy.
        .no_proxy()
        .build()?;
    let url = format!("http://{SERVER_IP}:{HTTP_PORT}/join");

    for round in 0..JOIN_ROUNDS {
        if round > 0 {
            tokio::time::sleep(RETRY_DELAY).await;
        }
        for &seed in seeds {
            boot.set_client(keys, seed)?;
            let mut attempt = 0;
            while attempt < MAX_IP_ATTEMPTS {
                let peer = MeshPeer {
                    public_key: public_key.to_string(),
                    mesh_ip: mesh::mesh_ip(node_id, attempt),
                    endpoint,
                };
                let request = JoinRequest {
                    node_id: node_id.to_string(),
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
