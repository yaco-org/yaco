//! Definitions of the YACO node API: the paths and the request and response types.
//!
//! The agent serves the API, and its handlers use the paths from here,
//! so the server and the clients (the CLI, third parties) share them.
//! The OpenAPI spec comes from the handlers in the agent: `cargo run -p yaco-agent --example openapi`.

mod tests;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// All container manifests.
pub const CONTAINERS_PATH: &str = "/v1/containers";

/// One container manifest. `{name}` is the name of the container.
pub const CONTAINER_PATH: &str = "/v1/containers/{name}";

/// All nodes of the cluster.
pub const NODES_PATH: &str = "/v1/nodes";

/// Stream of cluster events (server-sent events).
pub const EVENTS_PATH: &str = "/v1/events";

/// Header with the sender of a write request.
/// Every write request must have it (architecture section 5.3).
pub const SENDER_HEADER: &str = "X-Yaco-Sender";

/// A container manifest: the desired state of one container.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContainerManifest {
    /// Unique in the cluster.
    /// Must be equal to the last segment of the path.
    #[schema(example = "web")]
    pub name: String,
    /// Docker image reference.
    #[schema(example = "nginx:1.29")]
    pub image: String,
    /// Replaces the command of the image.
    /// Empty: the container runs the command of the image.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(example = json!(["nginx", "-g", "daemon off;"]))]
    pub command: Vec<String>,
    /// Environment variables.
    /// Keys that start with `YACO_` are reserved for the agent.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schema(example = json!({"TZ": "UTC"}))]
    pub env: BTreeMap<String, String>,
}

/// Body of every failed request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// What went wrong, for people.
    #[schema(example = "no container has the name \"web\"")]
    pub message: String,
}

/// Liveness of a node, as this node sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    /// The failure detector hears the node.
    Live,
    /// The failure detector does not hear the node.
    /// It can come back, for example after a network cut.
    Dead,
    /// The node left the cluster gracefully.
    Leaving,
}

/// One node of the cluster, as this node sees it.
/// Only the latest generation of each node ID is shown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Node {
    /// Node ID, chosen by the operator.
    #[schema(example = "n1")]
    pub id: String,
    /// Start time of the agent, in seconds since the Unix epoch.
    /// A restarted node has a new generation.
    #[schema(example = 1790000000)]
    pub generation: u64,
    pub liveness: Liveness,
    pub facts: NodeFacts,
}

/// Facts that a node publishes about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeFacts {
    /// Absent if the node published no mesh facts, or facts that this node cannot read.
    pub mesh: Option<MeshFacts>,
}

/// How to reach a node over the mesh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MeshFacts {
    /// WireGuard public key of the mesh interface, base64.
    #[schema(example = "ERERERERERERERERERERERERERERERERERERERERERE=")]
    pub wg_public_key: String,
    /// Address of the node inside the mesh.
    #[schema(value_type = String, format = Ipv4, example = "10.42.58.124")]
    pub mesh_ip: Ipv4Addr,
    /// Public address and port of the mesh WireGuard interface.
    #[schema(value_type = String, example = "203.0.113.1:7281")]
    pub endpoint: SocketAddr,
}

/// One event of the event stream.
///
/// Every stream starts with `snapshot`.
/// The other events carry the whole node, so a client can apply an event twice with no harm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// All nodes.
    /// The first event of every stream,
    /// and again when the stream was too slow and missed events.
    Snapshot { nodes: Vec<Node> },
    /// A node ID that this node did not know.
    NodeAdded { node: Node },
    /// A known node changed: its liveness, its generation or its facts.
    /// A graceful leave is a change to `leaving`.
    NodeChanged { node: Node },
    /// This node forgot the node:
    /// it was dead or leaving for longer than `cluster.dead_node_grace_period`.
    NodeRemoved { id: String },
}
