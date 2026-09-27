//! Definitions of the YACO node API: the paths and the request and response types.
//!
//! The agent serves the API, and its handlers use the paths from here,
//! so the server and the clients (the CLI, third parties) share them.
//! The OpenAPI spec comes from the handlers in the agent: `cargo run -p yaco-agent --example openapi`.

mod tests;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// All container manifests.
pub const CONTAINERS_PATH: &str = "/v1/containers";

/// One container manifest. `{name}` is the name of the container.
pub const CONTAINER_PATH: &str = "/v1/containers/{name}";

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
