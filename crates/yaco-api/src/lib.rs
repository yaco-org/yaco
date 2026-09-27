//! Definitions of the YACO node API.
//!
//! This crate has the paths, the request and response types, and the OpenAPI spec.

mod tests;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

/// Base path of the container operations.
/// One container is at `{CONTAINERS_PATH}/{name}`.
pub const CONTAINERS_PATH: &str = "/v1/containers";

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

/// The OpenAPI spec of the node API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "YACO node API",
        description = "Every node of a YACO cluster serves this API on its mesh IP."
    ),
    paths(
        operations::put_container,
        operations::get_container,
        operations::list_containers,
        operations::delete_container,
    ),
    components(schemas(ContainerManifest, ErrorResponse)),
    tags((name = "containers", description = "Container manifests"))
)]
pub struct ApiDoc;

/// Declarations of the operations, for the spec only.
/// The functions are empty because this crate is only for the spec
/// and the agent implements the handlers.
/// A test checks that they match `CONTAINERS_PATH`.
#[allow(dead_code)]
mod operations {
    use super::{ContainerManifest, ErrorResponse};

    /// Creates or replaces a container manifest.
    #[utoipa::path(
        put,
        path = "/v1/containers/{name}",
        tag = "containers",
        params(
            ("name" = String, Path, description = "Name of the container"),
            ("X-Yaco-Sender" = String, Header, description = "Sender of the request"),
        ),
        request_body = ContainerManifest,
        responses(
            (status = 200, description = "The manifest was replaced", body = ContainerManifest),
            (status = 201, description = "The manifest was created", body = ContainerManifest),
            (status = 400, description = "The manifest is not valid", body = ErrorResponse),
        )
    )]
    fn put_container() {}

    /// Returns one container manifest.
    #[utoipa::path(
        get,
        path = "/v1/containers/{name}",
        tag = "containers",
        params(("name" = String, Path, description = "Name of the container")),
        responses(
            (status = 200, description = "The manifest", body = ContainerManifest),
            (status = 404, description = "No container has this name", body = ErrorResponse),
        )
    )]
    fn get_container() {}

    /// Returns all container manifests.
    #[utoipa::path(
        get,
        path = "/v1/containers",
        tag = "containers",
        responses((status = 200, description = "All manifests", body = Vec<ContainerManifest>))
    )]
    fn list_containers() {}

    /// Deletes a container manifest.
    #[utoipa::path(
        delete,
        path = "/v1/containers/{name}",
        tag = "containers",
        params(
            ("name" = String, Path, description = "Name of the container"),
            ("X-Yaco-Sender" = String, Header, description = "Sender of the request"),
        ),
        responses(
            (status = 204, description = "The manifest was deleted"),
            (status = 404, description = "No container has this name", body = ErrorResponse),
        )
    )]
    fn delete_container() {}
}
