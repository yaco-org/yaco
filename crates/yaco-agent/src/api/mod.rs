//! The node API server.
//!
//! Every handler has its path and its OpenAPI description in `#[utoipa::path]`,
//! and `utoipa-axum` builds both the axum router and the spec from them.
//! So each path is written once, as a constant in the crate `yaco-api`,
//! which the clients use too.
//!
//! For now every operation answers 501 Not Implemented.

mod tests;

use axum::http::StatusCode;
use axum::{Json, Router};
use tokio::net::TcpListener;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use yaco_api::{CONTAINER_PATH, CONTAINERS_PATH, ContainerManifest, ErrorResponse};

/// Parts of the spec that do not come from the handlers.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "YACO node API",
        description = "Every node of a YACO cluster serves this API on its mesh IP."
    ),
    tags((name = "containers", description = "Container manifests"))
)]
struct ApiDoc;

pub fn router() -> (Router, utoipa::openapi::OpenApi) {
    // `routes!` takes only handlers of the same path.
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(list_containers))
        .routes(routes!(put_container, get_container, delete_container))
        .split_for_parts()
}

/// Returns the OpenAPI spec of the node API.
pub fn spec() -> utoipa::openapi::OpenApi {
    router().1
}

/// Serves the node API on `listener`.
/// Returns only on an error.
pub async fn serve(listener: TcpListener) -> anyhow::Result<()> {
    let (router, _) = router();
    axum::serve(listener, router).await?;
    Ok(())
}

/// The answer of every operation that is not implemented yet.
/// Not in the spec, because the spec describes the finished API.
type NotImplemented = (StatusCode, Json<ErrorResponse>);

fn not_implemented() -> NotImplemented {
    let message = "not implemented yet".to_string();
    (StatusCode::NOT_IMPLEMENTED, Json(ErrorResponse { message }))
}

/// Returns all container manifests.
#[utoipa::path(
    get,
    path = CONTAINERS_PATH,
    tag = "containers",
    responses((status = 200, description = "All manifests", body = Vec<ContainerManifest>))
)]
async fn list_containers() -> NotImplemented {
    not_implemented()
}

/// Creates or replaces a container manifest.
#[utoipa::path(
    put,
    path = CONTAINER_PATH,
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
async fn put_container() -> NotImplemented {
    not_implemented()
}

/// Returns one container manifest.
#[utoipa::path(
    get,
    path = CONTAINER_PATH,
    tag = "containers",
    params(("name" = String, Path, description = "Name of the container")),
    responses(
        (status = 200, description = "The manifest", body = ContainerManifest),
        (status = 404, description = "No container has this name", body = ErrorResponse),
    )
)]
async fn get_container() -> NotImplemented {
    not_implemented()
}

/// Deletes a container manifest.
#[utoipa::path(
    delete,
    path = CONTAINER_PATH,
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
async fn delete_container() -> NotImplemented {
    not_implemented()
}
