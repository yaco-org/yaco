//! The node API server.
//!
//! Every handler has its path and its OpenAPI description in `#[utoipa::path]`,
//! and `utoipa-axum` builds both the axum router and the spec from them.
//! So each path is written once, as a constant in the crate `yaco-api`,
//! which the clients use too.
//!
//! The node and event operations read the cluster view (see `view`).
//! The container operations answer 501 Not Implemented for now.

mod tests;

use std::convert::Infallible;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{self, KeepAlive, Sse};
use axum::{Json, Router};
use futures_util::Stream;
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, watch};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use yaco_api::{
    CONTAINER_PATH, CONTAINERS_PATH, ContainerManifest, EVENTS_PATH, ErrorResponse, Event,
    NODES_PATH, Node,
};

use crate::view::{self, ClusterView};

/// Parts of the spec that do not come from the handlers.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "YACO node API",
        description = "Every node of a YACO cluster serves this API on its mesh IP."
    ),
    tags(
        (name = "nodes", description = "Nodes of the cluster"),
        (name = "events", description = "Changes of the cluster"),
        (name = "containers", description = "Container manifests"),
    )
)]
struct ApiDoc;

/// What the handlers read. Both come from the view task (`view::run`).
#[derive(Clone)]
pub struct ApiState {
    pub view: watch::Receiver<ClusterView>,
    /// Only for `subscribe`: every event stream gets its own receiver.
    pub events: broadcast::Sender<Event>,
}

fn open_api_router() -> OpenApiRouter<ApiState> {
    // `routes!` takes only handlers of the same path.
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(list_nodes))
        .routes(routes!(events))
        .routes(routes!(list_containers))
        .routes(routes!(put_container, get_container, delete_container))
}

/// Returns the axum router of the node API.
pub fn router(state: ApiState) -> Router {
    let (router, _) = open_api_router().split_for_parts();
    router.with_state(state)
}

/// Returns the OpenAPI spec of the node API.
pub fn spec() -> utoipa::openapi::OpenApi {
    let (_, spec) = open_api_router().split_for_parts();
    spec
}

/// Serves the node API on `listener`.
/// Returns only on an error.
pub async fn serve(listener: TcpListener, state: ApiState) -> anyhow::Result<()> {
    axum::serve(listener, router(state)).await?;
    Ok(())
}

/// Returns all nodes of the cluster, as this node sees them.
#[utoipa::path(
    get,
    path = NODES_PATH,
    tag = "nodes",
    responses((status = 200, description = "All nodes, in the order of their IDs", body = Vec<Node>))
)]
async fn list_nodes(State(state): State<ApiState>) -> Json<Vec<Node>> {
    let nodes = state.view.borrow().nodes.values().cloned().collect();
    Json(nodes)
}

/// Streams the changes of the cluster as server-sent events.
///
/// Every event has one JSON `Event` in its `data` field.
/// The stream starts with a `snapshot`.
/// A client that reads too slowly gets a new `snapshot` instead of the events that it missed.
#[utoipa::path(
    get,
    path = EVENTS_PATH,
    tag = "events",
    responses((
        status = 200,
        description = "Endless stream of events",
        content_type = "text/event-stream",
        body = Event
    ))
)]
async fn events(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<sse::Event, Infallible>>> {
    Sse::new(event_stream(state)).keep_alive(KeepAlive::default())
}

/// The events of one stream: a snapshot, then every change.
fn event_stream(state: ApiState) -> impl Stream<Item = Result<sse::Event, Infallible>> {
    // Subscribe before the snapshot, so that no change falls between them.
    // A change can then be in the snapshot and also come as an event.
    // That is no problem, because an event carries the whole node.
    let receiver = state.events.subscribe();
    let first = view::snapshot(&state.view.borrow());
    let start = (Some(first), receiver, state.view);
    futures_util::stream::unfold(start, |(next, mut receiver, view)| async move {
        let event = match next {
            Some(event) => event,
            None => match receiver.recv().await {
                Ok(event) => event,
                Err(RecvError::Lagged(_)) => view::snapshot(&view.borrow()),
                Err(RecvError::Closed) => return None,
            },
        };
        Some((Ok(to_sse(&event)), (None, receiver, view)))
    })
}

fn to_sse(event: &Event) -> sse::Event {
    let json = serde_json::to_string(event).expect("an event always serializes");
    sse::Event::default().data(json)
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
