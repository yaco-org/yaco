#![cfg(test)]

use super::*;

use defguard_wireguard_rs::key::Key;

use crate::facts::{Facts, MeshFacts};
use crate::view::{Liveness, NodeView};

/// A running API server on 127.0.0.1 with `view`.
/// Returns its base URL and the senders that the view task has in the agent.
async fn start(
    view: ClusterView,
    change_buffer: usize,
) -> (
    String,
    watch::Sender<ClusterView>,
    broadcast::Sender<Change>,
) {
    let (view_tx, view_rx) = watch::channel(view);
    let (changes_tx, _) = broadcast::channel(change_buffer);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = ApiState {
        view: view_rx,
        changes: changes_tx.clone(),
    };
    tokio::spawn(serve(listener, state));
    (base, view_tx, changes_tx)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

fn node(id: &str, liveness: Liveness) -> NodeView {
    NodeView {
        id: id.to_string(),
        generation: 1,
        liveness,
        facts: Facts::default(),
    }
}

/// The view of n1, which knows n2.
fn two_nodes() -> ClusterView {
    let mut view = ClusterView::empty("n1");
    for node in [node("n1", Liveness::Live), node("n2", Liveness::Dead)] {
        view.nodes.insert(node.id.clone(), node);
    }
    view
}

/// Reads server-sent events from a response, one at a time.
struct EventReader {
    response: reqwest::Response,
    buffer: String,
}

impl EventReader {
    async fn next(&mut self) -> Event {
        loop {
            // An event ends with an empty line. Keep-alive comments start with ':'.
            if let Some(end) = self.buffer.find("\n\n") {
                let block: String = self.buffer.drain(..end + 2).collect();
                let data: String = block
                    .lines()
                    .filter_map(|line| line.strip_prefix("data: "))
                    .collect();
                if !data.is_empty() {
                    return serde_json::from_str(&data).unwrap();
                }
                continue;
            }
            let chunk = self.response.chunk().await.unwrap().expect("stream ended");
            self.buffer.push_str(std::str::from_utf8(&chunk).unwrap());
        }
    }
}

async fn read_events(base: &str) -> EventReader {
    let response = client()
        .get(format!("{base}{EVENTS_PATH}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    EventReader {
        response,
        buffer: String::new(),
    }
}

fn spec_json() -> serde_json::Value {
    serde_json::from_str(&spec().to_json().unwrap()).unwrap()
}

#[test]
fn spec_has_every_operation() {
    let spec = spec();
    let paths = &spec.paths.paths;

    assert!(paths[NODES_PATH].get.is_some());
    assert!(paths[EVENTS_PATH].get.is_some());
    assert!(paths[CONTAINERS_PATH].get.is_some());
    let one = &paths[CONTAINER_PATH];
    assert!(one.put.is_some());
    assert!(one.get.is_some());
    assert!(one.delete.is_some());

    assert_eq!(paths.len(), 4, "unexpected paths: {:?}", paths.keys());
}

#[test]
fn write_operations_document_the_sender_header() {
    let spec = spec_json();
    for (path, operations) in spec["paths"].as_object().unwrap() {
        for (method, operation) in operations.as_object().unwrap() {
            if ["put", "post", "delete"].contains(&method.as_str()) {
                let parameters = operation["parameters"].as_array().unwrap();
                let has_sender = parameters
                    .iter()
                    .any(|p| p["name"] == yaco_api::SENDER_HEADER && p["in"] == "header");
                assert!(has_sender, "{method} {path} has no sender header");
            }
        }
    }
}

#[test]
fn spec_has_the_schemas_of_the_bodies() {
    let spec = spec_json();
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(schemas.contains_key("ContainerManifest"));
    assert!(schemas.contains_key("ErrorResponse"));
    assert!(schemas.contains_key("Node"));
    assert!(schemas.contains_key("Event"));
}

#[tokio::test]
async fn nodes_are_the_nodes_of_the_view() {
    let (base, _view, _events) = start(two_nodes(), 16).await;
    let response = client()
        .get(format!("{base}{NODES_PATH}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let nodes: Vec<Node> = response.json().await.unwrap();
    assert_eq!(nodes, convert::nodes(&two_nodes()));
}

#[tokio::test]
async fn event_stream_starts_with_a_snapshot_then_sends_every_change() {
    let (base, _view, changes) = start(two_nodes(), 16).await;
    let mut reader = read_events(&base).await;

    assert_eq!(reader.next().await, convert::snapshot(&two_nodes()));

    let change = Change::Changed(node("n2", Liveness::Live));
    changes.send(change.clone()).unwrap();
    assert_eq!(reader.next().await, Event::from(&change));
}

#[tokio::test]
async fn slow_stream_gets_a_new_snapshot_instead_of_the_missed_changes() {
    // The channel keeps only one change, so a reader that misses more lags.
    let (base, view, changes) = start(two_nodes(), 1).await;
    let mut reader = read_events(&base).await;
    reader.next().await;

    // Send a bunch of "missed" changes about removing some nodes
    for id in ["n2", "n3", "n4"] {
        changes.send(Change::Removed(id.to_string())).unwrap();
    }
    // Force change the view to something testable.
    let mut changed = two_nodes();
    changed.nodes.remove("n2");
    view.send_replace(changed.clone());

    assert_eq!(reader.next().await, convert::snapshot(&changed));
}

#[test]
fn facts_become_api_facts() {
    let node = NodeView {
        facts: Facts {
            mesh: Some(MeshFacts {
                // Base64 of 32 bytes of 0x11.
                wg_public_key: Key::try_from("ERERERERERERERERERERERERERERERERERERERERERE=")
                    .unwrap(),
                mesh_ip: "10.42.0.2".parse().unwrap(),
                endpoint: "192.0.2.2:7281".parse().unwrap(),
            }),
        },
        ..node("n2", Liveness::Leaving)
    };
    let json = serde_json::to_value(Node::from(&node)).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "id": "n2",
            "generation": 1,
            "liveness": "leaving",
            "facts": {
                "mesh": {
                    "wg_public_key": "ERERERERERERERERERERERERERERERERERERERERERE=",
                    "mesh_ip": "10.42.0.2",
                    "endpoint": "192.0.2.2:7281"
                }
            }
        })
    );
}

#[tokio::test]
async fn container_operation_answers_not_implemented() {
    let (base, _view, _events) = start(two_nodes(), 16).await;
    let client = client();
    let one = format!("{base}{}", CONTAINER_PATH.replace("{name}", "web"));
    let requests = [
        client.get(format!("{base}{CONTAINERS_PATH}")),
        client.put(&one),
        client.get(&one),
        client.delete(&one),
    ];
    for request in requests {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body: ErrorResponse = response.json().await.unwrap();
        assert_eq!(body.message, "not implemented yet");
    }
}
