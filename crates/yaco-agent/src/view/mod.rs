//! The cluster view: the only reader of chitchat state.
//!
//! `run` turns the chitchat state into a plain `ClusterView` and publishes it two ways:
//!
//! - `watch<ClusterView>`: the latest view, for readers that need the current state
//!   (the mesh peer sync, the membership log, `GET /v1/nodes`).
//! - `broadcast<Event>`: the changes between two views, for readers that need every change
//!   (the event stream `GET /v1/events`).
//!
//! `build` and `changes` are pure functions, so they are easy to test.
//! Membership hysteresis (architecture section 5.7) will go into `run` later.

mod tests;

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chitchat::{Chitchat, ChitchatHandle, ChitchatId};
use tokio::sync::{Notify, broadcast, watch};
use yaco_api::{Event, Liveness, Node};

use crate::gossip::LEAVING_KEY;

/// Prefix of the fact keys in a chitchat namespace.
/// The view shows the facts without it.
pub const FACTS_PREFIX: &str = "facts/";

/// How many events the broadcast channel keeps for a slow reader.
/// A reader that falls further behind gets a new snapshot.
pub const EVENT_BUFFER: usize = 1024;

/// All nodes that chitchat knows, as this node sees them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterView {
    /// ID of this node.
    pub self_id: String,
    /// The latest generation of every node ID, this node included.
    pub nodes: BTreeMap<String, Node>,
}

impl ClusterView {
    /// A view with no nodes, before the first update.
    pub fn empty(self_id: &str) -> ClusterView {
        ClusterView {
            self_id: self_id.to_string(),
            nodes: BTreeMap::new(),
        }
    }

    /// The IDs of the live nodes, in order.
    pub fn live_ids(&self) -> Vec<String> {
        self.nodes
            .values()
            .filter(|node| node.liveness == Liveness::Live)
            .map(|node| node.id.clone())
            .collect()
    }

    /// Builds the view from the chitchat state.
    ///
    /// Takes only the latest generation of each node ID.
    /// A restarted node has a new generation (and a new key),
    /// and chitchat keeps the old generation as a dead node for a while.
    pub fn from_chitchat(chitchat: &Chitchat) -> Self {
        let live: HashSet<&ChitchatId> = chitchat.live_nodes().collect();

        let mut latest: BTreeMap<&str, &ChitchatId> = BTreeMap::new();
        for id in chitchat.node_states().keys() {
            let is_newer = match latest.get(&*id.node_id) {
                Some(known) => id.generation_id > known.generation_id,
                None => true,
            };
            if is_newer {
                latest.insert(&id.node_id, id);
            }
        }

        let mut nodes = BTreeMap::new();
        for (node_id, id) in latest {
            let state = &chitchat.node_states()[id];
            // A leaving node can still be live for the failure detector.
            let liveness = if state.get(LEAVING_KEY).is_some() {
                Liveness::Leaving
            } else if live.contains(id) {
                Liveness::Live
            } else {
                Liveness::Dead
            };
            let facts = state
                .key_values()
                .filter_map(|(key, value)| {
                    let name = key.strip_prefix(FACTS_PREFIX)?;
                    Some((name.to_string(), value.to_string()))
                })
                .collect();
            let node = Node {
                id: node_id.to_string(),
                generation: id.generation_id,
                liveness,
                facts,
            };
            nodes.insert(node_id.to_string(), node);
        }

        Self {
            self_id: chitchat.self_chitchat_id().node_id.to_string(),
            nodes,
        }
    }
}

/// Returns the events that turn `old` into `new`, in the order of the node IDs.
pub fn get_view_changes(old: &ClusterView, new: &ClusterView) -> Vec<Event> {
    let mut events = Vec::new();
    for (id, node) in &new.nodes {
        match old.nodes.get(id) {
            None => events.push(Event::NodeAdded { node: node.clone() }),
            Some(old_node) if old_node != node => {
                events.push(Event::NodeChanged { node: node.clone() })
            }
            Some(_) => {}
        }
    }
    for id in old.nodes.keys() {
        if !new.nodes.contains_key(id) {
            events.push(Event::NodeRemoved { id: id.clone() });
        }
    }
    events
}

/// The snapshot event of a view.
pub fn snapshot(view: &ClusterView) -> Event {
    Event::Snapshot {
        nodes: view.nodes.values().cloned().collect(),
    }
}

/// Keeps `view` equal to the chitchat state, and sends every change to `events`.
///
/// Updates on every change of the live set, on every key change,
/// and every `resync_interval`, to see the nodes that chitchat forgot.
/// Returns when chitchat stops.
pub async fn run(
    handle: &ChitchatHandle,
    view: watch::Sender<ClusterView>,
    events: broadcast::Sender<Event>,
    resync_interval: Duration,
) {
    let key_changed = Arc::new(Notify::new());
    // The listener stays subscribed while `_listener` exists.
    let (mut watcher, _listener) = {
        let chitchat = handle.chitchat();
        let chitchat = chitchat.lock().await;
        let notify = key_changed.clone();
        let listener = chitchat.subscribe_event("", move |_| notify.notify_one());
        (chitchat.live_nodes_watcher(), listener)
    };

    loop {
        // The live set is only the trigger. Mark it as seen.
        watcher.borrow_and_update();
        let new = ClusterView::from_chitchat(&*handle.chitchat().lock().await);
        let changes = get_view_changes(&view.borrow(), &new);
        if !changes.is_empty() {
            // The view first, so that a reader that gets an event
            // and then reads the view sees the change.
            view.send_replace(new);
            for event in changes {
                // An error only means that nobody listens now.
                let _ = events.send(event);
            }
        }

        tokio::select! {
            changed = watcher.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            _ = key_changed.notified() => {}
            _ = tokio::time::sleep(resync_interval) => {}
        }
    }
}

/// Logs the live node set every time it changes.
/// Returns when the view task stops.
pub async fn log_membership(mut view: watch::Receiver<ClusterView>) {
    let mut logged: Vec<String> = Vec::new();
    loop {
        let live = view.borrow_and_update().live_ids();
        // The first view before the first update is empty. Do not log it.
        if live != logged {
            tracing::info!(live = ?live, "membership changed");
            logged = live;
        }
        if view.changed().await.is_err() {
            return;
        }
    }
}
