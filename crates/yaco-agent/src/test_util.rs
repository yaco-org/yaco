//! Helpers for unit tests only.

use std::collections::HashSet;

use chitchat::{Chitchat, ChitchatId, DeletionStatus, NodeState, VersionedValue};
use tokio::sync::watch;

use crate::config::ClusterConfig;
use crate::gossip;

pub fn chitchat_id(node_id: &str, generation: u64) -> ChitchatId {
    ChitchatId::new(node_id, generation, "127.0.0.1:7280".parse().unwrap())
}

/// A chitchat instance of node `own`, with no network and no server task.
/// `others` are node states that the instance knows, as gossip would bring them.
/// So `Chitchat::node_states()` returns real node states for the tests.
pub fn chitchat_with_nodes(
    own: &ChitchatId,
    own_key_values: Vec<(String, String)>,
    others: Vec<(ChitchatId, Vec<(String, String)>)>,
) -> Chitchat {
    let mut config = gossip::config(
        &own.node_id,
        own.gossip_advertise_addr,
        &[],
        &ClusterConfig::default(),
    );
    config.chitchat_id = own.clone();
    let (_seeds_tx, seeds_rx) = watch::channel(HashSet::new());
    let mut chitchat = Chitchat::with_chitchat_id_and_seeds(config, seeds_rx, own_key_values);

    for (id, key_values) in others {
        let max_version = key_values.len() as u64;
        let key_values = key_values.into_iter().enumerate().map(|(i, (key, value))| {
            let versioned = VersionedValue {
                value,
                version: i as u64 + 1,
                status: DeletionStatus::Set,
            };
            (key, versioned)
        });
        chitchat.reset_node_state_if_update(&id, key_values, max_version, 0);
    }
    chitchat
}

/// The state of node `id` with `key_values`, as gossip would bring it.
pub fn node_state(id: &ChitchatId, key_values: Vec<(String, String)>) -> NodeState {
    let chitchat = chitchat_with_nodes(
        &chitchat_id("observer", 1),
        Vec::new(),
        vec![(id.clone(), key_values)],
    );
    chitchat.node_state(id).unwrap().clone()
}

/// Converts `(&str, &str)` pairs to owned key-value pairs.
pub fn key_values(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}
