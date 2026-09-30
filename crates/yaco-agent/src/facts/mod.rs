//! Facts: what a node publishes about itself in its own chitchat namespace.
//!
//! This module is the only code that knows the fact keys and their encoding.
//! Each group of facts that changes together is one key with one JSON value,
//! so a reader never sees half of a change.
//!
//! The values do not refuse unknown fields.
//! A newer agent can add a field, and an older agent still reads the value.
//! A new field that older agents do not send needs `#[serde(default)]`.

mod tests;

use std::net::{Ipv4Addr, SocketAddr};

use chitchat::NodeState;
use defguard_wireguard_rs::key::Key;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Key of `MeshFacts`.
pub const MESH_KEY: &str = "facts/mesh";

/// How to reach a node over the mesh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshFacts {
    /// Base64 in JSON, as `wg` prints it.
    pub wg_public_key: Key,
    pub mesh_ip: Ipv4Addr,
    /// Public address and port of the mesh WireGuard interface.
    pub endpoint: SocketAddr,
}

/// All facts of one node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// None if the node published no mesh facts, or a value that cannot be read.
    pub mesh: Option<MeshFacts>,
}

impl Facts {
    /// Reads the facts from the chitchat state of a node.
    /// Received data can be malformed: a bad value is logged and skipped, and this never panics.
    pub fn from_node_state(state: &NodeState) -> Self {
        Self {
            mesh: read(state, MESH_KEY),
        }
    }

    /// The key-value pairs to publish in the own chitchat namespace.
    pub fn to_key_values(&self) -> Vec<(String, String)> {
        let mut key_values = Vec::new();
        if let Some(mesh) = &self.mesh {
            key_values.push((MESH_KEY.to_string(), to_json(mesh)));
        }
        key_values
    }
}

fn read<T: DeserializeOwned>(state: &NodeState, key: &str) -> Option<T> {
    let value = state.get(key)?;
    match serde_json::from_str(value) {
        Ok(value) => Some(value),
        Err(err) => {
            let node_id = &state.chitchat_id().node_id;
            tracing::warn!(%node_id, %key, "skipping a bad fact: {err}");
            None
        }
    }
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("a fact always serializes")
}
