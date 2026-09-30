//! Conversions from the internal types into the `yaco-api` types.
//!
//! Only the API module uses `yaco-api`.
//! A change of the API changes these conversions, not the rest of the agent.

use yaco_api::{Event, Liveness, MeshFacts, Node, NodeFacts};

use crate::facts;
use crate::view::{self, Change, ClusterView, NodeView};

impl From<view::Liveness> for Liveness {
    fn from(liveness: view::Liveness) -> Liveness {
        match liveness {
            view::Liveness::Live => Liveness::Live,
            view::Liveness::Dead => Liveness::Dead,
            view::Liveness::Leaving => Liveness::Leaving,
        }
    }
}

impl From<&facts::MeshFacts> for MeshFacts {
    fn from(facts: &facts::MeshFacts) -> MeshFacts {
        MeshFacts {
            wg_public_key: facts.wg_public_key.to_string(),
            mesh_ip: facts.mesh_ip,
            endpoint: facts.endpoint,
        }
    }
}

impl From<&facts::Facts> for NodeFacts {
    fn from(facts: &facts::Facts) -> NodeFacts {
        NodeFacts {
            mesh: facts.mesh.as_ref().map(MeshFacts::from),
        }
    }
}

impl From<&NodeView> for Node {
    fn from(node: &NodeView) -> Node {
        Node {
            id: node.id.clone(),
            generation: node.generation,
            liveness: node.liveness.into(),
            facts: (&node.facts).into(),
        }
    }
}

impl From<&Change> for Event {
    fn from(change: &Change) -> Event {
        match change {
            Change::Added(node) => Event::NodeAdded { node: node.into() },
            Change::Changed(node) => Event::NodeChanged { node: node.into() },
            Change::Removed(id) => Event::NodeRemoved { id: id.clone() },
        }
    }
}

/// All nodes of a view, in the order of their IDs.
pub fn nodes(view: &ClusterView) -> Vec<Node> {
    view.nodes.values().map(Node::from).collect()
}

/// The snapshot event of a view.
pub fn snapshot(view: &ClusterView) -> Event {
    Event::Snapshot { nodes: nodes(view) }
}
