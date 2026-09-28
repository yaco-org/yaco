#![cfg(test)]

use super::*;
use crate::test_util::{chitchat_id, chitchat_with_nodes, key_values};

fn node(id: &str, generation: u64, liveness: Liveness) -> Node {
    Node {
        id: id.to_string(),
        generation,
        liveness,
        facts: BTreeMap::new(),
    }
}

fn view(nodes: Vec<Node>) -> ClusterView {
    let mut view = ClusterView::empty("n1");
    for node in nodes {
        view.nodes.insert(node.id.clone(), node);
    }
    view
}

/// `chitchat_with_nodes` adds the other nodes without heartbeats,
/// so the failure detector never hears them, and they are dead.
mod build {
    use super::*;

    #[test]
    fn has_every_node_with_its_facts_and_liveness() {
        let chitchat = chitchat_with_nodes(
            &chitchat_id("n1", 1),
            key_values(&[("facts/mesh_ip", "10.42.0.1")]),
            vec![(
                chitchat_id("n2", 5),
                key_values(&[("facts/mesh_ip", "10.42.0.2"), ("other", "x")]),
            )],
        );

        let view = ClusterView::from_chitchat(&chitchat);

        assert_eq!(view.self_id, "n1");
        assert_eq!(view.nodes.keys().collect::<Vec<_>>(), vec!["n1", "n2"]);
        assert_eq!(view.nodes["n1"].liveness, Liveness::Live);
        let n2 = &view.nodes["n2"];
        assert_eq!(n2.generation, 5);
        assert_eq!(n2.liveness, Liveness::Dead);
        // Only facts, without the prefix.
        let facts: Vec<_> = n2.facts.iter().collect();
        assert_eq!(
            facts,
            vec![(&"mesh_ip".to_string(), &"10.42.0.2".to_string())]
        );
    }

    #[test]
    fn a_node_with_the_leaving_key_is_leaving() {
        let chitchat = chitchat_with_nodes(
            &chitchat_id("n1", 1),
            Vec::new(),
            vec![(chitchat_id("n2", 1), key_values(&[(LEAVING_KEY, "true")]))],
        );
        let view = ClusterView::from_chitchat(&chitchat);
        assert_eq!(view.nodes["n2"].liveness, Liveness::Leaving);
        assert!(view.nodes["n2"].facts.is_empty());
    }

    #[test]
    fn takes_the_latest_generation_of_a_restarted_node() {
        let chitchat = chitchat_with_nodes(
            &chitchat_id("n1", 1),
            Vec::new(),
            vec![
                // The order does not matter.
                (
                    chitchat_id("n2", 200),
                    key_values(&[("facts/mesh_ip", "10.42.0.2")]),
                ),
                (
                    chitchat_id("n2", 100),
                    key_values(&[("facts/mesh_ip", "10.42.0.9")]),
                ),
            ],
        );
        let n2 = &ClusterView::from_chitchat(&chitchat).nodes["n2"];
        assert_eq!(n2.generation, 200);
        assert_eq!(n2.facts["mesh_ip"], "10.42.0.2");
    }

    #[test]
    fn a_leaving_latest_generation_hides_the_older_ones() {
        // The old generation crashed, the new one left gracefully.
        let chitchat = chitchat_with_nodes(
            &chitchat_id("n1", 1),
            Vec::new(),
            vec![
                (
                    chitchat_id("n2", 100),
                    key_values(&[("facts/mesh_ip", "10.42.0.9")]),
                ),
                (chitchat_id("n2", 200), key_values(&[(LEAVING_KEY, "true")])),
            ],
        );
        let n2 = &ClusterView::from_chitchat(&chitchat).nodes["n2"];
        assert_eq!(n2.generation, 200);
        assert_eq!(n2.liveness, Liveness::Leaving);
    }

    #[test]
    fn a_restarted_own_node_is_live_only_in_its_new_generation() {
        let chitchat = chitchat_with_nodes(
            &chitchat_id("n1", 200),
            Vec::new(),
            vec![(chitchat_id("n1", 100), Vec::new())],
        );
        let n1 = &ClusterView::from_chitchat(&chitchat).nodes["n1"];
        assert_eq!(n1.generation, 200);
        assert_eq!(n1.liveness, Liveness::Live);
    }
}

mod changes {
    use super::*;

    #[test]
    fn equal_views_have_no_changes() {
        let view = view(vec![node("n1", 1, Liveness::Live)]);
        assert!(get_view_changes(&view, &view).is_empty());
    }

    #[test]
    fn a_new_node_is_added() {
        let old = view(vec![node("n1", 1, Liveness::Live)]);
        let new = view(vec![
            node("n1", 1, Liveness::Live),
            node("n2", 1, Liveness::Live),
        ]);
        assert_eq!(
            get_view_changes(&old, &new),
            vec![Event::NodeAdded {
                node: node("n2", 1, Liveness::Live)
            }]
        );
    }

    #[test]
    fn liveness_generation_and_facts_are_changes() {
        let old = view(vec![node("n2", 1, Liveness::Live)]);
        let mut with_fact = node("n2", 1, Liveness::Live);
        with_fact
            .facts
            .insert("mesh_ip".to_string(), "10.42.0.2".to_string());
        for changed in [
            node("n2", 1, Liveness::Dead),
            node("n2", 1, Liveness::Leaving),
            node("n2", 2, Liveness::Live),
            with_fact,
        ] {
            let new = view(vec![changed.clone()]);
            assert_eq!(
                get_view_changes(&old, &new),
                vec![Event::NodeChanged { node: changed }]
            );
        }
    }

    #[test]
    fn a_forgotten_node_is_removed() {
        let old = view(vec![
            node("n1", 1, Liveness::Live),
            node("n2", 1, Liveness::Dead),
        ]);
        let new = view(vec![node("n1", 1, Liveness::Live)]);
        assert_eq!(
            get_view_changes(&old, &new),
            vec![Event::NodeRemoved {
                id: "n2".to_string()
            }]
        );
    }

    #[test]
    fn the_first_view_adds_every_node() {
        let new = view(vec![
            node("n1", 1, Liveness::Live),
            node("n2", 1, Liveness::Dead),
        ]);
        let events = get_view_changes(&ClusterView::empty("n1"), &new);
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, Event::NodeAdded { .. }))
        );
    }
}

#[test]
fn live_ids_are_the_live_nodes_in_order() {
    let view = view(vec![
        node("n3", 1, Liveness::Live),
        node("n1", 1, Liveness::Live),
        node("n2", 1, Liveness::Dead),
        node("n4", 1, Liveness::Leaving),
    ]);
    assert_eq!(view.live_ids(), vec!["n1", "n3"]);
}
