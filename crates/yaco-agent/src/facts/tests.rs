#![cfg(test)]

use super::*;
use crate::test_util::{chitchat_id, chitchat_with_nodes, key_values};

// Base64 of 32 bytes of 0x11.
const KEY: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";

fn mesh() -> MeshFacts {
    MeshFacts {
        wg_public_key: Key::try_from(KEY).unwrap(),
        mesh_ip: "10.42.0.2".parse().unwrap(),
        endpoint: "192.0.2.2:7281".parse().unwrap(),
    }
}

/// The facts that node n1 reads from node n2, which published `key_values`.
fn read_from_other_node(key_values: Vec<(String, String)>) -> Facts {
    let chitchat = chitchat_with_nodes(
        &chitchat_id("n1", 1),
        Vec::new(),
        vec![(chitchat_id("n2", 1), key_values)],
    );
    Facts::from_node_state(chitchat.node_state(&chitchat_id("n2", 1)).unwrap())
}

#[test]
fn facts_round_trip_through_chitchat() {
    let facts = Facts { mesh: Some(mesh()) };
    assert_eq!(read_from_other_node(facts.to_key_values()), facts);
}

#[test]
fn mesh_facts_are_one_json_value() {
    let facts = Facts { mesh: Some(mesh()) };
    assert_eq!(
        facts.to_key_values(),
        vec![(
            MESH_KEY.to_string(),
            format!(
                r#"{{"wg_public_key":"{KEY}","mesh_ip":"10.42.0.2","endpoint":"192.0.2.2:7281"}}"#
            )
        )]
    );
}

#[test]
fn no_facts_are_no_key_values() {
    assert!(Facts::default().to_key_values().is_empty());
    assert_eq!(read_from_other_node(Vec::new()), Facts::default());
}

#[test]
fn a_bad_value_is_skipped() {
    for bad in [
        "not json",
        r#"{"wg_public_key": "not a key", "mesh_ip": "10.42.0.2", "endpoint": "192.0.2.2:7281"}"#,
        r#"{"wg_public_key": "ERERERERERERERERERERERERERERERERERERERERERE=", "mesh_ip": "10.42.0.2"}"#,
    ] {
        let facts = read_from_other_node(key_values(&[(MESH_KEY, bad)]));
        assert_eq!(facts.mesh, None, "{bad}");
    }
}

#[test]
fn unknown_fields_of_a_newer_agent_are_ignored() {
    let newer = format!(
        r#"{{"wg_public_key": "{KEY}", "mesh_ip": "10.42.0.2", "endpoint": "192.0.2.2:7281", "new_field": 1}}"#
    );
    let facts = read_from_other_node(key_values(&[(MESH_KEY, &newer)]));
    assert_eq!(facts.mesh, Some(mesh()));
}
