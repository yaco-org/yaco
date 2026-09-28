#![cfg(test)]

use super::*;

#[test]
fn container_path_is_below_containers_path() {
    assert_eq!(CONTAINER_PATH, format!("{CONTAINERS_PATH}/{{name}}"));
}

#[test]
fn minimal_manifest_has_only_name_and_image() {
    let manifest: ContainerManifest =
        serde_json::from_str(r#"{"name": "web", "image": "nginx:1.29"}"#).unwrap();
    assert!(manifest.command.is_empty());
    assert!(manifest.env.is_empty());
    assert_eq!(
        serde_json::to_string(&manifest).unwrap(),
        r#"{"name":"web","image":"nginx:1.29"}"#
    );
}

#[test]
fn unknown_manifest_fields_are_errors() {
    let result = serde_json::from_str::<ContainerManifest>(
        r#"{"name": "web", "image": "nginx:1.29", "imgae": "typo"}"#,
    );
    assert!(result.is_err());
}

#[test]
fn events_are_tagged_with_their_type() {
    let event = Event::NodeRemoved {
        id: "n1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(json, r#"{"type":"node_removed","id":"n1"}"#);
    assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);
}

#[test]
fn liveness_is_snake_case() {
    assert_eq!(
        serde_json::to_string(&Liveness::Leaving).unwrap(),
        r#""leaving""#
    );
}
