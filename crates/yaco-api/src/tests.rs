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
