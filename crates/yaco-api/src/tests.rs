#![cfg(test)]

use super::*;

#[test]
fn spec_has_every_container_operation() {
    let spec = ApiDoc::openapi();
    let paths = &spec.paths.paths;

    let list = &paths[CONTAINERS_PATH];
    assert!(list.get.is_some());

    let one = &paths[&format!("{CONTAINERS_PATH}/{{name}}")];
    assert!(one.put.is_some());
    assert!(one.get.is_some());
    assert!(one.delete.is_some());

    assert_eq!(paths.len(), 2, "unexpected paths: {:?}", paths.keys());
}

#[test]
fn write_operations_document_the_sender_header() {
    let spec: serde_json::Value =
        serde_json::from_str(&ApiDoc::openapi().to_json().unwrap()).unwrap();
    let paths = spec["paths"].as_object().unwrap();
    for path in paths.values() {
        let path = path.as_object().unwrap();
        for (method, spec) in path {
            if ["put", "post", "delete"].contains(&&**method) {
                let parameters = spec["parameters"].as_array().unwrap();
                let has_sender = parameters
                    .iter()
                    .any(|p| p["name"] == SENDER_HEADER && p["in"] == "header");
                assert!(has_sender, "{method} has no {SENDER_HEADER} header");
            }
        }
    }
}

#[test]
fn spec_renders_as_json() {
    let json = ApiDoc::openapi().to_pretty_json().unwrap();
    assert!(json.contains("\"ContainerManifest\""));
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
