#![cfg(test)]

use super::*;

fn spec_json() -> serde_json::Value {
    serde_json::from_str(&spec().to_json().unwrap()).unwrap()
}

#[test]
fn spec_has_every_container_operation() {
    let spec = spec();
    let paths = &spec.paths.paths;

    assert!(paths[CONTAINERS_PATH].get.is_some());
    let one = &paths[CONTAINER_PATH];
    assert!(one.put.is_some());
    assert!(one.get.is_some());
    assert!(one.delete.is_some());

    assert_eq!(paths.len(), 2, "unexpected paths: {:?}", paths.keys());
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
}

#[tokio::test]
async fn every_operation_answers_not_implemented() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(listener));

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
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
