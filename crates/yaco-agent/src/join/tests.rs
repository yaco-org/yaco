#![cfg(test)]

use super::*;

// Base64 of 32 bytes of 0x11 and of 32 bytes of 0x22.
const KEY_NODE_1: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const KEY_NODE_2: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";

fn peer(public_key: &str, mesh_ip: [u8; 4]) -> MeshPeer {
    MeshPeer {
        public_key: public_key.to_string(),
        mesh_ip: Ipv4Addr::from(mesh_ip),
        endpoint: "192.0.2.1:7281".parse().unwrap(),
    }
}

fn request(public_key: &str, mesh_ip: [u8; 4]) -> JoinRequest {
    JoinRequest {
        node_id: "node-2".to_string(),
        peer: peer(public_key, mesh_ip),
    }
}

#[test]
fn free_mesh_ip_is_accepted() {
    let members = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert_eq!(
        check_join(&request(KEY_NODE_2, [10, 42, 0, 2]), &members),
        Ok(())
    );
}

#[test]
fn used_mesh_ip_is_a_conflict() {
    let members = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert_eq!(
        check_join(&request(KEY_NODE_2, [10, 42, 0, 1]), &members),
        Err(JoinRefusal::MeshIpInUse)
    );
}

#[test]
fn retried_join_of_the_same_node_is_accepted() {
    let members = vec![peer(KEY_NODE_2, [10, 42, 0, 2])];
    assert_eq!(
        check_join(&request(KEY_NODE_2, [10, 42, 0, 2]), &members),
        Ok(())
    );
}

#[test]
fn malformed_requests_are_refused() {
    let bad = |r: JoinRequest| matches!(check_join(&r, &[]), Err(JoinRefusal::BadRequest(_)));

    let mut empty_id = request(KEY_NODE_2, [10, 42, 0, 2]);
    empty_id.node_id.clear();
    assert!(bad(empty_id));
    assert!(bad(request("not a key", [10, 42, 0, 2])));
    assert!(bad(request(KEY_NODE_2, [192, 0, 2, 1])));
    assert!(bad(request(KEY_NODE_2, [10, 42, 0, 0])));
}

#[test]
fn messages_round_trip_as_json() {
    let request = request(KEY_NODE_2, [10, 42, 0, 2]);
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(serde_json::from_str::<JoinRequest>(&json).unwrap(), request);

    let response = JoinResponse {
        members: vec![peer(KEY_NODE_1, [10, 42, 0, 1])],
        gossip_seed: "192.0.2.1:7280".parse().unwrap(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert_eq!(
        serde_json::from_str::<JoinResponse>(&json).unwrap(),
        response
    );
}
