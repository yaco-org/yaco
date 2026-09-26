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

/// The mesh subnet is set here, not taken from the default of the config,
/// so a change of the default does not break the tests.
fn cluster() -> ClusterConfig {
    ClusterConfig {
        mesh_subnet: "10.42.0.0/16".parse().unwrap(),
        ..ClusterConfig::default()
    }
}

fn request(public_key: &str, mesh_ip: [u8; 4]) -> JoinRequest {
    JoinRequest {
        node_id: "node-2".to_string(),
        config_fingerprint: cluster().fingerprint(),
        peer: peer(public_key, mesh_ip),
    }
}

#[test]
fn free_mesh_ip_is_accepted() {
    let members = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert_eq!(
        check_join(&request(KEY_NODE_2, [10, 42, 0, 2]), &cluster(), &members),
        Ok(())
    );
}

#[test]
fn used_mesh_ip_is_a_conflict() {
    let members = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert_eq!(
        check_join(&request(KEY_NODE_2, [10, 42, 0, 1]), &cluster(), &members),
        Err(JoinRefusal::MeshIpInUse)
    );
}

#[test]
fn retried_join_of_the_same_node_is_accepted() {
    let members = vec![peer(KEY_NODE_2, [10, 42, 0, 2])];
    assert_eq!(
        check_join(&request(KEY_NODE_2, [10, 42, 0, 2]), &cluster(), &members),
        Ok(())
    );
}

#[test]
fn malformed_requests_are_refused() {
    let bad = |r: JoinRequest| {
        matches!(
            check_join(&r, &cluster(), &[]),
            Err(JoinRefusal::BadRequest(_))
        )
    };

    let mut empty_id = request(KEY_NODE_2, [10, 42, 0, 2]);
    empty_id.node_id.clear();
    assert!(bad(empty_id));
    assert!(bad(request("not a key", [10, 42, 0, 2])));
    assert!(bad(request(KEY_NODE_2, [192, 0, 2, 1])));
    assert!(bad(request(KEY_NODE_2, [10, 42, 0, 0])));
}

#[test]
fn other_cluster_config_is_refused() {
    let mut other = cluster();
    other.gossip_interval *= 2;
    let mut request = request(KEY_NODE_2, [10, 42, 0, 2]);
    request.config_fingerprint = other.fingerprint();
    assert_eq!(
        check_join(&request, &cluster(), &[]),
        Err(JoinRefusal::ConfigMismatch)
    );
}

#[test]
fn mesh_ip_outside_the_configured_subnet_is_refused() {
    let small = ClusterConfig {
        mesh_subnet: "10.42.0.0/24".parse().unwrap(),
        ..cluster()
    };
    let mut request = request(KEY_NODE_2, [10, 42, 1, 2]);
    request.config_fingerprint = small.fingerprint();
    assert!(matches!(
        check_join(&request, &small, &[]),
        Err(JoinRefusal::BadRequest(_))
    ));
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

#[test]
fn jitter_adds_up_to_the_same_delay() {
    let delay = Duration::from_secs(1);
    for _ in 0..1000 {
        let jittered = with_jitter(delay);
        assert!(jittered >= delay && jittered < delay * 2, "{jittered:?}");
    }
}
