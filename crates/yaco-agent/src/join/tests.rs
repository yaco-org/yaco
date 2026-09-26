#![cfg(test)]

use super::*;

// Not real keys: base64 of 32 bytes of 0x11, 0x22, 0x33, 0x44 and 0x55.
// Node `node-N` has key `KEY_NODE_N` and mesh IP 10.42.0.N.
const KEY_NODE_1: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const KEY_NODE_2: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
const KEY_NODE_3: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";
const KEY_NODE_4: &str = "REREREREREREREREREREREREREREREREREREREREREQ=";
/// The new key of `node-2` after a restart.
const KEY_NODE_2_RESTARTED: &str = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=";

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

/// A join request of `node_id` with the config of `cluster()`.
fn request(node_id: &str, public_key: &str, mesh_ip: [u8; 4]) -> JoinRequest {
    JoinRequest {
        node_id: node_id.to_string(),
        config_fingerprint: cluster().fingerprint(),
        peer: peer(public_key, mesh_ip),
    }
}

#[test]
fn free_mesh_ip_is_accepted() {
    let members = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert_eq!(
        check_join(
            &request("node-2", KEY_NODE_2, [10, 42, 0, 2]),
            &cluster(),
            &members
        ),
        Ok(())
    );
}

#[test]
fn used_mesh_ip_is_a_conflict() {
    let members = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert_eq!(
        check_join(
            &request("node-2", KEY_NODE_2, [10, 42, 0, 1]),
            &cluster(),
            &members
        ),
        Err(JoinRefusal::MeshIpInUse)
    );
}

#[test]
fn retried_join_of_the_same_node_is_accepted() {
    let members = vec![peer(KEY_NODE_2, [10, 42, 0, 2])];
    assert_eq!(
        check_join(
            &request("node-2", KEY_NODE_2, [10, 42, 0, 2]),
            &cluster(),
            &members
        ),
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

    assert!(bad(request("", KEY_NODE_2, [10, 42, 0, 2])));
    assert!(bad(request("node-2", "not a key", [10, 42, 0, 2])));
    assert!(bad(request("node-2", KEY_NODE_2, [192, 0, 2, 1])));
    assert!(bad(request("node-2", KEY_NODE_2, [10, 42, 0, 0])));
}

#[test]
fn other_cluster_config_is_refused() {
    let mut other = cluster();
    other.gossip_interval *= 2;
    let mut request = request("node-2", KEY_NODE_2, [10, 42, 0, 2]);
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
    let mut request = request("node-2", KEY_NODE_2, [10, 42, 1, 2]);
    request.config_fingerprint = small.fingerprint();
    assert!(matches!(
        check_join(&request, &small, &[]),
        Err(JoinRefusal::BadRequest(_))
    ));
}

#[test]
fn messages_round_trip_as_json() {
    let request = request("node-2", KEY_NODE_2, [10, 42, 0, 2]);
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

/// The seed's side of the join.
///
/// Every test starts with the same cluster:
///
/// | Node   | Role               | Mesh IP   | Key          |
/// |--------|--------------------|-----------|--------------|
/// | node-1 | the seed           | 10.42.0.1 | `KEY_NODE_1` |
/// | node-2 | known to the seed  | 10.42.0.2 | `KEY_NODE_2` |
///
/// `node-3` and `node-4` are new nodes that join.
mod handle_join {
    use super::*;
    use crate::test_util::{chitchat_id, chitchat_with_nodes};

    fn seed() -> Arc<JoinServer> {
        let mut config =
            Config::parse("[node]\nid = \"node-1\"\npublic_ip = \"192.0.2.1\"\n").unwrap();
        config.cluster = cluster();

        let self_id = chitchat_id("node-1", 1);
        let own = peer(KEY_NODE_1, [10, 42, 0, 1]);
        let node_2 = peer(KEY_NODE_2, [10, 42, 0, 2]);
        let chitchat = chitchat_with_nodes(
            &self_id,
            own.to_facts(),
            vec![(chitchat_id("node-2", 1), node_2.to_facts())],
        );

        Arc::new(JoinServer {
            pending: Arc::new(PendingPeers::new(config.cluster.pending_peer_ttl)),
            config,
            chitchat: Arc::new(Mutex::new(chitchat)),
            self_id,
            own,
        })
    }

    /// Calls the handler, and returns the response or the status of the refusal.
    async fn call(
        server: &Arc<JoinServer>,
        request: JoinRequest,
    ) -> Result<JoinResponse, StatusCode> {
        handle_join(State(server.clone()), Json(request))
            .await
            .map(|Json(response)| response)
            .map_err(|(status, _)| status)
    }

    #[tokio::test]
    async fn accepted_join_returns_the_members_and_adds_a_pending_peer() {
        let server = seed();
        let request = request("node-3", KEY_NODE_3, [10, 42, 0, 3]);

        let response = call(&server, request.clone()).await.unwrap();

        let mut mesh_ips: Vec<Ipv4Addr> = response.members.iter().map(|m| m.mesh_ip).collect();
        mesh_ips.sort();
        assert_eq!(
            mesh_ips,
            vec![Ipv4Addr::new(10, 42, 0, 1), Ipv4Addr::new(10, 42, 0, 2)]
        );
        assert_eq!(response.gossip_seed, server.self_id.gossip_advertise_addr);
        assert_eq!(server.pending.current(&[]), vec![request.peer]);
    }

    #[tokio::test]
    async fn other_config_is_a_bad_request() {
        let server = seed();
        let mut other = cluster();
        other.mtu -= 1;
        let mut request = request("node-3", KEY_NODE_3, [10, 42, 0, 3]);
        request.config_fingerprint = other.fingerprint();

        assert_eq!(call(&server, request).await, Err(StatusCode::BAD_REQUEST));
        assert!(server.pending.current(&[]).is_empty());
    }

    #[tokio::test]
    async fn malformed_request_is_a_bad_request() {
        let server = seed();
        // Outside the mesh subnet.
        let request = request("node-3", KEY_NODE_3, [192, 0, 2, 3]);

        assert_eq!(call(&server, request).await, Err(StatusCode::BAD_REQUEST));
        assert!(server.pending.current(&[]).is_empty());
    }

    #[tokio::test]
    async fn mesh_ip_of_the_seed_or_a_known_node_is_a_conflict() {
        let server = seed();
        for taken in [[10, 42, 0, 1], [10, 42, 0, 2]] {
            let request = request("node-3", KEY_NODE_3, taken);
            assert_eq!(
                call(&server, request).await,
                Err(StatusCode::CONFLICT),
                "{taken:?}"
            );
        }
    }

    #[tokio::test]
    async fn mesh_ip_of_a_pending_peer_is_a_conflict() {
        let server = seed();
        // node-3 joins. Gossip does not have it yet, so it is only a pending peer.
        call(&server, request("node-3", KEY_NODE_3, [10, 42, 0, 3]))
            .await
            .unwrap();

        // node-4 proposes the same IP.
        let request = request("node-4", KEY_NODE_4, [10, 42, 0, 3]);
        assert_eq!(call(&server, request).await, Err(StatusCode::CONFLICT));
    }

    #[tokio::test]
    async fn restarted_node_gets_its_old_mesh_ip_back() {
        let server = seed();
        // node-2 restarted with a new key and proposes the IP of its old generation.
        let request = request("node-2", KEY_NODE_2_RESTARTED, [10, 42, 0, 2]);

        let response = call(&server, request).await.unwrap();
        assert!(
            response.members.iter().all(|m| m.public_key != KEY_NODE_2),
            "the old generation of node-2 is not a member"
        );
    }
}
