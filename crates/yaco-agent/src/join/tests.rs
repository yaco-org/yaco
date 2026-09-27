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

fn peer(node_id: &str, public_key: &str, mesh_ip: [u8; 4]) -> MeshPeer {
    MeshPeer {
        node_id: node_id.to_string(),
        public_key: Key::try_from(public_key).unwrap(),
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
        config_fingerprint: cluster().fingerprint(),
        peer: peer(node_id, public_key, mesh_ip),
    }
}

/// Checks of the seed, without the HTTP handler.
///
/// Every test starts with the same cluster:
///
/// | Node   | Role               | Mesh IP   | Key          |
/// |--------|--------------------|-----------|--------------|
/// | node-1 | the seed           | 10.42.0.1 | `KEY_NODE_1` |
/// | node-2 | a peer of the seed | 10.42.0.2 | `KEY_NODE_2` |
///
/// `node-3` is a new node that joins.
mod check_join {
    use super::*;

    fn own() -> MeshPeer {
        peer("node-1", KEY_NODE_1, [10, 42, 0, 1])
    }

    fn peers() -> Vec<MeshPeer> {
        vec![peer("node-2", KEY_NODE_2, [10, 42, 0, 2])]
    }

    fn check(request: &JoinRequest) -> Result<Vec<MeshPeer>, JoinRefusal> {
        check_join(request, &cluster(), &own(), &peers())
    }

    #[test]
    fn free_mesh_ip_is_accepted_with_the_seed_and_its_peers_as_members() {
        let members = check(&request("node-3", KEY_NODE_3, [10, 42, 0, 3])).unwrap();
        assert_eq!(members, vec![own(), peers()[0].clone()]);
    }

    #[test]
    fn mesh_ip_of_the_seed_or_a_peer_is_a_conflict() {
        for taken in [[10, 42, 0, 1], [10, 42, 0, 2]] {
            assert_eq!(
                check(&request("node-3", KEY_NODE_3, taken)),
                Err(JoinRefusal::MeshIpInUse),
                "{taken:?}"
            );
        }
    }

    #[test]
    fn retried_join_of_the_same_node_is_accepted() {
        // node-3 joined, and it is a peer of the seed now. Its response was lost, so it asks again.
        let node_3 = peer("node-3", KEY_NODE_3, [10, 42, 0, 3]);
        let mut peers = peers();
        peers.push(node_3.clone());

        let request = request("node-3", KEY_NODE_3, [10, 42, 0, 3]);
        let members = check_join(&request, &cluster(), &own(), &peers).unwrap();
        assert!(!members.contains(&node_3), "node-3 is not its own member");
    }

    #[test]
    fn restarted_node_gets_its_old_mesh_ip_back() {
        // node-2 restarted with a new key and proposes the IP of its old generation.
        let request = request("node-2", KEY_NODE_2_RESTARTED, [10, 42, 0, 2]);
        assert_eq!(check(&request), Ok(vec![own()]));
    }

    #[test]
    fn node_with_the_id_of_the_seed_cannot_take_its_mesh_ip() {
        let request = request("node-1", KEY_NODE_3, [10, 42, 0, 1]);
        assert_eq!(check(&request), Err(JoinRefusal::MeshIpInUse));
    }

    #[test]
    fn malformed_requests_are_refused() {
        let bad = |r: JoinRequest| matches!(check(&r), Err(JoinRefusal::BadRequest(_)));

        assert!(bad(request("", KEY_NODE_3, [10, 42, 0, 3])));
        assert!(bad(request("node-3", KEY_NODE_3, [192, 0, 2, 1])));
        assert!(bad(request("node-3", KEY_NODE_3, [10, 42, 0, 0])));
    }

    #[test]
    fn other_cluster_config_is_refused() {
        let mut other = cluster();
        other.gossip_interval *= 2;
        let mut request = request("node-3", KEY_NODE_3, [10, 42, 0, 3]);
        request.config_fingerprint = other.fingerprint();
        assert_eq!(check(&request), Err(JoinRefusal::ConfigMismatch));
    }

    #[test]
    fn mesh_ip_outside_the_configured_subnet_is_refused() {
        let small = ClusterConfig {
            mesh_subnet: "10.42.0.0/24".parse().unwrap(),
            ..cluster()
        };
        let mut request = request("node-3", KEY_NODE_3, [10, 42, 1, 3]);
        request.config_fingerprint = small.fingerprint();
        assert!(matches!(
            check_join(&request, &small, &own(), &peers()),
            Err(JoinRefusal::BadRequest(_))
        ));
    }
}

#[test]
fn messages_round_trip_as_json() {
    let request = request("node-2", KEY_NODE_2, [10, 42, 0, 2]);
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(serde_json::from_str::<JoinRequest>(&json).unwrap(), request);

    let response = JoinResponse {
        members: vec![peer("node-1", KEY_NODE_1, [10, 42, 0, 1])],
        gossip_seed: "192.0.2.1:7280".parse().unwrap(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert_eq!(
        serde_json::from_str::<JoinResponse>(&json).unwrap(),
        response
    );
}

#[test]
fn request_with_a_bad_key_does_not_parse() {
    let json = serde_json::to_string(&request("node-2", KEY_NODE_2, [10, 42, 0, 2])).unwrap();
    let bad = json.replace(KEY_NODE_2, "not a key");
    assert_ne!(bad, json);
    assert!(serde_json::from_str::<JoinRequest>(&bad).is_err());
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
/// | node-2 | a peer of the seed | 10.42.0.2 | `KEY_NODE_2` |
///
/// `node-3` and `node-4` are new nodes that join.
mod handle_join {
    use super::*;

    /// The join server of node-1, and the two ends of the channels
    /// that `mesh::sync_peers` has in the agent.
    struct Seed {
        server: Arc<JoinServer>,
        new_peers: mpsc::UnboundedReceiver<MeshPeer>,
        peers: watch::Sender<Vec<MeshPeer>>,
    }

    fn seed() -> Seed {
        let mut config =
            Config::parse("[node]\nid = \"node-1\"\npublic_ip = \"192.0.2.1\"\n").unwrap();
        config.cluster = cluster();

        let (new_peers_tx, new_peers) = mpsc::unbounded_channel();
        let (peers, peers_rx) = watch::channel(vec![peer("node-2", KEY_NODE_2, [10, 42, 0, 2])]);
        let server = Arc::new(JoinServer::new(
            config,
            peer("node-1", KEY_NODE_1, [10, 42, 0, 1]),
            "10.42.0.1:7280".parse().unwrap(),
            new_peers_tx,
            peers_rx,
        ));
        Seed {
            server,
            new_peers,
            peers,
        }
    }

    /// Calls the handler, and returns the response or the status of the refusal.
    async fn call(seed: &Seed, request: JoinRequest) -> Result<JoinResponse, StatusCode> {
        handle_join(State(seed.server.clone()), Json(request))
            .await
            .map(|Json(response)| response)
            .map_err(|(status, _)| status)
    }

    fn mesh_ips(response: &JoinResponse) -> Vec<Ipv4Addr> {
        let mut ips: Vec<Ipv4Addr> = response.members.iter().map(|m| m.mesh_ip).collect();
        ips.sort();
        ips
    }

    #[tokio::test]
    async fn accepted_join_returns_the_members_and_sends_the_new_peer() {
        let mut seed = seed();
        let request = request("node-3", KEY_NODE_3, [10, 42, 0, 3]);

        let response = call(&seed, request.clone()).await.unwrap();

        assert_eq!(
            mesh_ips(&response),
            vec![Ipv4Addr::new(10, 42, 0, 1), Ipv4Addr::new(10, 42, 0, 2)]
        );
        assert_eq!(response.gossip_seed, "10.42.0.1:7280".parse().unwrap());
        assert_eq!(seed.new_peers.try_recv(), Ok(request.peer));
    }

    #[tokio::test]
    async fn other_config_is_a_bad_request() {
        let mut seed = seed();
        let mut other = cluster();
        other.mtu -= 1;
        let mut request = request("node-3", KEY_NODE_3, [10, 42, 0, 3]);
        request.config_fingerprint = other.fingerprint();

        assert_eq!(call(&seed, request).await, Err(StatusCode::BAD_REQUEST));
        assert!(seed.new_peers.try_recv().is_err());
    }

    #[tokio::test]
    async fn malformed_request_is_a_bad_request() {
        let mut seed = seed();
        // Outside the mesh subnet.
        let request = request("node-3", KEY_NODE_3, [192, 0, 2, 3]);

        assert_eq!(call(&seed, request).await, Err(StatusCode::BAD_REQUEST));
        assert!(seed.new_peers.try_recv().is_err());
    }

    #[tokio::test]
    async fn mesh_ip_of_the_seed_or_a_peer_is_a_conflict() {
        let mut seed = seed();
        for taken in [[10, 42, 0, 1], [10, 42, 0, 2]] {
            let request = request("node-3", KEY_NODE_3, taken);
            assert_eq!(
                call(&seed, request).await,
                Err(StatusCode::CONFLICT),
                "{taken:?}"
            );
        }
        assert!(seed.new_peers.try_recv().is_err());
    }

    #[tokio::test]
    async fn node_that_just_joined_counts_after_the_peer_sync() {
        let mut seed = seed();
        // node-3 joins.
        call(&seed, request("node-3", KEY_NODE_3, [10, 42, 0, 3]))
            .await
            .unwrap();
        // The peer sync adds node-3 as a pending peer,
        // and sends all peers back to the join server.
        let node_3 = seed.new_peers.try_recv().unwrap();
        seed.peers.send_modify(|peers| peers.push(node_3));

        // node-4 proposes the IP of node-3.
        let taken = request("node-4", KEY_NODE_4, [10, 42, 0, 3]);
        assert_eq!(call(&seed, taken).await, Err(StatusCode::CONFLICT));

        // node-4 proposes a free IP and gets node-3 as a member.
        let free = request("node-4", KEY_NODE_4, [10, 42, 0, 4]);
        let response = call(&seed, free).await.unwrap();
        assert_eq!(
            mesh_ips(&response),
            vec![
                Ipv4Addr::new(10, 42, 0, 1),
                Ipv4Addr::new(10, 42, 0, 2),
                Ipv4Addr::new(10, 42, 0, 3)
            ]
        );
    }

    #[tokio::test]
    async fn restarted_node_gets_its_old_mesh_ip_back() {
        let seed = seed();
        // node-2 restarted with a new key and proposes the IP of its old generation.
        let request = request("node-2", KEY_NODE_2_RESTARTED, [10, 42, 0, 2]);

        let response = call(&seed, request).await.unwrap();
        assert!(
            response.members.iter().all(|m| m.node_id != "node-2"),
            "the old generation of node-2 is not a member"
        );
    }

    #[tokio::test]
    async fn stopped_peer_sync_is_an_error() {
        let seed = seed();
        drop(seed.new_peers);
        let server = seed.server.clone();
        let request = request("node-3", KEY_NODE_3, [10, 42, 0, 3]);

        let result = handle_join(State(server), Json(request)).await;
        assert!(matches!(result, Err((StatusCode::SERVICE_UNAVAILABLE, _))));
    }
}
