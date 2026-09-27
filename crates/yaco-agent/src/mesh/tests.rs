#![cfg(test)]

use super::*;

// Base64 of 32 bytes of 0x11, of 0x22 and of 0x55,
// so the keys are easy to tell apart at a glance.
const KEY_NODE_1: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const KEY_NODE_2: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
/// The new key of `node-1` after a restart.
const KEY_NODE_1_RESTARTED: &str = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=";

/// The tests use their own subnets, not the default of the config,
/// so a change of the default does not break them.
fn subnet(text: &str) -> MeshSubnet {
    text.parse().unwrap()
}

fn peer(node_id: &str, public_key: &str, mesh_ip: [u8; 4]) -> MeshPeer {
    MeshPeer {
        node_id: node_id.to_string(),
        public_key: Key::try_from(public_key).unwrap(),
        mesh_ip: Ipv4Addr::from(mesh_ip),
        endpoint: "192.0.2.1:7281".parse().unwrap(),
    }
}

#[test]
fn mesh_ip_is_stable() {
    // If these values change, nodes get new addresses after an upgrade.
    let net = subnet("10.42.0.0/16");
    assert_eq!(net.mesh_ip("node-1", 0), Ipv4Addr::new(10, 42, 58, 124));
    assert_eq!(
        subnet("192.168.0.0/24").mesh_ip("node-1", 0),
        Ipv4Addr::new(192, 168, 0, 140)
    );
    assert_ne!(net.mesh_ip("node-1", 0), net.mesh_ip("node-1", 1));
    assert_ne!(net.mesh_ip("node-1", 0), net.mesh_ip("node-2", 0));
}

#[test]
fn mesh_ip_is_a_host_in_the_subnet() {
    for text in [
        "10.42.0.0/16",
        "192.168.4.0/24",
        "172.16.0.0/12",
        "10.0.0.8/30",
    ] {
        let net = subnet(text);
        for attempt in 0..10_000 {
            let ip = net.mesh_ip("node", attempt);
            assert!(net.is_host(ip), "{text}, attempt {attempt}: {ip}");
        }
    }
}

#[test]
fn mesh_ip_uses_both_hosts_of_a_30() {
    let net = subnet("10.0.0.8/30");
    let ips: std::collections::BTreeSet<Ipv4Addr> = (0..100)
        .map(|attempt| net.mesh_ip("node", attempt))
        .collect();
    assert_eq!(
        ips.into_iter().collect::<Vec<_>>(),
        vec![Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 10)]
    );
}

#[test]
fn subnet_without_room_for_hosts_or_with_host_bits_is_refused() {
    assert!("10.42.0.0/30".parse::<MeshSubnet>().is_ok());
    assert!("10.42.0.0/31".parse::<MeshSubnet>().is_err());
    assert!("10.42.0.1/32".parse::<MeshSubnet>().is_err());
    assert!("10.42.1.0/16".parse::<MeshSubnet>().is_err());
    assert!("not a subnet".parse::<MeshSubnet>().is_err());
}

#[test]
fn subnet_is_a_plain_string_in_json() {
    // The config fingerprint depends on this form.
    let net = subnet("10.42.0.0/16");
    assert_eq!(serde_json::to_string(&net).unwrap(), "\"10.42.0.0/16\"");
    assert_eq!(
        serde_json::from_str::<MeshSubnet>("\"10.42.0.0/16\"").unwrap(),
        net
    );
    assert!(serde_json::from_str::<MeshSubnet>("\"10.42.1.0/16\"").is_err());
}

#[test]
fn is_host_accepts_hosts_only() {
    let net = subnet("10.42.0.0/16");
    assert!(net.is_host(Ipv4Addr::new(10, 42, 0, 1)));
    assert!(net.is_host(Ipv4Addr::new(10, 42, 255, 254)));
    assert!(!net.is_host(Ipv4Addr::new(10, 42, 0, 0)));
    assert!(!net.is_host(Ipv4Addr::new(10, 42, 255, 255)));
    assert!(!net.is_host(Ipv4Addr::new(10, 43, 0, 1)));
    assert!(!net.is_host(Ipv4Addr::new(10, 41, 255, 254)));
}

#[test]
fn own_facts_come_from_the_config() {
    let config = Config::parse(
        "[node]\nid = \"node-1\"\npublic_ip = \"192.0.2.1\"\nmesh_port = 9001\n\
         [cluster]\nmesh_subnet = \"10.42.0.0/16\"\n",
    )
    .unwrap();
    let key = Key::try_from(KEY_NODE_1).unwrap();

    let own = MeshPeer::own(&config, &key, 1);
    assert_eq!(own.node_id, "node-1");
    assert_eq!(own.public_key, key);
    assert_eq!(own.mesh_ip, subnet("10.42.0.0/16").mesh_ip("node-1", 1));
    assert_eq!(own.endpoint, "192.0.2.1:9001".parse().unwrap());
}

mod from_node_state {
    use super::*;
    use crate::test_util::{chitchat_id, key_values, node_state};

    #[test]
    fn facts_round_trip() {
        let original = peer("node-1", KEY_NODE_1, [10, 42, 0, 1]);
        let state = node_state(&chitchat_id("node-1", 1), original.to_facts());
        assert_eq!(MeshPeer::from_node_state(&state).unwrap(), original);
    }

    #[test]
    fn bad_facts_are_errors() {
        let parse = |pairs: &[(&str, &str)]| {
            let state = node_state(&chitchat_id("node-1", 1), key_values(pairs));
            MeshPeer::from_node_state(&state)
        };
        let key = (WG_PUBLIC_KEY_KEY, KEY_NODE_1);
        let ip = (MESH_IP_KEY, "10.42.0.1");
        let endpoint = (ENDPOINT_KEY, "192.0.2.1:7281");
        assert!(parse(&[key, ip, endpoint]).is_ok());

        assert!(parse(&[ip, endpoint]).is_err());
        assert!(parse(&[(WG_PUBLIC_KEY_KEY, "not a key"), ip, endpoint]).is_err());
        assert!(parse(&[key, (MESH_IP_KEY, "10.42.0"), endpoint]).is_err());
        assert!(parse(&[key, ip]).is_err());
        assert!(parse(&[key, ip, (ENDPOINT_KEY, "192.0.2.1")]).is_err());
    }
}

#[test]
fn a_queued_peer_replaces_the_older_queued_peer_of_the_same_node() {
    let mut pending = Vec::new();
    add_pending(&mut pending, peer("node-1", KEY_NODE_1, [10, 42, 0, 1]));
    add_pending(&mut pending, peer("node-2", KEY_NODE_2, [10, 42, 0, 2]));
    // node-1 restarted and joined again, with a new key and another IP.
    let restarted = peer("node-1", KEY_NODE_1_RESTARTED, [10, 42, 0, 9]);
    add_pending(&mut pending, restarted.clone());
    assert_eq!(
        pending,
        vec![peer("node-2", KEY_NODE_2, [10, 42, 0, 2]), restarted]
    );
}

mod gossip_changes {
    use super::*;

    #[test]
    fn equal_views_have_no_changes() {
        let view = vec![peer("node-1", KEY_NODE_1, [10, 42, 0, 1])];
        assert_eq!(gossip_changes(&view, &view), PeersDiff::default());
    }

    #[test]
    fn a_new_node_is_changed() {
        let old = vec![peer("node-1", KEY_NODE_1, [10, 42, 0, 1])];
        let new = vec![
            peer("node-1", KEY_NODE_1, [10, 42, 0, 1]),
            peer("node-2", KEY_NODE_2, [10, 42, 0, 2]),
        ];
        assert_eq!(
            gossip_changes(&old, &new),
            PeersDiff {
                changed: vec![peer("node-2", KEY_NODE_2, [10, 42, 0, 2])],
                gone: Vec::new(),
            }
        );
    }

    #[test]
    fn a_restarted_node_is_changed_not_gone() {
        let old = vec![peer("node-1", KEY_NODE_1, [10, 42, 0, 1])];
        let new = vec![peer("node-1", KEY_NODE_1_RESTARTED, [10, 42, 0, 1])];
        assert_eq!(
            gossip_changes(&old, &new),
            PeersDiff {
                changed: new.clone(),
                gone: Vec::new()
            }
        );
    }

    #[test]
    fn a_missing_node_is_gone() {
        let old = vec![
            peer("node-1", KEY_NODE_1, [10, 42, 0, 1]),
            peer("node-2", KEY_NODE_2, [10, 42, 0, 2]),
        ];
        let new = vec![peer("node-1", KEY_NODE_1, [10, 42, 0, 1])];
        assert_eq!(
            gossip_changes(&old, &new),
            PeersDiff {
                changed: Vec::new(),
                gone: vec![peer("node-2", KEY_NODE_2, [10, 42, 0, 2])],
            }
        );
    }
}

fn chitchat_id(node_id: &str, generation: u64) -> ChitchatId {
    ChitchatId::new(node_id, generation, "10.42.0.1:7280".parse().unwrap())
}

#[test]
fn latest_generations_keeps_the_newest_generation_of_each_node() {
    let old = chitchat_id("node-1", 100);
    let new = chitchat_id("node-1", 200);
    let other = chitchat_id("node-2", 50);
    // The order of the input does not matter.
    let latest = latest_generations([(&new, "new"), (&other, "other"), (&old, "old")]);
    assert_eq!(latest.len(), 2);
    assert_eq!(latest["node-1"], "new");
    assert_eq!(latest["node-2"], "other");
}

mod known_peers {
    use super::*;
    use crate::test_util::{chitchat_id, chitchat_with_nodes, key_values};

    /// The facts do not have the node ID, so it does not matter here.
    fn facts(public_key: &str, mesh_ip: [u8; 4]) -> Vec<(String, String)> {
        peer("", public_key, mesh_ip).to_facts()
    }

    #[test]
    fn returns_every_other_node_with_valid_facts() {
        let chitchat = chitchat_with_nodes(
            &chitchat_id("node-1", 1),
            facts(KEY_NODE_1, [10, 42, 0, 1]),
            vec![(chitchat_id("node-2", 1), facts(KEY_NODE_2, [10, 42, 0, 2]))],
        );
        assert_eq!(
            good_known_peers(&chitchat),
            vec![peer("node-2", KEY_NODE_2, [10, 42, 0, 2])]
        );
    }

    #[test]
    fn skips_older_generations_of_the_own_node() {
        let chitchat = chitchat_with_nodes(
            &chitchat_id("node-1", 200),
            facts(KEY_NODE_1_RESTARTED, [10, 42, 0, 1]),
            vec![(
                chitchat_id("node-1", 100),
                facts(KEY_NODE_1, [10, 42, 0, 1]),
            )],
        );
        assert!(good_known_peers(&chitchat).is_empty());
    }

    #[test]
    fn skips_nodes_with_bad_or_missing_facts() {
        let mut bad_ip = facts(KEY_NODE_2, [10, 42, 0, 2]);
        bad_ip[1].1 = "not an ip".to_string();
        let chitchat = chitchat_with_nodes(
            &chitchat_id("node-1", 1),
            facts(KEY_NODE_1, [10, 42, 0, 1]),
            vec![
                (chitchat_id("node-2", 1), bad_ip),
                (chitchat_id("node-3", 1), key_values(&[("unrelated", "x")])),
                (chitchat_id("node-4", 1), facts(KEY_NODE_2, [10, 42, 0, 4])),
            ],
        );
        assert_eq!(
            good_known_peers(&chitchat),
            vec![peer("node-4", KEY_NODE_2, [10, 42, 0, 4])]
        );
    }

    #[test]
    fn skips_nodes_that_left() {
        let mut leaving = facts(KEY_NODE_2, [10, 42, 0, 2]);
        leaving.push((LEAVING_KEY.to_string(), "true".to_string()));
        let chitchat = chitchat_with_nodes(
            &chitchat_id("node-1", 1),
            facts(KEY_NODE_1, [10, 42, 0, 1]),
            vec![(chitchat_id("node-2", 1), leaving)],
        );
        assert!(good_known_peers(&chitchat).is_empty());
    }

    #[test]
    fn takes_the_latest_generation_of_a_restarted_node() {
        let chitchat = chitchat_with_nodes(
            &chitchat_id("node-1", 1),
            facts(KEY_NODE_1, [10, 42, 0, 1]),
            vec![
                // The node restarted with a new key.
                (
                    chitchat_id("node-2", 200),
                    facts(KEY_NODE_2, [10, 42, 0, 2]),
                ),
                (
                    chitchat_id("node-2", 100),
                    facts(KEY_NODE_1, [10, 42, 0, 9]),
                ),
            ],
        );
        assert_eq!(
            good_known_peers(&chitchat),
            vec![peer("node-2", KEY_NODE_2, [10, 42, 0, 2])]
        );
    }

    #[test]
    fn a_leaving_latest_generation_hides_the_older_ones() {
        // The old generation crashed, the new one left gracefully:
        // the old key must not come back as a peer.
        let mut leaving = facts(KEY_NODE_2, [10, 42, 0, 2]);
        leaving.push((LEAVING_KEY.to_string(), "true".to_string()));
        let chitchat = chitchat_with_nodes(
            &chitchat_id("node-1", 1),
            facts(KEY_NODE_1, [10, 42, 0, 1]),
            vec![
                (
                    chitchat_id("node-2", 100),
                    facts(KEY_NODE_1, [10, 42, 0, 9]),
                ),
                (chitchat_id("node-2", 200), leaving),
            ],
        );
        assert!(good_known_peers(&chitchat).is_empty());
    }
}
