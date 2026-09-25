#![cfg(test)]

use super::*;

// Base64 of 32 bytes of 0x11 and of 32 bytes of 0x22,
// so the two are easy to tell apart at a glance.
const KEY_NODE_1: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const KEY_NODE_2: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";

fn peer(public_key: &str, mesh_ip: [u8; 4]) -> MeshPeer {
    MeshPeer {
        public_key: public_key.to_string(),
        mesh_ip: Ipv4Addr::from(mesh_ip),
        endpoint: "192.0.2.1:7281".parse().unwrap(),
    }
}

#[test]
fn mesh_ip_is_stable() {
    // If this value changes, nodes get new addresses after an upgrade.
    assert_eq!(mesh_ip("node-1", 0), Ipv4Addr::new(10, 42, 58, 124));
    assert_eq!(mesh_ip("node-1", 0), mesh_ip("node-1", 0));
    assert_ne!(mesh_ip("node-1", 0), mesh_ip("node-1", 1));
    assert_ne!(mesh_ip("node-1", 0), mesh_ip("node-2", 0));
}

#[test]
fn mesh_ip_is_a_host_in_the_subnet() {
    for attempt in 0..10_000 {
        let ip = u32::from(mesh_ip("node", attempt));
        let host = ip - u32::from(SUBNET);
        assert!((1..=65534).contains(&host), "attempt {attempt}: {ip}");
    }
}

#[test]
fn facts_round_trip() {
    let original = peer(KEY_NODE_1, [10, 42, 0, 1]);
    let facts: BTreeMap<String, String> = original.to_facts().into_iter().collect();
    let parsed = MeshPeer::from_facts(
        facts.get(WG_PUBLIC_KEY_KEY).map(String::as_str),
        facts.get(MESH_IP_KEY).map(String::as_str),
        facts.get(ENDPOINT_KEY).map(String::as_str),
    )
    .unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn bad_facts_are_errors() {
    let ip = Some("10.42.0.1");
    let endpoint = Some("192.0.2.1:7281");
    assert!(MeshPeer::from_facts(None, ip, endpoint).is_err());
    assert!(MeshPeer::from_facts(Some("not a key"), ip, endpoint).is_err());
    assert!(MeshPeer::from_facts(Some(KEY_NODE_1), Some("10.42.0"), endpoint).is_err());
    assert!(MeshPeer::from_facts(Some(KEY_NODE_1), ip, None).is_err());
    assert!(MeshPeer::from_facts(Some(KEY_NODE_1), ip, Some("192.0.2.1")).is_err());
}

#[test]
fn diff_adds_updates_and_removes() {
    let current = vec![
        peer(KEY_NODE_1, [10, 42, 0, 1]),
        peer(KEY_NODE_2, [10, 42, 0, 2]),
    ];
    let desired = vec![peer(KEY_NODE_1, [10, 42, 0, 9])];
    let (to_configure, to_remove) = diff_peers(&current, &desired);
    assert_eq!(to_configure, vec![&desired[0]]);
    assert_eq!(to_remove, vec![KEY_NODE_2.to_string()]);
}

#[test]
fn diff_of_equal_lists_is_empty() {
    let peers = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    let (to_configure, to_remove) = diff_peers(&peers, &peers);
    assert!(to_configure.is_empty());
    assert!(to_remove.is_empty());
}

#[test]
fn is_mesh_ip_accepts_hosts_only() {
    assert!(is_mesh_ip(Ipv4Addr::new(10, 42, 0, 1)));
    assert!(is_mesh_ip(Ipv4Addr::new(10, 42, 255, 254)));
    assert!(!is_mesh_ip(Ipv4Addr::new(10, 42, 0, 0)));
    assert!(!is_mesh_ip(Ipv4Addr::new(10, 42, 255, 255)));
    assert!(!is_mesh_ip(Ipv4Addr::new(10, 43, 0, 1)));
    assert!(!is_mesh_ip(Ipv4Addr::new(10, 41, 255, 254)));
}

#[test]
fn desired_peers_adds_pending_peers_that_are_not_live() {
    let live = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    let pending = vec![
        // Also live, with other facts: the live facts win.
        peer(KEY_NODE_1, [10, 42, 0, 9]),
        peer(KEY_NODE_2, [10, 42, 0, 2]),
    ];
    let desired = desired_peers(live, pending, "own key");
    assert_eq!(
        desired,
        vec![
            peer(KEY_NODE_1, [10, 42, 0, 1]),
            peer(KEY_NODE_2, [10, 42, 0, 2]),
        ]
    );
}

#[test]
fn desired_peers_skips_own_node() {
    let pending = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert!(desired_peers(Vec::new(), pending, KEY_NODE_1).is_empty());
}

#[test]
fn pending_peers_replace_by_public_key() {
    let pending = PendingPeers::default();
    pending.add(vec![peer(KEY_NODE_1, [10, 42, 0, 1])]);
    pending.add(vec![peer(KEY_NODE_1, [10, 42, 0, 2])]);
    assert_eq!(pending.current(&[]), vec![peer(KEY_NODE_1, [10, 42, 0, 2])]);
}

#[test]
fn pending_peers_are_forgotten_once_live() {
    let pending = PendingPeers::default();
    pending.add(vec![
        peer(KEY_NODE_1, [10, 42, 0, 1]),
        peer(KEY_NODE_2, [10, 42, 0, 2]),
    ]);
    let live = vec![peer(KEY_NODE_1, [10, 42, 0, 1])];
    assert_eq!(
        pending.current(&live),
        vec![peer(KEY_NODE_2, [10, 42, 0, 2])]
    );
    // The node leaves gossip later: it must not come back from the pending list.
    assert_eq!(pending.current(&[]), vec![peer(KEY_NODE_2, [10, 42, 0, 2])]);
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
