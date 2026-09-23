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
