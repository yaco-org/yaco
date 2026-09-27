#![cfg(test)]

use super::*;

const EXAMPLE: &str = include_str!("../../../../yaco.example.toml");

const MINIMAL: &str = r#"
[node]
id = "node-1"
public_ip = "192.0.2.1"
"#;

/// A minimal file plus one more line in the `[cluster]` table.
fn with_cluster_line(line: &str) -> String {
    format!("{MINIMAL}\n[cluster]\n{line}\n")
}

#[test]
fn minimal_file_gets_the_defaults() {
    let config = Config::parse(MINIMAL).unwrap();
    assert_eq!(config.node.id, "node-1");
    assert_eq!(
        config.node.public_ip,
        "192.0.2.1".parse::<IpAddr>().unwrap()
    );
    assert!(config.node.seeds.is_empty());
    assert_eq!(config.node.mesh_port, default_mesh_port());
    assert_eq!(config.node.boot_port, default_boot_port());
    assert_eq!(config.node.mesh_interface, default_mesh_interface());
    assert_eq!(config.node.boot_interface, default_boot_interface());
    assert_eq!(config.cluster, ClusterConfig::default());
}

#[test]
fn example_file_is_valid_and_shows_the_defaults() {
    let text = EXAMPLE;
    let config = Config::parse(text).unwrap();
    assert_eq!(config.cluster, ClusterConfig::default());
    assert_eq!(config.node.mesh_port, default_mesh_port());
    assert_eq!(config.node.boot_port, default_boot_port());
    assert_eq!(config.node.mesh_interface, default_mesh_interface());
    assert_eq!(config.node.boot_interface, default_boot_interface());
}

#[test]
fn values_are_read_from_the_file() {
    let text = r#"
[node]
id = "node-2"
public_ip = "192.0.2.2"
seeds = ["192.0.2.1:7282", "192.0.2.3:9000"]
mesh_port = 9001

[cluster]
mesh_subnet = "192.168.0.0/24"
gossip_interval = "250ms"
"#;
    let config = Config::parse(text).unwrap();
    assert_eq!(
        config.node.seeds,
        vec![
            "192.0.2.1:7282".parse::<SocketAddr>().unwrap(),
            "192.0.2.3:9000".parse().unwrap()
        ]
    );
    assert_eq!(config.node.mesh_port, 9001);
    assert_eq!(
        config.cluster.mesh_subnet,
        "192.168.0.0/24".parse().unwrap()
    );
    assert_eq!(config.cluster.gossip_interval, Duration::from_millis(250));
}

#[test]
fn required_node_values_are_required() {
    assert!(Config::parse("[node]\nid = \"node-1\"\n").is_err());
    assert!(Config::parse("[node]\npublic_ip = \"192.0.2.1\"\n").is_err());
    assert!(Config::parse("").is_err());
}

#[test]
fn unknown_keys_are_errors() {
    assert!(Config::parse(&format!("{MINIMAL}typo = 1\n")).is_err());
    assert!(Config::parse(&with_cluster_line("gossip_intervall = \"1s\"")).is_err());
    assert!(Config::parse(&format!("{MINIMAL}\n[extra]\n")).is_err());
}

#[test]
fn invalid_values_are_errors() {
    let bad_cluster_lines = [
        // Host bits set.
        "mesh_subnet = \"10.42.1.0/16\"",
        // Too small for the addresses that the agent needs.
        "mesh_subnet = \"10.42.0.0/31\"",
        // Contains the fixed bootstrap addresses.
        "mesh_subnet = \"169.254.0.0/16\"",
        "mesh_subnet = \"169.254.42.0/30\"",
        // No longer configurable.
        "boot_subnet = \"169.254.42.0/30\"",
        "gossip_interval = \"0s\"",
        "join_rounds = 0",
        "max_mesh_ip_attempts = 0",
        "cluster_id = \"\"",
        "gossip_interval = \"soon\"",
    ];
    for line in bad_cluster_lines {
        assert!(
            Config::parse(&with_cluster_line(line)).is_err(),
            "accepted: {line}"
        );
    }

    let bad_node_lines = [
        "mesh_interface = \"a-name-that-is-too-long\"",
        "boot_interface = \"\"",
        "boot_interface = \"yaco-mesh\"",
    ];
    for line in bad_node_lines {
        let text = MINIMAL.replace("[node]", &format!("[node]\n{line}"));
        assert!(Config::parse(&text).is_err(), "accepted: {line}");
    }
    assert!(Config::parse(&MINIMAL.replace("\"node-1\"", "\"\"")).is_err());
}

#[test]
fn fingerprint_ignores_formatting_and_key_order() {
    let a = Config::parse(&with_cluster_line("gossip_interval = \"2s\"\nmtu = 1400")).unwrap();
    let b = Config::parse(&with_cluster_line(
        "# a comment\nmtu    =   1400\n\ngossip_interval = \"2000ms\"",
    ))
    .unwrap();
    assert_eq!(a.cluster.fingerprint(), b.cluster.fingerprint());
}

#[test]
fn fingerprint_changes_with_any_cluster_value() {
    let base = ClusterConfig::default().fingerprint();
    let changed_lines = [
        "mesh_subnet = \"10.43.0.0/16\"",
        "mtu = 1400",
        "peer_resync_interval = \"31s\"",
        "cluster_id = \"other\"",
        "gossip_port = 7290",
        "phi_threshold = 9.0",
        "join_port = 7293",
        "max_mesh_ip_attempts = 17",
        "api_port = 7294",
    ];
    for line in changed_lines {
        let config = Config::parse(&with_cluster_line(line)).unwrap();
        assert_ne!(
            config.cluster.fingerprint(),
            base,
            "same fingerprint with: {line}"
        );
    }
}

#[test]
fn fingerprint_does_not_depend_on_node_values() {
    let a = Config::parse(MINIMAL).unwrap();
    let text = r#"
[node]
id = "node-9"
public_ip = "198.51.100.9"
seeds = ["192.0.2.1:7282"]
mesh_port = 9001
"#;
    let b = Config::parse(text).unwrap();
    assert_eq!(a.cluster.fingerprint(), b.cluster.fingerprint());
}

/// Collects the dotted paths of all keys in `value`, for example `cluster.mtu`.
/// Arrays are values, so their items are not keys.
fn key_paths(value: &toml::Value, prefix: &str, paths: &mut Vec<String>) {
    if let toml::Value::Table(table) = value {
        for (key, value) in table {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            key_paths(value, &path, paths);
            if !value.is_table() {
                paths.push(path);
            }
        }
    }
    paths.sort();
}

#[test]
fn example_file_shows_every_config_key() {
    // All keys that `Config` has, from a serialized config.
    let config = toml::Value::try_from(Config::parse(MINIMAL).unwrap()).unwrap();
    let mut expected = Vec::new();
    key_paths(&config, "", &mut expected);

    let example: toml::Value = toml::from_str(EXAMPLE).unwrap();
    let mut shown = Vec::new();
    key_paths(&example, "", &mut shown);

    // Unknown keys in the example already fail `example_file_is_valid_and_shows_the_defaults`.
    let missing: Vec<&String> = expected.iter().filter(|key| !shown.contains(key)).collect();
    assert!(
        missing.is_empty(),
        "yaco.example.toml does not show these config keys: {missing:?}"
    );
}

#[test]
fn load_reads_the_file() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, MINIMAL.as_bytes()).unwrap();
    let config = Config::load(file.path()).unwrap();
    assert_eq!(config.node.id, "node-1");
}

#[test]
fn load_errors_name_the_file() {
    let missing = std::path::Path::new("/nonexistent/yaco.toml");
    let err = Config::load(missing).unwrap_err();
    assert!(
        format!("{err:#}").contains("/nonexistent/yaco.toml"),
        "{err:#}"
    );

    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, b"[node]\nid = 1\n").unwrap();
    let err = Config::load(file.path()).unwrap_err();
    let path = file.path().display().to_string();
    assert!(format!("{err:#}").contains(&path), "{err:#}");
}

#[test]
fn fingerprint_is_shown_as_64_lowercase_hex_characters() {
    let shown = ClusterConfig::default().fingerprint().to_string();
    assert_eq!(shown.len(), 64);
    assert!(
        shown
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "{shown}"
    );
}
