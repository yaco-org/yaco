//! Runs `tests/netns/mesh.sh`: three agents in separate network namespaces
//! join over the bootstrap tunnel and reach each other over the mesh.
//! The script needs no root, but it needs some system tools,
//! so the test is ignored by default:
//!
//!     cargo test -p yaco-agent --test netns_mesh -- --ignored

use std::process::Command;

#[test]
#[ignore = "needs unshare, iproute2, ping and the WireGuard kernel module; run with --ignored"]
fn three_nodes_reach_each_other_over_the_mesh() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/netns/mesh.sh");
    let status = Command::new("sh")
        .arg(script)
        .env("YACO_AGENT", env!("CARGO_BIN_EXE_yaco-agent"))
        .status()
        .expect("cannot run the netns script");
    assert!(status.success(), "{script} failed");
}
