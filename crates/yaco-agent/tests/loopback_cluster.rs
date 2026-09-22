//! Agents on loopback find each other through one seed,
//! and a leaving agent disappears from the live set at once.

use std::net::SocketAddr;
use std::time::Duration;

use chitchat::ChitchatHandle;
use yaco_agent::gossip;

const GOSSIP_INTERVAL: Duration = Duration::from_millis(100);
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(10);

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Starts node `names[0]` as the seed, and the others with it as seed.
async fn start_cluster(names: &[&str], first_port: u16) -> Vec<ChitchatHandle> {
    let seed = addr(first_port);
    let mut handles = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let listen = addr(first_port + i as u16);
        let seeds = if i == 0 { vec![] } else { vec![seed] };
        let config = gossip::config(name, listen, &seeds, GOSSIP_INTERVAL);
        handles.push(gossip::start(config).await.unwrap());
    }
    handles
}

/// Waits until every handle sees exactly `expected` as live nodes.
/// Returns false on timeout.
async fn wait_for_live(handles: &[ChitchatHandle], expected: &[&str], timeout: Duration) -> bool {
    let result = tokio::time::timeout(timeout, async {
        loop {
            let mut all_match = true;
            for handle in handles {
                if gossip::live_node_ids(handle).await != expected {
                    all_match = false;
                }
            }
            if all_match {
                return;
            }
            tokio::time::sleep(GOSSIP_INTERVAL).await;
        }
    })
    .await;

    for handle in handles {
        println!(
            "{:?} sees {:?}",
            handle.chitchat_id(),
            gossip::live_node_ids(handle).await
        );
    }
    result.is_ok()
}

#[tokio::test]
async fn three_nodes_converge() {
    let handles = start_cluster(&["node-1", "node-2", "node-3"], 17281).await;

    assert!(
        wait_for_live(&handles, &["node-1", "node-2", "node-3"], CONVERGE_TIMEOUT).await,
        "cluster did not converge"
    );

    for handle in handles {
        handle.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn leaving_node_is_removed_before_failure_detection() {
    let mut handles = start_cluster(&["node-1", "node-2", "node-3"], 17291).await;
    assert!(
        wait_for_live(&handles, &["node-1", "node-2", "node-3"], CONVERGE_TIMEOUT).await,
        "cluster did not converge"
    );

    let node_3 = handles.pop().unwrap();
    gossip::leave(node_3, GOSSIP_INTERVAL).await.unwrap();

    // The failure detector needs several seconds to mark a node dead.
    // A graceful leave must be visible much sooner.
    assert!(
        wait_for_live(&handles, &["node-1", "node-2"], Duration::from_secs(1)).await,
        "leaving node is still live"
    );

    for handle in handles {
        handle.shutdown().await.unwrap();
    }
}
