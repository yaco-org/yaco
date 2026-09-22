//! Three agents on loopback find each other through one seed.

use std::net::SocketAddr;
use std::time::Duration;

use yaco_agent::gossip;

const GOSSIP_INTERVAL: Duration = Duration::from_millis(100);
const TIMEOUT: Duration = Duration::from_secs(10);

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn three_nodes_converge() {
    let seed = addr(17281);

    // node-1 starts the cluster. node-2 and node-3 know only node-1.
    let node_1 = gossip::start(gossip::config("node-1", seed, &[], GOSSIP_INTERVAL))
        .await
        .unwrap();
    let node_2 = gossip::start(gossip::config(
        "node-2",
        addr(17282),
        &[seed],
        GOSSIP_INTERVAL,
    ))
    .await
    .unwrap();
    let node_3 = gossip::start(gossip::config(
        "node-3",
        addr(17283),
        &[seed],
        GOSSIP_INTERVAL,
    ))
    .await
    .unwrap();

    let expected = vec!["node-1", "node-2", "node-3"];
    let handles = [&node_1, &node_2, &node_3];

    let converged = tokio::time::timeout(TIMEOUT, async {
        loop {
            let mut all_see_all = true;
            for handle in handles {
                if gossip::live_node_ids(handle).await != expected {
                    all_see_all = false;
                }
            }
            if all_see_all {
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
    assert!(converged.is_ok(), "cluster did not converge in {TIMEOUT:?}");

    node_1.shutdown().await.unwrap();
    node_2.shutdown().await.unwrap();
    node_3.shutdown().await.unwrap();
}
