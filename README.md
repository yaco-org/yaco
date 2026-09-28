# YACO

Egalitarian container orchestration platform.

[![OpenAPI spec](https://img.shields.io/badge/OpenAPI-node%20API-6BA539?logo=openapiinitiative&logoColor=white)](https://yaco-org.github.io/yaco/api/)
[![Coverage](https://img.shields.io/badge/coverage-report-blue)](https://yaco-org.github.io/yaco/coverage/)

## Privileges

The agent manages two WireGuard interfaces (`yaco-mesh` and `yaco-boot`), so it needs superuser permissions.

Alternatively, on a node, run it as a normal user with an ambient capability:

```ini
[Service]
User=yaco
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

## Starting a cluster

Every node of a cluster has the same join token.
You can make one with `openssl rand -base64 32`.
It must have at least 16 characters.

Every node has a config file, by default `/etc/yaco/yaco.toml` (change it with `--config` or `YACO_CONFIG`).
`yaco.example.toml` shows every value with its default.
Only `node.id` and `node.public_ip` are required.
The token is not in the config file and should be supplied with `YACO_TOKEN`.

The `[cluster]` table must be the same on every node.
A joining node sends a fingerprint of it, and a seed with another `[cluster]` table refuses the join.

The first node has no seeds:

```toml
[node]
id = "n1"
public_ip = "203.0.113.1"
```

Every other node has the public IP and bootstrap port of any existing node:

```toml
[node]
id = "n2"
public_ip = "203.0.113.2"
seeds = ["203.0.113.1:7282"]
```

```sh
YACO_TOKEN=<token> yaco-agent --config /etc/yaco/yaco.toml
```

Open these UDP ports on every node (the defaults are shown):

| Port | Config key       | Use                                              |
| ---- | ---------------- | ------------------------------------------------ |
| 7281 | `node.mesh_port` | Mesh WireGuard interface                         |
| 7282 | `node.boot_port` | Bootstrap WireGuard interface, for joining nodes |

Gossip (`cluster.gossip_port`, UDP 7280) and the node API (`cluster.api_port`, TCP 7284)
run inside the mesh, on the mesh IP only.
Do not open them on the public interface.

## Tests

```sh
cargo test
```

The mesh test runs three agents in separate network namespaces.
It uses a user namespace, so it also needs no root.
It needs `unshare`, `ip`, `ping` and the WireGuard kernel module,
so it is ignored by default:

```sh
cargo test -p yaco-agent --test netns_mesh -- --ignored
```

To run one node by hand without root,
start a shell in a new user and network namespace:

```sh
unshare --user --map-root-user --net sh
```

## Node API

Every node serves the node API on its mesh IP (`cluster.api_port`, TCP 7284).
`GET /v1/nodes` lists the nodes of the cluster, and `GET /v1/events` streams their changes as server-sent events.
For example, on a node:

```sh
curl http://<mesh IP>:7284/v1/nodes
curl -N http://<mesh IP>:7284/v1/events
```

The container operations answer 501 Not Implemented for now.

The handlers are in `crates/yaco-agent/src/api`, and the paths and types are in the `yaco-api` crate,
which clients can use too.
