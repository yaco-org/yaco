# YACO

Egalitarian container orchestration platform.

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

Start the first node without seeds:

```sh
YACO_TOKEN=<token> yaco-agent --node-id n1 --listen <public IP>:7280
```

Start every other node with the public IP and bootstrap port of any existing node:

```sh
YACO_TOKEN=<token> yaco-agent --node-id n2 --listen <public IP>:7280 --seed <IP of n1>:7282
```

Open these UDP ports on every node:

| Port | Use                                              |
| ---- | ------------------------------------------------ |
| 7280 | Gossip (moves into the mesh in a later step)     |
| 7281 | Mesh WireGuard interface                         |
| 7282 | Bootstrap WireGuard interface, for joining nodes |

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
