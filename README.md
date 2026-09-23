# YACO

Egalitarian container orchestration platform.

## Privileges

The agent manages a WireGuard interface (`yaco-mesh`), so it needs superuser permissions.

Alternatively, on a node, run it as a normal user with an ambient capability:

```ini
[Service]
User=yaco
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

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
