#!/bin/sh
# Starts three agents, each in its own network namespace,
# and checks that every node reaches every other node over the mesh.
#
# The script runs itself in a new user namespace,
# where it has CAP_NET_ADMIN over the namespaces that it creates.
#
# Needs: unshare (util-linux), ip (iproute2), ping,
# and the WireGuard kernel module (Linux 5.6 or later has it).
#
# Environment:
#   YACO_AGENT      path to the yaco-agent binary (required)
#   YACO_LOG_DIR    directory for agent logs (default: a new temporary directory)

set -eu

if [ "${YACO_IN_USERNS:-}" != 1 ]; then
  exec env YACO_IN_USERNS=1 unshare --user --map-root-user --net --mount "$0" "$@"
fi

AGENT=${YACO_AGENT:?set YACO_AGENT to the yaco-agent binary}
LOG_DIR=${YACO_LOG_DIR:-$(mktemp -d)}
NODES="1 2 3"

pids=""
cleanup() {
  for pid in $pids; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*"
  for n in $NODES; do
    echo "--- log of n$n"
    cat "$LOG_DIR/n$n.log"
  done
  exit 1
}

# A private /run, so that "ip netns" does not touch the /run of the host.
mount -t tmpfs none /run
mkdir -p /run/netns

# One underlay network: a bridge with one veth per node.
# Node n$i has the underlay address 10.99.0.$i.
ip link set lo up
ip link add yaco-test-br type bridge
ip link set yaco-test-br up
for n in $NODES; do
  ip netns add "n$n"
  ip link add "yaco-test-v$n" type veth peer name eth0 netns "n$n"
  ip link set "yaco-test-v$n" master yaco-test-br up
  ip -n "n$n" link set lo up
  ip -n "n$n" addr add "10.99.0.$n/24" dev eth0
  ip -n "n$n" link set eth0 up
done

# Start the agents. Node n1 is the seed.
for n in $NODES; do
  seed=""
  if [ "$n" != 1 ]; then
    seed="--seed 10.99.0.1:7280"
  fi
  # shellcheck disable=SC2086
  ip netns exec "n$n" "$AGENT" --node-id "n$n" --listen "10.99.0.$n:7280" $seed \
    >"$LOG_DIR/n$n.log" 2>&1 &
  pids="$pids $!"
  last_pid=$!
done

mesh_ip() {
  ip -n "$1" -4 -o addr show dev yaco-mesh 2>/dev/null | awk '{print $4}' | cut -d/ -f1
}

# Wait until every node reaches every other node.
deadline=$(($(date +%s) + 30))
for from in $NODES; do
  for to in $NODES; do
    [ "$from" = "$to" ] && continue
    while :; do
      for pid in $pids; do
        kill -0 "$pid" 2>/dev/null || fail "an agent exited early"
      done
      ip=$(mesh_ip "n$to")
      if [ -n "$ip" ] && ip netns exec "n$from" ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
        echo "ok: n$from -> n$to ($ip)"
        break
      fi
      [ "$(date +%s)" -lt "$deadline" ] || fail "n$from cannot reach n$to over the mesh"
      sleep 1
    done
  done
done

# Traffic must go through the mesh interface, not the underlay.
route=$(ip -n n1 route get "$(mesh_ip n2)")
case "$route" in
*"dev yaco-mesh"*) echo "ok: n1 routes mesh traffic through yaco-mesh" ;;
*) fail "unexpected route: $route" ;;
esac

# A graceful leave of n3 must remove its peer on n1 and n2.
# "ip netns exec" keeps the PID, so $last_pid is the agent of n3.
kill -INT "$last_pid"
wait "$last_pid" || fail "n3 did not exit cleanly"
for n in 1 2; do
  deadline=$(($(date +%s) + 10))
  until grep -q "removed mesh peer" "$LOG_DIR/n$n.log"; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "n$n did not remove the peer of n3"
    sleep 1
  done
  echo "ok: n$n removed the peer of n3"
done

echo "PASS"
