#!/bin/sh
# Starts three agents, each in its own network namespace.
# n2 and n3 join through n1 over the bootstrap tunnel.
# Checks that:
# - every node reaches every other node over the mesh,
# - gossip listens on the mesh IP only,
# - a node cut off for a while comes back without a restart,
# - the node API lists the nodes and streams events,
# - a graceful leave removes the peer and shows the node as leaving in the API,
# - a node with a wrong join token cannot join (n4),
# - a node with another [cluster] config cannot join (n5).
#
# The script runs itself in a new user namespace,
# where it has CAP_NET_ADMIN over the namespaces that it creates.
#
# Needs: unshare (util-linux), ip and ss (iproute2), ping, curl,
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
TOKEN="netns-test-token-0123456789"
WRONG_TOKEN="netns-test-token-wrong-9876"

# Fixed ports of the agent, inside the mesh. They are not configurable.
GOSSIP_PORT=7280
API_PORT=7284
# The script writes these values into the config files and checks them later,
# so the test does not depend on the defaults of the agent.
BOOT_PORT=7282
MESH_INTERFACE=yaco-test-mesh

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
  for n in $NODES 4 5; do
    echo "--- log of n$n"
    cat "$LOG_DIR/n$n.log" 2>/dev/null || true
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
for n in $NODES 4 5; do
  ip netns add "n$n"
  ip link add "yaco-test-v$n" type veth peer name eth0 netns "n$n"
  ip link set "yaco-test-v$n" master yaco-test-br up
  ip -n "n$n" link set lo up
  ip -n "n$n" addr add "10.99.0.$n/24" dev eth0
  ip -n "n$n" link set eth0 up
done

# Writes the config file of node n$1 to $LOG_DIR/n$1.toml.
# $2 is the seed list, $3 is extra lines for the [cluster] table.
write_config() {
  cat >"$LOG_DIR/n$1.toml" <<EOF
[node]
id = "n$1"
public_ip = "10.99.0.$1"
seeds = [$2]
boot_port = $BOOT_PORT
mesh_interface = "$MESH_INTERFACE"

[cluster]
$3
EOF
}

# Start the agents. Node n1 starts the cluster, the others join through it.
# The seed address is the public bootstrap endpoint of n1.
for n in $NODES; do
  seeds=""
  if [ "$n" != 1 ]; then
    seeds="\"10.99.0.1:$BOOT_PORT\""
  fi
  write_config "$n" "$seeds" ""
  YACO_TOKEN=$TOKEN ip netns exec "n$n" "$AGENT" --config "$LOG_DIR/n$n.toml" \
    >"$LOG_DIR/n$n.log" 2>&1 &
  pids="$pids $!"
  last_pid=$!
done

# n4 has a wrong token, n5 has another [cluster] config.
# They run in parallel and must give up.
write_config 4 "\"10.99.0.1:$BOOT_PORT\"" ""
YACO_TOKEN=$WRONG_TOKEN ip netns exec n4 "$AGENT" --config "$LOG_DIR/n4.toml" \
  >"$LOG_DIR/n4.log" 2>&1 &
intruder_pid=$!
write_config 5 "\"10.99.0.1:$BOOT_PORT\"" 'dead_node_grace_period = "2days"'
YACO_TOKEN=$TOKEN ip netns exec n5 "$AGENT" --config "$LOG_DIR/n5.toml" \
  >"$LOG_DIR/n5.log" 2>&1 &
mismatch_pid=$!

mesh_ip() {
  ip -n "$1" -4 -o addr show dev "$MESH_INTERFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1
}

# Prints the node IDs of the last live set that node $1 logged.
last_live_set() {
  grep "membership changed" "$LOG_DIR/$1.log" | tail -n 1 | sed 's/.*live=//'
}

# Waits until node $1 logs a live set that equals $2, for example '["n1", "n2"]'.
wait_for_live_set() {
  deadline=$(($(date +%s) + $3))
  until [ "$(last_live_set "$1")" = "$2" ]; do
    [ "$(date +%s)" -lt "$deadline" ] || fail "$1 does not see the live set $2"
    sleep 1
  done
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
*"dev $MESH_INTERFACE"*) echo "ok: n1 routes mesh traffic through $MESH_INTERFACE" ;;
*) fail "unexpected route: $route" ;;
esac

# Gossip must listen on the mesh IP only, not on the public interface.
for n in $NODES; do
  sockets=$(ip netns exec "n$n" ss -Hlun "sport = :$GOSSIP_PORT" | awk '{print $4}')
  [ "$sockets" = "$(mesh_ip "n$n"):$GOSSIP_PORT" ] || fail "n$n gossip sockets: $sockets"
done
echo "ok: gossip listens on the mesh IP only"

# Prints the answer of the node API of node $1 to GET $2.
api_get() {
  ip netns exec "$1" curl -sf --noproxy '*' "http://$(mesh_ip "$1"):$API_PORT$2"
}

# The node API of n1 lists all nodes, and its event stream starts with a snapshot.
wait_for_live_set n1 '["n1", "n2", "n3"]' 30
nodes=$(api_get n1 /v1/nodes) || fail "the node API of n1 does not answer"
for n in $NODES; do
  case "$nodes" in
  *"\"id\":\"n$n\""*) ;;
  *) fail "the node API of n1 does not list n$n: $nodes" ;;
  esac
done
echo "ok: the node API lists all nodes"
# The stream never ends, so curl stops after one second.
events=$(ip netns exec n1 curl -sN --noproxy '*' --max-time 1 "http://$(mesh_ip n1):$API_PORT/v1/events" || true)
case "$events" in
"data: {\"type\":\"snapshot\""*) echo "ok: the event stream starts with a snapshot" ;;
*) fail "unexpected start of the event stream: $events" ;;
esac

# Cut n2 off until every node sees the split.
# The nodes must keep the peers of dead nodes,
# so that n2 comes back when the link is up again.
# If they removed them, no path would be left for gossip between n2 and the others.
wait_for_live_set n1 '["n1", "n2", "n3"]' 30
ip link set yaco-test-v2 down
wait_for_live_set n1 '["n1", "n3"]' 60
wait_for_live_set n3 '["n1", "n3"]' 60
wait_for_live_set n2 '["n2"]' 60
echo "ok: all nodes see the split"
ip link set yaco-test-v2 up
wait_for_live_set n1 '["n1", "n2", "n3"]' 60
wait_for_live_set n2 '["n1", "n2", "n3"]' 60
ip netns exec n1 ping -c 1 -W 2 "$(mesh_ip n2)" >/dev/null || fail "n1 cannot reach n2 after the cut"
if grep -q "removed mesh peer" "$LOG_DIR/n1.log" "$LOG_DIR/n2.log"; then
  fail "a peer was removed during the cut"
fi
echo "ok: n2 came back after the cut"

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
api_get n1 /v1/nodes | grep -q '"id":"n3","generation":[0-9]*,"liveness":"leaving"' ||
  fail "the node API of n1 does not show n3 as leaving"
echo "ok: the node API shows n3 as leaving"

# The node with the wrong token must fail to join and exit.
deadline=$(($(date +%s) + 60))
while kill -0 "$intruder_pid" 2>/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "n4 with a wrong token did not give up"
  sleep 1
done
if wait "$intruder_pid"; then
  fail "n4 with a wrong token exited with success"
fi
grep -q "cannot join through any seed" "$LOG_DIR/n4.log" || fail "n4 exited for another reason"
grep -q "accepted join" "$LOG_DIR/n1.log" || fail "n1 accepted no join"
if grep -q "node_id=n4" "$LOG_DIR/n1.log"; then
  fail "n1 received a join request from n4"
fi
echo "ok: n4 with a wrong token cannot join"

# The node with another [cluster] config must be refused by the seed and exit.
deadline=$(($(date +%s) + 60))
while kill -0 "$mismatch_pid" 2>/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || fail "n5 with another config did not give up"
  sleep 1
done
if wait "$mismatch_pid"; then
  fail "n5 with another config exited with success"
fi
grep -q "cannot join through any seed" "$LOG_DIR/n5.log" || fail "n5 exited for another reason"
grep "refused join" "$LOG_DIR/n1.log" | grep "node_id=n5" | grep -q "config differs" ||
  fail "n1 did not refuse n5 because of the config"
echo "ok: n5 with another [cluster] config cannot join"

echo "PASS"
