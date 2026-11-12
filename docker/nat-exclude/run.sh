#!/usr/bin/env bash
# #1455 acceptance leg, against the real nextgcore-upfd binary:
# - --nat-exclude: an uplink G-PDU from the UE address reaches a DN server with
#   the UPF's N6 address as source (default, masqueraded), and with the UE's own
#   address when the DN prefix is excluded. Also when a container wrapper has
#   installed its own MASQUERADE before upfd starts (k8s/Helm/EKS), and across a
#   restart with a different list (no stale exclusion survives);
# - --session-metrics: /metrics carries upf_session_ul_bytes_total for the session,
#   equal to the inner bytes sent; nothing per-session when off.
#
# Everything runs in network namespaces of its own (upfd's iptables rules
# included), so the host's nat table is never touched:
#   ran (10.90.0.2) --veth-- upf (10.90.0.1 N3 | 10.91.0.1 N6, TUN 10.46.0.1/16) --veth-- dn (10.91.0.2)
#
# Usage (root): run.sh <path-to-nextgcore-upfd> <out-dir>
set -euo pipefail
BIN=$(readlink -f "$1")
OUT=$(readlink -f "$2")
HERE=$(dirname "$(readlink -f "$0")")
PY=(python3 -I "$HERE/nat_exclude_smf.py")
TEID=0x1455
UE=10.46.0.2
COUNT=5
INNER=$((COUNT * 128))
UPF_PID=
mkdir -p "$OUT"
: > "$OUT/summary.txt"

cleanup() {
  ip netns pids nx-upf 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns pids nx-dn 2>/dev/null | xargs -r kill 2>/dev/null || true
  for ns in nx-upf nx-ran nx-dn; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT

# A fresh topology per arm: conntrack lives in the namespace, and nat rules only
# see a connection's FIRST packet, so a flow masqueraded by one arm would stay
# masqueraded in the next one whatever its rules say. Within an arm, each probe
# uses its own UE source port, so it is a new flow.
topology() {
  cleanup
  for ns in nx-upf nx-ran nx-dn; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
  ip link add nxran0 netns nx-upf type veth peer name nxran1 netns nx-ran
  ip link add nxdn0 netns nx-upf type veth peer name nxdn1 netns nx-dn
  ip -n nx-upf addr add 10.90.0.1/24 dev nxran0
  ip -n nx-upf addr add 10.91.0.1/24 dev nxdn0
  ip -n nx-ran addr add 10.90.0.2/24 dev nxran1
  ip -n nx-dn addr add 10.91.0.2/24 dev nxdn1
  ip -n nx-upf link set nxran0 up
  ip -n nx-upf link set nxdn0 up
  ip -n nx-ran link set nxran1 up
  ip -n nx-dn link set nxdn1 up
  # The DN routes back via the UPF (a "UPF without NAT" DN), so strict reverse-path
  # filtering accepts the UE's own source address.
  ip -n nx-dn route add default via 10.91.0.1
  ip netns exec nx-upf sysctl -qw net.ipv4.ip_forward=1
}

# start_upfd <tag> [flags...]: start upfd and wait until /metrics answers.
start_upfd() {
  local tag=$1; shift
  UPF_METRICS_PORT=19455 ip netns exec nx-upf "$BIN" --pfcp-addr 127.0.0.1 --pfcp-port 8805 \
    --pfcp-allowed-peers 127.0.0.1 --gtpu-addr 10.90.0.1 --tun-ifname nxtun \
    --tun-ip 10.46.0.1 --tun-prefix 16 -e info "$@" > "$OUT/upfd-$tag.log" 2>&1 &
  UPF_PID=$!
  for _ in $(seq 100); do
    ip netns exec nx-upf curl -fsS -o /dev/null http://127.0.0.1:19455/metrics 2>/dev/null && return 0
    kill -0 "$UPF_PID" 2>/dev/null || { echo "upfd $tag exited" | tee -a "$OUT/summary.txt"; return 1; }
    sleep 0.1
  done
  echo "upfd $tag never served /metrics" | tee -a "$OUT/summary.txt"
  return 1
}

stop_upfd() {
  kill "$UPF_PID" 2>/dev/null || true
  wait "$UPF_PID" 2>/dev/null || true
}

# probe <tag> <expected DN source> <UE source port>: establish a session, send
# COUNT G-PDUs, and check every datagram reached the DN from <expected source>.
probe() {
  local tag=$1 want_src=$2 sport=$3 ok=0
  ip netns exec nx-upf iptables -t nat -S | tee "$OUT/nat-$tag.txt" >> "$OUT/summary.txt"
  ip netns exec nx-dn "${PY[@]}" dn 10.91.0.2 "$COUNT" 6 > "$OUT/dn-$tag.txt" 2>&1 &
  local dnpid=$!
  sleep 0.5
  ip netns exec nx-upf "${PY[@]}" establish 127.0.0.1:8805 10.90.0.1 "$TEID" "$UE" 2>&1 | tee -a "$OUT/summary.txt" || ok=1
  ip netns exec nx-ran "${PY[@]}" send 10.90.0.1 "$TEID" "$UE" 10.91.0.2 "$COUNT" "$sport" 2>&1 | tee -a "$OUT/summary.txt"
  wait "$dnpid" || true
  cat "$OUT/dn-$tag.txt" >> "$OUT/summary.txt"
  local n
  n=$(grep -c "^src=$want_src len=100$" "$OUT/dn-$tag.txt" || true)
  [ "$n" -eq "$COUNT" ] || { echo "$tag: DN saw $n/$COUNT datagrams from $want_src" | tee -a "$OUT/summary.txt"; ok=1; }
  return $ok
}

# series <tag> <yes|no>: the per-session counter is exactly the inner bytes / is absent.
series() {
  local tag=$1 want=$2 s
  ip netns exec nx-upf curl -fsS http://127.0.0.1:19455/metrics > "$OUT/metrics-$tag.txt" || return 1
  s=$(grep '^upf_session_ul_bytes_total{' "$OUT/metrics-$tag.txt" || true)
  echo "per-session series: ${s:-none}" | tee -a "$OUT/summary.txt"
  if [ "$want" = yes ]; then
    echo "$s" | grep -Eq "^upf_session_ul_bytes_total\{seid=\"0x[0-9a-f]+\"\} $INNER$"
  else
    [ -z "$s" ] && ! grep -q '^# TYPE upf_session_' "$OUT/metrics-$tag.txt"
  fi
}

rc=0
# verdict <arm> <got pass|fail> <wanted pass|fail>. "fail" is a negative control:
# the checks must reject a wrong expectation.
verdict() {
  echo "arm $1: checks said $2, wanted $3" | tee -a "$OUT/summary.txt"
  [ "$2" = "$3" ] || rc=1
}

# arm <name> <expected DN source> <series yes|no> <pass|fail> [upfd flags...]
arm() {
  local name=$1 want_src=$2 want_series=$3 want=$4; shift 4
  echo "=== arm $name: expect DN source $want_src, per-session series $want_series, flags: ${*:-none}" | tee -a "$OUT/summary.txt"
  topology
  local got=pass
  start_upfd "$name" "$@" || got=fail
  probe "$name" "$want_src" 40000 || got=fail
  series "$name" "$want_series" || got=fail
  stop_upfd
  verdict "$name" "$got" "$want"
}

arm off 10.91.0.1 no pass
arm excluded "$UE" yes pass --nat-exclude 10.91.0.0/24 --session-metrics seid
# Negative controls: an exclusion of ANOTHER prefix still masquerades, so expecting
# the UE source must fail; and without --session-metrics there is no series.
arm neg-other-prefix "$UE" no fail --nat-exclude 10.92.0.0/24
arm neg-no-series 10.91.0.1 yes fail

# The k8s/Helm/EKS wrapper installs its own MASQUERADE BEFORE upfd starts; the
# exclusion must still win (its jump goes to the head of POSTROUTING).
echo "=== arm wrapper-masquerade: a MASQUERADE installed before upfd; expect $UE" | tee -a "$OUT/summary.txt"
topology
ip netns exec nx-upf iptables -t nat -A POSTROUTING -s 10.46.0.0/16 ! -o nxtun -j MASQUERADE
got=pass
start_upfd wrapper --nat-exclude 10.91.0.0/24 || got=fail
probe wrapper "$UE" 40001 || got=fail
stop_upfd
verdict wrapper-masquerade "$got" pass

# A restart with a CHANGED list: the first run excludes the DN, the second run
# excludes another prefix only, so the DN must be masqueraded again (no stale
# ACCEPT survives) with one jump; a third run with no flag excludes nothing.
echo "=== arm restart: excluded, then another prefix, then none; expect $UE, then 10.91.0.1 twice" | tee -a "$OUT/summary.txt"
topology
got=pass
start_upfd restart-1 --nat-exclude 10.91.0.0/24 || got=fail
probe restart-1 "$UE" 40002 || got=fail
stop_upfd
start_upfd restart-2 --nat-exclude 10.92.0.0/24 || got=fail
probe restart-2 10.91.0.1 40003 || got=fail
jumps=$(grep -c -- '-A POSTROUTING -j UPF-NAT-EXCLUDE' "$OUT/nat-restart-2.txt" || true)
[ "$jumps" -eq 1 ] || { echo "restart-2: $jumps jumps" | tee -a "$OUT/summary.txt"; got=fail; }
stop_upfd
start_upfd restart-3 || got=fail
probe restart-3 10.91.0.1 40004 || got=fail
if grep -q -- '-A UPF-NAT-EXCLUDE' "$OUT/nat-restart-3.txt"; then
  echo "restart-3: stale exclusion" | tee -a "$OUT/summary.txt"; got=fail
fi
stop_upfd
verdict restart "$got" pass

echo "nat-exclude leg exit $rc" | tee -a "$OUT/summary.txt"
exit $rc
