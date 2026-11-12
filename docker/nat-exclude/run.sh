#!/usr/bin/env bash
# #1455 acceptance leg, against the real nextgcore-upfd binary:
# - --nat-exclude: an uplink G-PDU from the UE address reaches a DN server with
#   the UPF's N6 address as source (default, masqueraded), and with the UE's own
#   address when the DN prefix is excluded;
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
# masqueraded in the next one whatever its rules say.
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

rc=0
# arm <name> <expected DN source> <expect-session-series yes|no> <pass|fail> [upfd flags...]
# "fail" is the negative control: the checks must reject a wrong expectation.
arm() {
  local name=$1 want_src=$2 want_series=$3 want=$4; shift 4
  echo "=== arm $name: expect DN source $want_src, per-session series $want_series, flags: ${*:-none}" | tee -a "$OUT/summary.txt"
  topology
  UPF_METRICS_PORT=19455 ip netns exec nx-upf "$BIN" --pfcp-addr 127.0.0.1 --pfcp-port 8805 \
    --pfcp-allowed-peers 127.0.0.1 --gtpu-addr 10.90.0.1 --tun-ifname nxtun \
    --tun-ip 10.46.0.1 --tun-prefix 16 -e info "$@" > "$OUT/upfd-$name.log" 2>&1 &
  local pid=$!
  sleep 3
  ip netns exec nx-upf iptables -t nat -S POSTROUTING | tee "$OUT/nat-$name.txt" >> "$OUT/summary.txt"
  ip netns exec nx-dn "${PY[@]}" dn 10.91.0.2 "$COUNT" 6 > "$OUT/dn-$name.txt" 2>&1 &
  local dnpid=$!
  sleep 0.5
  local got=pass
  ip netns exec nx-upf "${PY[@]}" establish 127.0.0.1:8805 10.90.0.1 "$TEID" "$UE" 2>&1 | tee -a "$OUT/summary.txt" || got=fail
  ip netns exec nx-ran "${PY[@]}" send 10.90.0.1 "$TEID" "$UE" 10.91.0.2 "$COUNT" 2>&1 | tee -a "$OUT/summary.txt"
  wait "$dnpid" || true
  cat "$OUT/dn-$name.txt" >> "$OUT/summary.txt"
  local n_ok
  n_ok=$(grep -c "^src=$want_src len=100$" "$OUT/dn-$name.txt" || true)
  [ "$n_ok" -eq "$COUNT" ] || { echo "DN saw $n_ok/$COUNT datagrams from $want_src" | tee -a "$OUT/summary.txt"; got=fail; }
  ip netns exec nx-upf curl -fsS http://127.0.0.1:19455/metrics > "$OUT/metrics-$name.txt" || got=fail
  local series
  series=$(grep '^upf_session_ul_bytes_total{' "$OUT/metrics-$name.txt" || true)
  echo "per-session series: ${series:-none}" | tee -a "$OUT/summary.txt"
  if [ "$want_series" = yes ]; then
    echo "$series" | grep -Eq "^upf_session_ul_bytes_total\{seid=\"0x[0-9a-f]+\"\} $INNER$" || got=fail
  else
    [ -z "$series" ] && ! grep -q '^# TYPE upf_session_' "$OUT/metrics-$name.txt" || got=fail
  fi
  echo "arm $name: checks said $got, wanted $want" | tee -a "$OUT/summary.txt"
  [ "$got" = "$want" ] || rc=1
  kill "$pid"; wait "$pid" 2>/dev/null || true
  sleep 1
}

arm off 10.91.0.1 no pass
arm excluded "$UE" yes pass --nat-exclude 10.91.0.0/24 --session-metrics seid
# Negative controls: an exclusion of ANOTHER prefix still masquerades, so expecting
# the UE source must fail; and without --session-metrics there is no series.
arm neg-other-prefix "$UE" no fail --nat-exclude 10.92.0.0/24
arm neg-no-series 10.91.0.1 yes fail
echo "nat-exclude leg exit $rc" | tee -a "$OUT/summary.txt"
exit $rc
