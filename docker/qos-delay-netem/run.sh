#!/usr/bin/env bash
# #1389 acceptance leg: injected delay (tc netem, NET_ADMIN) on the path between
# upfd and a far-end responder; the GTP-U path delay (GPQM, TS 29.244 §5.24.5)
# and the N6 delay (UN6DM, §5.33.8) upfd reports must be within a stated
# tolerance of the injected one-way delay. Plus a demo-off arm: neither feature
# flag, so nothing is advertised or measured.
#
# Topology: upfd in the root namespace on 10.89.0.1 (GTP-U), a veth to the
# namespace qosfar (10.89.0.2) running the STAMP reflector (862) and a GTP-U
# Echo responder (2152). netem adds D ms on each direction, so the round trip
# grows by 2D and the expected one-way delay is D.
#
# #1389 part 3, per QoS flow QoS monitoring (QFQM, §5.24.4): the far end also
# stands in for the NG-RAN, answering every QoS Monitoring Packet on the
# session's tunnel with T2/T3 and stated RAN delays of 2 ms (DL) and 3 ms (UL).
# netem is set per direction (D_DL on qos0's egress, D_UL on qos1's), so the
# expected UPF-to-UE delays are DL = D_DL + 2, UL = D_UL + 3, RTT = their sum.
# Both ends share one clock, so the clock-synced arm measures each direction.
#
# Usage (root): run.sh <path-to-nextgcore-upfd> <out-dir>
set -euo pipefail
BIN=$(readlink -f "$1")
OUT=$(readlink -f "$2")
HERE=$(dirname "$(readlink -f "$0")")
TOL_MS=${TOL_MS:-5}
mkdir -p "$OUT"

cleanup() {
  pkill -f qos_delay_responder.py || true
  pkill -f "$BIN" || true
  ip netns del qosfar 2>/dev/null || true
  ip link del qos0 2>/dev/null || true
}
trap cleanup EXIT

modprobe sch_netem 2>/dev/null || true
ip netns add qosfar
ip link add qos0 type veth peer name qos1
ip link set qos1 netns qosfar
ip addr add 10.89.0.1/24 dev qos0
ip link set qos0 up
ip netns exec qosfar ip addr add 10.89.0.2/24 dev qos1
ip netns exec qosfar ip link set qos1 up
ip netns exec qosfar ip link set lo up
ip netns exec qosfar python3 -I "$HERE/qos_delay_responder.py" 10.89.0.2 2 3 > "$OUT/responder.log" 2>&1 &
sleep 1

rc=0
# arm <name> <netem delay ms> <expected one-way ms|off> <pass|fail> [upfd flags...]
# "fail" is the negative control: the checker must reject a wrong expectation.
arm() {
  local name=$1 delay=$2 expect=$3 want=$4; shift 4
  tc qdisc replace dev qos0 root netem delay "${delay}ms"
  ip netns exec qosfar tc qdisc replace dev qos1 root netem delay "${delay}ms"
  echo "=== arm $name: netem ${delay} ms each way (injected one-way ${delay} ms), expected ${expect}, flags: ${*:-none}" | tee -a "$OUT/summary.txt"
  ip netns exec qosfar ping -c 3 -q 10.89.0.1 | tail -1 | tee -a "$OUT/summary.txt"
  "$BIN" --pfcp-addr 127.0.0.1 --pfcp-port 8805 --pfcp-allowed-peers 127.0.0.1 \
    --gtpu-addr 10.89.0.1 --tun-ifname qostun --tun-ip 10.46.0.1 \
    --gtpu-path-qos-probe-interval-ms 500 --n6-delay-probe-interval-ms 500 -e info "$@" \
    > "$OUT/upfd-$name.log" 2>&1 &
  local pid=$!
  sleep 3
  local got=pass
  if ! python3 -I "$HERE/qos_delay_smf.py" 127.0.0.1:8805 10.89.0.2 "$expect" "$TOL_MS" 9 \
      2>&1 | tee -a "$OUT/summary.txt"; then
    got=fail
  fi
  echo "arm $name: checker said $got, wanted $want" | tee -a "$OUT/summary.txt"
  [ "$got" = "$want" ] || rc=1
  kill "$pid"; wait "$pid" 2>/dev/null || true
  sleep 1
}

# qfqm_arm <name> <DL netem ms> <UL netem ms> <expected DL,UL,RTT ms|off> <pass|fail> [flags...]
# Downlink traffic (ping toward the UE IP, into upfd's TUN) runs during the arm,
# so QMPs ride on real G-PDUs as well as on dummies.
qfqm_arm() {
  local name=$1 dl=$2 ul=$3 expect=$4 want=$5; shift 5
  tc qdisc replace dev qos0 root netem delay "${dl}ms"
  ip netns exec qosfar tc qdisc replace dev qos1 root netem delay "${ul}ms"
  echo "=== arm $name: netem DL ${dl} ms, UL ${ul} ms (RAN DL 2 ms, UL 3 ms stated), expected DL,UL,RTT ${expect}, flags: ${*:-none}" | tee -a "$OUT/summary.txt"
  local q0 r0
  q0=$(grep -c '^QMP ' "$OUT/responder.log" || true)
  r0=$(grep -c 'tpdu=[1-9]' "$OUT/responder.log" || true)
  "$BIN" --pfcp-addr 127.0.0.1 --pfcp-port 8805 --pfcp-allowed-peers 127.0.0.1 \
    --gtpu-addr 10.89.0.1 --tun-ifname qostun --tun-ip 10.46.0.1 \
    --qos-flow-monitoring-probe-interval-ms 500 -e info "$@" \
    > "$OUT/upfd-$name.log" 2>&1 &
  local pid=$!
  sleep 3
  ping -q -i 0.2 -w 10 10.46.0.2 > /dev/null 2>&1 &
  local ping_pid=$!
  local got=pass
  if ! python3 -I "$HERE/qos_flow_smf.py" 127.0.0.1:8805 10.89.0.1 10.89.0.2 "$expect" "$TOL_MS" 9 \
      2>&1 | tee -a "$OUT/summary.txt"; then
    got=fail
  fi
  kill "$ping_pid" 2>/dev/null || true
  local q1 r1
  q1=$(grep -c '^QMP ' "$OUT/responder.log" || true)
  r1=$(grep -c 'tpdu=[1-9]' "$OUT/responder.log" || true)
  echo "arm $name: $((q1 - q0)) QMP(s) answered, $((r1 - r0)) of them on a G-PDU with a T-PDU" | tee -a "$OUT/summary.txt"
  if [ "$expect" = off ]; then
    [ $((q1 - q0)) -eq 0 ] || got=fail
  elif [ $((r1 - r0)) -lt 1 ]; then
    echo "arm $name: no QMP rode on a real downlink packet" | tee -a "$OUT/summary.txt"
    got=fail
  fi
  echo "arm $name: checker said $got, wanted $want" | tee -a "$OUT/summary.txt"
  [ "$got" = "$want" ] || rc=1
  kill "$pid"; wait "$pid" 2>/dev/null || true
  sleep 1
}

FLAGS=(--gtpu-path-qos-monitoring --n6-delay-measurement)
arm off 20 off pass
arm d20 20 20 pass "${FLAGS[@]}"
arm d50 50 50 pass "${FLAGS[@]}"
# Negative controls: 20 ms injected but 35 ms expected must be rejected, and so
# must the off-arm check when the features are on.
arm neg-wrong-delay 20 35 fail "${FLAGS[@]}"
arm neg-off-with-flags 20 off fail "${FLAGS[@]}"

# #1389 part 3 (QFQM). Off arm: no flag, so no QFQM bit, no QMP, no report.
qfqm_arm qfqm-off 20 20 off pass
qfqm_arm qfqm-d20 20 20 22,23,45 pass --qos-flow-monitoring
qfqm_arm qfqm-asym-synced 20 40 22,43,65 pass --qos-flow-monitoring --qos-flow-monitoring-clock-synced
# Negative controls: without the clock-synced flag the asymmetric path is split
# evenly (DL = UL = 30 + RAN), so the per-direction expectation must be
# rejected; and so must the off check with the flag on.
qfqm_arm neg-qfqm-asym-unsynced 20 40 22,43,65 fail --qos-flow-monitoring
qfqm_arm neg-qfqm-off-with-flag 20 20 off fail --qos-flow-monitoring
echo "netem leg exit $rc" | tee -a "$OUT/summary.txt"
exit $rc
