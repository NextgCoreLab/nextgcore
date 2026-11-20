#!/usr/bin/env bash
# #2222: the nightly real-binary run of #2208's per-flow delay through an I-UPF.
#
# The REAL smfd and two REAL upfd binaries (a PSA and an I-UPF, each in a
# privileged container with a TUN device), and one harness process standing in
# for the AMF, the PCF and the gNB's GTP-U side (src/tests/e2e/
# iupf_delay_harness.rs). The PCF's PCC rule asks for QoS monitoring (DL, UL,
# round trip, every 1 s); the SMF runs `smf.qos_monitoring.method: gtpu_path`
# and inserts the I-UPF on N9 (`smf.intermediate_upf`). Known delays:
#   - N3: the gNB holds each Echo Response ECHO_HOLD_MS, so the I-UPF measures
#     about ECHO_HOLD_MS/2 to it;
#   - N9: tc netem delays each UPF's packets toward the other N9_MS;
#   - RAN: the gNB's uplink carries DL/UL Delay Results of 2 and 3 ms.
# The run passes when the PCF's third report with delays has DL = 2 + N3 + N9
# and UL = 3 + N3 + N9 (within -1 / +TOLERANCE_MS) and RTT = DL + UL.
#
# What this proves that the per-PR in-process test
# (smfd tests/iupf_e2e_tests.rs, `the_per_flow_delay_through_an_i_upf_reaches_the_pcf_2208`)
# does not:
#   - the binaries' own start-up: the YAML keys and flags (`smf.qos_monitoring`,
#     `smf.intermediate_upf`, upfd's --gtpu-path-qos-monitoring), the N4
#     associations to two UPFs on separate hosts, and the SBI over real h2c;
#   - upfd's real data plane: the TUN device and the kernel's UDP sockets, not
#     the library's datagram socketpair;
#   - a non-zero N9 delay: in process both UPFs are on loopback, so N9 is ~0 and
#     a defect that dropped the PSA's own N9 part would still pass there.
# What neither proves: a real gNB's time stamps and RAN delays, a real AMF and
# PCF (pcfd has no qosMonDecs path), and clock-synchronised one-way delays.
#
# Environment: ECHO_HOLD_MS (40), N9_MS (15, expected), NETEM_N9_MS (N9_MS,
# injected), TOLERANCE_MS (20).
#
# Usage: run.sh <dir with nextgcore-smfd, nextgcore-upfd, iupf-delay-harness> <out-dir>
# Needs docker with privileged containers and the sch_netem module; plain
# `docker run`, no compose.
set -euo pipefail

BIN="$(cd "${1:?binaries dir}" && pwd)"
OUT="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUST="$HERE/../rust"

IUPF_DELAY_CORE_IMAGE="${IUPF_DELAY_CORE_IMAGE:-nextgcore-core:latest}"
IUPF_DELAY_SMF_IMAGE=nextgcore-rust/smf:iupf-delay
IUPF_DELAY_UPF_IMAGE=nextgcore-rust/upf:iupf-delay
IUPF_DELAY_ECHO_HOLD_MS="${ECHO_HOLD_MS:-40}"
IUPF_DELAY_N9_MS="${N9_MS:-15}"
IUPF_DELAY_TOLERANCE_MS="${TOLERANCE_MS:-20}"
# The N9 delay tc netem actually adds; the negative control sets it to 0 and
# expects the run to fail, because the PSA's N9 part is then missing.
IUPF_DELAY_NETEM_N9_MS="${NETEM_N9_MS:-$IUPF_DELAY_N9_MS}"
IUPF_DELAY_HARNESS_DIR="$OUT/harness"

for b in nextgcore-smfd nextgcore-upfd iupf-delay-harness; do
  test -x "$BIN/$b" || { echo "missing $BIN/$b" >&2; exit 2; }
done
mkdir -p "$IUPF_DELAY_HARNESS_DIR"
cp "$BIN/iupf-delay-harness" "$IUPF_DELAY_HARNESS_DIR/"

docker image inspect "$IUPF_DELAY_CORE_IMAGE" >/dev/null 2>&1 ||
  docker build -q -f "$RUST/Dockerfile.core" -t "$IUPF_DELAY_CORE_IMAGE" "$RUST" >/dev/null
ctx="$OUT/image-context"
mkdir -p "$ctx/binaries"
cp "$BIN/nextgcore-smfd" "$BIN/nextgcore-upfd" "$ctx/binaries/"
for nf in smf upf; do
  docker build -q -f "$RUST/Dockerfile.nf" --build-arg CORE_IMAGE="$IUPF_DELAY_CORE_IMAGE" \
    --build-arg NF_NAME="nextgcore-${nf}d" -t "nextgcore-rust/${nf}:iupf-delay" "$ctx" >/dev/null
done

NET=nextg-iupf-delay
SMF=172.29.22.4 PSA=172.29.22.7 IUPF=172.29.22.8 HARNESS=172.29.22.20
names=(iupf-delay-harness iupf-delay-smf iupf-delay-iupf iupf-delay-psa)
cleanup() {
  for c in "${names[@]}"; do
    docker logs "$c" > "$OUT/${c#iupf-delay-}.log" 2>&1 || true
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create --subnet 172.29.22.0/24 "$NET" >/dev/null

# A UPF: tc netem delays its packets to the other UPF (N9) by N9_MS, then the
# REAL upfd starts with GTP-U path (GPQM) and QoS flow (QFQM) monitoring.
upf() { # <name> <own ip> <the other UPF's ip> <tun ip>
  docker run -d --name "iupf-delay-$1" --network "$NET" --ip "$2" \
    --privileged --user root --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e RUST_LOG=info \
    --entrypoint /bin/sh "$IUPF_DELAY_UPF_IMAGE" -c "
      tc qdisc add dev eth0 root handle 1: prio &&
      tc qdisc add dev eth0 parent 1:3 handle 30: netem delay ${IUPF_DELAY_NETEM_N9_MS}ms &&
      tc filter add dev eth0 parent 1:0 protocol ip u32 match ip dst $3/32 flowid 1:3 &&
      exec nextgcore-upfd --pfcp-addr $2 --gtpu-addr $2 --pfcp-allowed-peers $SMF \
        --tun-ip $4 --tun-prefix 16 \
        --gtpu-path-qos-monitoring --gtpu-path-qos-probe-interval-ms 200 \
        --qos-flow-monitoring --qos-flow-monitoring-probe-interval-ms 200 -e info" >/dev/null
}
upf psa "$PSA" "$IUPF" 10.45.0.1
upf iupf "$IUPF" "$PSA" 10.46.0.1

# The REAL smfd: the PSA is UPF_PFCP_ADDR, the I-UPF is smf.yaml's
# `intermediate_upf`; a private network of stand-ins, so cleartext h2c.
docker run -d --name iupf-delay-smf --network "$NET" --ip "$SMF" \
  -e RUST_LOG=info -e NEXTGCORE_SBI_PROFILE=dev \
  -e SMF_PFCP_ADDR="$SMF" -e UPF_PFCP_ADDR="$PSA" -e UPF_PFCP_PORT=8805 \
  -e PCF_URI="http://$HARNESS:7777" \
  -v "$HERE/smf.yaml:/etc/nextgcore/smf.yaml:ro" \
  "$IUPF_DELAY_SMF_IMAGE" -c /etc/nextgcore/smf.yaml >/dev/null

set +e
docker run --name iupf-delay-harness --network "$NET" --ip "$HARNESS" \
  -e RUST_LOG=info -e NEXTGCORE_SBI_PROFILE=dev \
  -v "$IUPF_DELAY_HARNESS_DIR:/harness:ro" --entrypoint /harness/iupf-delay-harness \
  "$IUPF_DELAY_CORE_IMAGE" \
  --smf "$SMF:7777" --pcf "$HARNESS:7777" --gnb "$HARNESS" --iupf-n3 "$IUPF" \
  --echo-hold-ms "$IUPF_DELAY_ECHO_HOLD_MS" --n9-ms "$IUPF_DELAY_N9_MS" \
  --ran-dl-ms 2 --ran-ul-ms 3 --tolerance-ms "$IUPF_DELAY_TOLERANCE_MS" --timeout-s 90 \
  > "$OUT/harness.out" 2>&1
rc=$?
set -e
grep -E '^(RESULT|PASS|FAIL)' "$OUT/harness.out" > "$OUT/results.txt" || true
cat "$OUT/results.txt"
if [ "$rc" -ne 0 ]; then
  echo "::error::the I-UPF per-flow delay run failed (harness exit $rc); logs in $OUT" >&2
  tail -n 40 "$OUT/harness.out" >&2
  exit 1
fi
grep -q '^PASS' "$OUT/results.txt"
