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
# TOLERANCE_MS must stay below min(N3, N9) (R43 on #2264): with a wider band
# an N9 part counted twice, or N3 or N9 reported as a round trip, still lands
# inside it. The nightly job also checks the pass arm's DL minus the no-N9
# arm's DL against N9 (check-n9.sh).
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
# injected), TOLERANCE_MS (8; below min(ECHO_HOLD_MS/2, N9_MS)), RUN_ID (this
# shell's PID), NET_OCTET (derived from RUN_ID).
#
# Usage: run.sh <dir with nextgcore-smfd, nextgcore-upfd, iupf-delay-harness> <out-dir>
# Needs docker and the sch_netem module; plain `docker run`, no compose. Each run
# has its own container names, network, subnet and image tags (RUN_ID), so two
# runs on one host do not clobber each other; a subnet already taken refuses the
# run rather than reusing it.
set -euo pipefail

BIN="$(cd "${1:?binaries dir}" && pwd)"
OUT="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUST="$HERE/../rust"

RUN_ID="${RUN_ID:-$$}"
OCTET="${NET_OCTET:-$((RUN_ID % 200 + 30))}"
CORE_IMAGE="${IUPF_DELAY_CORE_IMAGE:-nextgcore-core:latest}"
SMF_IMAGE="nextgcore-rust/smf:iupf-delay-$RUN_ID"
UPF_IMAGE="nextgcore-rust/upf:iupf-delay-$RUN_ID"
ECHO_HOLD_MS="${ECHO_HOLD_MS:-40}"
N9_MS="${N9_MS:-15}"
TOLERANCE_MS="${TOLERANCE_MS:-8}"
# The N9 delay tc netem actually adds; the negative control sets it to 0 and
# expects the run to fail, because the PSA's N9 part is then missing.
NETEM_N9_MS="${NETEM_N9_MS:-$N9_MS}"
N3_MS=$((ECHO_HOLD_MS / 2))
if [ "$TOLERANCE_MS" -ge "$N9_MS" ] || [ "$TOLERANCE_MS" -ge "$N3_MS" ]; then
  echo "TOLERANCE_MS ($TOLERANCE_MS) must be below N3 ($N3_MS) and N9 ($N9_MS)" >&2
  exit 2
fi

for b in nextgcore-smfd nextgcore-upfd iupf-delay-harness; do
  test -x "$BIN/$b" || { echo "missing $BIN/$b" >&2; exit 2; }
done
mkdir -p "$OUT/harness"
cp "$BIN/iupf-delay-harness" "$OUT/harness/"

docker image inspect "$CORE_IMAGE" >/dev/null 2>&1 ||
  docker build -q -f "$RUST/Dockerfile.core" -t "$CORE_IMAGE" "$RUST" >/dev/null
ctx="$OUT/image-context"
mkdir -p "$ctx/binaries"
cp "$BIN/nextgcore-smfd" "$BIN/nextgcore-upfd" "$ctx/binaries/"
docker build -q -f "$RUST/Dockerfile.nf" --build-arg CORE_IMAGE="$CORE_IMAGE" \
  --build-arg NF_NAME=nextgcore-smfd -t "$SMF_IMAGE" "$ctx" >/dev/null
docker build -q -f "$RUST/Dockerfile.nf" --build-arg CORE_IMAGE="$CORE_IMAGE" \
  --build-arg NF_NAME=nextgcore-upfd -t "$UPF_IMAGE" "$ctx" >/dev/null

NET="nextg-iupf-delay-$RUN_ID"
P="172.29.$OCTET"
SMF=$P.4 PSA=$P.7 IUPF=$P.8 HARNESS=$P.20
# The SMF's YAML with this run's addresses.
sed "s/172\.29\.22\./$P./g" "$HERE/smf.yaml" > "$OUT/smf.yaml"
names=(harness smf iupf psa)
cleanup() {
  for c in "${names[@]}"; do
    docker logs "iupf-delay-$RUN_ID-$c" > "$OUT/$c.log" 2>&1 || true
    docker rm -f "iupf-delay-$RUN_ID-$c" >/dev/null 2>&1 || true
  done
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker image rm "$SMF_IMAGE" "$UPF_IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network create --subnet "$P.0/24" "$NET" >/dev/null || {
  echo "cannot create $NET on $P.0/24 (taken?); set NET_OCTET or RUN_ID" >&2
  exit 2
}

# A UPF: tc netem delays its packets to the other UPF (N9) by NETEM_N9_MS, then
# the REAL upfd starts with GTP-U path (GPQM) and QoS flow (QFQM) monitoring.
# NET_ADMIN for tc and the TUN, the TUN device itself; not privileged.
upf() { # <name> <own ip> <the other UPF's ip> <tun ip>
  docker run -d --name "iupf-delay-$RUN_ID-$1" --network "$NET" --ip "$2" \
    --user root --cap-add NET_ADMIN --device /dev/net/tun \
    --sysctl net.ipv4.ip_forward=1 -e RUST_LOG=info \
    --entrypoint /bin/sh "$UPF_IMAGE" -c "
      tc qdisc add dev eth0 root handle 1: prio &&
      tc qdisc add dev eth0 parent 1:3 handle 30: netem delay ${NETEM_N9_MS}ms &&
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
docker run -d --name "iupf-delay-$RUN_ID-smf" --network "$NET" --ip "$SMF" \
  -e RUST_LOG=info -e NEXTGCORE_SBI_PROFILE=dev \
  -e SMF_PFCP_ADDR="$SMF" -e UPF_PFCP_ADDR="$PSA" -e UPF_PFCP_PORT=8805 \
  -e PCF_URI="http://$HARNESS:7777" \
  -v "$OUT/smf.yaml:/etc/nextgcore/smf.yaml:ro" \
  "$SMF_IMAGE" -c /etc/nextgcore/smf.yaml >/dev/null

set +e
docker run --name "iupf-delay-$RUN_ID-harness" --network "$NET" --ip "$HARNESS" \
  -e RUST_LOG=info -e NEXTGCORE_SBI_PROFILE=dev \
  -v "$OUT/harness:/harness:ro" --entrypoint /harness/iupf-delay-harness \
  "$CORE_IMAGE" \
  --smf "$SMF:7777" --pcf "$HARNESS:7777" --gnb "$HARNESS" --iupf-n3 "$IUPF" \
  --echo-hold-ms "$ECHO_HOLD_MS" --n9-ms "$N9_MS" \
  --ran-dl-ms 2 --ran-ul-ms 3 --tolerance-ms "$TOLERANCE_MS" --timeout-s 90 \
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
