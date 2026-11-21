#!/usr/bin/env bash
# #2222: the nightly real-binary run of #2208's per-flow delay through an I-UPF.
#
# The REAL smfd and two REAL upfd binaries (a PSA and an I-UPF, each in a
# container with NET_ADMIN and a TUN device), and one harness process standing in
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
# shell's PID; digits only), NET_OCTET (derived from RUN_ID; 1-254),
# STALE_AFTER_S (3600), LEASE_S (3600; keep both above the longest run),
# SWEEP_ONLY (1: take the lease, sweep, exit), PAUSE_AFTER_LEASE_S (0; a test
# hook that holds the run in its pre-build window), CLEAN_UNSTAMPED (1: remove
# labelled resources that have no `started` label, then exit).
#
# Usage: run.sh <dir with nextgcore-smfd, nextgcore-upfd, iupf-delay-harness> <out-dir>
# Needs docker and the sch_netem module; plain `docker run`, no compose.
#
# Isolation and cleanup. Each run has its own container names, network, subnet
# and image tags (RUN_ID), and a subnet already taken refuses the run. Every
# container, network and image carries nextg.iupf-delay.run=<RUN_ID> and
# nextg.iupf-delay.started=<epoch>, the time this invocation began.
#   - The lease (R43 on #2275). The first thing a run does, before any build,
#     is start a small labelled container, iupf-delay-<RUN_ID>-lease, that
#     sleeps LEASE_S. It is the run's lock and its liveness signal: a second
#     start with the same RUN_ID hits the name clash and refuses (exit 2)
#     without touching anything. A run is live while its lease or its harness
#     runs. Cleanup on exit removes only this invocation's resources (run and
#     started labels both), lease included. A SIGKILLed run's lease ends after
#     LEASE_S and removes itself (--rm).
#   - The sweep. At start, every other run that is not live and whose newest
#     `started` is older than STALE_AFTER_S is removed: a killed run's
#     leftovers. Build timestamps are never read, since a cached BuildKit
#     rebuild keeps the first build's .Created. The leftovers of an earlier
#     invocation with this RUN_ID go too, once the lease is held, unless its
#     harness still runs (then the run refuses).
#   - A resource with no `started` label counts as just started and is never
#     swept. Runs of the version before it (8e35337a) left such resources;
#     remove them once with `CLEAN_UNSTAMPED=1 run.sh . .`.
set -euo pipefail

BIN="$(cd "${1:?binaries dir}" && pwd)"
OUT="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUST="$HERE/../rust"

RUN_ID="${RUN_ID:-$$}"
if ! [[ $RUN_ID =~ ^[0-9]+$ ]]; then
  echo "RUN_ID must be digits only (it names resources and picks the subnet): '$RUN_ID'" >&2
  exit 2
fi
# 10# so a leading zero is not read as octal.
OCTET="${NET_OCTET:-$((10#$RUN_ID % 200 + 30))}"
if ! [[ $OCTET =~ ^[0-9]+$ ]] || [ "$((10#$OCTET))" -lt 1 ] || [ "$((10#$OCTET))" -gt 254 ]; then
  echo "NET_OCTET must be 1-254: '$OCTET'" >&2
  exit 2
fi
OCTET=$((10#$OCTET))
STALE_AFTER_S="${STALE_AFTER_S:-3600}"
LABEL=nextg.iupf-delay.run
STARTED_LABEL=nextg.iupf-delay.started
LEASE_LABEL=nextg.iupf-delay.lease
LEASE_S="${LEASE_S:-3600}"
STARTED="$(date +%s)"
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

# The ids of the labelled resources of one kind matching the given filters.
ids_of() { # <container|network|image> [--filter ...]...
  local kind=$1
  shift
  case $kind in
    container) docker ps -aq "$@" ;;
    network) docker network ls -q "$@" ;;
    image) docker images -q "$@" | sort -u ;;
  esac
}
labels_fmt() { [ "$1" = network ] && echo .Labels || echo .Config.Labels; }
# Remove the given resources of each kind: containers, then networks, then images.
remove_matching() { # [--filter ...]...
  local kind ids=()
  for kind in container network image; do
    mapfile -t ids < <(ids_of "$kind" "$@")
    [ "${#ids[@]}" -eq 0 ] && continue
    case $kind in
      container) docker rm -f "${ids[@]}" >/dev/null 2>&1 || true ;;
      network) docker network rm "${ids[@]}" >/dev/null 2>&1 || true ;;
      image) docker image rm -f "${ids[@]}" >/dev/null 2>&1 || true ;;
    esac
  done
}
remove_run() { remove_matching --filter "label=$LABEL=$1"; } # every invocation of <run>
# Every labelled resource as "<kind> <id> <run> <started>", one per line.
labelled() {
  local kind fmt ids id
  for kind in container network image; do
    fmt="$(labels_fmt "$kind")"
    mapfile -t ids < <(ids_of "$kind" --filter "label=$LABEL")
    # ${a[@]+...}: an empty array under set -u in bash < 4.4.
    for id in ${ids[@]+"${ids[@]}"}; do
      docker "$kind" inspect -f \
        "$kind $id {{index $fmt \"$LABEL\"}} {{index $fmt \"$STARTED_LABEL\"}}" "$id" \
        2>/dev/null || true
    done
  done
}
# `labelled` lines with containers first, then networks, then images.
in_removal_order() {
  awk '{ print ($1 == "container" ? 1 : $1 == "network" ? 2 : 3), $0 }' | sort -n -k1,1 | cut -d' ' -f2-
}
running() { # <run> <container suffix>
  [ -n "$(docker ps -q --filter "label=$LABEL=$1" --filter "name=^iupf-delay-$1-$2\$")" ]
}
live() { running "$1" lease || running "$1" harness; } # <run>
# Not live, and its newest `started` is older than STALE_AFTER_S. A missing or
# non-numeric `started` counts as now, so such a resource is never swept.
is_stale() { # <run>
  local newest=0 now kind id run started
  live "$1" && return 1
  now="$(date +%s)"
  while read -r kind id run started; do
    [ "$run" = "$1" ] || continue
    [[ ${started:-} =~ ^[0-9]+$ ]] || started=$now
    [ "$started" -gt "$newest" ] && newest=$started
  done < <(labelled)
  # Nothing left (it finished between the listing and now): nothing to sweep.
  [ "$newest" -gt 0 ] || return 1
  [ $((now - newest)) -gt "$STALE_AFTER_S" ]
}
sweep_stale() {
  local run
  for run in $(labelled | cut -d' ' -f3 | sort -u); do
    if ! [[ $run =~ ^[0-9]+$ ]] || [ "$run" = "$RUN_ID" ]; then
      continue
    fi
    if is_stale "$run"; then
      echo "sweeping stale iupf-delay run $run" >&2
      remove_run "$run"
    fi
  done
}

if [ "${CLEAN_UNSTAMPED:-0}" = 1 ]; then
  while read -r kind id run started; do
    if [ -z "${started:-}" ] || [ "$started" = "<no value>" ]; then
      echo "removing unstamped $kind $id (run $run)" >&2
      case $kind in
        container) docker rm -f "$id" >/dev/null ;;
        network) docker network rm "$id" >/dev/null ;;
        image) docker image rm -f "$id" >/dev/null ;;
      esac
    fi
  done < <(labelled | in_removal_order)
  exit 0
fi

for b in nextgcore-smfd nextgcore-upfd iupf-delay-harness; do
  test -x "$BIN/$b" || { echo "missing $BIN/$b" >&2; exit 2; }
done
mkdir -p "$OUT/harness"
cp "$BIN/iupf-delay-harness" "$OUT/harness/"

# The shared base image, unlabelled: no sweep ever touches it.
docker image inspect "$CORE_IMAGE" >/dev/null 2>&1 ||
  docker build -q -f "$RUST/Dockerfile.core" -t "$CORE_IMAGE" "$RUST" >/dev/null
ctx="$OUT/image-context"
mkdir -p "$ctx/binaries"
cp "$BIN/nextgcore-smfd" "$BIN/nextgcore-upfd" "$ctx/binaries/"

# The lease: this run's lock and liveness signal, before anything else.
docker run -d --rm --name "iupf-delay-$RUN_ID-lease" \
  --label "$LABEL=$RUN_ID" --label "$STARTED_LABEL=$STARTED" --label "$LEASE_LABEL=1" \
  --entrypoint sleep "$CORE_IMAGE" "$LEASE_S" >/dev/null 2>&1 || {
  echo "run $RUN_ID has live resources (its lease is held); refusing to start (pick another RUN_ID)" >&2
  exit 2
}
names=(harness smf iupf psa)
cleanup() {
  for c in "${names[@]}"; do
    docker logs "iupf-delay-$RUN_ID-$c" > "$OUT/$c.log" 2>&1 || true
  done
  # This invocation's resources only, lease included.
  remove_matching --filter "label=$LABEL=$RUN_ID" --filter "label=$STARTED_LABEL=$STARTED"
}
trap cleanup EXIT

# An earlier invocation with this RUN_ID: its lease is gone (we hold the name),
# so it is dead unless its harness still runs.
if labelled | awk -v r="$RUN_ID" -v s="$STARTED" '$3 == r && $4 != s' | grep -q .; then
  if running "$RUN_ID" harness; then
    echo "run $RUN_ID has live resources (its harness runs); refusing to start (pick another RUN_ID)" >&2
    exit 2
  fi
  echo "removing the leftovers of an earlier iupf-delay run $RUN_ID" >&2
  while read -r kind id _ _; do
    case $kind in
      container) docker rm -f "$id" >/dev/null 2>&1 || true ;;
      network) docker network rm "$id" >/dev/null 2>&1 || true ;;
      image) docker image rm -f "$id" >/dev/null 2>&1 || true ;;
    esac
  done < <(labelled | awk -v r="$RUN_ID" -v s="$STARTED" '$3 == r && $4 != s' | in_removal_order)
fi
sweep_stale
[ "${SWEEP_ONLY:-0}" != 1 ] || exit 0
sleep "${PAUSE_AFTER_LEASE_S:-0}"

docker build -q -f "$RUST/Dockerfile.nf" --build-arg CORE_IMAGE="$CORE_IMAGE" \
  --label "$LABEL=$RUN_ID" --label "$STARTED_LABEL=$STARTED" \
  --build-arg NF_NAME=nextgcore-smfd -t "$SMF_IMAGE" "$ctx" >/dev/null
docker build -q -f "$RUST/Dockerfile.nf" --build-arg CORE_IMAGE="$CORE_IMAGE" \
  --label "$LABEL=$RUN_ID" --label "$STARTED_LABEL=$STARTED" \
  --build-arg NF_NAME=nextgcore-upfd -t "$UPF_IMAGE" "$ctx" >/dev/null

NET="nextg-iupf-delay-$RUN_ID"
P="172.29.$OCTET"
SMF=$P.4 PSA=$P.7 IUPF=$P.8 HARNESS=$P.20
# The SMF's YAML with this run's addresses.
sed "s/172\.29\.22\./$P./g" "$HERE/smf.yaml" > "$OUT/smf.yaml"
docker network create --label "$LABEL=$RUN_ID" --label "$STARTED_LABEL=$STARTED" --subnet "$P.0/24" "$NET" >/dev/null || {
  echo "cannot create $NET on $P.0/24 (taken?); set NET_OCTET or RUN_ID" >&2
  exit 2
}

# A UPF: tc netem delays its packets to the other UPF (N9) by NETEM_N9_MS, then
# the REAL upfd starts with GTP-U path (GPQM) and QoS flow (QFQM) monitoring.
# NET_ADMIN for tc and the TUN, the TUN device itself; not privileged.
upf() { # <name> <own ip> <the other UPF's ip> <tun ip>
  docker run -d --name "iupf-delay-$RUN_ID-$1" --label "$LABEL=$RUN_ID" --label "$STARTED_LABEL=$STARTED" --network "$NET" --ip "$2" \
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
docker run -d --name "iupf-delay-$RUN_ID-smf" --label "$LABEL=$RUN_ID" --label "$STARTED_LABEL=$STARTED" --network "$NET" --ip "$SMF" \
  -e RUST_LOG=info -e NEXTGCORE_SBI_PROFILE=dev \
  -e SMF_PFCP_ADDR="$SMF" -e UPF_PFCP_ADDR="$PSA" -e UPF_PFCP_PORT=8805 \
  -e PCF_URI="http://$HARNESS:7777" \
  -v "$OUT/smf.yaml:/etc/nextgcore/smf.yaml:ro" \
  "$SMF_IMAGE" -c /etc/nextgcore/smf.yaml >/dev/null

set +e
docker run --name "iupf-delay-$RUN_ID-harness" --label "$LABEL=$RUN_ID" --label "$STARTED_LABEL=$STARTED" --network "$NET" --ip "$HARNESS" \
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
