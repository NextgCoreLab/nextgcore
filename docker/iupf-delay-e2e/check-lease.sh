#!/usr/bin/env bash
# #2286 R43: the lease survives a hammered heartbeat, and run.sh leaves nothing
# holding a caller's pipe.
#   1. A run with LEASE_S=8 and RENEW_EVERY_S=0 (its renewer writes back to
#      back) is held HOLD_S before its builds. Meanwhile three more writers run
#      run.sh's own heartbeat write (HB_WRITE, read from run.sh) back to back
#      against the lease. Its lease must be running every second throughout.
#      A torn read used to abort the lease's shell within seconds.
#   2. `$(SWEEP_ONLY=1 run.sh)` with the default lease returns within 15 s.
#      The renewer's in-flight `sleep LEASE_S/4` (30 s) used to keep the pipe
#      open after run.sh had exited.
# Usage: check-lease.sh <binaries dir> <out dir>
set -euo pipefail
BIN="${1:?binaries dir}"
OUT="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
RUN="$(cd "$(dirname "$0")" && pwd)/run.sh"
LABEL=nextg.iupf-delay.run
HOLD_S="${HOLD_S:-60}"
base=$(((RANDOM % 900 + 100) * 10))
L=$((base + 1)) P=$((base + 2))
fail() { echo "check-lease: FAIL: $*" >&2; exit 1; }
running() { [ -n "$(docker ps -q --filter "label=$LABEL=$1" --filter "name=^iupf-delay-$1-$2\$")" ]; }
# shellcheck disable=SC2016 # sed program
hb_write="$(sed -n "s/^HB_WRITE='\(.*\)'\$/\1/p" "$RUN")"
[ -n "$hb_write" ] || fail "no HB_WRITE in run.sh"

echo "1. run $L (LEASE_S=8, RENEW_EVERY_S=0), held ${HOLD_S}s with 3 more writers"
RUN_ID=$L LEASE_S=8 RENEW_EVERY_S=0 PAUSE_AFTER_LEASE_S=$HOLD_S \
  bash "$RUN" "$BIN" "$OUT/l" > "$OUT/l.log" 2>&1 & l=$!
for ((i = 0; i < 120; i++)); do running "$L" lease && break; sleep 0.5; done
running "$L" lease || fail "run $L never took its lease"
writers=()
for _ in 1 2 3; do
  (
    end=$((SECONDS + HOLD_S - 5))
    while [ "$SECONDS" -lt "$end" ]; do
      docker exec "iupf-delay-$L-lease" sh -c "$hb_write" >/dev/null 2>&1 || true
    done
  ) &
  writers+=($!)
done
for ((t = 0; t < HOLD_S - 5; t++)); do
  running "$L" lease || fail "the lease of live run $L died after ${t}s of renewals"
  sleep 1
done
wait "${writers[@]}"
wait "$l" || fail "run $L exited $?"

echo "2. \$(run.sh) returns promptly"
t0=$SECONDS
out="$(RUN_ID=$P SWEEP_ONLY=1 bash "$RUN" "$BIN" "$OUT/p" 2>&1)" || fail "the sweep-only run failed: $out"
[ $((SECONDS - t0)) -lt 15 ] || fail "\$(run.sh) took $((SECONDS - t0))s"

left="$(docker ps -aq --filter "label=$LABEL"; docker network ls -q --filter "label=$LABEL"; docker images -q --filter "label=$LABEL")"
[ -z "$left" ] || fail "labelled resources left: $left"
echo "check-lease: PASS"
