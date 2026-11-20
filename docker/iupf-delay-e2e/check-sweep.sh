#!/usr/bin/env bash
# #2275 R43: the stale sweep must never remove a live run. R43's scenario: a run
# that warms the build cache, then run A, then run B started while A is up with
# a small STALE_AFTER_S. A cached rebuild gives A's images the warm run's
# .Created, which the first sweep read as "stale" and so killed A (exit 137).
# Also checked:
#   - a sweep with STALE_AFTER_S=0 while A's harness runs spares A;
#   - a second run with A's RUN_ID refuses (exit 2) and leaves A alone;
#   - a SIGKILLed run is swept once its harness has exited;
#   - nothing labelled is left at the end.
# Usage: check-sweep.sh <binaries dir> <out dir>
set -euo pipefail
BIN="${1:?binaries dir}"
OUT="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
RUN="$(cd "$(dirname "$0")" && pwd)/run.sh"
LABEL=nextg.iupf-delay.run
base=$(( ($$ % 90 + 10) * 100 ))
W=$((base + 1)) A=$((base + 2)) B=$((base + 3)) C=$((base + 4)) K=$((base + 5))
fail() { echo "check-sweep: FAIL: $*" >&2; exit 1; }
alive() { [ -n "$(docker ps -q --filter "label=$LABEL=$1" --filter "name=^iupf-delay-$1-$2\$")" ]; }
wait_for() { # <run> <container> <seconds>
  local i
  for ((i = 0; i < $3 * 2; i++)); do alive "$1" "$2" && return 0; sleep 0.5; done
  return 1
}

echo "warm the build cache (run $W)"
RUN_ID=$W bash "$RUN" "$BIN" "$OUT/warm" > "$OUT/warm.log" 2>&1 || fail "the warm run failed"

echo "run A ($A), then B ($B, STALE_AFTER_S=30) once A's SMF is up"
RUN_ID=$A bash "$RUN" "$BIN" "$OUT/a" > "$OUT/a.log" 2>&1 & a=$!
wait_for "$A" smf 120 || fail "A never started its SMF"
RUN_ID=$B STALE_AFTER_S=30 bash "$RUN" "$BIN" "$OUT/b" > "$OUT/b.log" 2>&1 & b=$!
wait_for "$A" harness 120 || fail "A never started its harness"
echo "sweep only (run $C, STALE_AFTER_S=0) while A's harness runs"
RUN_ID=$C STALE_AFTER_S=0 SWEEP_ONLY=1 bash "$RUN" "$BIN" "$OUT/c" > "$OUT/c.log" 2>&1 ||
  fail "the sweep-only run failed"
echo "a second run with A's RUN_ID ($A) must refuse"
set +e
RUN_ID=$A bash "$RUN" "$BIN" "$OUT/a2" > "$OUT/a2.log" 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ] || ! grep -q "has live resources" "$OUT/a2.log"; then
  fail "a second run $A exited $rc, not 2 with 'has live resources'"
fi
set +e
wait "$a"; ra=$?
wait "$b"; rb=$?
set -e
! grep -q "sweeping stale iupf-delay run $A" "$OUT/b.log" "$OUT/c.log" || fail "A was swept while live"
[ "$ra" -eq 0 ] || fail "A exited $ra (killed by a sweep?)"
[ "$rb" -eq 0 ] || fail "B exited $rb"

echo "a SIGKILLed run ($K) is swept once its harness exits"
RUN_ID=$K bash "$RUN" "$BIN" "$OUT/k" > "$OUT/k.log" 2>&1 & k=$!
wait_for "$K" smf 120 || fail "K never started its SMF"
kill -9 "$k"
wait "$k" 2>/dev/null || true
# Its harness may already be on its way up (docker run follows the SMF at
# once); wait for it to appear, then to exit.
wait_for "$K" harness 10 || true
for ((i = 0; i < 240; i++)); do alive "$K" harness || break; sleep 0.5; done
[ -n "$(docker ps -aq --filter "label=$LABEL=$K")" ] || fail "K left nothing to sweep"
RUN_ID=$((base + 6)) STALE_AFTER_S=0 SWEEP_ONLY=1 bash "$RUN" "$BIN" "$OUT/s" > "$OUT/s.log" 2>&1 ||
  fail "the sweep of K failed"
grep -q "sweeping stale iupf-delay run $K" "$OUT/s.log" || fail "K was not swept"

left="$(docker ps -aq --filter "label=$LABEL"; docker network ls -q --filter "label=$LABEL"; docker images -q --filter "label=$LABEL")"
[ -z "$left" ] || fail "labelled resources left: $left"
echo "check-sweep: PASS (A and B passed while swept at; same RUN_ID refused; K swept)"
