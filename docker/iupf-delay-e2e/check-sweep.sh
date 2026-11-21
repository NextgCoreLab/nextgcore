#!/usr/bin/env bash
# #2275 R43: the stale sweep never removes a live run, and RUN_ID is a lock.
#   1. Warm the build cache (run W), so A's images carry W's .Created.
#   2. A; once A's SMF is up, B with STALE_AFTER_S=30 (R43's first scenario).
#   3. D with PAUSE_AFTER_LEASE_S: held after taking its lease, before any
#      build. While D is in that window, deterministically, a sweep-only C with
#      STALE_AFTER_S=0 must spare both D (lease only) and A (R43's second).
#      D runs with LEASE_S=8 and is held 30 s, so its lease outlives LEASE_S
#      only by being renewed; a second STALE_AFTER_S=0 sweep after that spares
#      it too.
#   4. A second start with D's RUN_ID, while D is still held, refuses (exit 2):
#      the lease is the lock.
#   5. Two starts with one fresh RUN_ID at once: exactly one refuses, the other
#      passes.
#   6. A, B and D pass.
#   7. K is SIGKILLed with a short lease. While its lease runs a STALE_AFTER_S=0
#      sweep spares it; once the lease has ended, the next sweep removes it.
#   8. Nothing labelled is left.
# Usage: check-sweep.sh <binaries dir> <out dir>
set -euo pipefail
BIN="${1:?binaries dir}"
OUT="$(mkdir -p "${2:?out dir}" && cd "$2" && pwd)"
RUN="$(cd "$(dirname "$0")" && pwd)/run.sh"
LABEL=nextg.iupf-delay.run
base=$(((RANDOM % 900 + 100) * 10))
W=$((base + 1)) A=$((base + 2)) B=$((base + 3)) C=$((base + 4)) D=$((base + 5))
E=$((base + 6)) K=$((base + 7)) S=$((base + 8))
fail() { echo "check-sweep: FAIL: $*" >&2; exit 1; }
running() { [ -n "$(docker ps -q --filter "label=$LABEL=$1" --filter "name=^iupf-delay-$1-$2\$")" ]; }
exists() { [ -n "$(docker ps -aq --filter "label=$LABEL=$1")" ]; }
wait_for() { # <run> <container> <seconds>
  local i
  for ((i = 0; i < $3 * 2; i++)); do running "$1" "$2" && return 0; sleep 0.5; done
  return 1
}
swept() { grep -q "sweeping stale iupf-delay run $1\$" "$OUT"/*.log; }

echo "1. warm the build cache (run $W)"
RUN_ID=$W bash "$RUN" "$BIN" "$OUT/w" > "$OUT/w.log" 2>&1 || fail "the warm run failed"

echo "2. A ($A), then B ($B, STALE_AFTER_S=30) once A's SMF is up"
RUN_ID=$A bash "$RUN" "$BIN" "$OUT/a" > "$OUT/a.log" 2>&1 & a=$!
wait_for "$A" smf 120 || fail "A never started its SMF"
RUN_ID=$B STALE_AFTER_S=30 bash "$RUN" "$BIN" "$OUT/b" > "$OUT/b.log" 2>&1 & b=$!

echo "3. D ($D) held before its builds; a STALE_AFTER_S=0 sweep (C, $C) meanwhile"
RUN_ID=$D LEASE_S=8 PAUSE_AFTER_LEASE_S=30 bash "$RUN" "$BIN" "$OUT/d" > "$OUT/d.log" 2>&1 & d=$!
wait_for "$D" lease 60 || fail "D never took its lease"
running "$D" harness && fail "D is past its build window already"
[ -z "$(docker images -q --filter "label=$LABEL=$D")" ] || fail "D has built already"
RUN_ID=$C STALE_AFTER_S=0 SWEEP_ONLY=1 bash "$RUN" "$BIN" "$OUT/c" > "$OUT/c.log" 2>&1 ||
  fail "the sweep-only run C failed"
swept "$D" && fail "C swept D in its build window"
swept "$A" && fail "C swept live A"
sleep 12
running "$D" lease || fail "D's lease was not renewed past LEASE_S=8"
RUN_ID=$C STALE_AFTER_S=0 SWEEP_ONLY=1 bash "$RUN" "$BIN" "$OUT/c2" > "$OUT/c2.log" 2>&1 ||
  fail "the second sweep-only run C failed"
swept "$D" && fail "a sweep after LEASE_S removed renewed D"

echo "4. a second start with D's RUN_ID ($D) refuses while D is held"
running "$D" lease || fail "D's lease ended before step 4"
set +e
RUN_ID=$D bash "$RUN" "$BIN" "$OUT/d2" > "$OUT/d2.log" 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ] || ! grep -q "has live resources" "$OUT/d2.log"; then
  fail "a second start of $D exited $rc, not 2 with 'has live resources'"
fi
running "$D" lease || fail "the refused start removed D's lease"

echo "5. two starts with RUN_ID $E at once: one refuses, one passes"
set +e
RUN_ID=$E PAUSE_AFTER_LEASE_S=3 bash "$RUN" "$BIN" "$OUT/e1" > "$OUT/e1.log" 2>&1 & e1=$!
RUN_ID=$E PAUSE_AFTER_LEASE_S=3 bash "$RUN" "$BIN" "$OUT/e2" > "$OUT/e2.log" 2>&1 & e2=$!
wait "$e1"; r1=$?
wait "$e2"; r2=$?
echo "6. A, B and D pass"
wait "$a"; ra=$?
wait "$b"; rb=$?
wait "$d"; rd=$?
set -e
case "$r1 $r2" in
  "0 2" | "2 0") ;;
  *) fail "the two starts of $E exited $r1 and $r2, not one 0 and one 2" ;;
esac
[ "$ra" -eq 0 ] || fail "A exited $ra (swept?)"
[ "$rb" -eq 0 ] || fail "B exited $rb"
[ "$rd" -eq 0 ] || fail "D exited $rd (swept in its build window?)"
swept "$A" && fail "A was swept"
swept "$D" && fail "D was swept"

echo "7. K ($K, LEASE_S=15) SIGKILLed: spared while its lease runs, then swept"
RUN_ID=$K LEASE_S=15 bash "$RUN" "$BIN" "$OUT/k" > "$OUT/k.log" 2>&1 & k=$!
wait_for "$K" smf 120 || fail "K never started its SMF"
kill -9 "$k"
wait "$k" 2>/dev/null || true
running "$K" lease || fail "K's lease ended too soon for this check"
RUN_ID=$S STALE_AFTER_S=0 SWEEP_ONLY=1 bash "$RUN" "$BIN" "$OUT/s1" > "$OUT/s1.log" 2>&1 ||
  fail "the first sweep of K failed"
swept "$K" && fail "K was swept while its lease ran"
exists "$K" || fail "K left nothing"
for ((i = 0; i < 120; i++)); do
  running "$K" lease || running "$K" harness || break
  sleep 0.5
done
RUN_ID=$S STALE_AFTER_S=0 SWEEP_ONLY=1 bash "$RUN" "$BIN" "$OUT/s2" > "$OUT/s2.log" 2>&1 ||
  fail "the second sweep of K failed"
grep -q "sweeping stale iupf-delay run $K\$" "$OUT/s2.log" || fail "K was not swept after its lease"

echo "8. nothing labelled is left"
left="$(docker ps -aq --filter "label=$LABEL"; docker network ls -q --filter "label=$LABEL"; docker images -q --filter "label=$LABEL")"
[ -z "$left" ] || fail "labelled resources left: $left"
echo "check-sweep: PASS"
