#!/usr/bin/env bash
# Self-test of demo d440a-ai-paging's scenario checks (nextgsim#462), run by CI
# with the other overlays' test-scenario.sh. Needs bash and python3 with PyYAML,
# and nextgsim checked out beside nextgcore (CI does, for the renders).
#
#   1. Fixture parity: sim-grid.yaml, gnb-grid.yaml and seed.env are what gen.py
#      writes from nextgsim's config/demo-ai-paging/ (Service names, no demo
#      block, the route parked; module doc of gen.py). Positive control: a moved
#      waypoint in a copy of nextgsim's seed-1 UE fails the check.
#   2. The deployed UE route is parked at 86400 and is nextgsim's otherwise;
#      scenario.sh's unpark regex matches it exactly once.
#   3. analyze.py passes each arm's fixture (fixtures.py: real line formats) and
#      FAILS, naming the check, on every negative control. Every check name in
#      analyze.py fails in at least one control.
# Exit 0 when every case holds.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM="${NEXTGSIM_DIR:-${HERE}/../../../../../nextgsim}"
T="$(mktemp -d -t d440a-scenario-test-XXXXXX)"
trap 'rm -rf -- "${T}"' EXIT
bad=0
ok()  { echo "ok   $*"; }
nok() { echo "FAIL $*"; bad=1; }

# --- 1. parity ---------------------------------------------------------------------------
if python3 "${HERE}/gen.py" --check "${SIM}"; then ok "gen.py --check: the grid files match nextgsim"; else nok "gen.py --check"; fi
mkdir -p "${T}/sim/config"
# The control needs nextgsim's real files, then exactly one moved waypoint: a
# missing copy would fail gen.py --check for the wrong reason.
if cp -r "${SIM}/config/demo-ai-paging" "${T}/sim/config/" && python3 - "${T}/sim/config/demo-ai-paging/ue-seed-1.yaml" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s, n = re.subn(r"(?m)^(    - \{ x: )(-?\d+)", lambda m: m.group(1) + str(int(m.group(2)) + 1), s, count=1)
assert n == 1
open(p, "w").write(s)
PY
then
  if python3 "${HERE}/gen.py" --check "${T}/sim" 2>/dev/null; then nok "a moved waypoint passes gen.py --check"; else ok "a moved waypoint fails gen.py --check"; fi
else
  nok "cannot build the moved-waypoint control from ${SIM}/config/demo-ai-paging"
fi

# --- 2. the parked route -----------------------------------------------------------------
if python3 - "${HERE}/sim-grid.yaml" "${SIM}/config/demo-ai-paging/ue-seed-1.yaml" "${HERE}/seed.env" <<'PY'
import re, sys, yaml
cm = yaml.safe_load(open(sys.argv[1]))
ue_text = cm["data"]["ue.yaml"]
ue = yaml.safe_load(ue_text)
src = yaml.safe_load(open(sys.argv[2]))
env = dict(l.split("=", 1) for l in open(sys.argv[3]) if "=" in l and not l.startswith("#"))
assert ue["sim_route"]["start_after_secs"] == 86400
unparked, n = re.subn(r"(?m)^(\s*start_after_secs:)\s*86400\b.*$", r"\g<1> " + env["ROUTE_START_SECS"].strip(), ue_text)
assert n == 1, n
assert yaml.safe_load(unparked)["sim_route"] == src["sim_route"], "unparked route differs from nextgsim's"
PY
then ok "the route is parked, unparks to nextgsim's value, and is otherwise nextgsim's"; else nok "parked route"; fi

# --- 3. analyze.py -------------------------------------------------------------------------
run() {   # <mode> <mutation|-> <variant>: analyze.py's output
  local d="${T}/cap-$1-$2"
  rm -rf "${d}"
  python3 "${HERE}/fixtures.py" "${d}" "$1" "$([[ $2 == - ]] || echo "$2")" || return 2
  python3 "${HERE}/analyze.py" "${d}" "$1" "$3"
}
for mode in ct last-served lsq page-all off; do
  if out="$(run "${mode}" - none)"; then ok "${mode}: the fixture passes"; else nok "${mode}: the fixture fails: $(grep '^FAIL' <<<"${out}" | head -3)"; fi
done
FAILED_CHECKS=""
expect() {   # <mode> <mutation> <check that must fail> [variant]
  local out
  if out="$(run "$1" "$2" "${4:-none}")"; then
    nok "$1 + $2: passes"
  elif grep -q "^FAIL \[$3\]" <<<"${out}"; then
    ok "$1 + $2: fails at [$3]"
    FAILED_CHECKS+=" $3"
  else
    nok "$1 + $2: fails, but not at [$3]: $(grep '^FAIL' <<<"${out}" | head -2 | tr '\n' ' ')"
  fi
}
expect ct no-paged ue
expect ct empty-ue ue
expect ct no-base-scope amf
expect ct no-strategy amf-demo
expect ct no-demo-sent amf-demo
expect ct no-demo-answer amf-demo
expect ct no-recommendation serving
expect ct wrong-visited serving
expect ct targets-differ serving
expect lsq no-banner gnbs
expect ct no-grid gnbs
expect ct wrong-mode-banner gnbs
expect page-all page-all-recommends gnbs
expect off off-demo-line gnbs
expect ct metric-zero metrics
expect page-all page-all-metric metrics
expect ct no-ping upf
# The revert arm HOLDS only on a failure at exactly [amf] step 1 with every other
# check holding (R14 MAJOR on #1783): an unrelated failure must not pass for it.
revert_case() {   # <label> <want: holds|not> <mode> <mutation> [sed-script file-in-capture]
  local d="${T}/rev-$1" out rc
  rm -rf "${d}"
  python3 "${HERE}/fixtures.py" "${d}" "$3" "$4" || { nok "revert $1: fixture"; return; }
  if [[ $# -ge 6 ]]; then sed -i -E "$5" "${d}/$6"; fi
  out="$(python3 "${HERE}/analyze.py" "${d}" "$3" revert)"; rc=$?
  FAILED_CHECKS+=" $(grep -oE '^FAIL \[[a-z-]+\]' <<<"${out}" | grep -oE '[a-z-]+\]' | tr -d ']' | tr '\n' ' ')"
  if [[ "$2" == holds ]]; then
    if [[ ${rc} == 0 ]] && grep -q '^VERDICT: REVERT HOLDS' <<<"${out}"; then ok "revert $1: holds"; else nok "revert $1: does not hold: $(grep VERDICT <<<"${out}")"; fi
  else
    if [[ ${rc} != 0 ]] && grep -q '^VERDICT: REVERT DOES NOT HOLD\|^VERDICT: FAIL (arm)' <<<"${out}"; then ok "revert $1: does not hold"; else nok "revert $1: holds, but must not: $(grep VERDICT <<<"${out}")"; fi
  fi
}
revert_case bites                 holds ct revert
revert_case lsq-bites             holds lsq revert
revert_case plus-no-ping          not   ct revert 's/ [0-9]+ received/ 0 received/' ping.txt
revert_case plus-ue-not-paged     not   ct revert '/Paged by cell/d' ue.log
revert_case plus-no-recommendation not  ct revert '/paging recommendation/d' gnb-6.log
revert_case plus-lost-banner      not   ct revert '/DEMO MODE ACTIVE/d' gnb-3.log
revert_case at-step-2             not   ct revert '/page answered, T3513 stopped/d' amf.log
revert_case no-area-page          not   ct revert '/serving the registration area/d' amf.log
revert_case still-recommended     not   ct revert-still-recommended
revert_case not-a-predictor       not   page-all revert
# Every check analyze.py names has a control that fails it.
for c in $(grep -oE 'r\.check\("[a-z-]+"|chain\(r, "[a-z-]+"' "${HERE}/analyze.py" | grep -oE '"[a-z-]+"' | tr -d '"' | sort -u); do
  if [[ " ${FAILED_CHECKS} " == *" ${c} "* ]]; then ok "check [${c}] has a failing control"; else nok "check [${c}] has no failing control"; fi
done
exit "${bad}"
