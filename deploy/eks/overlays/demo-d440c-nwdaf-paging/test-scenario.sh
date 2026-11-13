#!/usr/bin/env bash
# Self-test of demo d440c-nwdaf-paging's scenario checks (nextgsim#464), run by
# CI with the other overlays' test-scenario.sh. Needs bash and python3 with
# PyYAML, and nextgsim checked out beside nextgcore (CI does, for the renders).
#
#   1. Fixture parity: the overlay's gNB and UE configs (sim-lap.yaml,
#      gnb-b.yaml, gnb-c.yaml) are nextgsim's config/demo-nwdaf-paging/ files
#      with only the addresses changed and the demo block removed, so the EKS run
#      rides the committed seed-464 route. Positive control: a moved waypoint
#      fails.
#   2. The release time scenario.sh derives from the deployed route is the
#      dwell's far point (waypoint 10, 172.8 s after the motion starts), inside
#      the dwell; the route ends 216.1 s after it. The deployed route is parked
#      (start_after_secs 86400), the only allowed difference, and scenario.sh
#      restores nextgsim's committed value.
#   3. analyze.py passes each arm's fixture (fixtures.py: real line formats and
#      timing) and FAILS, naming the step, on each negative control: a missing
#      line, a wrong target set, the wrong arm's capture, a late PAGING, a lost
#      handover, a missing idle reselection, and an empty capture. Every
#      r.check in analyze.py has its own control: a sweep making any one of them
#      always-true fails this file.
# Exit 0 when every case holds.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM="${NEXTGSIM_DIR:-${HERE}/../../../../../nextgsim}"
T="$(mktemp -d -t d440c-scenario-test-XXXXXX)"
trap 'rm -rf -- "${T}"' EXIT
bad=0
ok()   { echo "ok   $*"; }
nok()  { echo "FAIL $*"; bad=1; }

# --- 1. fixture parity with nextgsim's committed configs -----------------------------
parity() {   # <nextgsim config dir>
  python3 - "${HERE}" "$1" <<'PY'
import sys, yaml
here, src = sys.argv[1], sys.argv[2]
def cm_data(path, name):
    for d in yaml.safe_load_all(open(path)):
        if d and d.get("kind") == "ConfigMap" and d["metadata"]["name"] == name:
            return d["data"]
    raise SystemExit("no ConfigMap %s in %s" % (name, path))
lap = cm_data("%s/sim-lap.yaml" % here, "nextgsim-configs")
pairs = [
    (yaml.safe_load(lap["gnb.yaml"]), "gnb-a.yaml"),
    (yaml.safe_load(cm_data("%s/gnb-b.yaml" % here, "gnb-b-config")["gnb-b.yaml"]), "gnb-b.yaml"),
    (yaml.safe_load(cm_data("%s/gnb-c.yaml" % here, "gnb-c-config")["gnb-c.yaml"]), "gnb-c.yaml"),
]
ns = "nextg-system"
for ours, name in pairs:
    theirs = yaml.safe_load(open("%s/%s" % (src, name)))
    assert "demo" in theirs, "%s: the nextgsim file lost its demo block" % name
    theirs.pop("demo")
    assert "demo" not in ours, "%s: the overlay copy carries a demo block" % name
    theirs["amf_configs"] = [{"address": "amf.%s.svc.cluster.local" % ns, "port": 38412}]
    theirs["upf_addr"] = "upf.%s.svc.cluster.local" % ns
    for k in ("link_ip", "ngap_ip", "gtp_ip"):
        theirs[k] = "0.0.0.0"
    if ours != theirs:
        diff = sorted(k for k in set(ours) | set(theirs) if ours.get(k) != theirs.get(k))
        raise SystemExit("%s differs from nextgsim's in %s" % (name, diff))
ue = yaml.safe_load(lap["ue.yaml"])
theirs = yaml.safe_load(open("%s/ue-lap.yaml" % src))
# The one allowed difference: the deployed route is parked, and scenario.sh
# restores nextgsim's committed start_after_secs before it restarts the UE.
import re
assert ue["sim_route"]["start_after_secs"] == 86400, "the deployed route is not parked at 86400"
restored = re.search(r"(?m)^ROUTE_START_SECS=(\d+)$", open("%s/scenario.sh" % here).read())
assert restored and int(restored.group(1)) == theirs["sim_route"]["start_after_secs"], (
    "scenario.sh restores start_after_secs %s, nextgsim commits %s"
    % (restored and restored.group(1), theirs["sim_route"]["start_after_secs"]))
ue["sim_route"]["start_after_secs"] = theirs["sim_route"]["start_after_secs"]
# The compose addresses, gNB A, B, C, become the three gNB Services.
assert theirs["gnb_search_list"] == ["172.23.0.100", "172.23.0.102", "172.23.0.103"], theirs["gnb_search_list"]
theirs["gnb_search_list"] = ["gnb.%s.svc.cluster.local" % ns, "gnb-b.%s.svc.cluster.local" % ns,
                             "gnb-c.%s.svc.cluster.local" % ns]
if ue != theirs:
    diff = sorted(k for k in set(ue) | set(theirs) if ue.get(k) != theirs.get(k))
    raise SystemExit("ue.yaml differs from nextgsim's ue-lap.yaml in %s" % diff)
print("parity: gnb-a/b/c and ue-lap match nextgsim's config/demo-nwdaf-paging/ "
      "(the route parked, scenario.sh restores start_after_secs %s)" % restored.group(1))
PY
}
if [[ -d "${SIM}/config/demo-nwdaf-paging" ]]; then
  if out="$(parity "${SIM}/config/demo-nwdaf-paging" 2>&1)"; then ok "${out}"; else nok "${out}"; fi
  cp -r "${SIM}/config/demo-nwdaf-paging" "${T}/moved"
  sed -i 's/- { x: -21, y: -10, z: 0 }/- { x: -22, y: -10, z: 0 }/' "${T}/moved/ue-lap.yaml"
  if out="$(parity "${T}/moved" 2>&1)"; then nok "parity missed a moved waypoint"
  else ok "parity fails on a moved waypoint (${out##*: })"; fi
  cp -r "${SIM}/config/demo-nwdaf-paging" "${T}/later"
  sed -i 's/^\(  start_after_secs:\) 60/\1 75/' "${T}/later/ue-lap.yaml"
  if out="$(parity "${T}/later" 2>&1)"; then nok "parity missed a committed start_after_secs scenario.sh does not restore"
  else ok "parity fails when scenario.sh would restore another start_after_secs (${out##*: })"; fi
else
  nok "no nextgsim checkout at ${SIM} (set NEXTGSIM_DIR): fixture parity unchecked"
fi

# --- 2. the release time from the deployed route ---------------------------------------
times="$(python3 - "${HERE}/sim-lap.yaml" <<'PY'
import math, sys, yaml
lap = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d][0]
u = yaml.safe_load(lap["data"]["ue.yaml"])
r = u["sim_route"]; p = u["sim_position"]
pts = [(p["x"], p["y"])] + [(w["x"], w["y"]) for w in r["waypoints"]]
cum = [0.0]
for a, b in zip(pts, pts[1:]):
    cum.append(cum[-1] + math.hypot(b[0] - a[0], b[1] - a[1]))
print("%.1f %.1f %.1f %.1f" % (cum[10] / r["speed_mps"], cum[-1] / r["speed_mps"],
                               cum[9] / r["speed_mps"], cum[11] / r["speed_mps"]))
PY
)"
# scenario.sh's own computation, over the same file.
read -r far end dwell_in dwell_out <<<"${times}"
scen="$(sed -n "/^route_times()/,/^}/p" "${HERE}/scenario.sh" | grep -c 'cum\[10\]')"
if [[ "${far}" == 172.8 && "${end}" == 216.1 && "${scen}" == 1 ]] \
   && python3 -c "import sys; sys.exit(not (${dwell_in} < ${far} < ${dwell_out}))"; then
  ok "release at +${far} s (inside the dwell ${dwell_in}..${dwell_out} s), route end +${end} s"
else
  nok "release/route times: far=${far} end=${end} dwell=${dwell_in}..${dwell_out} scenario-uses-waypoint-10=${scen}"
fi

# --- 3. analyze.py on the arm fixtures ---------------------------------------------------
# case <expect pass|fail> <fixture arm> <mode> <variant> <why: grep -F in the output> [drop] [from to]
n=0
case_() {
  local expect="$1" arm="$2" mode="$3" variant="$4" why="$5"; shift 5
  local d="${T}/c$((n += 1))"
  mkdir -p "${d}"
  python3 "${HERE}/fixtures.py" "${d}" "${arm}" "$@"
  local out rc
  out="$(python3 "${HERE}/analyze.py" "${d}" "${mode}" "${variant}" 2>&1)"; rc=$?
  if [[ "${expect}" == pass ]]; then
    if [[ ${rc} == 0 ]] && grep -qF -- "${why}" <<<"${out}"; then ok "pass: ${arm} as ${mode}+${variant}"
    else nok "expected PASS: ${arm} as ${mode}+${variant}"; grep FAIL <<<"${out}"; fi
  else
    if [[ ${rc} != 0 ]] && grep -F "FAIL" <<<"${out}" | grep -qF -- "${why}"; then
      # shellcheck disable=SC2016  # the quotes are literal, around the arguments
      ok "fail: ${arm} as ${mode}+${variant} ${1:+drop '$1' }${2:+'$2'->'$3' }-> ${why}"
    else nok "expected FAIL naming '${why}': ${arm} as ${mode}+${variant} ${*}"; grep -E "FAIL|PASS" <<<"${out}"; fi
  fi
}
case_ pass nwdaf-mobility    nwdaf-mobility    none       "PASS (nwdaf-mobility)"
case_ pass registration-area registration-area none       "PASS (registration-area)"
case_ pass off               off               none       "PASS (off)"
case_ pass nwdaf-down        nwdaf-mobility    nwdaf-down "PASS (nwdaf-mobility+nwdaf-down)"
case_ pass revert            nwdaf-mobility    revert     "PASS (nwdaf-mobility+revert)"

# The success chain, one step at a time.
case_ fail nwdaf-mobility nwdaf-mobility none "the ordered success chain: no amfd" "predicted=\("
case_ fail nwdaf-mobility nwdaf-mobility none "the ordered success chain: amfd predicted another cell" "" \
  "predicted=(999-70, 0x000000020)" "predicted=(999-70, 0x000000030)"
case_ fail nwdaf-mobility nwdaf-mobility none "the ordered success chain: no \`Paging sent to 2/2" "" \
  "targets=[gNB 0x2,gNB 0x1]" "targets=[gNB 0x2]"
case_ fail nwdaf-mobility nwdaf-mobility none "the ordered success chain: no gNB B" "gnb::ngap::task.*cells=\[0x10,0x20\]"
case_ fail nwdaf-mobility nwdaf-mobility none "the ordered success chain: no \`page answered" "page answered ue="
case_ fail nwdaf-mobility nwdaf-mobility none "the ordered success chain: no smfd" "PFCP Session Report Request"
case_ fail nwdaf-mobility+paged-c nwdaf-mobility none "attempt 1 paged gNB B and gNB A only"
case_ fail nwdaf-mobility+late-b nwdaf-mobility none "the ordered success chain: out of order"
case_ fail nwdaf-mobility nwdaf-mobility none 'outcome="predicted"} 1' 'outcome="predicted"'
case_ fail nwdaf-mobility nwdaf-mobility none "200 predicting cell 000000020" "" '"nrCellId": "000000020"' '"nrCellId": "000000030"'
# Another arm's capture never passes as the success arm, nor the reverse.
case_ fail revert            nwdaf-mobility none "the ordered success chain"
case_ fail nwdaf-down        nwdaf-mobility none "the ordered success chain"
case_ fail registration-area nwdaf-mobility none "the ordered success chain"
case_ fail nwdaf-mobility    nwdaf-mobility revert "the success chain does NOT hold"
case_ fail nwdaf-mobility    registration-area none "every gNB got one PAGING"
case_ fail registration-area off none "off: amfd logged no demo or NWDAF line"
case_ fail nwdaf-mobility    off none "off: amfd made no UE_MOBILITY query"
# Arm-specific evidence.
case_ fail registration-area registration-area none "no Assistance Data at any gNB" "" \
  "triggering RRC Paging" "triggering RRC Paging [demo:d440c-nwdaf-paging] PAGING assistance: cells=[] attempt 1/5"
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "amfd logged a fail-open reason" "no prediction \("
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "no nwdaf pod was left" "nwdaf pods before"
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "next-scope=same" "gnb::ngap::task.*next-scope=same"
case_ fail revert nwdaf-mobility revert "UE_MOBILITY GET is 204" "" "204" "200"
case_ fail revert nwdaf-mobility revert 'outcome="no_prediction"} 1' 'outcome="no_prediction"'
case_ fail nwdaf-mobility nwdaf-mobility revert "revert: nwdafd ingested no LOCATION_REPORT"
# Each check in analyze.py has a control that fails on it (round 1: a sweep
# making every check always-true must be caught by this file).
# Arms that could pass for the wrong reason.
case_ fail registration-area+queried registration-area none "registration-area: amfd made no UE_MOBILITY query"
case_ fail registration-area+attempt2 registration-area none "exactly one PAGING round, attempt 1 (2 round(s))"
case_ fail off+attempt2 off none "exactly one PAGING round, attempt 1 (2 round(s))"
case_ fail registration-area registration-area none "registration-area: \`page answered" "" \
  "via gNB 0x2 attempt 1" "via gNB 0x2 attempt 2"
case_ fail registration-area registration-area none "registration-area: \`Paging sent to 3/3" "" \
  "targets=[gNB 0x1,gNB 0x2,gNB 0x3]" "targets=[gNB 0x1,gNB 0x2]"
case_ fail off+unpaged-c off none "off: every gNB got one PAGING"
case_ fail off off none "off: \`Paging sent to 3/3 gNB(s) serving the registration area\`" "" \
  "Paging sent to 3/3 gNB(s) serving" "Paging sent to 2/3 gNB(s) serving"
case_ fail off off none "off: no gNB logged a PAGING assistance line" "" \
  "triggering RRC Paging" "triggering RRC Paging [demo:d440c-nwdaf-paging] PAGING assistance: cells=[] attempt 1/5"
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "one error or timeout hint outcome" "" \
  'outcome="error"} 1' 'outcome="error"} 0'
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "one error or timeout hint outcome" "" \
  'outcome="predicted"} 0' 'outcome="predicted"} 1'
case_ fail nwdaf-down+unpaged-c nwdaf-mobility nwdaf-down "nwdaf-down: every gNB got one PAGING"
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "nwdaf-down: \`Paging sent to 3/3 gNB(s) serving" "" \
  "3/3 gNB(s) serving the registration area" "3/3 gNB(s) predicted by NWDAF UE mobility in the registration area"
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "nwdaf-down: demo line scope=registration-area" "" \
  "scope=registration-area" "scope=nwdaf-mobility"
case_ fail nwdaf-down nwdaf-mobility nwdaf-down "nwdaf-down: \`page answered" "" \
  "via gNB 0x2 attempt 1" "via gNB 0x2 attempt 2"
case_ fail revert+timeout nwdaf-mobility revert "revert: amfd logged neither a prediction nor a failure"
case_ fail revert+nwdaf-on nwdaf-mobility revert "revert: nwdafd never logged \`ue-mobility: on\`"
# The common chain.
case_ fail nwdaf-mobility nwdaf-mobility none "nine N2 handovers before the release (got 8)" "ran_ue_ngap_id=6\)"
case_ fail nwdaf-mobility nwdaf-mobility none "idle reselection away from gNB A" "Cell reselection: id=0,"
case_ fail nwdaf-mobility nwdaf-mobility none "UE released to RRC_IDLE" "Received RRC Release"
case_ fail nwdaf-mobility nwdaf-mobility none "UE route started" "Simulated motion started"
case_ fail nwdaf-mobility nwdaf-mobility none "in order (got 10,20,30,10,30,10" "10:02:04\.002.*ue-mobility ingest"
case_ fail nwdaf-mobility nwdaf-mobility none "the answer came through gNB B" "nci=0x20"
case_ fail nwdaf-mobility nwdaf-mobility none "page answered, T3513 stopped" "T3513 stopped"
case_ fail nwdaf-mobility nwdaf-mobility none "UE paged by its camped cell" "Paged by cell"
case_ fail nwdaf-mobility nwdaf-mobility none "downlink pings answered: 12/20" "" "20 received" "12 received"
case_ fail nwdaf-mobility nwdaf-mobility none "budget 2000 ms" "" "10:04:40.100000123Z" "10:04:37.900000123Z"
case_ fail nwdaf-mobility nwdaf-mobility none "registered through gNB A" "ran_ue_ngap_id=2, nas_pdu_len=23"
case_ fail nwdaf-mobility nwdaf-mobility none "UE CM-IDLE after the release" "CM-IDLE"
case_ fail nwdaf-mobility nwdaf-mobility none "amfd sent a PAGING after the release" "Paging sent to"
case_ fail nwdaf-mobility+late-resel nwdaf-mobility none "the UE reselected before the page"
case_ fail nwdaf-mobility nwdaf-mobility none "exactly one PAGING round, attempt 1" "" \
  "0xc0000002), attempt 1" "0xc0000002), attempt 2"
case_ fail nwdaf-mobility nwdaf-mobility none "UE sent a mobile-terminated Service Request" "Sending Service Request"
case_ fail nwdaf-mobility nwdaf-mobility none "UE: Service Accept received" "Service Accept received"
case_ fail nwdaf-mobility nwdaf-mobility none "amf.log captured and non-empty" "."

[[ ${bad} == 0 ]] && echo "d440c test-scenario ok (${n} analyze cases)"
exit "${bad}"
