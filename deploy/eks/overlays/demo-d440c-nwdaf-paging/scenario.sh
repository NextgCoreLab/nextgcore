#!/usr/bin/env bash
# Seeded acceptance run of demo d440c-nwdaf-paging (nextgsim#464), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_MODE, DEMO_VARIANT and OUT set.
#
#   k8s/demo-check.sh d440c-nwdaf-paging nwdaf-mobility        the success chain
#   k8s/demo-check.sh d440c-nwdaf-paging registration-area     the page-all baseline
#   k8s/demo-check.sh d440c-nwdaf-paging off                   no demo block
#   DEMO_VARIANT=nwdaf-down k8s/demo-check.sh d440c-nwdaf-paging nwdaf-mobility
#                     nwdafd scaled to 0 just before the downlink: fail-open
#   DEMO_VARIANT=revert     k8s/demo-check.sh d440c-nwdaf-paging nwdaf-mobility
#                     nwdafd's UE_MOBILITY knob off (the #466 ingest patched
#                     out): 204, the whole area is paged, the success chain fails
#
# The same run in every arm (times from the UE's start-up, sim-lap.yaml):
#   1. revert only: nwdafd's knob off, nwdafd restarted. Otherwise wait for its
#      AMF LOCATION_REPORT subscription;
#   2. restart the UE, so its registration on gNB A and its nine handovers
#      (60-209 s) all come after the subscription;
#   3. at the dwell's far point (233 s, computed from the deployed route and the
#      UE's own `Simulated motion started` line) release it to CM-IDLE with
#      gNB A's `nr-cli ue-release`;
#   4. wait for its idle reselection away from A and for the end of its route
#      (276 s, 22 m from B), then ask nwdafd for its UE_MOBILITY prediction
#      (ue-mobility.http). Corroboration only: a separate request seconds
#      before amfd's, with its own window; amfd's `predicted=` line and its
#      hint counter are the evidence for amfd's own exchange (nextgcore#1494);
#   5. nwdaf-down only: scale nwdafd to 0 and wait until no pod is left;
#   6. downlink: 20 pings from the UPF to the UE's address, so smfd's
#      N1N2MessageTransfer makes amfd page it; wait for the Service Request;
#   7. capture every log and amfd's /metrics under $OUT/scenario/, then
#      analyze.py gives the verdict for the arm (its header lists the checks).
#
# Everything goes through kubectl exec/cp inside the namespace: no
# port-forward, nothing published. NR_CLI names the nr-cli binary copied into
# gNB A (default: ../nextgsim/binaries/nr-cli beside this nextgcore checkout).
set -uo pipefail
: "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
VARIANT="${DEMO_VARIANT:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$(cd "${HERE}/../../../.." && pwd)"
NR_CLI="${NR_CLI:-${CORE}/../nextgsim/binaries/nr-cli}"
K=(kubectl -n "${NAMESPACE}")
S="${OUT}/scenario"
mkdir -p "${S}"
SUPI="imsi-999700000000001"
# nextgsim's committed start_after_secs (config/demo-nwdaf-paging/ue-lap.yaml);
# test-scenario.sh checks the two agree.
ROUTE_START_SECS=60
say() { printf '[scenario] %s\n' "$*"; }
die() { printf '[scenario] FAIL: %s\n' "$*"; capture; exit 1; }
# wait_for <seconds> <command...>: poll until the command succeeds.
wait_for() {
  local t="$1"; shift
  local end=$(( $(date +%s) + t ))
  until "$@" >/dev/null 2>&1; do
    [[ $(date +%s) -ge ${end} ]] && return 1
    sleep 2
  done
}
# The Running, not-terminating pod of a Deployment.
pod_of() {
  "${K[@]}" get pods -l "app.kubernetes.io/name=$1" \
    -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name} {.metadata.deletionTimestamp}{"\n"}{end}' \
    2>/dev/null | awk 'NF == 1 { print $1; exit }'
}
logs_of() { "${K[@]}" logs "$1" -c "$2" --timestamps 2>/dev/null; }
# Through a file, never `logs | grep -q`: under pipefail grep's early exit
# SIGPIPEs kubectl and turns a match into a failure (a UE log is ~35k lines).
grep_log() {
  local f
  f="$(mktemp)"
  logs_of "$1" "$2" >"${f}"
  grep -qE -- "$3" "${f}"
  local rc=$?
  rm -f "${f}"
  return "${rc}"
}
UE_POD=""
CAPTURED=false
capture() {
  [[ "${CAPTURED}" == true ]] && return
  CAPTURED=true
  local d p
  for d in amf smf gnb ue; do
    p="$(pod_of "${d}")"
    [[ "${d}" == ue && -n "${UE_POD}" ]] && p="${UE_POD}"
    [[ -n "${p}" ]] && logs_of "${p}" "${d}" >"${S}/${d}.log"
  done
  mv -f "${S}/gnb.log" "${S}/gnb-a.log" 2>/dev/null
  for d in gnb-b gnb-c; do
    p="$(pod_of "${d}")"; [[ -n "${p}" ]] && logs_of "${p}" gnb >"${S}/${d}.log"
  done
  # nwdaf-down captured nwdafd's log before scaling it away.
  if [[ "${VARIANT}" != nwdaf-down || ! -s "${S}/nwdaf.log" ]]; then
    p="$(pod_of nwdaf)"; [[ -n "${p}" ]] && logs_of "${p}" nwdaf >"${S}/nwdaf.log"
  fi
  p="$(pod_of amf)"
  if [[ -n "${p}" ]]; then
    local ip
    ip="$("${K[@]}" get pod "${p}" -o jsonpath='{.status.podIP}')"
    "${K[@]}" exec "${p}" -c amf -- sh -c \
      "curl -s --max-time 5 http://${ip}:9090/metrics || curl -s --max-time 5 http://127.0.0.1:9090/metrics" \
      >"${S}/amf.prom" 2>/dev/null
  fi
}
route_times() {
  # "<seconds from motion start to the dwell's far point> <... to the route's end>"
  # from the deployed UE config: waypoint 10 is the far point (sim-lap.yaml).
  "${K[@]}" get configmap nextgsim-configs -o jsonpath='{.data.ue\.yaml}' | python3 -c '
import math, sys, yaml
u = yaml.safe_load(sys.stdin)
r = u["sim_route"]; p = u["sim_position"]
pts = [(p["x"], p["y"])] + [(w["x"], w["y"]) for w in r["waypoints"]]
cum = [0.0]
for a, b in zip(pts, pts[1:]):
    cum.append(cum[-1] + math.hypot(b[0] - a[0], b[1] - a[1]))
print("%.1f %.1f" % (cum[10] / r["speed_mps"], cum[-1] / r["speed_mps"]))'
}
epoch_of() { date -u -d "$1" +%s.%N; }

case "${DEMO_MODE}+${VARIANT}" in
  nwdaf-mobility+|nwdaf-mobility+nwdaf-down|nwdaf-mobility+revert|registration-area+|off+) ;;
  *) say "FAIL: no arm mode=${DEMO_MODE} variant=${VARIANT:-none}"; exit 1 ;;
esac
[[ -x "${NR_CLI}" ]] || { say "FAIL: no nr-cli at ${NR_CLI} (set NR_CLI)"; exit 1; }
say "arm: mode=${DEMO_MODE} variant=${VARIANT:-none}"

# --- 1. nwdafd ---------------------------------------------------------------------
if [[ "${VARIANT}" == revert ]]; then
  say "revert: nwdafd's UE_MOBILITY knob off, nwdafd restarted"
  "${K[@]}" get configmap nwdaf-config -o json | python3 -c '
import json, sys, yaml
cm = json.load(sys.stdin)
cfg = yaml.safe_load(cm["data"]["nwdaf.yaml"])
assert cfg["nwdaf"]["amf_mobility"]["enabled"] is True, cfg
cfg["nwdaf"]["amf_mobility"]["enabled"] = False
cm["data"]["nwdaf.yaml"] = yaml.safe_dump(cfg, default_flow_style=False)
for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields"):
    cm["metadata"].pop(k, None)
json.dump(cm, sys.stdout)' >"${S}/nwdaf-config-revert.json" || die "cannot edit nwdaf-config"
  "${K[@]}" replace -f "${S}/nwdaf-config-revert.json" >/dev/null || die "cannot replace nwdaf-config"
  "${K[@]}" rollout restart deployment/nwdaf >/dev/null
  "${K[@]}" rollout status deployment/nwdaf --timeout=180s >/dev/null || die "nwdafd rollout"
  # The new pod's own line: `logs deploy/nwdaf` could still read the old,
  # terminating pod, which logged it at deploy.
  for _ in $(seq 1 30); do NWDAF_POD="$(pod_of nwdaf)"; [[ -n "${NWDAF_POD}" ]] && break; sleep 2; done
  [[ -n "${NWDAF_POD}" ]] || die "no restarted nwdafd pod"
  wait_for 120 grep_log "${NWDAF_POD}" nwdaf 'NWDAF registered with NRF' \
    || die "the restarted nwdafd (${NWDAF_POD}) never registered with the NRF"
else
  wait_for 180 sh -c "kubectl -n ${NAMESPACE} logs deploy/nwdaf | grep -q 'subscribed to AMF LOCATION_REPORT id='" \
    || die "nwdafd never subscribed to amfd's LOCATION_REPORT"
fi

# --- 2. gNB A's nr-cli and the UE restart ------------------------------------------
GNB_A="$(pod_of gnb)"
[[ -n "${GNB_A}" ]] || die "no gNB A pod"
"${K[@]}" cp "${NR_CLI}" "${GNB_A}:/tmp/nr-cli" -c gnb >/dev/null 2>&1 || die "kubectl cp nr-cli into ${GNB_A}"
NODE="$("${K[@]}" exec "${GNB_A}" -c gnb -- /tmp/nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')"
[[ -n "${NODE}" ]] || die "nr-cli --dump lists no node in ${GNB_A}"
cli() { "${K[@]}" exec "${GNB_A}" -c gnb -- /tmp/nr-cli "${NODE}" --exec "$*" 2>&1; }

# The deployed route is parked (sim-lap.yaml): write nextgsim's committed
# start_after_secs back, so the restarted UE rides the seed-464 route. The new
# pod mounts the ConfigMap as it is now; route_times reads it too.
say "unparking the route (start_after_secs ${ROUTE_START_SECS}) and restarting the UE"
"${K[@]}" get configmap nextgsim-configs -o json | python3 -c '
import json, re, sys
cm = json.load(sys.stdin)
ue, n = re.subn(r"(?m)^(\s*start_after_secs:)\s*86400\b.*$", r"\g<1> " + sys.argv[1], cm["data"]["ue.yaml"])
assert n == 1, "the deployed route is not parked at 86400"
cm["data"]["ue.yaml"] = ue
for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields"):
    cm["metadata"].pop(k, None)
json.dump(cm, sys.stdout)' "${ROUTE_START_SECS}" >"${S}/nextgsim-configs-unparked.json" || die "cannot unpark the route"
"${K[@]}" replace -f "${S}/nextgsim-configs-unparked.json" >/dev/null || die "cannot replace nextgsim-configs"
"${K[@]}" rollout restart deployment/ue >/dev/null
"${K[@]}" rollout status deployment/ue --timeout=300s >/dev/null || die "UE rollout"
for _ in $(seq 1 30); do
  UE_POD="$(pod_of ue)"
  [[ -n "${UE_POD}" ]] && [[ "$("${K[@]}" get pods -l app.kubernetes.io/name=ue --no-headers 2>/dev/null | wc -l)" == 1 ]] && break
  sleep 2
done
[[ -n "${UE_POD}" ]] || die "no restarted UE pod"
say "UE pod ${UE_POD}"

# --- 3. the release at the dwell's far point -----------------------------------------
wait_for 150 grep_log "${UE_POD}" ue 'Simulated motion started: sim_route' \
  || die "the UE's route never started"
MOTION_TS="$(logs_of "${UE_POD}" ue | grep -m1 'Simulated motion started: sim_route' | cut -d' ' -f1)"
read -r FAR END < <(route_times) || die "cannot read the deployed route"
RELEASE_AT="$(python3 -c "print('%.3f' % ($(epoch_of "${MOTION_TS}") + ${FAR}))")"
END_AT="$(python3 -c "print('%.3f' % ($(epoch_of "${MOTION_TS}") + ${END}))")"
say "route started ${MOTION_TS}; release at +${FAR} s, route ends at +${END} s"
python3 -c "import time; time.sleep(max(0.0, ${RELEASE_AT} - time.time()))"
# The context to release: the one gNB A holds for the restarted UE, by the AMF
# UE NGAP ID of its last handover (into A), never the first of a list.
AMF_UE_ID="$(logs_of "$(pod_of amf)" amf | grep 'HandoverNotify from association' | tail -1 | sed -nE 's/.*amf_ue_ngap_id=([0-9]+),.*/\1/p')"
cli ue-list >"${S}/ue-list.txt"
UE_ID="$(python3 -c '
import sys, yaml
want = int(sys.argv[2])
text = open(sys.argv[1]).read()
ues = (yaml.safe_load(text[text.index("ues:"):]) or {}).get("ues") or []
ids = [u["ue_id"] for u in ues if u.get("amf_ngap_id") == want]
print(ids[0] if len(ids) == 1 else "")' "${S}/ue-list.txt" "${AMF_UE_ID:-0}" 2>/dev/null)"
[[ -n "${UE_ID}" ]] || die "gNB A holds no single context with amf_ngap_id ${AMF_UE_ID:-?} at the dwell ($(tr '\n' ' ' <"${S}/ue-list.txt"))"
cli "ue-release ${UE_ID}" >"${S}/ue-release.txt"
say "ue-release ${UE_ID} on gNB A at $(date -u +%FT%T.%3NZ)"
wait_for 30 grep_log "${UE_POD}" ue 'Received RRC Release from cell' || die "the UE never got its RRC Release"

# --- 4. idle reselection, route end, the producer's answer ---------------------------
python3 -c "import time; time.sleep(max(0.0, ${END_AT} + 3 - time.time()))"
grep_log "${UE_POD}" ue 'Cell reselection: id=' || say "no Cell reselection line yet (analyze.py decides)"
NOW="$(date -u +%FT%TZ)"; LATER="$(date -u -d '+30 seconds' +%FT%TZ)"
Q="$(python3 -c '
import json, sys, urllib.parse as u
q = lambda v: u.quote(json.dumps(v, separators=(",", ":")), safe="")
print("event-id=UE_MOBILITY&tgt-ue=%s&ana-req=%s" % (q({"supis": [sys.argv[1]]}), q({"startTs": sys.argv[2], "endTs": sys.argv[3]})))' \
  "${SUPI}" "${NOW}" "${LATER}")"
"${K[@]}" exec deploy/nwdaf -c nwdaf -- sh -c \
  "curl -s --http2-prior-knowledge --max-time 10 -o /tmp/body -w '%{http_code}\n' 'http://127.0.0.1:7777/nnwdaf-analyticsinfo/v1/analytics?${Q}'; cat /tmp/body 2>/dev/null" \
  >"${S}/ue-mobility.http" 2>&1
say "UE_MOBILITY GET (prediction window ${NOW}..${LATER}): $(head -1 "${S}/ue-mobility.http")"

# --- 5. nwdaf-down --------------------------------------------------------------------
if [[ "${VARIANT}" == nwdaf-down ]]; then
  p="$(pod_of nwdaf)"; [[ -n "${p}" ]] && logs_of "${p}" nwdaf >"${S}/nwdaf.log"
  "${K[@]}" scale deployment/nwdaf --replicas=0 >/dev/null
  wait_for 120 sh -c "[ -z \"\$(kubectl -n ${NAMESPACE} get pods -l app.kubernetes.io/name=nwdaf -o name)\" ]" \
    || die "nwdafd pods still present 120 s after scaling to 0"
  echo "nwdaf pods before the downlink: $("${K[@]}" get pods -l app.kubernetes.io/name=nwdaf -o name | wc -l)" \
    >"${S}/nwdaf-down.txt"
  say "$(cat "${S}/nwdaf-down.txt")"
fi

# --- 6. downlink data ------------------------------------------------------------------
UE_IP="$(logs_of "${UE_POD}" ue | sed -nE 's/.*is now ACTIVE \(IPv4: Some\(\[([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)\]\)\).*/\1.\2.\3.\4/p' | tail -1)"
[[ -n "${UE_IP}" ]] || die "no PDU session address in the restarted UE's log"
say "downlink: 20 pings from the UPF to ${UE_IP}"
"${K[@]}" exec deploy/upf -c upf -- ping -c 20 -i 0.5 -W 3 "${UE_IP}" >"${S}/ping.txt" 2>&1
tail -2 "${S}/ping.txt"
wait_for 30 sh -c "kubectl -n ${NAMESPACE} logs deploy/amf | grep -q 'page answered, T3513 stopped'" \
  || say "no 'page answered' at amfd within 30 s (analyze.py decides)"

# --- 7. capture and verdict --------------------------------------------------------------
capture
python3 "${HERE}/analyze.py" "${S}" "${DEMO_MODE}" "${VARIANT:-none}" | tee "${S}/analyze.txt"
exit "${PIPESTATUS[0]}"
