#!/usr/bin/env bash
# Seeded acceptance run of demo d440a-ai-paging (nextgsim#462), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_MODE, DEMO_VARIANT and OUT set.
#
#   k8s/demo-check.sh d440a-ai-paging ct            the success chain (also
#                                                   last-served, lsq)
#   k8s/demo-check.sh d440a-ai-paging page-all      the page-all baseline: the gNB
#                                                   recommends nothing
#   k8s/demo-check.sh d440a-ai-paging off           no demo block anywhere
#   DEMO_VARIANT=revert k8s/demo-check.sh d440a-ai-paging ct
#                     amfd's demo block removed and amfd restarted, so its
#                     paging.strategy is the default registration-area: the gNB
#                     still recommends and amfd pages the area. scenario.sh
#                     exits 0 only when the revert HOLDS: the success chain
#                     fails at exactly [amf] step 1 and every other check holds
#                     (analyze.py). demo-check.sh's own verdict is then FAIL on
#                     one line only, the missing nextg_demo_enabled series:
#                     amfd's demo is off and no gNB serves /metrics.
#
# The same run in every arm, on live seed 1 (seed.env, generated from nextgsim's
# config/demo-ai-paging/d440a-live-seeds.yaml; times from the UE's `Simulated
# motion started` line):
#   1. revert only: amfd's demo block out of nextgcore-configs, amfd restarted,
#      and every gNB's NG Setup redone with the new amfd;
#   2. copy nr-cli into the six gNBs; unpark the route and restart the UE, so it
#      registers, starts its PDU session and then rides seed 1's route;
#   3. at RELEASE_AT_S release it on whichever gNB holds its context then
#      (`nr-cli ue-release`); with a predictor mode that gNB recommends the RAN
#      nodes for paging in its UE Context Release Complete;
#   4. at PAGE_AT_S 40 pings from the UPF to the idle UE, so amfd pages it;
#   5. capture every log and amfd's /metrics under $OUT/scenario/, then
#      analyze.py gives the verdict for the arm (its header lists the checks)
#      and records the measurement in result.txt.
#
# Everything goes through kubectl exec/cp inside the namespace: no
# port-forward, nothing published. NR_CLI names the nr-cli binary copied into
# the gNBs (default: ../nextgsim/binaries/nr-cli beside this nextgcore checkout).
set -uo pipefail
: "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
VARIANT="${DEMO_VARIANT:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$(cd "${HERE}/../../../.." && pwd)"
NR_CLI="${NR_CLI:-${CORE}/../nextgsim/binaries/nr-cli}"
K=(kubectl -n "${NAMESPACE}")
S="${OUT}/scenario"
mkdir -p "${S}"
# shellcheck source=deploy/eks/overlays/demo-d440a-ai-paging/seed.env
. "${HERE}/seed.env"
GNBS=(gnb gnb-2 gnb-3 gnb-4 gnb-5 gnb-6)
say() { printf '[scenario] %s\n' "$*"; }
die() { printf '[scenario] FAIL: %s\n' "$*"; capture; exit 1; }
wait_for() {   # <seconds> <command...>: poll until the command succeeds
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
# SIGPIPEs kubectl and turns a match into a failure.
grep_log() {
  local f="${S}/.grep_log.tmp"
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
  for d in amf smf upf "${GNBS[@]}"; do
    p="$(pod_of "${d}")"
    [[ -n "${p}" ]] || continue
    case "${d}" in gnb*) logs_of "${p}" gnb >"${S}/${d}.log" ;; *) logs_of "${p}" "${d}" >"${S}/${d}.log" ;; esac
  done
  p="${UE_POD:-$(pod_of ue)}"
  [[ -n "${p}" ]] && logs_of "${p}" ue >"${S}/ue.log"
  p="$(pod_of amf)"
  if [[ -n "${p}" ]]; then
    local ip
    ip="$("${K[@]}" get pod "${p}" -o jsonpath='{.status.podIP}')"
    "${K[@]}" exec "${p}" -c amf -- sh -c \
      "curl -s --max-time 5 http://${ip}:9090/metrics || curl -s --max-time 5 http://127.0.0.1:9090/metrics" \
      >"${S}/amf.prom" 2>/dev/null
  fi
}
epoch_of() { date -u -d "$1" +%s.%N; }
sleep_until() { python3 -c "import time; time.sleep(max(0.0, $1 - time.time()))"; }

case "${DEMO_MODE}+${VARIANT}" in
  ct+|last-served+|lsq+|page-all+|off+|ct+revert|last-served+revert|lsq+revert) ;;
  *) say "FAIL: no arm mode=${DEMO_MODE} variant=${VARIANT:-none}"; exit 1 ;;
esac
[[ -x "${NR_CLI}" ]] || { say "FAIL: no nr-cli at ${NR_CLI} (set NR_CLI)"; exit 1; }
say "arm: mode=${DEMO_MODE} variant=${VARIANT:-none} seed=${SEED}"

# --- 1. revert: amfd without its demo block ---------------------------------------------
if [[ "${VARIANT}" == revert ]]; then
  say "revert: amfd's demo block removed (paging.strategy back to its default), amfd restarted"
  "${K[@]}" get configmap nextgcore-configs -o json | python3 -c '
import json, sys, yaml
cm = json.load(sys.stdin)
cfg = yaml.safe_load(cm["data"]["amf.yaml"])
assert cfg["demo"]["d440a-ai-paging"]["enabled"] is True, cfg.get("demo")
del cfg["demo"]
assert "strategy" not in (cfg["amf"].get("paging") or {}), cfg["amf"].get("paging")
cm["data"]["amf.yaml"] = yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False)
for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields"):
    cm["metadata"].pop(k, None)
json.dump(cm, sys.stdout)' >"${S}/nextgcore-configs-revert.json" || die "cannot edit amfd's config"
  "${K[@]}" replace -f "${S}/nextgcore-configs-revert.json" >/dev/null || die "cannot replace nextgcore-configs"
  "${K[@]}" rollout restart deployment/amf >/dev/null
  "${K[@]}" rollout status deployment/amf --timeout=180s >/dev/null || die "amfd rollout"
  for g in "${GNBS[@]}"; do
    p="$(pod_of "${g}")"
    [[ -n "${p}" ]] || die "no ${g} pod"
    wait_for 180 sh -c "[ \"\$(kubectl -n ${NAMESPACE} logs ${p} -c gnb | grep -c 'Received NG Setup Response')\" -ge 2 ]" \
      || die "${g} never redid NG Setup with the restarted amfd"
  done
fi

# --- 2. nr-cli, the route and the UE restart ---------------------------------------------
declare -A POD NODE
for g in "${GNBS[@]}"; do
  POD[${g}]="$(pod_of "${g}")"
  [[ -n "${POD[${g}]}" ]] || die "no ${g} pod"
  "${K[@]}" cp "${NR_CLI}" "${POD[${g}]}:/tmp/nr-cli" -c gnb >/dev/null 2>&1 || die "kubectl cp nr-cli into ${g}"
  NODE[${g}]="$("${K[@]}" exec "${POD[${g}]}" -c gnb -- /tmp/nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')"
  [[ -n "${NODE[${g}]}" ]] || die "nr-cli --dump lists no node in ${g}"
done
cli() { local g="$1"; shift; "${K[@]}" exec "${POD[${g}]}" -c gnb -- /tmp/nr-cli "${NODE[${g}]}" --exec "$*" 2>&1; }

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

# --- 3. the release ----------------------------------------------------------------------
wait_for 150 grep_log "${UE_POD}" ue 'Simulated motion started: sim_route' || die "the UE's route never started"
logs_of "${UE_POD}" ue >"${S}/ue-start.log"
ACTIVE_N="$(grep -n 'is now ACTIVE' "${S}/ue-start.log" | head -1 | cut -d: -f1)"
MOTION_N="$(grep -n 'Simulated motion started: sim_route' "${S}/ue-start.log" | head -1 | cut -d: -f1)"
[[ -n "${ACTIVE_N}" && "${ACTIVE_N}" -lt "${MOTION_N}" ]] \
  || die "harness timing: the route started before the PDU session was up"
T0="$(epoch_of "$(sed -n "${MOTION_N}p" "${S}/ue-start.log" | cut -d' ' -f1)")"
say "route started; release at +${RELEASE_AT_S} s, downlink at +${PAGE_AT_S} s"
sleep_until "${T0} + ${RELEASE_AT_S}"
SERVING=""; UE_ID=""
for g in "${GNBS[@]}"; do
  id="$(cli "${g}" ue-list | grep -oE 'ue_id: [0-9]+' | head -1 | grep -oE '[0-9]+' || true)"
  if [[ -n "${id}" ]]; then SERVING="${g}"; UE_ID="${id}"; break; fi
done
[[ -n "${SERVING}" ]] || die "no gNB holds the UE's context at +${RELEASE_AT_S} s"
cli "${SERVING}" "ue-release ${UE_ID}" >"${S}/ue-release.txt"
echo "${SERVING}" >"${S}/serving.txt"
# The release's actual offset on the route's clock (wanted: RELEASE_AT_S),
# recorded in result.txt.
python3 -c "import time; print('%.1f' % (time.time() - ${T0}))" >"${S}/release-offset.txt"
say "ue-release ${UE_ID} on ${SERVING} at +$(cat "${S}/release-offset.txt") s (wanted +${RELEASE_AT_S} s)"
wait_for 30 grep_log "${UE_POD}" ue 'RRC connection released' || die "the UE never got its RRC Release"

# --- 4. downlink data ----------------------------------------------------------------------
sleep_until "${T0} + ${PAGE_AT_S}"
UE_IP="$(logs_of "${UE_POD}" ue | sed -nE 's/.*is now ACTIVE \(IPv4: Some\(\[([0-9]+), ([0-9]+), ([0-9]+), ([0-9]+)\]\)\).*/\1.\2.\3.\4/p' | tail -1)"
[[ -n "${UE_IP}" ]] || die "no PDU session address in the restarted UE's log"
say "downlink: 40 pings from the UPF to ${UE_IP}"
"${K[@]}" exec deploy/upf -c upf -- ping -c 40 -i 0.5 -W 3 "${UE_IP}" >"${S}/ping.txt" 2>&1
tail -2 "${S}/ping.txt"

# --- 5. capture and verdict ----------------------------------------------------------------
capture
python3 "${HERE}/analyze.py" "${S}" "${DEMO_MODE}" "${VARIANT:-none}" | tee "${S}/analyze.txt"
exit "${PIPESTATUS[0]}"
