#!/usr/bin/env bash
# Self-test of PROFILE=demo's profile_rollout (nextgsim#480 review round 6):
# every Deployment a demo overlay renders gets a rollout wait, whatever image
# backs it. Renders the real overlays with kubectl kustomize, then runs
# profile_rollout against a stub kubectl that records each call.
#
#   d445a-fl-t8         nef and the member UEs ue-2..ue-5 are waited on
#   d441e-model-retrain nwdaf-mtlf and nwdaf-anlf are waited on, and no
#                       Deployment named after the nwdaf image is
#   a failing rollout   warns, and profile_rollout still returns 0
#   no render           warns, and only the 5G waits run
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EKS="$(cd "${HERE}/../.." && pwd)"
REAL_KUBECTL="$(command -v kubectl)" || { echo "not ok - kubectl is needed to render the overlays"; exit 1; }
T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin"
# The stub: records every call; `rollout status` fails for the Deployment in
# STUB_FAIL, everything else succeeds.
cat >"${T}/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"${STUB_LOG}"
[[ "$1 $2" == "rollout status" && -n "${STUB_FAIL:-}" && "$3" == "deployment/${STUB_FAIL}" ]] && exit 1
exit 0
STUB
chmod +x "${T}/bin/kubectl"

n=0 bad=0
ok()  { n=$((n + 1)); echo "ok ${n} - $*"; }
nok() { n=$((n + 1)); bad=$((bad + 1)); echo "not ok ${n} - $*"; }

# run OVERLAY RENDER [FAIL] -> the stub log in ${T}/log, the output in ${T}/out
run() {
  : >"${T}/log"
  (
    log()  { echo "[log] $*"; }
    warn() { echo "[warn] $*"; }
    # shellcheck source=../../lib/profile.sh
    source "${EKS}/lib/profile.sh"
    DEMO_OVERLAY="$1" nextg_load_profile demo || exit 3
    NAMESPACE=nextg-demo RENDERED="$2" STUB_LOG="${T}/log" STUB_FAIL="${3:-}" \
      PATH="${T}/bin:${PATH}" profile_rollout
  ) >"${T}/out" 2>&1
}
waited() { grep -qx "rollout status deployment/$1 -n nextg-demo --timeout=300s" "${T}/log"; }

for o in demo-d445a-fl-t8 demo-d441e-model-retrain; do
  "${REAL_KUBECTL}" kustomize "${EKS}/overlays/${o}" >"${T}/${o}.yaml" \
    || { nok "render ${o}"; continue; }
done

run demo-d445a-fl-t8 "${T}/demo-d445a-fl-t8.yaml"; rc=$?
[[ ${rc} == 0 ]] && ok "d445a: profile_rollout returns 0" || nok "d445a: rc ${rc}: $(cat "${T}/out")"
for d in nef ue-2 ue-3 ue-4 ue-5 nrf upf; do
  waited "${d}" && ok "d445a: waits on ${d}" || nok "d445a: no wait on ${d}"
done
grep -q "rollout status statefulset/mongodb" "${T}/log" \
  && ok "d445a: the 5G waits still run first" || nok "d445a: no 5G mongodb wait"

run demo-d441e-model-retrain "${T}/demo-d441e-model-retrain.yaml"; rc=$?
[[ ${rc} == 0 ]] && ok "d441e: profile_rollout returns 0" || nok "d441e: rc ${rc}: $(cat "${T}/out")"
for d in nwdaf-mtlf nwdaf-anlf; do
  waited "${d}" && ok "d441e: waits on ${d}" || nok "d441e: no wait on ${d}"
done
waited nwdaf && nok "d441e: waits on a Deployment named after the nwdaf image" \
  || ok "d441e: no wait on the nonexistent nwdaf Deployment"

run demo-d445a-fl-t8 "${T}/demo-d445a-fl-t8.yaml" nef; rc=$?
[[ ${rc} == 0 ]] && grep -q '^\[warn\] nef not ready' "${T}/out" \
  && ok "a failing rollout warns and returns 0" || nok "failing rollout: rc ${rc}: $(cat "${T}/out")"

run demo-d445a-fl-t8 ""; rc=$?
if [[ ${rc} == 0 ]] && grep -q '^\[warn\] no rendered manifest' "${T}/out" && ! waited nef && waited nrf; then
  ok "no render: warns, only the 5G waits"
else nok "no render: rc ${rc}: $(cat "${T}/out")"; fi

echo "1..${n}"
[[ ${bad} == 0 ]]
