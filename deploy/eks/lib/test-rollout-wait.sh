#!/usr/bin/env bash
# Self-test of nextg_rollout_wait (lib/profile.sh, #1651): a rollout wait ends
# at once, with the container's last log lines, when a pod of the workload's
# current revision crash-loops, instead of waiting out its timeout. Runs the
# function against a stub kubectl whose `rollout status` would take
# STUB_ROLLOUT_SECS and whose pod listing comes from a fixture.
#
#   CrashLoopBackOff        returns 3 within seconds, warns, prints the logs
#   restarts over the limit returns 3 (not Ready, 4 restarts > 3)
#   with `die` defined      the deploy fails through it
#   healthy pods            the rollout's own status (0), no warning
#   the previous revision   crash-looping while replaced: not a crash loop
#   no cluster listing      no verdict, the rollout's own status
#   PROFILE=5g              profile_rollout fails at the crash-looping ue
#   every wait              deploy-eks.sh and the profiles call no bare
#                           `kubectl rollout status`
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EKS="$(cd "${HERE}/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin"

# The ue Deployment at revision 2 (ReplicaSet hash "new"), the revision-1
# ReplicaSet ("old") it replaces, and the mongodb StatefulSet.
cat >"${T}/workloads.json" <<'JSON'
{"items": [
 {"kind": "Deployment", "metadata": {"name": "ue", "uid": "u1",
   "annotations": {"deployment.kubernetes.io/revision": "2"}},
  "spec": {"selector": {"matchLabels": {"app.kubernetes.io/name": "ue"}}}},
 {"kind": "ReplicaSet", "metadata": {"name": "ue-new", "labels": {"pod-template-hash": "new"},
   "annotations": {"deployment.kubernetes.io/revision": "2"}, "ownerReferences": [{"uid": "u1"}]}},
 {"kind": "ReplicaSet", "metadata": {"name": "ue-old", "labels": {"pod-template-hash": "old"},
   "annotations": {"deployment.kubernetes.io/revision": "1"}, "ownerReferences": [{"uid": "u1"}]}}
]}
JSON
# pods_json HASH WAITING RESTARTS READY
pods_json() {
  local state=""
  [[ -n "$2" ]] && state="\"state\": {\"waiting\": {\"reason\": \"$2\"}},"
  cat <<JSON
{"items": [{"metadata": {"name": "ue-$1-x", "labels": {"app.kubernetes.io/name": "ue", "pod-template-hash": "$1"}},
  "status": {"containerStatuses": [{"name": "ue", ${state} "restartCount": $3, "ready": $4}]}}]}
JSON
}

cat >"${T}/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"${STUB_LOG}"
case "$1 $2" in
  "rollout status")
    sleep "${STUB_ROLLOUT_SECS:-30}"
    exit "${STUB_ROLLOUT_RC:-0}" ;;
  "get deployments,statefulsets,replicasets")
    [[ -n "${STUB_NO_LIST:-}" ]] && exit 1
    cat "${STUB_WORKLOADS}" ;;
  "get pods")
    [[ -n "${STUB_NO_LIST:-}" ]] && exit 1
    cat "${STUB_PODS}" ;;
  logs*)
    [[ " $* " == *" --previous "* ]] && echo "panic: ue lost its IPv6 sysctl (previous run)"
    ;;
esac
exit 0
STUB
chmod +x "${T}/bin/kubectl"

n=0 bad=0
ok()  { n=$((n + 1)); echo "ok ${n} - $*"; }
nok() { n=$((n + 1)); bad=$((bad + 1)); echo "not ok ${n} - $*"; }

# wait_on PODS_FIXTURE [die] -> rc in ${rc}, seconds in ${took}, output in ${T}/out
wait_on() {
  printf '%s\n' "$1" >"${T}/pods.json"
  : >"${T}/log"
  local start; start=$(date +%s)
  (
    log()  { echo "[log] $*"; }
    warn() { echo "[warn] $*"; }
    [[ "${2:-}" == die ]] && die() { echo "[fail] $*"; exit 1; }
    # shellcheck source=profile.sh
    source "${HERE}/profile.sh"
    NAMESPACE=nextg-demo STUB_LOG="${T}/log" STUB_WORKLOADS="${T}/workloads.json" \
      STUB_PODS="${T}/pods.json" NEXTG_ROLLOUT_POLL=1 PATH="${T}/bin:${PATH}" \
      nextg_rollout_wait deployment/ue 300
  ) >"${T}/out" 2>&1
  rc=$?
  took=$(( $(date +%s) - start ))
}

wait_on "$(pods_json new CrashLoopBackOff 2 false)"
if [[ ${rc} == 3 && ${took} -lt 10 ]] \
  && grep -q '^\[warn\] deployment/ue: pod ue-new-x container ue is crash-looping (CrashLoopBackOff, 2 restarts)' "${T}/out" \
  && grep -q 'panic: ue lost its IPv6 sysctl (previous run)' "${T}/out" \
  && grep -qx 'rollout status deployment/ue -n nextg-demo --timeout=300s' "${T}/log"; then
  ok "CrashLoopBackOff: returns 3 in ${took}s with the last log lines"
else nok "CrashLoopBackOff: rc ${rc} in ${took}s: $(cat "${T}/out")"; fi

wait_on "$(pods_json new "" 4 false)"
[[ ${rc} == 3 && ${took} -lt 10 ]] && grep -q 'crash-looping (Restarting, 4 restarts)' "${T}/out" \
  && ok "4 restarts, not Ready: returns 3 in ${took}s" || nok "restarts: rc ${rc} in ${took}s: $(cat "${T}/out")"

wait_on "$(pods_json new CrashLoopBackOff 2 false)" die
[[ ${rc} == 1 && ${took} -lt 10 ]] \
  && grep -q '^\[fail\] deployment/ue is crash-looping; not waiting out its 300s rollout timeout' "${T}/out" \
  && ok "with die defined: the deploy fails through it" || nok "die: rc ${rc}: $(cat "${T}/out")"

STUB_ROLLOUT_SECS=2 wait_on "$(pods_json new "" 0 true)"
[[ ${rc} == 0 ]] && ! grep -q crash-looping "${T}/out" \
  && ok "healthy: the rollout's status, no warning" || nok "healthy: rc ${rc}: $(cat "${T}/out")"

export STUB_ROLLOUT_SECS=2 STUB_ROLLOUT_RC=1
wait_on "$(pods_json old CrashLoopBackOff 12 false)"
[[ ${rc} == 1 ]] && ! grep -q crash-looping "${T}/out" \
  && ok "the previous revision's crash loop being replaced is not one" \
  || nok "previous revision: rc ${rc}: $(cat "${T}/out")"

STUB_NO_LIST=1 wait_on "$(pods_json new CrashLoopBackOff 2 false)"
[[ ${rc} == 1 ]] && ! grep -q crash-looping "${T}/out" \
  && ok "no cluster listing: no verdict, the rollout's status" || nok "no listing: rc ${rc}: $(cat "${T}/out")"
unset STUB_ROLLOUT_SECS STUB_ROLLOUT_RC

# PROFILE=5g end to end: every wait but the ue's passes at once; the ue
# crash-loops, so profile_rollout fails there instead of after 300 s.
cat >"${T}/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"${STUB_LOG}"
case "$1 $2" in
  "rollout status") [[ "$3" == deployment/ue ]] && sleep 60; exit 0 ;;
  "get deployments,statefulsets,replicasets") cat "${STUB_WORKLOADS}" ;;
  "get pods") cat "${STUB_PODS}" ;;
esac
exit 0
STUB
printf '%s\n' "$(pods_json new CrashLoopBackOff 3 false)" >"${T}/pods.json"
: >"${T}/log"
start=$(date +%s)
(
  log()  { echo "[log] $*"; }
  warn() { echo "[warn] $*"; }
  die()  { echo "[fail] $*"; exit 1; }
  # shellcheck source=profile.sh
  source "${HERE}/profile.sh"
  nextg_load_profile 5g || exit 3
  NAMESPACE=nextg-demo STUB_LOG="${T}/log" STUB_WORKLOADS="${T}/workloads.json" \
    STUB_PODS="${T}/pods.json" NEXTG_ROLLOUT_POLL=1 PATH="${T}/bin:${PATH}" profile_rollout
) >"${T}/out" 2>&1
rc=$?
took=$(( $(date +%s) - start ))
if [[ ${rc} == 1 && ${took} -lt 30 ]] && grep -q '^\[fail\] deployment/ue is crash-looping' "${T}/out" \
  && grep -qx 'rollout status deployment/gnb -n nextg-demo --timeout=300s' "${T}/log"; then
  ok "PROFILE=5g: profile_rollout fails at the crash-looping ue in ${took}s"
else nok "PROFILE=5g: rc ${rc} in ${took}s: $(cat "${T}/out")"; fi

# Every rollout wait of deploy-eks.sh and the profiles goes through it.
raw="$(grep -nE '^[[:space:]]*kubectl rollout status' "${EKS}/deploy-eks.sh" "${EKS}"/profiles/*/profile.env)"
[[ -z "${raw}" ]] && ok "no bare kubectl rollout status wait is left" || nok "bare waits: ${raw}"

echo "1..${n}"
[[ ${bad} == 0 ]]
