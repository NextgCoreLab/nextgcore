#!/usr/bin/env bash
# Run one demo arm on EKS and capture its evidence (nextgcore#1395, nextgsim#458).
#
#   k8s/demo-check.sh <key> <mode>      deploy/eks/overlays/demo-<key>, mode <mode>
#   k8s/demo-check.sh off off           the demo-OFF control: deploy/eks/overlays/demo
#
# Steps:
#   1. deploy the overlay with PROFILE=demo deploy/eks/deploy-eks.sh into its own
#      namespace (nextg-demo) and wait until every Deployment is Available;
#   2. run the base e2e (PROFILE=demo deploy/eks/e2e-internet.sh) and the demo's
#      seeded scenario, deploy/eks/overlays/demo-<key>/scenario.sh, if it has one;
#   3. capture the ordered log chain, a /metrics scrape of every NF, the pod
#      events and the pod/image list into /tmp/eks-val/demos/<key>/<mode>/<UTC>/
#      (and the `latest` link beside it);
#   4. print PASS or FAIL from the assertions below;
#   5. delete the namespace, on success AND on failure (KEEP=true keeps it).
#
# Assertions every run makes, on top of the e2e and the scenario:
#   off      no process logged "DEMO MODE ACTIVE", no "[demo:" line, and no scrape
#            has a nextg_demo_enabled series: the demo-off arm is the base core.
#   <key>    some process logged "DEMO MODE ACTIVE: ...<key>=<mode>..." and some
#            scrape has nextg_demo_enabled{demo="<key>",mode="<mode>"} 1.
#
# Environment:
#   KUBE_CONTEXT       kubeconfig context to deploy into (default devtest1). The
#                      run uses a private copy of that context; your current
#                      context is neither used nor changed.
#   YES=true           do not ask for confirmation
#   KEEP=true          leave the namespace up afterwards
#   OUT_ROOT           artefact root (default /tmp/eks-val/demos)
#   ENABLE_DATAPLANE   default true (the e2e needs the data-plane UPF)
#   EPHEMERAL_STORAGE  default true (devtest1 has no EBS CSI StorageClass)
#   CORE_IMAGE_TAG / SIM_IMAGE_TAG / IMAGE_TAG   passed to deploy-eks.sh
#
# Private by default: nothing here publishes a port or opens a port-forward.
# Metrics are read with `kubectl exec` inside each pod; the artefacts hold no
# Secret, and log lines are scrubbed of bearer tokens, JWTs and 128-bit hex keys.
#
# Exit: 0 PASS, 1 FAIL, 2 usage or environment error.
set -uo pipefail

usage() { sed -n '2,40p' "$0"; exit 2; }
[[ $# -eq 2 ]] || usage
KEY="$1"; MODE="$2"
NAME_RE='^[a-z0-9][a-z0-9-]*$'
[[ "${KEY}" =~ ${NAME_RE} && "${MODE}" =~ ${NAME_RE} ]] \
  || { echo "key and mode must be [a-z0-9-]+" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
EKS_DIR="${CORE_DIR}/deploy/eks"
NS="nextg-demo"

if [[ "${KEY}" == off ]]; then
  [[ "${MODE}" == off ]] || { echo "the demo-off control is: $0 off off" >&2; exit 2; }
  OVERLAY="demo"; DEMO_KEY=""; DEMO_MODE=""
else
  OVERLAY="demo-${KEY}"; DEMO_KEY="${KEY}"; DEMO_MODE="${MODE}"
  [[ -f "${EKS_DIR}/overlays/${OVERLAY}/kustomization.yaml" ]] \
    || { echo "no overlay deploy/eks/overlays/${OVERLAY}/" >&2; exit 2; }
fi

KUBE_CONTEXT="${KUBE_CONTEXT:-devtest1}"
OUT_ROOT="${OUT_ROOT:-/tmp/eks-val/demos}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT_ROOT}/${KEY}/${MODE}/${STAMP}"
mkdir -p "${OUT}/logs" "${OUT}/metrics" || exit 2
ln -sfn "${STAMP}" "${OUT_ROOT}/${KEY}/${MODE}/latest"

log()  { printf '\033[0;32m[demo-check]\033[0m %s\n' "$*" | tee -a "${OUT}/run.log"; }
fail_env() { printf '\033[0;31m[demo-check]\033[0m %s\n' "$*" | tee -a "${OUT}/run.log" >&2; exit 2; }

# A private kubeconfig holding only KUBE_CONTEXT, so deploy-eks.sh (which uses
# the current context) cannot land on whatever context the shell had.
KCFG="$(mktemp -t nextg-demo-kcfg-XXXXXX)"
chmod 600 "${KCFG}"
kubectl config view --minify --flatten --context "${KUBE_CONTEXT}" > "${KCFG}" 2>/dev/null \
  || fail_env "kubeconfig has no context ${KUBE_CONTEXT}"
export KUBECONFIG="${KCFG}"
K=(kubectl -n "${NS}")

TORN_DOWN=false
TEARDOWN=kept
teardown() {
  [[ "${TORN_DOWN}" == true ]] && return
  TORN_DOWN=true
  if [[ "${KEEP:-false}" == true ]]; then
    log "KEEP=true: namespace ${NS} left up"
  elif kubectl get namespace "${NS}" >/dev/null 2>&1; then
    log "teardown: deleting namespace ${NS}"
    kubectl delete namespace "${NS}" --wait=true --timeout=600s >>"${OUT}/run.log" 2>&1
    if kubectl get namespace "${NS}" >/dev/null 2>&1; then
      TEARDOWN=incomplete
      log "teardown: namespace ${NS} still present after 600 s"
    else
      TEARDOWN=ok
      log "teardown: namespace ${NS} gone"
    fi
  fi
  rm -f "${KCFG}"
}
trap teardown EXIT

kubectl cluster-info >/dev/null 2>&1 || fail_env "cannot reach cluster ${KUBE_CONTEXT}"
if kubectl get namespace "${NS}" >/dev/null 2>&1; then
  TORN_DOWN=true   # not ours: never delete a namespace this run did not create
  fail_env "namespace ${NS} already exists (another demo run?). Delete it or wait."
fi

log "cluster=${KUBE_CONTEXT} namespace=${NS} overlay=${OVERLAY} key=${KEY} mode=${MODE}"
log "artefacts: ${OUT}"
if [[ "${YES:-false}" != true ]]; then
  read -r -p "Deploy ${OVERLAY} into ${KUBE_CONTEXT}/${NS}? [y/N] " reply
  [[ "${reply}" =~ ^[Yy]$ ]] || { TORN_DOWN=true; log "aborted"; exit 2; }
fi

# --- 1. deploy ---------------------------------------------------------------
log "deploying (deploy-eks.sh PROFILE=demo, log: deploy.log)"
if ! echo y | env PROFILE=demo DEMO_OVERLAY="${OVERLAY}" DEMO_KEY="${DEMO_KEY}" DEMO_MODE="${DEMO_MODE}" \
    ENABLE_DATAPLANE="${ENABLE_DATAPLANE:-true}" EPHEMERAL_STORAGE="${EPHEMERAL_STORAGE:-true}" \
    "${EKS_DIR}/deploy-eks.sh" >"${OUT}/deploy.log" 2>&1; then
  DEPLOY_OK=false
  log "deploy-eks.sh FAILED (tail of deploy.log follows)"; tail -20 "${OUT}/deploy.log" | tee -a "${OUT}/run.log"
else
  DEPLOY_OK=true
fi
if [[ "${DEPLOY_OK}" == true ]]; then
  "${K[@]}" wait --for=condition=Available deployment --all --timeout=600s >>"${OUT}/run.log" 2>&1 \
    || { DEPLOY_OK=false; log "not every Deployment became Available within 600 s"; }
fi

# --- 2. e2e and scenario -------------------------------------------------------
E2E_RC=skipped; SCEN_RC=none
if [[ "${DEPLOY_OK}" == true ]]; then
  log "base e2e (PROFILE=demo e2e-internet.sh, log: e2e-internet.log)"
  PROFILE=demo "${EKS_DIR}/e2e-internet.sh" >"${OUT}/e2e-internet.log" 2>&1; E2E_RC=$?
  SCEN="${EKS_DIR}/overlays/${OVERLAY}/scenario.sh"
  if [[ -x "${SCEN}" ]]; then
    log "demo scenario ${OVERLAY}/scenario.sh (log: scenario.log)"
    NAMESPACE="${NS}" DEMO_KEY="${DEMO_KEY}" DEMO_MODE="${DEMO_MODE}" OUT="${OUT}" \
      "${SCEN}" >"${OUT}/scenario.log" 2>&1; SCEN_RC=$?
  fi
fi

# --- 3. capture ----------------------------------------------------------------
scrub() {
  sed -E -e 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1[REDACTED]/g' \
         -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/[REDACTED-JWT]/g' \
         -e 's/\b[0-9a-fA-F]{32}\b/[REDACTED-HEX128]/g'
}
log "capturing pods, events, logs and /metrics"
"${K[@]}" get pods -o wide >"${OUT}/pods.txt" 2>&1
"${K[@]}" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*]}{.image}{" "}{end}{"\n"}{end}' \
  >"${OUT}/images.txt" 2>&1
"${K[@]}" get events --sort-by=.lastTimestamp -o wide 2>&1 | scrub >"${OUT}/events.txt"
for pod in $("${K[@]}" get pods -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
  for c in $("${K[@]}" get pod "${pod}" -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null); do
    "${K[@]}" logs "${pod}" -c "${c}" --timestamps 2>/dev/null | scrub >"${OUT}/logs/${pod}_${c}.log"
    [[ -s "${OUT}/logs/${pod}_${c}.log" ]] || rm -f "${OUT}/logs/${pod}_${c}.log"
  done
  if "${K[@]}" get pod "${pod}" -o jsonpath='{.spec.containers[0].ports[*].containerPort}' 2>/dev/null \
      | tr ' ' '\n' | grep -qx 9090; then
    ip="$("${K[@]}" get pod "${pod}" -o jsonpath='{.status.podIP}')"
    c0="$("${K[@]}" get pod "${pod}" -o jsonpath='{.spec.containers[0].name}')"
    "${K[@]}" exec "${pod}" -c "${c0}" -- sh -c \
      "curl -s --max-time 5 http://${ip}:9090/metrics || curl -s --max-time 5 http://127.0.0.1:9090/metrics" \
      >"${OUT}/metrics/${pod}.prom" 2>/dev/null
    [[ -s "${OUT}/metrics/${pod}.prom" ]] || rm -f "${OUT}/metrics/${pod}.prom"
  fi
done
# One ordered chain: every line of every container, by its kubelet timestamp.
for f in "${OUT}"/logs/*.log; do
  [[ -e "${f}" ]] || continue
  b="$(basename "${f}" .log)"
  sed "s/^\([^ ]*\) /\1 [${b}] /" "${f}"
done | sort -s -k1,1 >"${OUT}/log-chain.txt"
if [[ -n "${DEMO_KEY}" ]]; then
  grep -E "DEMO MODE ACTIVE|\[demo:${DEMO_KEY}\]" "${OUT}/log-chain.txt" >"${OUT}/demo-chain.txt"
fi

# --- 4. verdict ----------------------------------------------------------------
FAILS=()
[[ "${DEPLOY_OK}" == true ]] || FAILS+=("deploy")
[[ "${E2E_RC}" == 0 ]] || FAILS+=("base e2e (rc ${E2E_RC})")
[[ "${SCEN_RC}" == none || "${SCEN_RC}" == 0 ]] || FAILS+=("scenario (rc ${SCEN_RC})")
metric_hits="$(cat "${OUT}"/metrics/*.prom 2>/dev/null | grep -c '^nextg_demo_enabled{' || true)"
banner_hits="$(grep -c 'DEMO MODE ACTIVE' "${OUT}/log-chain.txt" || true)"
prefix_hits="$(grep -c '\[demo:' "${OUT}/log-chain.txt" || true)"
scrapes="$(find "${OUT}/metrics" -name '*.prom' | wc -l)"
[[ "${scrapes}" -gt 0 ]] || FAILS+=("no /metrics scrape captured")
if [[ -z "${DEMO_KEY}" ]]; then
  [[ "${banner_hits}" == 0 ]] || FAILS+=("demo-off: ${banner_hits} DEMO MODE ACTIVE line(s)")
  [[ "${prefix_hits}" == 0 ]] || FAILS+=("demo-off: ${prefix_hits} [demo: line(s)")
  [[ "${metric_hits}" == 0 ]] || FAILS+=("demo-off: ${metric_hits} nextg_demo_enabled series")
else
  grep -q "DEMO MODE ACTIVE:.*\b${DEMO_KEY}=${DEMO_MODE}\b" "${OUT}/log-chain.txt" \
    || FAILS+=("no DEMO MODE ACTIVE banner for ${DEMO_KEY}=${DEMO_MODE}")
  cat "${OUT}"/metrics/*.prom 2>/dev/null \
    | grep -qF "nextg_demo_enabled{demo=\"${DEMO_KEY}\",mode=\"${DEMO_MODE}\"} 1" \
    || FAILS+=("no nextg_demo_enabled{demo=${DEMO_KEY},mode=${DEMO_MODE}} series")
fi

{
  echo "key=${KEY} mode=${MODE} overlay=${OVERLAY} cluster=${KUBE_CONTEXT} namespace=${NS} at=${STAMP}"
  echo "core=$(git -C "${CORE_DIR}" rev-parse --short=12 HEAD) sim=$(git -C "${CORE_DIR}/../nextgsim" rev-parse --short=12 HEAD 2>/dev/null)"
  echo "deploy=${DEPLOY_OK} e2e_rc=${E2E_RC} scenario_rc=${SCEN_RC} scrapes=${scrapes}"
  echo "demo_banner_lines=${banner_hits} demo_prefix_lines=${prefix_hits} nextg_demo_enabled_series=${metric_hits}"
  if [[ ${#FAILS[@]} -eq 0 ]]; then echo "VERDICT: PASS"; else printf 'FAIL: %s\n' "${FAILS[@]}"; echo "VERDICT: FAIL"; fi
} >"${OUT}/verdict.txt"
teardown
echo "teardown=${TEARDOWN}" >>"${OUT}/verdict.txt"
if [[ "${TEARDOWN}" == incomplete ]]; then
  FAILS+=("teardown incomplete")
  echo "VERDICT: FAIL (teardown incomplete)" >>"${OUT}/verdict.txt"
fi
tee -a "${OUT}/run.log" <"${OUT}/verdict.txt"
[[ ${#FAILS[@]} -eq 0 ]]
