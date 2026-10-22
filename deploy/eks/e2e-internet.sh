#!/usr/bin/env bash
# UE-to-internet check for a deployed profile: signalling from the logs, then
# real traffic from the UE through its tunnel to the internet.
#
# Usage:
#   PROFILE=5g  ./e2e-internet.sh        # or: ./e2e-internet.sh PROFILE=5g
#   PROFILE=epc ./e2e-internet.sh
#
# Asserts, each on evidence only reachable when the step really happened:
#   1. Bring-up    every Deployment in the namespace is Available.
#   2. Signalling  5g:  "Received Registration Accept" and
#                       "PDU Session N is now ACTIVE" in the UE log;
#                  epc: the MME accepted S1 Setup, the UE reached
#                       EMM-REGISTERED, and the MME and UE agree on the EBI of
#                       the default EPS bearer. The patterns are those of
#                       docker/rust/epc-attach-check.sh, the nightly EPC stage.
#   3. Internet    from the UE's tunnel interface (uesimtun* / lteuetun*):
#                  - ping -I <tun> -c 10 8.8.8.8 with 0% loss;
#                  - DNS: dig @8.8.8.8 example.com, sourced from the tunnel
#                    address, so the query crosses the tunnel;
#                  - curl --interface <tun> https://example.com, resolved with
#                    THAT answer, which must print 200;
#                  - the UPF / PGW-U data-plane counters moved by at least the
#                    ping count, so the packets crossed its TUN path.
#
# The UE images ship ping and ip but no dig/curl. Those run in an ephemeral
# debug container (E2E_TOOLS_IMAGE) in the UE pod, so it shares the UE's
# network namespace and its tunnel. A policy route sends traffic SOURCED from
# the tunnel address out of the tunnel. dig can only bind a source address,
# not a device, so without it the query would leave via eth0 with a 10.45.x
# source and be dropped. The route is removed on exit.
#
# Read-only apart from that route and the ephemeral container, which a pod
# cannot shed (it goes with the pod's next restart).
set -euo pipefail

for arg in "$@"; do
  case "$arg" in
    PROFILE=*) PROFILE="${arg#PROFILE=}" ;;
    *) echo "unknown argument: $arg (usage: PROFILE=5g|epc $0)" >&2; exit 64 ;;
  esac
done
PROFILE="${PROFILE:-5g}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log()  { printf '\033[0;32m[e2e ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }
pass() { printf '\033[0;32m[ OK ]\033[0m %s\n' "$*"; }

# shellcheck source=lib/profile.sh
source "${SCRIPT_DIR}/lib/profile.sh"
nextg_load_profile "${PROFILE}" || exit 64
NAMESPACE="${PROFILE_NAMESPACE}"

PING_TARGET="${E2E_PING_TARGET:-8.8.8.8}"
PING_COUNT="${E2E_PING_COUNT:-10}"
DNS_SERVER="${E2E_DNS_SERVER:-8.8.8.8}"
URL_HOST="${E2E_URL_HOST:-example.com}"
TOOLS_IMAGE="${E2E_TOOLS_IMAGE:-nicolaka/netshoot:v0.13}"
TIMEOUT="${E2E_TIMEOUT:-180}"
RT_TABLE="${E2E_RT_TABLE:-145}"

case "${PROFILE}" in
  5g)
    UE_DEPLOY=ue; UE_CONTAINER=ue; TUN_PREFIX=uesimtun
    UPF_DEPLOY=upf; UPF_CONTAINER=upf
    ;;
  epc)
    UE_DEPLOY=lte-ue; UE_CONTAINER=lte-ue; TUN_PREFIX=lteuetun
    UPF_DEPLOY=pgwu; UPF_CONTAINER=pgwu
    ;;
  *) fail "no e2e definition for PROFILE=${PROFILE}" ;;
esac

command -v kubectl >/dev/null || fail "kubectl not found"
CTX="$(kubectl config current-context 2>/dev/null || true)"
log "context ${CTX:-?}, profile ${PROFILE}, namespace ${NAMESPACE}"

LOGDIR="$(mktemp -d -t nextg-e2e-XXXXXX)"
UE_POD=""
PDN=""
cleanup() {
  if [[ -n "${UE_POD}" && -n "${PDN}" ]]; then
    kubectl exec -n "${NAMESPACE}" "${UE_POD}" -c "${UE_CONTAINER}" -- sh -c \
      "ip rule del from ${PDN}/32 table ${RT_TABLE} 2>/dev/null; ip route flush table ${RT_TABLE} 2>/dev/null; true" \
      >/dev/null 2>&1 || true
  fi
  rm -f "${LOGDIR}"/*.log
  rmdir "${LOGDIR}" 2>/dev/null || true
}
trap cleanup EXIT

# wait_log <deploy> <container> <ERE> <what>: poll the FULL log until it matches.
wait_log() {
  local dep="$1" c="$2" re="$3" what="$4" f="${LOGDIR}/$1.log" i
  for ((i = 0; i < TIMEOUT; i += 2)); do
    kubectl logs -n "${NAMESPACE}" "deployment/${dep}" -c "${c}" --tail=-1 > "${f}" 2>&1 || true
    if grep -Eq "${re}" "${f}"; then
      pass "${what}"
      grep -E "${re}" "${f}" | head -1 | sed 's/^/       /'
      return 0
    fi
    sleep 2
  done
  echo "----- ${dep} (last 40 lines) -----" >&2
  tail -n 40 "${f}" >&2 || true
  fail "${what}: no line matching /${re}/ in ${dep} within ${TIMEOUT}s"
}

# --- 1. bring-up --------------------------------------------------------------

log "waiting for every Deployment in ${NAMESPACE} to be Available..."
kubectl wait --for=condition=Available deployment --all -n "${NAMESPACE}" \
  --timeout="${TIMEOUT}s" >/dev/null \
  || { kubectl get pods -n "${NAMESPACE}" -o wide >&2; fail "not every Deployment is Available"; }
pass "all Deployments Available ($(kubectl get deploy -n "${NAMESPACE}" --no-headers | wc -l | tr -d ' '))"

UE_POD="$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=${UE_DEPLOY}" \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
[[ -n "${UE_POD}" ]] || fail "no running ${UE_DEPLOY} pod"

# --- 2. signalling ------------------------------------------------------------

if [[ "${PROFILE}" == 5g ]]; then
  wait_log ue ue 'Received Registration Accept' "UE registered (Registration Accept)"
  wait_log ue ue 'PDU Session [0-9]+ is now ACTIVE' "PDU session ACTIVE"
else
  wait_log mme mme 'S1 Setup: eNB 0x[0-9a-fA-F]+ .*accepted' "S1 Setup accepted by the MME"
  wait_log lte-ue lte-ue 'EMM-REGISTERED' "UE reached EMM-REGISTERED"
  wait_log lte-ue lte-ue 'default EPS bearer [0-9]+ activated' "UE activated its default EPS bearer"
  ebi="$(grep -Eo 'default EPS bearer [0-9]+ activated' "${LOGDIR}/lte-ue.log" | head -1 | awk '{print $4}')"
  wait_log mme mme "Default EPS bearer \\(ebi=${ebi}\\) activated" \
    "MME activated the same default bearer (ebi=${ebi})"
fi

# --- 3. internet through the tunnel ------------------------------------------

uexec() { kubectl exec -n "${NAMESPACE}" "${UE_POD}" -c "${UE_CONTAINER}" -- "$@"; }

TUN=""
for ((i = 0; i < 60; i += 2)); do
  read -r TUN PDN < <(uexec ip -4 -o addr show 2>/dev/null \
    | awk -v p="^${TUN_PREFIX}" '$2 ~ p { split($4, a, "/"); print $2, a[1]; exit }') || true
  [[ -n "${TUN}" && -n "${PDN}" ]] && break
  sleep 2
done
[[ -n "${TUN}" && -n "${PDN}" ]] || fail "UE pod ${UE_POD} has no ${TUN_PREFIX}* interface with an IPv4 address"
pass "UE tunnel ${TUN} has ${PDN}"

counter() { # <metric> -> value on the UPF / PGW-U, or empty
  kubectl exec -n "${NAMESPACE}" "deployment/${UPF_DEPLOY}" -c "${UPF_CONTAINER}" -- \
    curl -fsS http://localhost:9090/metrics 2>/dev/null | awk -v m="$1" '$1 == m { print $2 }'
}
ul0="$(counter upf_dataplane_ul_packets_total || true)"
dl0="$(counter upf_dataplane_dl_packets_total || true)"

log "ping -I ${TUN} -c ${PING_COUNT} ${PING_TARGET}"
ping_out="$(uexec ping -I "${TUN}" -c "${PING_COUNT}" -W 3 "${PING_TARGET}" 2>&1 || true)"
# shellcheck disable=SC2001
echo "${ping_out}" | sed 's/^/       /'
echo "${ping_out}" | grep -qE '(^| )0% packet loss' \
  || fail "ping ${PING_TARGET} through ${TUN} lost packets"
pass "ping ${PING_TARGET}: ${PING_COUNT}/${PING_COUNT} replies through ${TUN} (0% loss)"

ul1="$(counter upf_dataplane_ul_packets_total || true)"
dl1="$(counter upf_dataplane_dl_packets_total || true)"
if [[ -n "${ul0}" && -n "${ul1}" && -n "${dl0}" && -n "${dl1}" ]]; then
  dul=$(( ${ul1%.*} - ${ul0%.*} )); ddl=$(( ${dl1%.*} - ${dl0%.*} ))
  (( dul >= PING_COUNT && ddl >= PING_COUNT )) \
    || fail "${UPF_DEPLOY} data-plane counters moved UL+${dul} DL+${ddl}, below ${PING_COUNT}"
  pass "${UPF_DEPLOY} counted the ping on its TUN path (UL +${dul}, DL +${ddl})"
else
  warn "${UPF_DEPLOY} exposes no upf_dataplane_* counters; skipped the counter check"
fi

# Policy route: anything sourced from the PDN address leaves through the tunnel.
uexec sh -c "ip rule add from ${PDN}/32 table ${RT_TABLE} 2>/dev/null || true; \
  ip route replace default dev ${TUN} table ${RT_TABLE}" \
  || fail "cannot install the policy route for ${PDN} via ${TUN}"

log "DNS + HTTPS via ${TUN} (tools: ${TOOLS_IMAGE}, ephemeral container in ${UE_POD})"
tools_out="$(kubectl debug -n "${NAMESPACE}" "pod/${UE_POD}" --image="${TOOLS_IMAGE}" \
  --target="${UE_CONTAINER}" -i --quiet -- sh -c "
    ip=\$(dig +short +time=3 +tries=3 -b ${PDN} @${DNS_SERVER} ${URL_HOST} A | grep -E '^[0-9.]+\$' | head -n1)
    echo \"DNS_ANSWER=\${ip}\"
    [ -n \"\${ip}\" ] || exit 0
    code=\$(curl --interface ${TUN} -sS -o /dev/null -m 20 -w '%{http_code}' \
      --resolve ${URL_HOST}:443:\${ip} https://${URL_HOST}/ 2>&1)
    echo \"HTTP_CODE=\${code}\"
  " 2>&1 || true)"
# shellcheck disable=SC2001
echo "${tools_out}" | sed 's/^/       /'
answer="$(echo "${tools_out}" | sed -n 's/^DNS_ANSWER=//p' | tail -1)"
code="$(echo "${tools_out}" | sed -n 's/^HTTP_CODE=//p' | tail -1)"
[[ "${answer}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "DNS through ${TUN}: no A record for ${URL_HOST} from ${DNS_SERVER}"
pass "DNS through ${TUN}: ${URL_HOST} -> ${answer} (from ${DNS_SERVER}, source ${PDN})"
[[ "${code}" == 200 ]] || fail "curl https://${URL_HOST} via ${TUN} printed '${code}', not 200"
pass "curl --interface ${TUN} https://${URL_HOST} -> 200"

echo
log "PROFILE=${PROFILE}: UE ${UE_POD} reaches the internet through ${TUN} (${PDN})."
