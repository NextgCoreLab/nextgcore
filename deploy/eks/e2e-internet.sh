#!/usr/bin/env bash
# UE-to-internet check for a deployed EKS profile.
#
#   PROFILE=5g ./e2e-internet.sh            # default namespace for the profile
#   NAMESPACE=nextg-system ./e2e-internet.sh
#
# What it proves, from INSIDE the UE pod's network namespace, with the UE's own
# PDU-session address as the source of every packet:
#
#   1. ping -I <tun> -c 10 8.8.8.8 has 0% loss
#   2. DNS through the tunnel: dig @8.8.8.8 -b <UE IP> example.com answers
#   3. HTTPS through the tunnel: curl --interface <tun> --resolve <dig answer>
#      returns 200
#   4. the UPF's "Data plane stats" UL and DL packet counters both increased,
#      so the traffic really crossed the UPF and was not leaked out of eth0
#
# No image change is needed: the tools come from an ephemeral
# `kubectl debug --target=<ue> --profile=netadmin` netshoot container. The pod
# shares one network namespace, so the debug container sees the UE's TUN.
#
# Why a policy route. The UE container's main routing table only knows eth0.
# `ping -I`/`curl --interface` bind to the TUN, but DNS (dig -b) and any reply
# path would otherwise follow the main table out of eth0 - "internet works"
# without ever touching the 5G core. A temporary rule
#     ip rule add from <UE IP> lookup 145
#     ip route add default dev <tun> table 145
# sends every packet sourced from the UE address into the PDU session. It is
# removed on exit, including on failure or Ctrl-C.
#
# Each run adds one (terminated after DEBUG_TTL seconds) ephemeral container to
# the UE pod: Kubernetes cannot remove ephemeral containers. They go away with
# the pod at the next rollout.
#
# Exit status: 0 when every step PASSes, 1 when any step FAILs, 2 on a usage or
# environment error (no UE pod, no TUN, ...). PROFILE=epc additionally checks
# the LTE attach (S1 Setup, EMM-REGISTERED, default bearer) from the logs.
# PROFILE=6g adds its section when that profile lands.
set -uo pipefail

PROFILE="${PROFILE:-5g}"
for arg in "$@"; do
  case "${arg}" in
    PROFILE=*) PROFILE="${arg#PROFILE=}" ;;
    NAMESPACE=*) NAMESPACE="${arg#NAMESPACE=}" ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/profile.sh
source "${SCRIPT_DIR}/lib/profile.sh"
nextg_load_profile "${PROFILE}" || exit 2

case "${PROFILE}" in
  5g)
    NAMESPACE="${NAMESPACE:-${PROFILE_NAMESPACE}}"
    UE_SELECTOR="${UE_SELECTOR:-app.kubernetes.io/name=ue}"
    UE_CONTAINER="${UE_CONTAINER:-ue}"
    UPF_SELECTOR="${UPF_SELECTOR:-app.kubernetes.io/name=upf}"
    UPF_CONTAINER="${UPF_CONTAINER:-upf}"
    # nextgsim's UE names each PDU session's interface <tun_name><N> (nextgsim
    # #427), so the name depends on its config and on how many sessions it
    # has. Found below as the first uesimtun* interface with an IPv4 address,
    # as docker/rust/ue-flow-check.sh does; TUN=<name> pins one (#1326).
    TUN="${TUN:-}"
    TUN_PREFIX="${TUN_PREFIX:-uesimtun}"
    ;;
  epc)
    # The LTE UE puts the default bearer's PDN address on lteuetun<EBI>; the
    # default bearer is EBI 5. The PGW-U is upfd, so it logs the same
    # "Data plane stats" line as the 5G UPF.
    NAMESPACE="${NAMESPACE:-${PROFILE_NAMESPACE}}"
    UE_SELECTOR="${UE_SELECTOR:-app.kubernetes.io/name=lte-ue}"
    UE_CONTAINER="${UE_CONTAINER:-lte-ue}"
    UPF_SELECTOR="${UPF_SELECTOR:-app.kubernetes.io/name=pgwu}"
    UPF_CONTAINER="${UPF_CONTAINER:-pgwu}"
    TUN="${TUN:-lteuetun5}"
    ;;
  # A new profile adds a section here, setting the same six knobs: the UE pod
  # selector and container, the core user-plane pod (whose log carries the
  # "Data plane stats" line) and container, and the UE tunnel interface.
  # NAMESPACE comes from the profile's profile.env.
  *)
    echo "PROFILE=${PROFILE} has no e2e-internet section yet (5g, epc)" >&2
    exit 2
    ;;
esac

PING_TARGET="${PING_TARGET:-8.8.8.8}"
DNS_SERVER="${DNS_SERVER:-8.8.8.8}"
HTTP_HOST="${HTTP_HOST:-example.com}"
DEBUG_IMAGE="${DEBUG_IMAGE:-nicolaka/netshoot:v0.13}"
DEBUG_TTL="${DEBUG_TTL:-300}"
RT_TABLE="${RT_TABLE:-145}"
# The UPF logs its counters every 30 s; allow one full period plus slack.
STATS_WAIT="${STATS_WAIT:-45}"

KUBECTL=(kubectl -n "${NAMESPACE}")
FAILS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
die()  { echo "ERROR $*" >&2; exit 2; }

running_pod() {
  "${KUBECTL[@]}" get pods -l "$1" --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

UE_POD="$(running_pod "${UE_SELECTOR}")"
[[ -n "${UE_POD}" ]] || die "no Running UE pod (${UE_SELECTOR}) in ${NAMESPACE}"
UPF_POD="$(running_pod "${UPF_SELECTOR}")"
[[ -n "${UPF_POD}" ]] || die "no Running UPF pod (${UPF_SELECTOR}) in ${NAMESPACE}"
echo "profile=${PROFILE} namespace=${NAMESPACE} ue=${UE_POD} upf=${UPF_POD}"

# ---- EPC signalling ---------------------------------------------------------
# The attach chain, from the full logs of the running pods, with the patterns of
# docker/rust/epc-attach-check.sh (the nightly EPC stage): S1 Setup accepted,
# EMM-REGISTERED, and the SAME default-bearer EBI on the UE and the MME.
if [[ "${PROFILE}" == epc ]]; then
  MME_LOG="$("${KUBECTL[@]}" logs deployment/mme -c mme --tail=-1 2>/dev/null)"
  UE_LOG="$("${KUBECTL[@]}" logs "${UE_POD}" -c "${UE_CONTAINER}" --tail=-1 2>/dev/null)"
  if line="$(grep -Em1 'S1 Setup: eNB 0x[0-9a-fA-F]+ .*accepted' <<<"${MME_LOG}")"; then
    pass "S1 Setup accepted by the MME: ${line##*] }"
  else
    fail "S1 Setup: no 'S1 Setup: eNB ... accepted' in the mme log"
  fi
  if grep -q 'EMM-REGISTERED' <<<"${UE_LOG}"; then
    pass "UE reached EMM-REGISTERED"
  else
    fail "UE never logged EMM-REGISTERED"
  fi
  EBI="$(grep -Eo 'default EPS bearer [0-9]+ activated' <<<"${UE_LOG}" | head -n1 | awk '{print $4}')"
  if [[ -n "${EBI}" ]] && grep -Eq "Default EPS bearer \(ebi=${EBI}\) activated" <<<"${MME_LOG}"; then
    pass "default EPS bearer EBI ${EBI} activated on the UE and the MME"
  else
    fail "default EPS bearer: UE EBI '${EBI:-none}' not activated in the mme log"
  fi
fi

# ---- UPF counters ---------------------------------------------------------
# "Data plane stats: UL=47 pkts/4590 B, DL=44 pkts/13675 B, dropped=9 ..."
# Prints "<ul_pkts> <dl_pkts>" from the newest stats line, "0 0" when none yet.
upf_counters() {
  "${KUBECTL[@]}" logs "${UPF_POD}" -c "${UPF_CONTAINER}" --tail=400 2>/dev/null \
    | sed -n 's/.*Data plane stats: UL=\([0-9]*\) pkts.*DL=\([0-9]*\) pkts.*/\1 \2/p' \
    | tail -n 1 | grep . || echo "0 0"
}
read -r UL0 DL0 < <(upf_counters)
echo "UPF counters before: UL=${UL0} DL=${DL0} pkts"

# ---- debug container ------------------------------------------------------
DBG="e2e-inet-$(date +%s)"
"${KUBECTL[@]}" debug "${UE_POD}" --target="${UE_CONTAINER}" --profile=netadmin \
  --image="${DEBUG_IMAGE}" --container="${DBG}" -- sleep "${DEBUG_TTL}" >/dev/null \
  || die "kubectl debug failed"
for _ in $(seq 1 60); do
  state="$("${KUBECTL[@]}" get pod "${UE_POD}" \
    -o jsonpath="{.status.ephemeralContainerStatuses[?(@.name=='${DBG}')].state.running.startedAt}")"
  [[ -n "${state}" ]] && break
  sleep 2
done
[[ -n "${state:-}" ]] || die "debug container ${DBG} never started"
dbg() { "${KUBECTL[@]}" exec "${UE_POD}" -c "${DBG}" -- "$@"; }

if [[ -z "${TUN}" ]]; then
  TUN="$(dbg sh -c "ip -4 -o addr show | awk '\$2 ~ /^${TUN_PREFIX}/ { print \$2; exit }'")"
  [[ -n "${TUN}" ]] \
    || die "no ${TUN_PREFIX}* interface with an IPv4 address in ${UE_POD} (interfaces: $(dbg sh -c "ip -o link show | awk -F': ' '{print \$2}' | tr '\n' ' '")): is the PDU session up?"
fi
UE_IP="$(dbg sh -c "ip -4 -o addr show dev ${TUN} | awk '{print \$4}' | cut -d/ -f1 | head -n1")"
[[ "${UE_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || die "no IPv4 address on ${TUN} in ${UE_POD} (interfaces: $(dbg sh -c "ip -o link show | awk -F': ' '{print \$2}' | tr '\n' ' '")): is the PDU session up?"
echo "UE IP on ${TUN}: ${UE_IP}"

# shellcheck disable=SC2317  # invoked by the EXIT trap
cleanup() {
  dbg sh -c "ip rule del from ${UE_IP} lookup ${RT_TABLE} priority ${RT_TABLE} 2>/dev/null; \
             ip route flush table ${RT_TABLE} 2>/dev/null; true" >/dev/null 2>&1 \
    && echo "policy route removed" \
    || echo "WARN could not remove the policy route; run: kubectl -n ${NAMESPACE} exec ${UE_POD} -c ${DBG} -- ip rule del from ${UE_IP} lookup ${RT_TABLE}" >&2
}
trap cleanup EXIT
trap 'exit 130' INT TERM

dbg sh -c "set -e
  ip route replace default dev ${TUN} table ${RT_TABLE}
  ip rule del from ${UE_IP} lookup ${RT_TABLE} priority ${RT_TABLE} 2>/dev/null || true
  ip rule add from ${UE_IP} lookup ${RT_TABLE} priority ${RT_TABLE}" \
  || die "could not install the policy route"
echo "policy route: from ${UE_IP} lookup ${RT_TABLE}; default dev ${TUN} table ${RT_TABLE}"

# ---- 1. ping --------------------------------------------------------------
PING_OUT="$(dbg ping -I "${TUN}" -c 10 -W 2 "${PING_TARGET}" 2>&1)"
LOSS="$(sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p' <<<"${PING_OUT}")"
if [[ "${LOSS}" == "0" ]]; then
  pass "ping -I ${TUN} -c 10 ${PING_TARGET}: 0% loss"
else
  fail "ping -I ${TUN} -c 10 ${PING_TARGET}: ${LOSS:-?}% loss"
  echo "${PING_OUT}" | tail -n 4 | sed 's/^/      /'
fi

# ---- 2. DNS through the tunnel ---------------------------------------------
DIG_OUT="$(dbg dig +short +time=3 +tries=2 "@${DNS_SERVER}" -b "${UE_IP}" "${HTTP_HOST}" A 2>&1)"
HTTP_IP="$(grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"${DIG_OUT}" | head -n 1)"
if [[ -n "${HTTP_IP}" ]]; then
  pass "dig @${DNS_SERVER} -b ${UE_IP} ${HTTP_HOST}: ${HTTP_IP}"
else
  fail "dig @${DNS_SERVER} -b ${UE_IP} ${HTTP_HOST}: no A record ($(head -n1 <<<"${DIG_OUT}"))"
fi

# ---- 3. HTTPS through the tunnel -------------------------------------------
if [[ -n "${HTTP_IP}" ]]; then
  CODE="$(dbg curl --interface "${TUN}" --resolve "${HTTP_HOST}:443:${HTTP_IP}" \
    -sS -o /dev/null -m 20 -w '%{http_code}' "https://${HTTP_HOST}/" 2>&1)"
  if [[ "${CODE}" == "200" ]]; then
    pass "curl --interface ${TUN} https://${HTTP_HOST} (${HTTP_IP}): 200"
  else
    fail "curl --interface ${TUN} https://${HTTP_HOST} (${HTTP_IP}): ${CODE}"
  fi
else
  fail "curl --interface ${TUN} https://${HTTP_HOST}: skipped, DNS gave no address"
fi

# ---- 4. UPF counters ------------------------------------------------------
UL1="${UL0}"; DL1="${DL0}"
for _ in $(seq 1 $((STATS_WAIT / 5))); do
  read -r UL1 DL1 < <(upf_counters)
  (( UL1 > UL0 && DL1 > DL0 )) && break
  sleep 5
done
if (( UL1 > UL0 && DL1 > DL0 )); then
  pass "UPF data plane stats: UL ${UL0}->${UL1} pkts, DL ${DL0}->${DL1} pkts"
else
  fail "UPF data plane stats did not increase within ${STATS_WAIT}s: UL ${UL0}->${UL1}, DL ${DL0}->${DL1}"
fi

echo
if (( FAILS == 0 )); then
  echo "e2e-internet PROFILE=${PROFILE}: PASS"
  exit 0
fi
echo "e2e-internet PROFILE=${PROFILE}: FAIL (${FAILS} step(s))"
exit 1
