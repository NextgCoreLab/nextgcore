#!/usr/bin/env bash
# nrf-tls-gate.sh -- every NF registered at the NRF over TLS with its own
# certificate (nextgcore#1617). The Kubernetes form of the compose gate in
# .github/workflows/ci.yml ("Every NF registers at the NRF over TLS").
#
#   nrf-tls-gate.sh <namespace> [<nfType>...]
#
# POSITIVE half: each <nfType> (default: the base core, AUSF UDM UDR PCF NSSF
# BSF AMF SMF) has an instance REGISTERED at the NRF. The NRF serves only TLS,
# so each registration crossed the TLS listener. NEGATIVE half, which the
# positive one cannot give: the NRF counts every NFRegister / NFUpdate
# (heartbeat) / NFDeregister whose caller presented no verified certificate
# identity (nrf_nf_management_unverified_total). It must be 0, read once the
# types are registered and again after NRF_TLS_GATE_SETTLE seconds (default
# 15), so a heartbeat sent without a certificate is seen too.
#
# The NRF's /metrics is read inside the NRF pod (kubectl exec deploy/<nrf>,
# NRF_DEPLOYMENT, default nrf; port NRF_METRICS_PORT, default 9090): nothing
# is port-forwarded or published.
#
# Environment: NRF_TLS_GATE_TRIES (default 45) reads, 2 s apart, for the
# positive half.
#
# Exit: 0 pass, 1 fail (the reason on stderr), 2 usage.
set -euo pipefail

die() { printf 'nrf-tls-gate: %s\n' "$*" >&2; exit "${2:-1}"; }
[[ $# -ge 1 && -n "$1" ]] || die "usage: $0 <namespace> [<nfType>...]" 2
NS="$1"
shift
TYPES=("$@")
[[ ${#TYPES[@]} -gt 0 ]] || TYPES=(AUSF UDM UDR PCF NSSF BSF AMF SMF)
for t in "${TYPES[@]}"; do
  [[ "${t}" =~ ^[A-Z0-9_]{1,32}$ ]] || die "${t} is not an nfType" 2
done
DEP="${NRF_DEPLOYMENT:-nrf}"
PORT="${NRF_METRICS_PORT:-9090}"
TRIES="${NRF_TLS_GATE_TRIES:-45}"
SETTLE="${NRF_TLS_GATE_SETTLE:-15}"

scrape() {
  kubectl -n "${NS}" exec "deploy/${DEP}" -c nrf -- \
    curl -sf --max-time 3 "http://127.0.0.1:${PORT}/metrics" 2>/dev/null
}

m=""
missing="${TYPES[*]}"
for ((i = 1; i <= TRIES; i++)); do
  m="$(scrape || true)"
  missing=""
  for t in "${TYPES[@]}"; do
    grep -Eq "^nrf_registered_nf_instances\{nf_type=\"${t}\",nf_status=\"REGISTERED\"\} [1-9]" <<<"${m}" \
      || missing="${missing} ${t}"
  done
  [[ -z "${missing}" ]] && break
  (( i < TRIES )) && sleep 2
done
[[ -n "${m}" ]] || die "could not read the NRF's /metrics (deploy/${DEP} in ${NS}, port ${PORT})"
[[ -z "${missing}" ]] || die "not REGISTERED at the NRF over TLS:${missing}"

unverified() {
  local n
  n="$(awk '/^nrf_nf_management_unverified_total /{print $2}' <<<"$1")"
  [[ -n "${n}" ]] || die "the NRF does not expose nrf_nf_management_unverified_total"
  [[ "${n}" == 0 ]] || die "${n} NF-management requests reached the NRF without a verified client certificate ($2)"
}
unverified "${m}" "at registration"
sleep "${SETTLE}"
m="$(scrape)" || die "could not read the NRF's /metrics after ${SETTLE} s"
unverified "${m}" "after ${SETTLE} s of heartbeats"
echo "nrf-tls-gate: ${TYPES[*]} REGISTERED over TLS; 0 unverified NF-management requests"
