#!/usr/bin/env bash
# The seeded acceptance run of demo d447a-nkef-live (nextgsim#488) on EKS, called by
# k8s/demo-check.sh after the base e2e (the UE is registered with a PDU session).
#
# Contract (deploy/eks/overlays/README.md): NAMESPACE, DEMO_KEY, DEMO_MODE, OUT,
# KUBECONFIG. Exit 0 when the assertions hold. Everything is read with
# `kubectl exec` / `kubectl logs`: no port-forward, no published port.
#
#   on        one internal bundle: domains=ran,n2,sba consistent=true
#             path=ue>cell>gnb>amf>nf-instance cm=CONNECTED stale=false, its AMF
#             nfInstanceId equal to the NRF's own answer; amf logs Event
#             subscription created then removed; external replies carry only
#             area congestion (Low at idle) and no identity; a bogus mode is
#             refused; after scaling bsf to 0 its fact gets expired_at.
#   baseline  the bundle carries no live domain; amf logs no subscription.
set -uo pipefail
NS="${NAMESPACE:?}"; MODE="${DEMO_MODE:?}"; OUT="${OUT:?}"
D="${OUT}/nkef"; mkdir -p "${D}"
Q='is my route congested and which core functions serve me?'
fails=0
say()  { printf '[nkef] %s\n' "$*" | tee -a "${D}/scenario.log"; }
bad()  { printf '[nkef] FAIL: %s\n' "$*" | tee -a "${D}/scenario.log" >&2; fails=$((fails + 1)); }
gnb_cli() {
  local node
  node="$(kubectl -n "${NS}" exec deploy/gnb -- nr-cli --dump 2>/dev/null | grep -m1 -i gnb)"
  kubectl -n "${NS}" exec deploy/gnb -- nr-cli "${node}" -e "$*"
}
ask() { local f="${D}/$1"; shift; gnb_cli nkef-query "$@" > "${f}" 2>&1; tee -a "${D}/scenario.log" < "${f}"; }

sleep 8  # an NRF poll and several RLS windows
gnb_cli demo metrics > "${D}/demo-metrics.txt" 2>&1
ask internal.txt "${Q}"
kubectl -n "${NS}" logs deploy/amf --tail=-1 > "${D}/amf.log" 2>&1

if [[ "${MODE}" == baseline ]]; then
  grep -qE '^NKEF bundle consumer=internal domains=none ' "${D}/internal.txt" || bad "baseline bundle carries live facts"
  if grep -q 'Event subscription created' "${D}/amf.log"; then bad "baseline subscribed at amfd"; fi
  exit $(( fails > 0 ))
fi

grep -qE '^NKEF bundle consumer=internal domains=ran,n2,sba consistent=true path=ue>cell>gnb>amf>nf-instance cm=CONNECTED stale=false ' \
  "${D}/internal.txt" || bad "internal header: $(head -1 "${D}/internal.txt")"
created="$(grep -n 'Event subscription created' "${D}/amf.log" | head -1 | cut -d: -f1)"
removed="$(grep -n 'Event subscription removed' "${D}/amf.log" | head -1 | cut -d: -f1)"
[[ -n "${created}" && -n "${removed}" && "${removed}" -gt "${created}" ]] || bad "amf: created/removed not in order"

bundle_nf="$(grep -oE 'amf_nf_instance=[0-9a-f-]+' "${D}/internal.txt" | head -1 | cut -d= -f2)"
kubectl -n "${NS}" run "nkef-nrf-curl-$$" --rm -i --restart=Never --image=curlimages/curl:8.11.1 --quiet -- \
  -s --http2-prior-knowledge 'http://nrf:7777/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=NEF' \
  > "${D}/nrf-amf.json" 2>&1
nrf_nf="$(grep -oE '"nfInstanceId":"[0-9a-f-]+"' "${D}/nrf-amf.json" | head -1 | cut -d'"' -f4)"
[[ -n "${bundle_nf}" && "${bundle_nf}" == "${nrf_nf}" ]] || bad "bundle AMF '${bundle_nf}' != NRF '${nrf_nf}'"

ask external-idle.txt --as external "${Q}"
grep -qE '^area-1 congestion=(Low|Medium|High) ' "${D}/external-idle.txt" || bad "external has no area line"
if grep -nE 'imsi-|ncgi|nrCellId|tac|nci|ngap_id|[0-9a-f]{8}-[0-9a-f]{4}-' "${D}/external-idle.txt"; then bad "external leaks"; fi

if gnb_cli demo d447a-nkef-live set mode=bogus > "${D}/set-bogus.txt" 2>&1; then bad "bogus mode accepted"; fi

ask before-stop.txt bsf instance
grep 'nfType=BSF' "${D}/before-stop.txt" | grep -q expired_at && bad "BSF expired before the stop"
t0=$(date +%s)
kubectl -n "${NS}" scale deploy/bsf --replicas=0 >/dev/null
for _ in $(seq 60); do
  kubectl -n "${NS}" logs deploy/gnb --tail=-1 > "${D}/gnb.log" 2>&1
  grep -q 'NKEF fact expired subject=nf-' "${D}/gnb.log" && break
  sleep 3
done
t1=$(date +%s); echo $((t1 - t0)) > "${D}/expiry-seconds"
ask after-stop.txt bsf instance
grep 'nfType=BSF' "${D}/after-stop.txt" | grep -qE 'expired_at=[0-9]{4}-' || bad "BSF has no expired_at after the stop"
say "BSF expiry after $((t1 - t0))s"
exit $(( fails > 0 ))
