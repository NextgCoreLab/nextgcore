#!/usr/bin/env bash
# Self-test of the D447A scenario checks (nextgsim#488). No cluster, no network.
#
#   deploy/eks/overlays/demo-d447a-nkef-live/test-scenario.sh
#
# Every check passes on a complete fixture and FAILS on the same fixture with its
# line removed (or its value wrong), so no assertion in scenario.sh can be
# vacuous; the ordered chain also fails out of order.
# `cond && ok ... || not_ok ...` throughout: ok only prints and cannot fail.
# shellcheck disable=SC2015
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
# shellcheck source-path=SCRIPTDIR source=scenario.sh
. "${here}/scenario.sh"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

n=0
ok() { n=$((n + 1)); printf 'ok %d - %s\n' "${n}" "$*"; }
not_ok() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
holds() { local name="$1"; shift; "$@" >/dev/null 2>&1 && ok "${name}" || not_ok "${name}"; }
breaks() { local name="$1"; shift; "$@" >/dev/null 2>&1 && not_ok "${name}" || ok "${name}"; }
put() { local f="${work}/$1"; shift; printf '%s\n' "$@" >"${f}"; echo "${f}"; }

amf_id=4f2a9c1e-7b3d-4e5f-8a6b-1c2d3e4f5a6b
bsf_id=9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a
on_hdr="NKEF bundle consumer=internal domains=ran,n2,sba consistent=true path=ue>cell>gnb>amf>nf-instance cm=CONNECTED stale=false amf_nf_instance=${amf_id}"
loc="fact domain=sba producer=amf subject=ue-imsi-999700000000001 age=2s ncgi=99970000000010 nrCellId=000000010 ueLocationTimestamp=2026-11-11T10:00:05Z ueLocationTimestampEpoch=1794391205"
bsf_fact="fact domain=sba producer=nrf subject=nf-${bsf_id} age=1s nfInstanceId=${bsf_id} nfStatus=REGISTERED nfType=BSF"
started='2026-11-11T10:00:05.000000Z  INFO nextgsim_gnb::nkef::task: NKEF task started at=2026-11-11T10:00:05Z'
noise='2026-11-11T10:00:06.000000Z  INFO Received NG Setup Response'
empty="$(put empty.txt "")"
absent="${work}/absent.txt"

# --- internal / baseline / stale headers -----------------------------------------
on="$(put on.txt "${on_hdr}" "${loc}")"
holds  "internal: full header"                 nkef_internal_on "${on}"
breaks "internal: domains without sba"         nkef_internal_on "$(put o1.txt "${on_hdr/ran,n2,sba/ran,n2}" "${loc}")"
breaks "internal: consistent=unknown"          nkef_internal_on "$(put o2.txt "${on_hdr/consistent=true/consistent=unknown}")"
breaks "internal: no nf-instance hop"          nkef_internal_on "$(put o3.txt "${on_hdr/>nf-instance/}")"
breaks "internal: cm=IDLE"                     nkef_internal_on "$(put o4.txt "${on_hdr/CONNECTED/IDLE}")"
breaks "internal: stale=true"                  nkef_internal_on "$(put o5.txt "${on_hdr/stale=false/stale=true}")"
breaks "internal: header not on line 1"        nkef_internal_on "$(put o6.txt "error: timeout" "${on_hdr}")"
breaks "internal: empty / absent"              nkef_internal_on "${empty}"
breaks "internal: absent file"                 nkef_internal_on "${absent}"
base="$(put base.txt 'NKEF bundle consumer=internal domains=none consistent=unknown path=none cm=unknown stale=unknown')"
holds  "baseline: domains=none"                nkef_internal_baseline "${base}"
breaks "baseline: a live bundle fails"         nkef_internal_baseline "${on}"
breaks "baseline: empty fails"                 nkef_internal_baseline "${empty}"
holds  "stale: stale=true"                     nkef_stale_true "$(put s1.txt "${on_hdr/stale=false/stale=true}")"
breaks "stale: stale=false fails"              nkef_stale_true "${on}"
breaks "stale: stale=unknown fails"            nkef_stale_true "${base}"
breaks "stale: empty fails"                    nkef_stale_true "${empty}"

# --- amfd subscription chain ---------------------------------------------------------
created='[INFO] Event subscription created: id=7, events=[LOCATION_REPORT, CONNECTIVITY_STATE_REPORT]'
removed='[INFO] Event subscription removed: 7'
holds  "sub chain: created then removed"       nkef_sub_chain "$(put a1.log x "${created}" y "${removed}")"
breaks "sub chain: removed missing"            nkef_sub_chain "$(put a2.log "${created}")"
breaks "sub chain: created missing"            nkef_sub_chain "$(put a3.log "${removed}")"
breaks "sub chain: out of order"               nkef_sub_chain "$(put a4.log "${removed}" "${created}")"
breaks "sub chain: no LOCATION_REPORT"         nkef_sub_chain "$(put a5.log "${created/LOCATION_REPORT, /}" "${removed}")"
breaks "sub chain: empty log"                  nkef_sub_chain "${empty}"
breaks "sub chain: absent log"                 nkef_sub_chain "${absent}"
breaks "ordered: an absent ERE never matches"  nkef_ordered "$(put a6.log x y)" 'no such line'
holds  "no sub: clean amf log"                 nkef_no_sub "$(put a7.log x "${removed}")"
breaks "no sub: a created line fails"          nkef_no_sub "$(put a8.log "${created}")"
breaks "no sub: absent log fails"              nkef_no_sub "${absent}"

# --- ueLocationTimestamp vs the task start ----------------------------------------
glog="$(put g.log "${noise}" "${started}")"
holds  "loc: same second as start"             nkef_loc_after_start "${glog}" "${on}"
holds  "loc: after start"                      nkef_loc_after_start "${glog}" "$(put l1.txt "${on_hdr}" "${loc/10:00:05Z/10:00:09Z}")"
breaks "loc: before start"                     nkef_loc_after_start "${glog}" "$(put l2.txt "${on_hdr}" "${loc/10:00:05Z/09:59:58Z}")"
breaks "loc: no ueLocationTimestamp"           nkef_loc_after_start "${glog}" "$(put l3.txt "${on_hdr}" "${loc/ueLocationTimestamp=*/}")"
breaks "loc: no task start line"               nkef_loc_after_start "$(put g2.log "${noise}")" "${on}"
breaks "loc: malformed timestamp"              nkef_loc_after_start "${glog}" "$(put l4.txt "${loc/2026-11-11T10:00:05Z/yesterday}")"
[[ "$(nkef_times "${glog}" "${on}")" == "2026-11-11T10:00:05Z 2026-11-11T10:00:05Z" ]] \
  && ok "loc: nkef_times prints started and loc" || not_ok "nkef_times: $(nkef_times "${glog}" "${on}")"

# --- AMF instance vs the NRF -------------------------------------------------------
nrf="$(put nrf.json "{\"validityPeriod\":3600,\"nfInstances\":[{\"nfInstanceId\":\"${amf_id}\",\"nfType\":\"AMF\"}]}")"
holds  "amf: bundle == NRF"                    nkef_same_amf "${on}" "${nrf}"
breaks "amf: other NRF instance"               nkef_same_amf "${on}" "$(put nrf2.json "{\"nfInstances\":[{\"nfInstanceId\":\"${bsf_id}\"}]}")"
breaks "amf: empty NRF answer"                 nkef_same_amf "${on}" "${empty}"
breaks "amf: no amf_nf_instance in bundle"     nkef_same_amf "$(put n1.txt "${on_hdr% amf_nf_instance=*}")" "${nrf}"
breaks "amf: both empty is not equal"          nkef_same_amf "${empty}" "${empty}"

# --- external ----------------------------------------------------------------------
ext_low="$(put e1.txt 'NKEF bundle consumer=external areas=1' 'area-1 congestion=Low age=1s')"
ext_med="$(put e2.txt 'NKEF bundle consumer=external areas=1' 'area-1 congestion=Medium age=0s')"
holds  "level: Low at idle"                    nkef_level "${ext_low}" Low
breaks "level: Medium is not Low"              nkef_level "${ext_med}" Low
holds  "level: Medium in the burst"            nkef_level "${ext_med}" 'Medium|High'
holds  "level: High in the burst"              nkef_level "$(put e3.txt 'area-1 congestion=High age=0s')" 'Medium|High'
breaks "level: Low is not Medium|High"         nkef_level "${ext_low}" 'Medium|High'
breaks "level: no area line"                   nkef_level "$(put e4.txt 'NKEF bundle consumer=external areas=0')" Low
breaks "level: empty"                          nkef_level "${empty}" Low
holds  "leak: clean external"                  nkef_no_leak "${ext_low}"
for leak in imsi-999700000000001 ncgi=1 nrCellId=10 tac=1 nci=16 amf_ue_ngap_id=7 10.45.0.2 192.168.12.7 "${amf_id}"; do
  breaks "leak: ${leak} fails"                 nkef_no_leak "$(put "leak-${n}.txt" 'area-1 congestion=Low age=1s' "x ${leak} y")"
done
breaks "leak: an empty reply fails"            nkef_no_leak "${empty}"
breaks "leak: an absent reply fails"           nkef_no_leak "${absent}"

# --- bogus mode -------------------------------------------------------------------
rej="$(put rej.txt 'demo config: unknown mode "bogus" for demo "d447a-nkef-live" (known modes ["on", "baseline"])')"
holds  "bogus: rc 1 and unknown mode"          nkef_bogus_rejected 1 "${rej}"
breaks "bogus: rc 0 fails"                     nkef_bogus_rejected 0 "${rej}"
breaks "bogus: rc 1, other error fails"        nkef_bogus_rejected 1 "$(put x.txt 'error: unable to upgrade connection')"
show="$(put show.txt 'demo=d447a-nkef-live active=true mode=on modes=on,baseline requires=-')"
holds  "show: mode stays on"                   nkef_mode_on "${show}"
breaks "show: baseline fails"                  nkef_mode_on "$(put sh2.txt 'demo=d447a-nkef-live active=true mode=baseline modes=on,baseline requires=-')"
breaks "show: inactive fails"                  nkef_mode_on "$(put sh3.txt 'demo=d447a-nkef-live active=false mode=- modes=on,baseline requires=-')"
breaks "show: empty fails"                     nkef_mode_on "${empty}"
audit='2026-11-11T10:01:00Z  WARN nextgsim_demo: [demo:d447a-nkef-live] audit: rejected set mode="bogus" from nr-cli: demo config: unknown mode "bogus"; mode unchanged (on)'
holds  "audit: present"                        nkef_audited "$(put au.log "${noise}" "${audit}")"
breaks "audit: missing"                        nkef_audited "${glog}"
breaks "audit: other demo"                     nkef_audited "$(put au2.log "${audit/d447a-nkef-live/d440b-model-verify}")"
breaks "audit: brackets are literal"           nkef_audited "$(put au3.log "${audit/\[demo:d447a-nkef-live\]/d447a-nkef-live}")"
breaks "audit: an accepted switch is not it"   nkef_audited "$(put au4.log '[demo:d447a-nkef-live] audit: mode on -> baseline from nr-cli')"

# --- expiry ------------------------------------------------------------------------
before="$(put b.txt "${on_hdr}" "${bsf_fact}")"
after="$(put af.txt "${on_hdr}" "${bsf_fact} expired_at=2026-11-11T10:02:10Z")"
[[ "$(nkef_bsf_id "${before}")" == "${bsf_id}" ]] && ok "bsf: id from the fact" || not_ok "bsf id: $(nkef_bsf_id "${before}")"
holds  "bsf: live before"                      nkef_bsf_live "${before}"
breaks "bsf: already expired fails"            nkef_bsf_live "${after}"
breaks "bsf: no BSF fact fails"                nkef_bsf_live "${on}"
breaks "bsf: nfType=BSFX is not BSF"           nkef_bsf_live "$(put bx.txt "${bsf_fact/nfType=BSF/nfType=BSFX}")"
holds  "bsf: expired after"                    nkef_bsf_expired "${after}" "${bsf_id}"
breaks "bsf: not expired"                      nkef_bsf_expired "${before}" "${bsf_id}"
breaks "bsf: another NF expired"               nkef_bsf_expired "$(put af2.txt "${bsf_fact} " "fact nfInstanceId=${amf_id} expired_at=2026-11-11T10:02:10Z")" "${bsf_id}"
breaks "bsf: empty id"                         nkef_bsf_expired "${after}" ""
susp="[WARN] NF instance ${bsf_id} missed heartbeat, marking SUSPENDED"
holds  "nrf: suspended"                        nkef_suspended "$(put n1.log x "${susp}")" "${bsf_id}"
breaks "nrf: another NF suspended"             nkef_suspended "$(put n2.log "${susp/${bsf_id}/${amf_id}}")" "${bsf_id}"
breaks "nrf: no suspension"                    nkef_suspended "$(put n3.log x)" "${bsf_id}"
breaks "nrf: empty id"                         nkef_suspended "$(put n4.log "${susp}")" ""
holds  "nrf: not deregistered"                 nkef_not_deregistered "$(put n5.log "${susp}")" "${bsf_id}"
breaks "nrf: NF Deregister fails"              nkef_not_deregistered "$(put n6.log "[INFO] NF Deregister: ${bsf_id}" "${susp}")" "${bsf_id}"
breaks "nrf: empty log fails"                  nkef_not_deregistered "${empty}" "${bsf_id}"
breaks "nrf: absent log fails"                 nkef_not_deregistered "${absent}" "${bsf_id}"
exp_line="2026-11-11T10:02:10.123456789Z 2026-11-11T10:02:10Z  INFO [demo:d447a-nkef-live] NKEF fact expired subject=nf-${bsf_id} producer=nrf expired_at=2026-11-11T10:02:10Z"
tslog="$(put ts.log "2026-11-11T10:01:00.0Z x" "${exp_line}")"
[[ "$(nkef_expired_at_epoch "${tslog}" "${bsf_id}")" == "$(date -u -d 2026-11-11T10:02:10Z +%s)" ]] \
  && ok "expiry: epoch of the kubelet timestamp" || not_ok "expiry epoch: $(nkef_expired_at_epoch "${tslog}" "${bsf_id}")"
breaks "expiry: another subject"               nkef_expired_at_epoch "${tslog}" "${amf_id}"
breaks "expiry: id prefix is not the id"       nkef_expired_at_epoch "$(put ts2.log "${exp_line/${bsf_id} /${bsf_id}0 }")" "${bsf_id}"
breaks "expiry: no line"                       nkef_expired_at_epoch "$(put ts3.log "2026-11-11T10:01:00.0Z x")" "${bsf_id}"
breaks "expiry: empty id"                      nkef_expired_at_epoch "${tslog}" ""
holds  "within: 25 <= 2x10+5"                  nkef_within 25 10 5
holds  "within: 0"                             nkef_within 0 10 5
breaks "within: 26 > 2x10+5"                   nkef_within 26 10 5
breaks "within: no heartBeatTimer"             nkef_within 3 "" 5
breaks "within: heartBeatTimer 0"              nkef_within 3 0 5
breaks "within: non-numeric elapsed"           nkef_within x 10 5

# --- metric ------------------------------------------------------------------------
prom="$(put m.prom '# TYPE nextg_demo_enabled gauge' 'nextg_demo_enabled{demo="d447a-nkef-live",mode="on"} 1')"
holds  "metric: series present"                nkef_metric "${prom}" on
breaks "metric: other mode"                    nkef_metric "${prom}" baseline
breaks "metric: header only"                   nkef_metric "$(put m2.prom '# TYPE nextg_demo_enabled gauge')" on
breaks "metric: absent file"                   nkef_metric "${absent}" on

echo "1..${n} all passed"
