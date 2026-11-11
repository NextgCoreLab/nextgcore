#!/usr/bin/env bash
# The seeded acceptance run of demo d447a-nkef-live (nextgsim#488) on EKS, called
# by k8s/demo-check.sh after the base e2e (the UE is registered with a PDU
# session), with NAMESPACE, DEMO_KEY, DEMO_MODE, OUT and KUBECONFIG set.
#
# Everything is read with `kubectl exec` / `kubectl logs`: no port-forward, no
# published port. The gNB has no /metrics listener, so `demo metrics` is read
# with nr-cli into OUT/metrics/<gnb-pod>-nr-cli.prom, where demo-check counts it.
# Artefacts under OUT/nkef/.
#
# Mode `on`, in this order (the ticket's acceptance list):
#   1. internal bundle `domains=ran,n2,sba consistent=true
#      path=ue>cell>gnb>amf>nf-instance cm=CONNECTED stale=false`, and its
#      ueLocationTimestamp not before `NKEF task started at=` (both RFC 3339
#      seconds: amfd's field has second resolution);
#   2. amf logs `Event subscription created` (LOCATION_REPORT) then `Event
#      subscription removed`;
#   3. the bundle's amf_nf_instance equals the AMF nfInstanceId a separate NRF
#      discovery returns (curl from inside the amf pod: no extra pod or image);
#   4. external replies: `area-1 congestion=Low` at idle and `Medium|High`
#      during a ping burst over the UE's PDU session, with no `imsi-`, `ncgi`,
#      `nrCellId`, `tac`, `nci`, `ngap_id`, dotted-quad IP or UUID in either;
#   5. `set mode=bogus` is refused, audited (`[demo:d447a-nkef-live] audit:
#      rejected set mode="bogus"`) and the mode stays `on`;
#   6. expiry: the BSF fact has no expired_at; then a NetworkPolicy
#      (bsf-no-egress.yaml, applied here, gone with the namespace) cuts the
#      BSF's egress, so it stops heartbeating WITHOUT the NFDeregister a
#      graceful stop sends (bsfd lib.rs, #235). The nrf logs `NF instance <bsf>
#      missed heartbeat, marking SUSPENDED` and no `NF Deregister: <bsf>`; the
#      gNB logs `NKEF fact expired subject=nf-<bsf>` for that instance at most
#      2 x heartBeatTimer (read from the NRF's profile) + nrf_poll_secs after
#      the policy was applied (by kubelet timestamp); the bundle then shows its
#      expired_at;
#   7. restart: with the UE scaled to 0 and the gNB restarted, the bundle says
#      `stale=true`.
# Mode `baseline`: the bundle carries no live domain and amfd logs no `Event
# subscription created`.
#
# The checks are the nkef_* functions below, over files and values only, so
# test-scenario.sh proves each one FAILS on input missing its line. Sourcing
# this file defines them and runs nothing.
# pass() and fail() always return 0, so `a && pass || fail` is an if-else here.
# shellcheck disable=SC2015
NKEF_KEY=d447a-nkef-live
NKEF_POLL_SECS=5   # nrf_poll_secs in gnb-nkef-config.yaml
NKEF_ON_RE='^NKEF bundle consumer=internal domains=ran,n2,sba consistent=true path=ue>cell>gnb>amf>nf-instance cm=CONNECTED stale=false( |$)'
NKEF_BASELINE_RE='^NKEF bundle consumer=internal domains=none( |$)'
NKEF_LEAK_RE='imsi-|ncgi|nrCellId|tac|nci|ngap_id|\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
NKEF_SUB_CREATED_RE='Event subscription created: id=[^,]+, events=.*LOCATION_REPORT'
NKEF_SUB_REMOVED_RE='Event subscription removed: '
NKEF_AUDIT_RE='\[demo:d447a-nkef-live\] audit: rejected set mode="bogus"'

# nkef_ordered FILE ERE...: each ERE matches a line strictly after the previous
# match. grep -E with the pattern as an argument (never an awk operand), so a
# missing line FAILS.
nkef_ordered() {
  local file="$1" after=0 re hit
  shift
  [[ -f "${file}" ]] || return 1
  for re in "$@"; do
    hit="$(tail -n "+$((after + 1))" "${file}" | grep -nE -- "${re}" | head -1 | cut -d: -f1)"
    [[ -n "${hit}" ]] || return 1
    after=$((after + hit))
  done
}
nkef_is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }
# RFC 3339 UTC (second or finer) -> epoch seconds; fails on anything else.
nkef_epoch() {
  [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$ ]] || return 1
  date -u -d "$1" +%s 2>/dev/null
}

nkef_internal_on() { head -1 "$1" 2>/dev/null | grep -qE -- "${NKEF_ON_RE}"; }             # BUNDLE
nkef_internal_baseline() { head -1 "$1" 2>/dev/null | grep -qE -- "${NKEF_BASELINE_RE}"; }  # BUNDLE
nkef_stale_true() { head -1 "$1" 2>/dev/null | grep -qE '^NKEF bundle consumer=internal .* stale=true( |$)'; }  # BUNDLE
nkef_sub_chain() { nkef_ordered "$1" "${NKEF_SUB_CREATED_RE}" "${NKEF_SUB_REMOVED_RE}"; }  # AMFLOG
nkef_no_sub() { [[ -f "$1" ]] && ! grep -qF 'Event subscription created' "$1"; }          # AMFLOG
# "started loc": the first `NKEF task started at=` of GNBLOG and the bundle's
# ueLocationTimestamp; fails if either is missing.
nkef_times() {                                                                          # GNBLOG BUNDLE
  local started loc
  started="$(grep -oE 'NKEF task started at=[0-9T:Z.-]+' "$1" 2>/dev/null | head -1 | cut -d= -f2)"
  loc="$(grep -oE 'ueLocationTimestamp=[0-9T:Z.-]+' "$2" 2>/dev/null | head -1 | cut -d= -f2)"
  [[ -n "${started}" && -n "${loc}" ]] || return 1
  echo "${started} ${loc}"
}
nkef_loc_after_start() {                                                                # GNBLOG BUNDLE
  local t s l
  t="$(nkef_times "$1" "$2")" || return 1
  s="$(nkef_epoch "${t% *}")" || return 1
  l="$(nkef_epoch "${t#* }")" || return 1
  [[ "${l}" -ge "${s}" ]]
}
nkef_bundle_amf() { head -1 "$1" 2>/dev/null | grep -oE 'amf_nf_instance=[0-9a-f-]+' | head -1 | cut -d= -f2; }  # BUNDLE
nkef_nrf_amf() { grep -oE '"nfInstanceId" *: *"[0-9a-f-]+"' "$1" 2>/dev/null | head -1 | grep -oE '[0-9a-f-]{36}'; }  # NRFJSON
nkef_same_amf() {                                                                       # BUNDLE NRFJSON
  local a b
  a="$(nkef_bundle_amf "$1")"; b="$(nkef_nrf_amf "$2")"
  [[ -n "${a}" && "${a}" == "${b}" ]]
}
nkef_level() { grep -qE -- "^area-1 congestion=($2)( |$)" "$1" 2>/dev/null; }          # EXTERNAL ERE
nkef_no_leak() { grep -q '[^[:space:]]' "$1" 2>/dev/null && ! grep -qE -- "${NKEF_LEAK_RE}" "$1"; }             # EXTERNAL
nkef_bogus_rejected() { [[ "$1" != 0 ]] && grep -qF 'unknown mode' "$2"; }              # RC OUTFILE
nkef_mode_on() { grep -qF "demo=${NKEF_KEY} active=true mode=on " "$1"; }                # SHOWFILE
nkef_audited() { grep -qE -- "${NKEF_AUDIT_RE}" "$1"; }                                 # GNBLOG
nkef_bsf_line() { grep -E 'nfType=BSF( |$)' "$1" 2>/dev/null | head -1; }               # BUNDLE
nkef_bsf_id() { nkef_bsf_line "$1" | grep -oE 'nfInstanceId=[0-9a-f-]+' | head -1 | cut -d= -f2; }  # BUNDLE
nkef_bsf_live() { local l; l="$(nkef_bsf_line "$1")"; [[ -n "${l}" && "${l}" != *expired_at=* ]]; }  # BUNDLE
nkef_bsf_expired() {                                                                    # BUNDLE ID
  [[ -n "$2" ]] && grep -E "nfInstanceId=$2( |$)" "$1" 2>/dev/null | grep -qE 'expired_at=[0-9]{4}-[0-9]{2}-[0-9]{2}T'
}
nkef_suspended() { [[ -n "$2" ]] && grep -qF "NF instance $2 missed heartbeat, marking SUSPENDED" "$1"; }  # NRFLOG ID
nkef_not_deregistered() { [[ -n "$2" ]] && grep -q '[^[:space:]]' "$1" 2>/dev/null && ! grep -qF "NF Deregister: $2" "$1"; }  # NRFLOG ID
# The kubelet timestamp (epoch s) of the gNB's expiry line for ID, from a
# `kubectl logs --timestamps` file; fails when there is none.
nkef_expired_at_epoch() {                                                               # TSLOG ID
  local ts
  [[ -n "$2" ]] || return 1
  ts="$(grep -F "NKEF fact expired subject=nf-$2 " "$1" 2>/dev/null | head -1 | cut -d' ' -f1)"
  [[ -n "${ts}" ]] || return 1
  nkef_epoch "${ts}"
}
nkef_within() {                                                                         # ELAPSED HB POLL
  nkef_is_int "$1" && nkef_is_int "$2" && nkef_is_int "$3" && [[ "$2" -gt 0 && "$1" -le $((2 * $2 + $3)) ]]
}
nkef_metric() { grep -qF "nextg_demo_enabled{demo=\"${NKEF_KEY}\",mode=\"$2\"} 1" "$1"; }  # PROMFILE MODE

nkef_main() {
  set -uo pipefail
  : "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
  local K=(kubectl -n "${NAMESPACE}") D="${OUT}/nkef" FAILS=() POD="" NODE="" rc
  local here q started_loc hb bound t0 t1 bsf burst ue dbg tun
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || return 2
  q='is my route congested and which core functions serve me?'
  mkdir -p "${D}" "${OUT}/metrics" || return 2
  fail() { echo "FAIL: $*"; FAILS+=("$*"); }
  pass() { echo "ok:   $*"; }

  running() { "${K[@]}" get pods -l "app.kubernetes.io/name=$1" --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
  attach() {   # (re)find the gNB pod and its nr-cli node; fails early on either
    POD="$(running gnb)"
    [[ -n "${POD}" ]] || { fail "no Running gNB pod"; return 1; }
    NODE="$("${K[@]}" exec "${POD}" -c gnb -- nr-cli --dump 2>/dev/null | grep -m1 -i gnb | tr -d '\r')"
    [[ -n "${NODE}" ]] || { fail "nr-cli --dump lists no gNB node in ${POD}"; return 1; }
    echo "gNB pod ${POD}, node ${NODE}"
  }
  cli() { "${K[@]}" exec "${POD}" -c gnb -- nr-cli "${NODE}" -e "$*"; }
  ask() { local f="${D}/$1"; shift; cli nkef-query "$@" >"${f}" 2>&1; echo "--- $(basename "${f}"):"; cat "${f}"; }
  gnb_log() { "${K[@]}" logs "${POD}" -c gnb --tail=-1 "${@:2}" >"${D}/$1" 2>&1; }
  nf_log() { "${K[@]}" logs "deploy/$1" -c "$1" --tail=-1 >"${D}/$1.log" 2>&1; }
  nrf_get() { "${K[@]}" exec deploy/amf -c amf -- curl -s --max-time 5 --http2-prior-knowledge "http://nrf:7777$1"; }

  attach || return 1
  sleep 8  # an NRF poll and several RLS windows
  cli "demo metrics" >"${OUT}/metrics/${POD}-nr-cli.prom" 2>&1
  nkef_metric "${OUT}/metrics/${POD}-nr-cli.prom" "${DEMO_MODE}" \
    && pass "nextg_demo_enabled{mode=${DEMO_MODE}} via nr-cli" || fail "no nextg_demo_enabled series via nr-cli"
  ask internal.txt "${q}"
  nf_log amf

  case "${DEMO_MODE}" in
  baseline)
    nkef_internal_baseline "${D}/internal.txt" \
      && pass "baseline bundle: domains=none" || fail "baseline bundle carries live facts: $(head -1 "${D}/internal.txt")"
    nkef_no_sub "${D}/amf.log" && pass "amfd logged no subscription" || fail "baseline subscribed at amfd"
    ;;
  on)
    # 1-2. the bundle and the amfd round
    nkef_internal_on "${D}/internal.txt" \
      && pass "internal header" || fail "internal header: $(head -1 "${D}/internal.txt")"
    gnb_log gnb.log
    started_loc="$(nkef_times "${D}/gnb.log" "${D}/internal.txt")"
    echo "${started_loc:-missing}" >"${D}/started-loc.txt"
    nkef_loc_after_start "${D}/gnb.log" "${D}/internal.txt" \
      && pass "ueLocationTimestamp >= NKEF task started at (started loc: ${started_loc})" \
      || fail "ueLocationTimestamp not at or after the task start (${started_loc:-missing})"
    nkef_sub_chain "${D}/amf.log" \
      && pass "amf: Event subscription created -> removed" || fail "amf: Event subscription created -> removed not in order"

    # 3. the AMF instance, as the NRF itself names it
    nrf_get '/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=NEF' \
      >"${D}/nrf-amf.json" 2>"${D}/nrf-amf.err"; rc=$?
    if [[ "${rc}" != 0 || ! -s "${D}/nrf-amf.json" ]]; then
      fail "NRF discovery from the amf pod failed (curl rc ${rc}: $(head -c 200 "${D}/nrf-amf.err"))"
    else
      nkef_same_amf "${D}/internal.txt" "${D}/nrf-amf.json" \
        && pass "bundle AMF $(nkef_bundle_amf "${D}/internal.txt") == NRF's" \
        || fail "bundle AMF '$(nkef_bundle_amf "${D}/internal.txt")' != NRF '$(nkef_nrf_amf "${D}/nrf-amf.json")'"
    fi

    # 4. external: Low at idle, Medium|High under a ping burst
    ask external-idle.txt --as external "${q}"
    nkef_level "${D}/external-idle.txt" Low && pass "external idle: Low" || fail "external idle is not Low"
    nkef_no_leak "${D}/external-idle.txt" && pass "external idle: no leak" || fail "external idle leaks (or is empty)"
    # The UE image has no ping: a netshoot debug container in the UE pod (the
    # base e2e's DEBUG_IMAGE), set up before the burst so it is not timed.
    ue="$(running ue)"; dbg="nkef-burst-$(date +%s)"; tun=""
    if [[ -n "${ue}" ]] && "${K[@]}" debug "${ue}" --target=ue --profile=netadmin \
        --image="${DEBUG_IMAGE:-nicolaka/netshoot:v0.13}" --container="${dbg}" -- sleep 180 >"${D}/burst-debug.txt" 2>&1; then
      for _ in $(seq 1 60); do
        "${K[@]}" exec "${ue}" -c "${dbg}" -- true >/dev/null 2>&1 && break
        sleep 2
      done
      tun="$("${K[@]}" exec "${ue}" -c "${dbg}" -- sh -c \
        "ip -4 -o addr show | awk '\$2 ~ /^uesimtun/ { print \$2; exit }'" 2>/dev/null)"
    fi
    if [[ -z "${tun}" ]]; then
      fail "no burst: UE pod '${ue}', debug container or uesimtun interface missing (burst-debug.txt)"
    else
      "${K[@]}" exec "${ue}" -c "${dbg}" -- ping -I "${tun}" -i 0.01 -s 1200 -c 1000 -q "${PING_TARGET:-8.8.8.8}" \
        >"${D}/ping-burst.txt" 2>&1 &
      burst=$!
      sleep 5  # one full RLS load window under the burst
      ask external-burst.txt --as external "${q}"
      wait "${burst}" || true
      nkef_level "${D}/external-burst.txt" 'Medium|High' \
        && pass "external burst: $(grep -oE 'congestion=[A-Za-z]+' "${D}/external-burst.txt" | head -1)" \
        || fail "the ping burst did not raise the level (ping-burst.txt)"
      nkef_no_leak "${D}/external-burst.txt" && pass "external burst: no leak" || fail "external burst leaks (or is empty)"
    fi

    # 5. a bogus mode at runtime
    cli "demo ${NKEF_KEY} set mode=bogus" >"${D}/set-bogus.txt" 2>&1; rc=$?
    nkef_bogus_rejected "${rc}" "${D}/set-bogus.txt" \
      && pass "set mode=bogus rejected (rc ${rc})" || fail "set mode=bogus not rejected: rc ${rc} $(cat "${D}/set-bogus.txt")"
    cli "demo ${NKEF_KEY} show" >"${D}/demo-show.txt" 2>&1
    nkef_mode_on "${D}/demo-show.txt" && pass "mode stays on" || fail "mode changed: $(cat "${D}/demo-show.txt")"
    gnb_log gnb.log
    nkef_audited "${D}/gnb.log" && pass "the rejected set is audited" || fail "no audit line for the rejected set"

    # 6. expiry by the NRF's no-heartbeat suspension
    ask before-stop.txt bsf instance
    bsf="$(nkef_bsf_id "${D}/before-stop.txt")"
    nkef_bsf_live "${D}/before-stop.txt" && pass "BSF ${bsf} live before the cut" || fail "no live BSF fact before the cut"
    nrf_get "/nnrf-nfm/v1/nf-instances/${bsf}" >"${D}/nrf-bsf.json" 2>&1
    hb="$(grep -oE '"heartBeatTimer" *: *[0-9]+' "${D}/nrf-bsf.json" | grep -oE '[0-9]+$')"
    if ! nkef_is_int "${hb}" || [[ -z "${bsf}" ]]; then
      fail "no BSF instance or heartBeatTimer (bsf='${bsf}' hb='${hb}')"
    else
      bound=$((2 * hb + NKEF_POLL_SECS))
      t0="$(date -u +%s)"
      "${K[@]}" apply -f "${here}/bsf-no-egress.yaml" >"${D}/policy.txt" 2>&1 \
        || fail "could not apply bsf-no-egress.yaml: $(cat "${D}/policy.txt")"
      for _ in $(seq 1 $(((bound + 30) / 3))); do
        gnb_log gnb-ts.log --timestamps
        nkef_expired_at_epoch "${D}/gnb-ts.log" "${bsf}" >/dev/null && break
        sleep 3
      done
      nf_log nrf
      nkef_suspended "${D}/nrf.log" "${bsf}" \
        && pass "nrf: ${bsf} missed heartbeat, marking SUSPENDED" || fail "nrf never suspended ${bsf} for a missed heartbeat"
      nkef_not_deregistered "${D}/nrf.log" "${bsf}" \
        && pass "nrf: no NF Deregister for ${bsf}" || fail "the BSF NFDeregistered (or no nrf log): the cut was graceful"
      t1="$(nkef_expired_at_epoch "${D}/gnb-ts.log" "${bsf}")"
      if [[ -z "${t1}" ]]; then
        fail "the gNB never expired nf-${bsf}"
      else
        printf 'elapsed=%s heartBeatTimer=%s poll=%s bound=%s\n' "$((t1 - t0))" "${hb}" "${NKEF_POLL_SECS}" "${bound}" \
          | tee "${D}/expiry.txt"
        nkef_within "$((t1 - t0))" "${hb}" "${NKEF_POLL_SECS}" \
          && pass "nf-${bsf} expired $((t1 - t0))s after the cut (bound ${bound}s)" \
          || fail "nf-${bsf} expired $((t1 - t0))s after the cut > bound ${bound}s"
      fi
      ask after-stop.txt bsf instance
      nkef_bsf_expired "${D}/after-stop.txt" "${bsf}" \
        && pass "the BSF fact shows expired_at" || fail "the BSF fact has no expired_at after the cut"
    fi

    # 7. restart without the UE: the AMF's location predates this run
    {
      "${K[@]}" scale deploy/ue --replicas=0
      "${K[@]}" wait --for=delete pod -l app.kubernetes.io/name=ue --timeout=120s
      "${K[@]}" rollout restart deploy/gnb
    } >"${D}/restart-steps.txt" 2>&1
    "${K[@]}" rollout status deploy/gnb --timeout=300s >>"${D}/restart-steps.txt" 2>&1 \
      || fail "the gNB did not come back after the restart"
    for _ in $(seq 1 40); do
      POD="$(running gnb)"
      [[ -n "${POD}" ]] && "${K[@]}" logs "${POD}" -c gnb --tail=-1 2>/dev/null \
        | grep -q 'Received NG Setup Response' && break
      sleep 3
    done
    if attach; then
      sleep 8  # an NRF poll; the subscription answers with the AMF's last location
      ask restart.txt "${q}"
      gnb_log gnb-restart.log
      nkef_stale_true "${D}/restart.txt" \
        && pass "after the restart without the UE: stale=true" \
        || fail "the bundle after the restart is not stale=true: $(head -1 "${D}/restart.txt")"
    fi
    ;;
  *) fail "unknown mode ${DEMO_MODE}" ;;
  esac

  if [[ ${#FAILS[@]} -eq 0 ]]; then echo "nkef scenario (${DEMO_MODE}): PASS"; return 0; fi
  echo "nkef scenario (${DEMO_MODE}): FAIL (${#FAILS[@]})"; printf '  - %s\n' "${FAILS[@]}"; return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  nkef_main
  exit $?
fi
