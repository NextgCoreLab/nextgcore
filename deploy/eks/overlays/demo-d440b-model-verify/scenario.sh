#!/usr/bin/env bash
# D440B acceptance run on EKS (nextgsim#463), called by k8s/demo-check.sh after
# the base e2e with NAMESPACE, DEMO_KEY, DEMO_MODE, OUT and KUBECONFIG set.
#
# The gNB has no /metrics listener, so everything is read with `nr-cli` inside
# the gNB pod (its CLI socket binds 127.0.0.1) through `kubectl exec`:
#   OUT/d440b/nwdaf-status.json      the status after the run (and *-before-*.json)
#   OUT/d440b/demo-show.txt          `demo d440b-model-verify show`
#   OUT/d440b/gnb.log                the gNB container log
#   OUT/d440b/chain.txt              the ordered gNB chain the run asserted
#   OUT/metrics/<gnb-pod>-nr-cli.prom   `demo metrics` (what demo-check counts)
#
# Assertions, by mode:
#   verify    `NWDAF: model verified ... sha256=<pinned> ... golden=ok`, then
#             verified=true, onnx_inferences > 0, fallback_inferences = 0;
#             then a runtime switch to fallback makes the next predictions
#             fallbacks (the revert arm), and a switch back serves onnx again.
#   fallback  no `model verified`; verified=false, onnx_inferences = 0,
#             fallback_inferences > 0; the #462-style consumer check fails.
#   both      the DEMO MODE ACTIVE banner; `set mode=bogus` is rejected with
#             `unknown mode`, audited, and the mode stays; the gNB log has, in
#             order, the banner -> [verify only: model verified -> audit
#             verify->fallback -> banner -> audit fallback->verify -> banner]
#             -> the rejected-set audit.
#
# The checks are the d440b_* functions below, over files and values only, so
# test-scenario.sh proves each one FAILS on input missing its line:
#   deploy/eks/overlays/demo-d440b-model-verify/test-scenario.sh
# Sourcing this file defines them and runs nothing.
# pass() and fail() always return 0, so `a && pass || fail` is an if-else here.
# shellcheck disable=SC2015
PINNED_SHA256=90a74d28c8e919ad8fdaa0f487976c8a4e803af3e318c5a30e02afcc3ec1f826
D440B_MODEL='id=nwdaf-trajectory-cv version=1.0.0'
D440B_VERIFIED_RE="NWDAF: model verified ${D440B_MODEL} sha256=${PINNED_SHA256} .*golden=ok"
D440B_AUDIT_RE='\[demo:d440b-model-verify\] audit: rejected set mode="bogus"'
d440b_banner_re() { echo "DEMO MODE ACTIVE: d440b-model-verify=$1([^a-z0-9-]|\$)"; }
# A runtime `set mode=` that took: `audit: mode <from> -> <to> from nr-cli`.
d440b_switch_re() { echo "\\[demo:d440b-model-verify\\] audit: mode $1 -> $2 from nr-cli"; }

# Ordered chain: each ERE must match a line strictly after the previous match.
# The ERE goes through the environment (the nextgsim scripts/demo/lib.sh
# pattern). Never as an awk operand `X=re`: that sets an awk variable, not
# ENVIRON, so `$0 ~ ENVIRON["X"]` is `$0 ~ ""` and matches every line. Never
# with -v either, which expands its escapes. Prints the matched lines.
d440b_order() {
  local file="$1" after=0 re hit
  shift
  [[ -f "${file}" ]] || { echo "no log ${file}"; return 1; }
  for re in "$@"; do
    hit="$(D440B_RE="${re}" awk -v after="${after}" \
      'NR > after && $0 ~ ENVIRON["D440B_RE"] { print NR; exit }' "${file}")"
    [[ -n "${hit}" ]] || { echo "missing or out of order: /${re}/"; return 1; }
    sed -n "${hit}p" "${file}"
    after="${hit}"
  done
}

d440b_banner() { grep -qE -- "$(d440b_banner_re "$2")" "$1"; }          # LOG MODE
d440b_verified_line() { grep -qE -- "${D440B_VERIFIED_RE}" "$1"; }      # LOG
d440b_no_verified_line() { [[ -f "$1" ]] && ! grep -qF 'model verified' "$1"; }  # LOG
d440b_audit_line() { grep -qE -- "${D440B_AUDIT_RE}" "$1"; }            # LOG
d440b_chain() {                                                         # LOG MODE
  if [[ "$2" == verify ]]; then
    # The revert arm's two switches sit between the verify and the rejected set.
    d440b_order "$1" "$(d440b_banner_re verify)" "${D440B_VERIFIED_RE}" \
      "$(d440b_switch_re verify fallback)" "$(d440b_banner_re fallback)" \
      "$(d440b_switch_re fallback verify)" "$(d440b_banner_re verify)" "${D440B_AUDIT_RE}"
  else
    d440b_order "$1" "$(d440b_banner_re "$2")" "${D440B_AUDIT_RE}"
  fi
}
# Counters, as `field` prints them: VERIFIED ONNX FALLBACK.
d440b_is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }
d440b_verify_counters() {
  d440b_is_int "$2" && d440b_is_int "$3" && [[ "$1" == true && "$2" -gt 0 && "$3" -eq 0 ]]
}
d440b_fallback_counters() {
  d440b_is_int "$2" && d440b_is_int "$3" && [[ "$1" == false && "$2" -eq 0 && "$3" -gt 0 ]]
}
d440b_bogus_rejected() { [[ "$1" != 0 ]] && grep -qF 'unknown mode' "$2"; }  # RC OUTFILE
d440b_mode_stays() { grep -qF "active=true mode=$2 " "$1"; }            # SHOWFILE MODE
d440b_metric() {                                                        # PROMFILE MODE
  grep -qF "nextg_demo_enabled{demo=\"d440b-model-verify\",mode=\"$2\"} 1" "$1"
}

d440b_main() {
  set -uo pipefail
  : "${NAMESPACE:?}" "${DEMO_KEY:?}" "${DEMO_MODE:?}" "${OUT:?}"
  local K=(kubectl -n "${NAMESPACE}") D="${OUT}/d440b" FAILS=() POD NODE s n s2 s3 o2 rc
  local verified onnx fb
  mkdir -p "${D}" "${OUT}/metrics"
  fail() { echo "FAIL: $*"; FAILS+=("$*"); }
  pass() { echo "ok:   $*"; }

  POD="$("${K[@]}" get pods -l app.kubernetes.io/name=gnb -o jsonpath='{.items[0].metadata.name}')"
  [[ -n "${POD}" ]] || { echo "no gNB pod"; return 1; }
  gx() { "${K[@]}" exec "${POD}" -c gnb -- "$@"; }
  NODE="$(gx nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')"
  [[ -n "${NODE}" ]] || { echo "nr-cli --dump found no gNB node in ${POD}"; return 1; }
  cli() { gx nr-cli "${NODE}" -e "$*"; }
  status() { cli nwdaf-status 2>&1; }
  field() { python3 -c 'import json,sys; v=json.load(sys.stdin)[sys.argv[1]]; print(json.dumps(v) if isinstance(v,(dict,list)) else str(v).lower())' "$1" 2>/dev/null; }
  gt() { d440b_is_int "$1" && d440b_is_int "$2" && [[ "$1" -gt "$2" ]]; }
  echo "gNB pod ${POD}, node ${NODE}, mode ${DEMO_MODE}"

  # Served predictions move with the RLS measurement forward; wait for some.
  for _ in $(seq 1 60); do
    s="$(status)"
    n="$(echo "${s}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["onnx_inferences"]+d["fallback_inferences"])' 2>/dev/null || echo 0)"
    gt "${n}" 4 && break
    sleep 2
  done
  echo "${s}" >"${D}/nwdaf-status-before-switch.json"
  "${K[@]}" logs "${POD}" -c gnb >"${D}/gnb.log" 2>&1

  verified="$(field verified <<<"${s}")"
  onnx="$(field onnx_inferences <<<"${s}")"
  fb="$(field fallback_inferences <<<"${s}")"
  echo "status: verified=${verified} onnx_inferences=${onnx} fallback_inferences=${fb}"

  d440b_banner "${D}/gnb.log" "${DEMO_MODE}" \
    && pass "DEMO MODE ACTIVE banner" || fail "no DEMO MODE ACTIVE banner"

  case "${DEMO_MODE}" in
    verify)
      d440b_verified_line "${D}/gnb.log" \
        && pass "model verified, pinned sha256, golden=ok" || fail "no 'model verified ... golden=ok' with the pinned sha256"
      d440b_verify_counters "${verified}" "${onnx}" "${fb}" \
        && pass "verified=true onnx_inferences>0 fallback_inferences=0" \
        || fail "verify counters: verified=${verified} onnx=${onnx} fallback=${fb}"
      # Revert arm: switch to fallback at runtime; the next predictions are fallbacks.
      cli "demo d440b-model-verify set mode=fallback" >"${D}/switch-to-fallback.txt" 2>&1
      for _ in $(seq 1 30); do
        s2="$(status)"; gt "$(field fallback_inferences <<<"${s2}")" 0 && break; sleep 2
      done
      echo "${s2}" >"${D}/nwdaf-status-after-switch.json"
      gt "$(field fallback_inferences <<<"${s2}")" 0 \
        && pass "runtime switch to fallback: fallback_inferences>0" || fail "switch to fallback did not reach the predictions"
      cli "demo d440b-model-verify set mode=verify" >"${D}/switch-back.txt" 2>&1
      o2="$(field onnx_inferences <<<"${s2}")"
      for _ in $(seq 1 30); do
        s3="$(status)"; gt "$(field onnx_inferences <<<"${s3}")" "${o2}" && break; sleep 2
      done
      echo "${s3}" >"${D}/nwdaf-status-after-switch-back.json"
      gt "$(field onnx_inferences <<<"${s3}")" "${o2}" \
        && pass "switch back to verify: onnx_inferences moves again" || fail "switch back to verify did not serve onnx"
      ;;
    fallback)
      d440b_no_verified_line "${D}/gnb.log" && pass "no 'model verified'" || fail "a 'model verified' line in mode fallback"
      d440b_fallback_counters "${verified}" "${onnx}" "${fb}" \
        && pass "verified=false onnx_inferences=0 fallback_inferences>0" \
        || fail "fallback counters: verified=${verified} onnx=${onnx} fallback=${fb}"
      # The consumer check (#462 onnx arm) must fail on this state.
      d440b_verify_counters "${verified}" "${onnx}" "${fb}" \
        && fail "the consumer check passed in mode fallback" || pass "the consumer check fails, as it must"
      ;;
    *) fail "unknown mode ${DEMO_MODE}" ;;
  esac

  # Invalid mode at runtime: rejected, audited, mode unchanged.
  cli "demo d440b-model-verify set mode=bogus" >"${D}/set-bogus.txt" 2>&1; rc=$?
  d440b_bogus_rejected "${rc}" "${D}/set-bogus.txt" \
    && pass "set mode=bogus rejected (rc ${rc}, unknown mode)" \
    || fail "set mode=bogus not rejected: rc ${rc} $(cat "${D}/set-bogus.txt")"
  cli "demo d440b-model-verify show" >"${D}/demo-show.txt" 2>&1
  d440b_mode_stays "${D}/demo-show.txt" "${DEMO_MODE}" \
    && pass "mode stays ${DEMO_MODE}" || fail "mode changed after a rejected set: $(cat "${D}/demo-show.txt")"
  "${K[@]}" logs "${POD}" -c gnb >"${D}/gnb.log" 2>&1
  d440b_audit_line "${D}/gnb.log" && pass "the rejected set is audited" || fail "no audit line for the rejected set"
  d440b_chain "${D}/gnb.log" "${DEMO_MODE}" >"${D}/chain.txt" \
    && pass "ordered gNB chain ($(wc -l <"${D}/chain.txt") steps)" || fail "gNB chain: $(tail -1 "${D}/chain.txt")"

  status >"${D}/nwdaf-status.json"
  cli "demo metrics" >"${OUT}/metrics/${POD}-nr-cli.prom" 2>&1
  d440b_metric "${OUT}/metrics/${POD}-nr-cli.prom" "${DEMO_MODE}" \
    && pass "nextg_demo_enabled series via nr-cli" || fail "no nextg_demo_enabled series via nr-cli"

  if [[ ${#FAILS[@]} -eq 0 ]]; then echo "d440b scenario: PASS"; return 0; fi
  echo "d440b scenario: FAIL (${#FAILS[@]})"; return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  d440b_main
  exit $?
fi
