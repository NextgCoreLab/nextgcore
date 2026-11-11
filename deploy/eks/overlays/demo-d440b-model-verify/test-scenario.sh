#!/usr/bin/env bash
# Self-test of the D440B scenario checks (nextgsim#463). No cluster, no network.
#
#   deploy/eks/overlays/demo-d440b-model-verify/test-scenario.sh
#
# Every check passes on a complete fixture and FAILS on the same fixture with its
# line removed (or its value wrong), so no assertion in scenario.sh can be
# vacuous; the ordered chain also fails out of order, and an ERE metacharacter
# in a pattern stays literal.
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
# holds NAME CMD...: must pass.  breaks NAME CMD...: must fail.
holds() { local name="$1"; shift; "$@" >/dev/null 2>&1 && ok "${name}" || not_ok "${name}"; }
breaks() { local name="$1"; shift; "$@" >/dev/null 2>&1 && not_ok "${name}" || ok "${name}"; }

ts='2026-11-11T10:00:00.000000Z'
banner_v="${ts}  WARN DEMO MODE ACTIVE: d440b-model-verify=verify"
banner_f="${ts}  WARN DEMO MODE ACTIVE: d440b-model-verify=fallback"
verified="${ts}  INFO NWDAF: model verified id=nwdaf-trajectory-cv version=1.0.0 sha256=${PINNED_SHA256} opset=17 inputs=[x:f32[1,8,2]] outputs=[y:f32[1,1,2]] golden=ok (3 vectors, tolerance 0.0001) path=/opt/nextgsim/models/nwdaf-trajectory-cv.onnx; trajectory predictions use the model"
audit="${ts}  WARN [demo:d440b-model-verify] audit: rejected set mode=\"bogus\" from nr-cli: demo config: unknown mode \"bogus\"; mode unchanged (verify)"
noise="${ts}  INFO NGSetupResponse received"
put() { local f="${work}/$1"; shift; printf '%s\n' "$@" >"${f}"; echo "${f}"; }

full_v="$(put full-v.log "${noise}" "${banner_v}" "${verified}" "${noise}" "${audit}")"
full_f="$(put full-f.log "${noise}" "${banner_f}" "${noise}" "${audit/verify)/fallback)}")"
no_banner="$(put no-banner.log "${noise}" "${verified}" "${audit}")"
no_verified="$(put no-verified.log "${banner_v}" "${noise}" "${audit}")"
no_audit="$(put no-audit.log "${banner_v}" "${verified}" "${noise}")"
empty="$(put empty.log "")"

# --- banner ---------------------------------------------------------------------
holds  "banner: present (verify)"               d440b_banner "${full_v}" verify
holds  "banner: present (fallback)"             d440b_banner "${full_f}" fallback
breaks "banner: missing line fails"             d440b_banner "${no_banner}" verify
breaks "banner: empty log fails"                d440b_banner "${empty}" verify
breaks "banner: other mode fails"               d440b_banner "${full_v}" fallback
breaks "banner: mode prefix is not the mode"    d440b_banner "$(put prefix.log "${banner_v}-x")" verify
breaks "banner: no log file fails"              d440b_banner "${work}/absent.log" verify

# --- model verified -------------------------------------------------------------
holds  "verified: present"                      d440b_verified_line "${full_v}"
breaks "verified: missing line fails"           d440b_verified_line "${no_verified}"
breaks "verified: empty log fails"              d440b_verified_line "${empty}"
breaks "verified: other sha256 fails"           d440b_verified_line "$(put sha.log "${verified/${PINNED_SHA256}/${PINNED_SHA256//0/1}}")"
breaks "verified: no golden=ok fails"           d440b_verified_line "$(put golden.log "${verified/golden=ok/golden=skipped}")"
breaks "verified: a refusal is not a verify"    d440b_verified_line "$(put refused.log "${ts}  WARN NWDAF: model refused (sha256 mismatch) id=nwdaf-trajectory-cv version=1.0.0")"
holds  "no-verified: fallback log passes"       d440b_no_verified_line "${full_f}"
breaks "no-verified: a verified line fails"     d440b_no_verified_line "${full_v}"
breaks "no-verified: no log file fails"         d440b_no_verified_line "${work}/absent.log"

# --- audit ----------------------------------------------------------------------
holds  "audit: present"                         d440b_audit_line "${full_v}"
breaks "audit: missing line fails"              d440b_audit_line "${no_audit}"
breaks "audit: other demo fails"                d440b_audit_line "$(put other.log "${audit/d440b-model-verify/d441a-congestion-loop}")"
# `\[` must stay literal: `[demo:...]` as a bracket expression matches "d".
breaks "audit: brackets are literal"            d440b_audit_line "$(put brk.log "${audit/\[demo:d440b-model-verify\]/d440b-model-verify}")"

# --- ordered chain (awk with the ERE in ENVIRON) --------------------------------
holds  "chain: verify in order"                 d440b_chain "${full_v}" verify
holds  "chain: fallback in order"               d440b_chain "${full_f}" fallback
breaks "chain: missing banner fails"            d440b_chain "${no_banner}" verify
breaks "chain: missing model verified fails"    d440b_chain "${no_verified}" verify
breaks "chain: missing audit fails"             d440b_chain "${no_audit}" verify
breaks "chain: empty log fails"                 d440b_chain "${empty}" verify
breaks "chain: no log file fails"               d440b_chain "${work}/absent.log" verify
breaks "chain: out of order fails"              d440b_chain "$(put ooo.log "${banner_v}" "${audit}" "${verified}")" verify
breaks "chain: fallback without audit fails"    d440b_chain "$(put f-noaudit.log "${banner_f}" "${noise}")" fallback
# The vacuous form this replaces: awk reading ENVIRON[...] that is never set
# matches every line. Prove that d440b_order sets it: a pattern no line has fails.
breaks "chain: an absent ERE never matches"     d440b_order "${full_v}" 'no such line anywhere'
out="$(d440b_chain "${full_v}" verify)"
[[ "$(wc -l <<<"${out}")" == 3 && "${out}" == *"model verified"* ]] \
  && ok "chain: prints the three matched lines" || not_ok "chain output: ${out}"

# --- counters -------------------------------------------------------------------
holds  "verify counters: true 12 0"             d440b_verify_counters true 12 0
breaks "verify counters: verified=false"        d440b_verify_counters false 12 0
breaks "verify counters: onnx=0"                d440b_verify_counters true 0 0
breaks "verify counters: a fallback"            d440b_verify_counters true 12 1
breaks "verify counters: missing values"        d440b_verify_counters "" "" ""
breaks "verify counters: non-numeric"           d440b_verify_counters true x 0
holds  "fallback counters: false 0 9"           d440b_fallback_counters false 0 9
breaks "fallback counters: verified=true"       d440b_fallback_counters true 0 9
breaks "fallback counters: an onnx inference"   d440b_fallback_counters false 1 9
breaks "fallback counters: no fallbacks"        d440b_fallback_counters false 0 0
breaks "fallback counters: missing values"      d440b_fallback_counters "" "" ""

# --- runtime set, show, metric --------------------------------------------------
rej="$(put rej.txt 'demo config: unknown mode "bogus" for demo "d440b-model-verify" (known modes ["verify", "fallback"])')"
holds  "bogus: rc 1 and unknown mode"           d440b_bogus_rejected 1 "${rej}"
breaks "bogus: rc 0 fails"                      d440b_bogus_rejected 0 "${rej}"
breaks "bogus: rc 1 without unknown mode fails" d440b_bogus_rejected 1 "$(put execfail.txt 'error: unable to upgrade connection')"
show="$(put show.txt 'demo=d440b-model-verify active=true mode=verify modes=verify,fallback requires=-')"
holds  "show: mode stays"                       d440b_mode_stays "${show}" verify
breaks "show: other mode fails"                 d440b_mode_stays "${show}" fallback
breaks "show: inactive fails"                   d440b_mode_stays "$(put inactive.txt 'demo=d440b-model-verify active=false mode=- modes=verify,fallback requires=-')" verify
breaks "show: empty fails"                      d440b_mode_stays "${empty}" verify
prom="$(put m.prom '# TYPE nextg_demo_enabled gauge' 'nextg_demo_enabled{demo="d440b-model-verify",mode="fallback"} 1')"
holds  "metric: series present"                 d440b_metric "${prom}" fallback
breaks "metric: other mode fails"               d440b_metric "${prom}" verify
breaks "metric: header only fails"              d440b_metric "$(put h.prom '# TYPE nextg_demo_enabled gauge')" fallback
breaks "metric: no file fails"                  d440b_metric "${work}/absent.prom" fallback

echo "1..${n} all passed"
