#!/usr/bin/env bash
# Self-test of the D441A scenario checks (nextgsim#465). No cluster, no network.
#
#   deploy/eks/overlays/demo-d441a-congestion-loop/test-scenario.sh
#
# Every check passes on a complete fixture and FAILS on the same fixture with a
# line removed, out of order, or its value wrong, so no assertion in scenario.sh
# is vacuous. The fixtures are shaped on the devtest1 captures of 2026-11-12
# (kubelet stamp, then the NF's own line).
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
# The check fails, and for the expected reason: its output (stdout and stderr)
# contains REASON, or, for a silent predicate (REASON ''), is empty. A case that
# fails for some other reason is not ok.                      NAME REASON CMD...
breaks() {
  local name="$1" reason="$2" out rc=0; shift 2
  out="$("$@" 2>&1)" || rc=$?
  (( rc != 0 )) || not_ok "${name}: passed"
  if [[ -z "${reason}" ]]; then
    [[ -z "${out}" ]] || not_ok "${name}: a silent check printed: ${out}"
  else
    [[ "${out}" == *"${reason}"* ]] || not_ok "${name}: expected '${reason}', got: ${out:-no output}"
  fi
  ok "${name}"
}
put() { local f="${work}/$1"; shift; printf '%s\n' "$@" >"${f}"; echo "${f}"; }
# kubelet stamp at 13:SS (seconds) plus LINE.                           SS LINE
at() { printf '2026-11-12T13:%s.000000000Z %s' "$1" "$2"; }

UE_V=imsi-999700000000001 UE_B=imsi-999700000000002 CELL="${D441A_CELL}"
nw() { printf '[2026-11-12T13:00:00.000Z INFO  nextgcore_nwdafd::ran_congestion] [demo:d441a-congestion-loop] %s' "$1"; }
pc() { printf '[2026-11-12T13:00:00.000Z INFO  nextgcore_pcfd::congestion_loop] [demo:d441a-congestion-loop] congestion-loop: %s' "$1"; }
ingest() { nw "ran-ingest cell=${CELL} tai=99970-000001 occupancy=$1% served_kbps=3603/5000 connected_ues=2 amf_ues_in_area=${2:-2} from=6b1d7e3c-0000-4000-8000-00000000465a"; }
refused="$(nw 'ran-ingest refused (401): Unauthorized("missing or malformed Bearer [REDACTED]"); nothing ingested')"
udc() { nw "udc GET USER_DATA_CONGESTION kind=$1 cell=000000010 congLevel=$2 → 200"; }
throttle() { pc "observed=congLevel=91(ran-user-data-congestion) action=throttle(supi=$1) sm_policy_id=a705 ambr=1000000/1000000 bps (subscribed 1000000000/1000000000 bps, floor 500 kbps)"; }
restore() { pc "observed=congLevel=0(ran-user-data-congestion) action=restore(supi=$1) sm_policy_id=a705 reason=below-threshold"; }
smf_cap='[2026-11-12T13:00:00.000Z INFO  nextgcore_smfd] Applying PCF-updated policy to ref=2: AMBR UL/DL=1000000/1000000 bps, 5QI=9'
smf_up='[2026-11-12T13:00:00.000Z INFO  nextgcore_smfd] Applying PCF-updated policy to ref=2: AMBR UL/DL=1000000000/1000000000 bps, 5QI=9'
qer='[2026-11-12T13:00:00.000Z INFO  nextgcore_upfd] Installed 1 QERs for SEID=0x2'
n1='2026-11-12T13:00:00.000000Z  INFO nextgsim_ue::app::task: PDU session 1: network set Session-AMBR DL 1 (unit 6) / UL 1 (unit 6)'

# One loop-mode capture directory. Overrides: NW PCF SMF UPF UEB (one line per
# array element). The default is a complete statistics run whose LAST nwdafd
# line is the refused tokenless POST (the devtest1 shape).
mkdir_run() {
  local d="${work}/$1"; mkdir -p "${d}"
  printf '%s\n' "${NW[@]}"  >"${d}/nwdaf-chain.txt"
  printf '%s\n' "${PCF[@]}" >"${d}/pcf-chain.txt"
  printf '%s\n' "${SMF[@]}" >"${d}/smf-chain.txt"
  printf '%s\n' "${UPF[@]}" >"${d}/upf-chain.txt"
  printf '%s\n' "${UEB[@]}" >"${d}/ue-b-chain.txt"
  echo "${d}"
}
defaults() {
  NW=("$(at 10:00 "$(ingest 20.0)")" "$(at 11:00 "$(udc statistics 20)")" "$(at 20:00 "$(ingest 95.0)")"
      "$(at 21:00 "$(udc statistics 95)")" "$(at 50:00 "$(ingest 1.0)")" "$(at 59:00 "${refused}")")
  PCF=("$(at 21:10 "$(throttle "${UE_B}")")" "$(at 50:10 "$(restore "${UE_B}")")")
  SMF=("$(at 21:20 "${smf_cap}")" "$(at 50:20 "${smf_up}")")
  UPF=("$(at 21:30 "${qer}")" "$(at 50:30 "${qer}")")
  UEB=("$(at 21:40 "${n1}")" "$(at 50:40 "${n1}")")
}

# --- ran-ingest: accepted reports only -------------------------------------------
holds "an accepted report is an ingest" d441a_ingests "$(put i1.log "$(at 01:00 "$(ingest 50.0)")")"
breaks "the refused tokenless POST is not an ingest" '' d441a_ingests "$(put i2.log "$(at 01:00 "${refused}")")"

# --- the loop-mode chain ------------------------------------------------------------
# d441a_chain on a run DIR in KIND mode, UE-B stopping at T_STOP (default 13:50:00,
# 10 s before the default restore), 15 s of quiet polls, min_hold_secs 10.
#                                                       DIR KIND [T_STOP] [MIN_HOLD]
T_STOP_DEFAULT='2026-11-12T13:50:00.000000000Z'
chain() { d441a_chain "$1" "${CELL}" "${UE_V}" "${UE_B}" "$2" "${3:-${T_STOP_DEFAULT}}" 15 "${4:-10}"; }
defaults
holds "statistics chain, refused POST last" chain "$(mkdir_run ok-stat)" statistics
defaults
NW=("${NW[@]//kind=statistics/kind=prediction}")
d="$(mkdir_run ok-pred)"
holds "prediction chain, refused POST among the ingests (no AttributeError)" chain "${d}" prediction
[[ "$(cat "${d}/lead-time.txt")" == "-70.0" ]] && ok "prediction lead time from the accepted >= 80 % report" || not_ok "lead time $(cat "${d}/lead-time.txt")"
defaults
breaks "statistics chain fails in prediction mode (no kind=prediction answer)" "no UDC 200 after" chain "$(mkdir_run kind)" prediction
defaults; NW=("$(at 59:00 "${refused}")" "$(at 21:00 "$(udc statistics 95)")")
breaks "no accepted ingest: only the refused POST" "no ran-ingest" chain "$(mkdir_run noingest)" statistics
defaults; PCF=("$(at 50:10 "$(restore "${UE_B}")")")
breaks "no throttle" "expected exactly one throttle" chain "$(mkdir_run nothrottle)" statistics
defaults; PCF=("$(at 21:10 "$(throttle "${UE_B}")")")
breaks "no restore" "expected exactly one restore" chain "$(mkdir_run norestore)" statistics
defaults; PCF=("$(at 21:10 "$(throttle "${UE_B}")")" "$(at 22:10 "$(throttle "${UE_B}")")" "$(at 50:10 "$(restore "${UE_B}")")")
breaks "two throttles" "expected exactly one throttle" chain "$(mkdir_run twothrottles)" statistics
defaults; PCF=("$(at 21:10 "$(throttle "${UE_V}")")" "$(at 50:10 "$(restore "${UE_V}")")")
breaks "UE-V throttled" "UE-V was throttled or restored" chain "$(mkdir_run uev)" statistics
defaults; PCF=("$(at 10:30 "$(throttle "${UE_B}")")" "$(at 50:10 "$(restore "${UE_B}")")")
breaks "throttle before the UDC answer" "the throttle precedes the UDC answer" chain "$(mkdir_run ooo)" statistics
defaults; SMF=("$(at 50:20 "${smf_up}")")
breaks "no capped smfd policy" "no smfd capped policy" chain "$(mkdir_run nosmf)" statistics
defaults; UPF=("$(at 50:30 "${qer}")")
breaks "no QER before the restore" "the restore precedes the QER install" chain "$(mkdir_run noqer)" statistics
defaults; UEB=("$(at 50:40 "${n1}")")
breaks "UE-B's throttle N1 missing: only the restore's (a rotated UE log)" "the throttle's N1 is missing" chain "$(mkdir_run non1)" statistics
defaults; NW[4]="$(at 50:00 "$(ingest 1.0 1)")"
breaks "AMF numberOfUes differs on the last accepted report" "AMF numberOfUes does not match" chain "$(mkdir_run amf)" statistics

# --- the restore follows the load's end, within a bound (nextgcore#1484) -------------
# By = max(T_STOP + 15 s of quiet polls, throttle 13:21:10 + min_hold) + 10 s slack.
defaults
breaks "a restore before UE-B stops (mid-load, as a stalled load step allows)" "precedes UE-B's stop" \
  chain "$(mkdir_run midload)" statistics '2026-11-12T13:55:00.000000000Z'
defaults
holds "a restore exactly at the bound (stop + 15 s + 10 s)" chain "$(mkdir_run atbound)" statistics '2026-11-12T13:49:45.000000000Z'
defaults
breaks "a restore 1 s past the bound" "comes 26.0 s after UE-B stopped, later than" \
  chain "$(mkdir_run late)" statistics '2026-11-12T13:49:44.000000000Z'
defaults
holds "min_hold_secs can set the bound: a long hold allows the later restore" \
  chain "$(mkdir_run minhold)" statistics '2026-11-12T13:49:00.000000000Z' 1800
defaults
breaks "an unparseable UE-B stop time" "is not an RFC 3339 UTC stamp" chain "$(mkdir_run badstop)" statistics 'yesterday'
[[ "$(d441a_quiet_secs "${here}/core-configs.yaml")" == 15 ]] && ok "quiet seconds from the overlay: 15 polls x 1000 ms" \
  || not_ok "quiet secs $(d441a_quiet_secs "${here}/core-configs.yaml")"
[[ -z "$(d441a_quiet_secs "$(put noquiet.yaml 'pcf:')")" ]] && ok "no quiet seconds without the knobs" || not_ok "quiet secs without knobs"

# --- UE-B's load: kubectl exec status (nextgcore#1484) -------------------------------
# A kubectl stand-in for d441a_ue_b_load. A ping exec prints an iputils summary
# and succeeds, unless "$*" matches STUB_FAIL (a glob) or its stdout is the hold
# file STUB_FAIL_HOLD; then it prints the 174900Z refusal and exits 1, sending
# nothing.
STUB_FAIL='' STUB_FAIL_HOLD=''
# shellcheck disable=SC2317  # called through "${K[@]}" in d441a_ue_b_load
kubectl() {
  local pid="${BASHPID}" out   # this process's stdout, not the substitution's
  out="$(readlink "/proc/${pid}/fd/1" 2>/dev/null || true)"
  # shellcheck disable=SC2053  # STUB_FAIL is a glob on purpose
  if [[ -n "${STUB_FAIL}" && "$*" == ${STUB_FAIL} ]] || [[ -n "${STUB_FAIL_HOLD}" && "${out}" == *"/${STUB_FAIL_HOLD}" ]]; then
    echo 'Unable to connect to the server: dial tcp: lookup x.eks.amazonaws.com on 169.254.253.253:53: write: operation not permitted' >&2
    return 1
  fi
  printf 'PING 10.45.0.1 (10.45.0.1) from 10.45.0.3 uesimtun0: 97(125) bytes of data.\n\n--- 10.45.0.1 ping statistics ---\n'
  printf '3216 packets transmitted, 294 received, 90.8582%% packet loss, time 3992ms\n'
}
load_run() { local d="${work}/$1"; mkdir -p "${d}"; : >"${d}/ue-b-ramp.txt"; NAMESPACE=nextg-demo d441a_ue_b_load "${d}" 10.45.0.1; }
ld="${work}/load-ok"
holds "every exec succeeds: no load failure" load_run load-ok
[[ "$(grep -c '^=== ' "${ld}/ue-b-ramp.txt")" == 13 ]] && ok "the transcript holds ten steps, the hold and two hold pings" || not_ok "load transcript headers"
holds "a complete load carried traffic in every step" d441a_load_traffic "${ld}/ue-b-ramp.txt"
STUB_FAIL='* -s 722 *'
breaks "a refused ramp exec fails the load (174900Z step 6)" "ramp step 6 (-s 722): kubectl exec exited 1" load_run load-step6
STUB_FAIL=''
breaks "and its step reads as no traffic, with the refusal" "load step 6 produced no traffic: no ping summary (Unable to connect to the server" \
  d441a_load_traffic "${work}/load-step6/ue-b-ramp.txt"
STUB_FAIL_HOLD=ue-b-hold-1.txt
breaks "a refused FIRST hold exec fails the load (not only the last pid's status)" "hold ping 1: kubectl exec exited 1" load_run load-hold1
STUB_FAIL_HOLD=''
breaks "and that hold ping reads as no traffic" "load hold ping 1 produced no traffic: no ping summary" \
  d441a_load_traffic "${work}/load-hold1/ue-b-ramp.txt"
unset -f kubectl

# --- UE-B's load: every step carried traffic (nextgcore#1484) ------------------------
# The transcript d441a_ue_b_load writes, every step at the devtest1 minimum
# (2751 requests in a 4 s step, 289 replies; 9605 in a 12 s hold ping).
summary() { printf -- '--- 10.45.0.1 ping statistics ---\n%s packets transmitted, %s received, 90%% packet loss, time 4000ms' "$1" "$2"; }
ramp() {   # STEP-TO-BREAK REPLACEMENT-BODY ('' = none)
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    printf '=== step %d: -s 97 (125-byte IP packets) at 2026-11-12T13:00:%02d.0Z\n' "${i}" "${i}"
    if [[ "step ${i}" == "$1" ]]; then [[ -z "$2" ]] || printf '%s\n' "$2"; else summary 2751 289; echo; fi
  done
  echo '=== hold: 2 x -s 1222 for 12 s at 2026-11-12T13:00:41.0Z'
  for i in 1 2; do
    printf '=== hold ping %d\n' "${i}"
    if [[ "hold ping ${i}" == "$1" ]]; then [[ -z "$2" ]] || printf '%s\n' "$2"; else summary 9605 503; echo; fi
  done
}
ramp none '' >"${work}/r-ok.txt"
holds "the devtest1 minimum rates carry traffic" d441a_load_traffic "${work}/r-ok.txt"
ramp 'step 6' 'Unable to connect to the server: dial tcp: lookup x on 169.254.253.253:53' >"${work}/r-stall.txt"
breaks "a step with no ping summary" "load step 6 produced no traffic: no ping summary (Unable to connect" d441a_load_traffic "${work}/r-stall.txt"
ramp 'step 3' '' >"${work}/r-empty.txt"
breaks "a step with no output at all" "load step 3 produced no traffic: no ping summary (no output)" d441a_load_traffic "${work}/r-empty.txt"
ramp 'step 4' "$(summary 12 12)" >"${work}/r-few.txt"
breaks "a step that sent almost nothing" "load step 4 produced no traffic: 12 requests in 4 s < 400" d441a_load_traffic "${work}/r-few.txt"
ramp 'step 9' "$(summary 3216 0)" >"${work}/r-norx.txt"
breaks "a step with requests but no replies (no downlink load)" "load step 9 produced no traffic: 3216 requests and no replies" d441a_load_traffic "${work}/r-norx.txt"
ramp 'hold ping 2' "$(summary 1100 50)" >"${work}/r-hold.txt"
breaks "a hold ping under 100/s of its 12 s" "load hold ping 2 produced no traffic: 1100 requests in 12 s < 1200" d441a_load_traffic "${work}/r-hold.txt"
ramp none '' | sed '/^=== step 10:/,/^=== hold:/{/^=== hold:/!d}' >"${work}/r-trunc.txt"
breaks "a transcript missing a step" "load step 10: not in the transcript" d441a_load_traffic "${work}/r-trunc.txt"

# --- restore hysteresis (nextgcore#1480) --------------------------------------------
# The overlay's own knobs pass; the devtest1 values that restored UE-B mid-load
# (restore_below 10, restore_after_polls 3) fail on each count.
holds "the overlay's restore knobs clear the throttled band" d441a_restore_hysteresis "${here}/core-configs.yaml" "${here}/gnb-config.yaml"
sed -E 's/^( +restore_below:).*/\1 10/' "${here}/core-configs.yaml" >"${work}/rb10.yaml"
breaks "restore_below 10 is not near the idle level" "restore_below 10 > 3" d441a_restore_hysteresis "${work}/rb10.yaml" "${here}/gnb-config.yaml"
sed -E 's/^( +restore_after_polls:).*/\1 3/' "${here}/core-configs.yaml" >"${work}/rp3.yaml"
breaks "restore_after_polls 3 is shorter than an in-load prediction dip" "3000 ms < 12000 ms" d441a_restore_hysteresis "${work}/rp3.yaml" "${here}/gnb-config.yaml"
sed -E -e 's/^( +restore_below:).*/\1 10/' -e 's/^( +restore_after_polls:).*/\1 3/' "${here}/core-configs.yaml" >"${work}/old.yaml"
breaks "the 2026-11-12 knobs (10, 3) fail on the poll count" "3000 ms < 12000 ms" d441a_restore_hysteresis "${work}/old.yaml" "${here}/gnb-config.yaml"
breaks "the 2026-11-12 knobs (10, 3) fail on restore_below" "restore_below 10 > 3" d441a_restore_hysteresis "${work}/old.yaml" "${here}/gnb-config.yaml"
sed -E 's/^( +restore_after_polls:).*/\1 90/' "${here}/core-configs.yaml" >"${work}/rp90.yaml"
breaks "a restore longer than the scenario's wait fails" "100 s > the scenario's 60 s restore wait" d441a_restore_hysteresis "${work}/rp90.yaml" "${here}/gnb-config.yaml"
sed -E 's/^( +cell_capacity_mbps:).*/\1 20.0/' "${here}/gnb-config.yaml" >"${work}/c20.yaml"
breaks "the same restore_below fails when C grows to 20 Mbps (the band is derived, not fixed)" "restore_below 3 > 0.75" d441a_restore_hysteresis "${here}/core-configs.yaml" "${work}/c20.yaml"
breaks "missing knobs fail" "restore knobs or the gNB capacity/window not found" d441a_restore_hysteresis "$(put noknobs.yaml 'pcf:')" "${here}/gnb-config.yaml"
# UE-B unthrottled: one throttle and as many restores; none, or an open throttle, is not.
holds "throttle then restore is unthrottled" d441a_unthrottled "$(put u1.log "$(throttle "${UE_B}")" "$(restore "${UE_B}")")"
breaks "an open throttle is not" '' d441a_unthrottled "$(put u2.log "$(throttle "${UE_B}")")"
breaks "no throttle at all is not" '' d441a_unthrottled "$(put u3.log "$(restore "${UE_B}")")"

# --- saturation ----------------------------------------------------------------------
status_sample() { printf '=== 2026-11-12T13:00:%02d.0Z\n{\n  "capacity_kbps": 5000,\n  "last_occupancy_pct": %s,\n  "queue_drops": 0,\n  "schema": "nextgsim.congestion-status/1"\n}\n' "$1" "$2"; }
st="${work}/status.txt"
{ status_sample 1 null; status_sample 2 41.5; status_sample 3 100.0; status_sample 4 97.2
  echo 'error: command failed: timeout'; } >"${st}"
[[ "$(d441a_peak_occupancy "${st}")" == 100.0 ]] && ok "peak occupancy over samples (null and a failed read skipped)" || not_ok "peak $(d441a_peak_occupancy "${st}")"
{ status_sample 1 73.9; status_sample 2 9.5; } >"${st}"
[[ "$(d441a_peak_occupancy "${st}")" == 73.9 ]] && ok "peak occupancy is numeric, not lexical (73.9 > 9.5)" || not_ok "numeric peak"
: >"${st}"
[[ -z "$(d441a_peak_occupancy "${st}")" ]] && ok "no samples: no peak" || not_ok "empty peak"
holds "90 % saturates" d441a_saturated 90
holds "100 % saturates" d441a_saturated 100.0
breaks "89.9 % does not saturate" '' d441a_saturated 89.9
breaks "74.3 % (the devtest1 peak) does not saturate" '' d441a_saturated 74.3
breaks "no peak does not saturate" '' d441a_saturated ""

# --- the p95 baseline -----------------------------------------------------------------
root="${work}/arms"
mkdir -p "${root}/no-loop/20261112T130714Z/scenario" "${root}/no-loop/20261112T150000Z/scenario"
echo 4.3 >"${root}/no-loop/20261112T130714Z/scenario/p95.txt"
printf 'peak_occupancy_pct=74.3\nsaturated=no\n' >"${root}/no-loop/20261112T130714Z/scenario/saturation.txt"
echo 412.0 >"${root}/no-loop/20261112T150000Z/scenario/p95.txt"
printf 'peak_occupancy_pct=100.0\nsaturated=yes\n' >"${root}/no-loop/20261112T150000Z/scenario/saturation.txt"
ln -sfn 20261112T130714Z "${root}/no-loop/latest"
[[ "$(d441a_baseline "${root}")" == 412.0 ]] && ok "baseline: the newest stamped no-loop arm, saturated" || not_ok "baseline saturated"
printf 'peak_occupancy_pct=74.3\nsaturated=no\n' >"${root}/no-loop/20261112T150000Z/scenario/saturation.txt"
rc=0; msg="$(d441a_baseline "${root}")" || rc=$?
[[ "${rc}" == 1 && "${msg}" == *"did not saturate"* ]] && ok "baseline: an unsaturated newest arm fails with the reason" || not_ok "unsaturated baseline rc=${rc} ${msg}"
rm "${root}/no-loop/20261112T150000Z/scenario/saturation.txt"
rc=0; d441a_baseline "${root}" >/dev/null || rc=$?
[[ "${rc}" == 1 ]] && ok "baseline: a newest arm without saturation.txt (an old harness) is no baseline" || not_ok "no saturation.txt rc=${rc}"
rc=0; d441a_baseline "${work}/none" >/dev/null || rc=$?
[[ "${rc}" == 2 ]] && ok "baseline: no no-loop arm yet" || not_ok "no arm rc=${rc}"

# --- capture coverage (kubelet rotation) -------------------------------------------------
full="$(put full.log "$(at 05:00 'boot')" "$(at 21:00 'mid')" "$(at 50:00 'end')")"
rot="$(put rot.log "$(at 21:00 'mid')" "$(at 50:00 'end')")"
t0='2026-11-12T13:10:00.000000000Z'
holds "a log from before the load start covers it" d441a_covers "${full}" "${t0}"
breaks "a log whose head was rotated away does not" '' d441a_covers "${rot}" "${t0}"
breaks "an empty log does not" '' d441a_covers "$(put empty.log)" "${t0}"
[[ "$(d441a_since "${full}" "${t0}" | wc -l)" == 2 ]] && ok "since: only lines stamped after TS" || not_ok "since"
[[ "$(d441a_first_ts "${rot}")" == 2026-11-12T13:21:00.000000000Z ]] && ok "first stamp" || not_ok "first stamp"

# --- the load plan ------------------------------------------------------------------------
m=0 prev=0 mono=true
for s in ${D441A_RAMP_SIZES}; do
  m=$((m + 1))
  [[ $((s + 28)) -eq $((125 * m)) ]] || mono=false
  [[ ${s} -gt ${prev} ]] || mono=false
  prev=${s}
done
[[ ${m} -eq 10 && ${mono} == true ]] && ok "ramp: ten steps, IP packets of 125·m bytes, increasing" || not_ok "ramp plan"
[[ ${D441A_HOLD_PINGS} -ge 2 && $((D441A_HOLD_SIZE + 28)) -eq 1250 ]] && ok "hold: two pings at 1250-byte packets" || not_ok "hold plan"
grep -qE 'ping -I uesimtun0 -q -s "\$\{m\}" -i 0\.001 -l 8 ' "${here}/scenario.sh" \
  && grep -qE 'ping -I uesimtun0 -q -s "\$\{D441A_HOLD_SIZE\}" -i 0\.001 -l 8 ' "${here}/scenario.sh" \
  && ok "every UE-B ping is preloaded (-l 8): not paced by the RTT" || not_ok "UE-B ping without -l"

# --- p95 ----------------------------------------------------------------------------------
pf="$(put ping.txt '64 bytes from 10.45.0.1: icmp_seq=1 ttl=64 time=3.1 ms' '64 bytes from 10.45.0.1: icmp_seq=2 ttl=64 time=250 ms')"
[[ "$(d441a_p95 "${pf}")" == 250.0 ]] && ok "p95" || not_ok "p95 $(d441a_p95 "${pf}")"
[[ "$(d441a_p95 "$(put noping.txt 'no answer')")" == nan ]] && ok "p95 without replies is nan" || not_ok "p95 nan"

echo "1..${n}"
