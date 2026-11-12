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
breaks() { local name="$1"; shift; "$@" >/dev/null 2>&1 && not_ok "${name}" || ok "${name}"; }
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
breaks "the refused tokenless POST is not an ingest" d441a_ingests "$(put i2.log "$(at 01:00 "${refused}")")"

# --- the loop-mode chain ------------------------------------------------------------
defaults
holds "statistics chain, refused POST last" d441a_chain "$(mkdir_run ok-stat)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults
NW=("${NW[@]//kind=statistics/kind=prediction}")
d="$(mkdir_run ok-pred)"
holds "prediction chain, refused POST among the ingests (no AttributeError)" d441a_chain "${d}" "${CELL}" "${UE_V}" "${UE_B}" prediction
[[ "$(cat "${d}/lead-time.txt")" == "-70.0" ]] && ok "prediction lead time from the accepted >= 80 % report" || not_ok "lead time $(cat "${d}/lead-time.txt")"
defaults
breaks "statistics chain fails in prediction mode (no kind=prediction answer)" d441a_chain "$(mkdir_run kind)" "${CELL}" "${UE_V}" "${UE_B}" prediction
defaults; NW=("$(at 59:00 "${refused}")" "$(at 21:00 "$(udc statistics 95)")")
breaks "no accepted ingest: only the refused POST" d441a_chain "$(mkdir_run noingest)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; PCF=("$(at 50:10 "$(restore "${UE_B}")")")
breaks "no throttle" d441a_chain "$(mkdir_run nothrottle)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; PCF=("$(at 21:10 "$(throttle "${UE_B}")")")
breaks "no restore" d441a_chain "$(mkdir_run norestore)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; PCF=("$(at 21:10 "$(throttle "${UE_B}")")" "$(at 22:10 "$(throttle "${UE_B}")")" "$(at 50:10 "$(restore "${UE_B}")")")
breaks "two throttles" d441a_chain "$(mkdir_run twothrottles)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; PCF=("$(at 21:10 "$(throttle "${UE_V}")")" "$(at 50:10 "$(restore "${UE_V}")")")
breaks "UE-V throttled" d441a_chain "$(mkdir_run uev)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; PCF=("$(at 10:30 "$(throttle "${UE_B}")")" "$(at 50:10 "$(restore "${UE_B}")")")
breaks "throttle before the UDC answer" d441a_chain "$(mkdir_run ooo)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; SMF=("$(at 50:20 "${smf_up}")")
breaks "no capped smfd policy" d441a_chain "$(mkdir_run nosmf)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; UPF=("$(at 50:30 "${qer}")")
breaks "no QER before the restore" d441a_chain "$(mkdir_run noqer)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; UEB=("$(at 50:40 "${n1}")")
breaks "UE-B's throttle N1 missing: only the restore's (a rotated UE log)" d441a_chain "$(mkdir_run non1)" "${CELL}" "${UE_V}" "${UE_B}" statistics
defaults; NW[4]="$(at 50:00 "$(ingest 1.0 1)")"
breaks "AMF numberOfUes differs on the last accepted report" d441a_chain "$(mkdir_run amf)" "${CELL}" "${UE_V}" "${UE_B}" statistics

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
breaks "89.9 % does not saturate" d441a_saturated 89.9
breaks "74.3 % (the devtest1 peak) does not saturate" d441a_saturated 74.3
breaks "no peak does not saturate" d441a_saturated ""

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
breaks "a log whose head was rotated away does not" d441a_covers "${rot}" "${t0}"
breaks "an empty log does not" d441a_covers "$(put empty.log)" "${t0}"
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
