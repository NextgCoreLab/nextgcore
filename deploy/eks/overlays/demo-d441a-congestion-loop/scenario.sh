#!/usr/bin/env bash
# Seeded acceptance run of demo d441a-congestion-loop (nextgsim#465), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_KEY, DEMO_MODE and OUT set. Sourcing it
# defines the checks only (test-scenario.sh); executing it runs d441a_main.
#
# The run is identical in every mode (statistics | prediction | no-loop); only
# the assertions differ:
#   1. trust the gNB exporter's CCA key at the NRF (the gNB generated it and
#      published its public JWK; it goes into the NRF's trusted-key ConfigMap);
#   2. seed UE-B's subscriber (imsi-...002) and start UE-B; UE-V is the base UE
#      (imsi-...001, protected);
#   3. UE-V pings the UPF gateway 10 times a second for the whole run; UE-B
#      loads the downlink with echo requests whose replies are the downlink: a
#      ramp of ten 4 s steps from ~0.2C to ~1.6C, then a 12 s hold at ~3C
#      (C = 5 Mbps), then it stops. In the loop modes the run then waits (at most
#      D441A_RESTORE_WAIT_SECS) until UE-B is restored, before the captures. The gNB's
#      `congestion-status` (the measured occupancy) is sampled once a second
#      throughout, through nr-cli in the gNB container (patches/gnb-d441a.yaml).
#      Every ramp and hold `kubectl exec` must succeed, and every step must have
#      carried traffic (d441a_load_traffic): a stalled step lets pcfd restore
#      UE-B mid-load, which would otherwise read as a restore defect
#      (nextgcore#1484, statistics 20261112T174900Z);
#   4. an unauthenticated POST to the ingest route.
#
# The load is NOT paced by the round trip. Plain `ping -i` sends one request per
# reply once the interval is below the RTT (iputils' receive loop), so on devtest1
# the old ramp levelled off at ~1 per RTT, ~3 Mbps, under C, and no arm built a
# queue. `-l 8` (preload; root, which the privileged UE container is) lets each
# wakeup send what its tokens allow whatever is in flight. Measured in the UE
# image: ~820 requests/s at `-i 0.001` for any size, and ~720/s at a 300 ms RTT
# (a full queue), against 100/s without it. So the step rate is set by the size.
#
#   statistics / prediction
#     ordered chain by kubelet timestamp: nwdafd "ran-ingest cell=99970-000000010",
#     nwdafd "udc GET USER_DATA_CONGESTION kind=<statistics|prediction> ...
#     congLevel=... → 200", pcfd "action=throttle(supi=imsi-999700000000002)",
#     smfd "Applying PCF-updated policy ... AMBR UL/DL=1000000/1000000 bps",
#     upfd "Installed 1 QERs for SEID=", UE-B "network set Session-AMBR" (before
#     the restore), then pcfd "action=restore(supi=imsi-999700000000002)";
#     exactly one throttle and one restore, none for UE-V; the restore after UE-B
#     stops and within D441A_RESTORE_SLACK_SECS of the earliest pcfd can restore
#     (restore_after_polls x poll_ms after the stop, min_hold_secs after the
#     throttle); nwdafd's AMF
#     numberOfUes equals the gNB's connected_ues; the tokenless POST is 401 and
#     adds no throttle. UE-V's ping p95 is written to p95.txt and compared with
#     the newest no-loop arm's (<= 0.25x), but only when that arm's load
#     saturated the cell (its saturation.txt); against an unsaturated baseline
#     the run FAILS with that reason, not a ratio. Prediction also reports the
#     lead time of its throttle over the first measured occupancy >= 80 %.
#   no-loop
#     nwdafd ingests nothing (204s), the gNB logs `export: off`, pcfd logs
#     hold(no-ran-data), no "Applying PCF-updated policy". The load must saturate
#     the cell: the peak measured occupancy (congestion-status) must be >= 90 %,
#     or the run FAILS with "load did not saturate" and takes no p95 comparison.
#     Saturated, UE-V's p95 must be >= 100 ms.
#
# Every capture is a whole container log taken after the load. A log whose first
# line is stamped after the load began was rotated by kubelet, and a capture a
# check needs that comes back empty fails the run explicitly, rather than reading
# as "no such line".
#
# Everything goes through kubectl exec inside the namespace: no port-forward,
# nothing published. Captures under $OUT/scenario/.

D441A_CELL="99970-000000010"
D441A_SATURATION_PCT=90
# The ramp: one ping per step at -i 0.001 -l 8, ICMP payloads giving IP packets
# of 125·m bytes (m = 1..10), so the step rates are proportional to m. The hold:
# two such pings at 1250-byte packets.
D441A_RAMP_SIZES="97 222 347 472 597 722 847 972 1097 1222"
D441A_HOLD_SIZE=1222
D441A_HOLD_PINGS=2

# Restore hysteresis (nextgcore#1480). pcfd sees the occupancy the gNB SERVES,
# and the throttle itself lowers it: with UE-B capped at throttle_kbps the cell
# can carry at most throttle_kbps / C of UE-B, and on devtest1 the served
# congLevel under the throttle went down to 6 (statistics 20261112T164134Z) and
# to 1 (statistics 20261112T180956Z). In prediction mode the gNB's least-squares
# fit extrapolates the throttle-induced drop to 0: congLevel stayed under 3 for
# up to 6 consecutive polls while UE-B still loaded the cell (prediction
# 20261112T165042Z and 20261112T170200Z). So no restore_below lies under the
# throttled floor, which can be 0; what prevents a mid-load restore is the poll
# count. With restore_after_polls 3 prediction restored UE-B mid-load in both
# runs. d441a_restore_hysteresis derives the throttled band from the config and
# requires:
#   restore_after_polls x poll_ms >= twice the longest measured in-load dip (the
#     guard);
#   restore_below near the idle level, at most 0.15 x the throttled ceiling (3 at
#     C = 5 Mbps): it bounds how busy a quiet cell may be. It does not keep
#     throttled readings out (statistics read 1 under the throttle); the poll
#     count does;
#   the restore fits in the scenario's restore wait.
D441A_RESTORE_BELOW_FRAC=0.15     # restore_below <= this x the throttled ceiling
D441A_INLOAD_LOW_RUN_POLLS=6      # measured longest in-load run under 3 (prediction)
D441A_RESTORE_WAIT_SECS=60
# The restore comes at most this long after the earliest pcfd can restore it: the
# statistics window and the prediction fit lag the load's end by 0-2 s on devtest1
# (restores 15-17 s after UE-B stopped, at 15 polls of 1000 ms).
D441A_RESTORE_SLACK_SECS=10
# A load step carried traffic: its ping summary is there, it sent at least this
# many requests a second of its deadline (measured >= ~690/s; 100/s is the
# RTT-paced rate that never saturated C), and it got replies (the downlink load).
D441A_MIN_STEP_PPS=100

# Lines of LOG stamped strictly after TS (kubelet RFC 3339 stamp in field 1).  LOG TS
d441a_since() { awk -v t="$2" '$1 > t' "$1"; }
# The first kubelet stamp of LOG; empty for an empty log.                   LOG
d441a_first_ts() { awk 'NF { print $1; exit }' "$1"; }
# LOG reaches back to TS: it is non-empty and its first line is stamped at or
# before TS. A later first line means kubelet rotated its head away.        LOG TS
d441a_covers() {
  local first
  first="$(d441a_first_ts "$1")"
  [[ -n "${first}" && ! "${first}" > "$2" ]]
}
# The nwdafd lines of ACCEPTED cell reports only. `ran-ingest refused (401)` (the
# scenario's own tokenless POST) is not an ingest.                         LOG
d441a_ingests() { grep -E 'ran-ingest cell=[^ ]+ ' "$1"; }
# The peak `last_occupancy_pct` over the congestion-status samples in FILE
# (pretty JSON, one object per sample); empty when no sample has a value.   FILE
d441a_peak_occupancy() {
  sed -nE 's/.*"last_occupancy_pct": *([0-9]+(\.[0-9]+)?).*/\1/p' "$1" \
    | sort -g | tail -1
}
# PEAK >= the saturation threshold.                                       PEAK
d441a_saturated() {
  [[ -n "$1" ]] && awk -v p="$1" -v t="${D441A_SATURATION_PCT}" 'BEGIN { exit !(p + 0 >= t + 0) }'
}
# The no-loop baseline for a p95 comparison: the newest no-loop arm under ROOT
# (ROOT/no-loop/<UTC stamp>/scenario). Prints its p95 on success. Otherwise
# prints the reason and returns 2 when there is no such arm yet, 1 when that
# arm's load did not saturate the cell: its p95 then says nothing of a queue.
d441a_baseline() {                                                        # ROOT
  local dir
  dir="$(find "$1/no-loop" -mindepth 2 -maxdepth 2 -type d -name scenario -path '*/no-loop/2*/scenario' 2>/dev/null | sort | tail -1)"
  [[ -n "${dir}" && -s "${dir}/p95.txt" ]] || { echo "no no-loop arm captured yet"; return 2; }
  if ! grep -qx 'saturated=yes' "${dir}/saturation.txt" 2>/dev/null; then
    echo "the newest no-loop arm (${dir}) did not saturate the cell ($(tr '\n' ' ' 2>/dev/null <"${dir}/saturation.txt" || echo 'no saturation.txt')): no p95 comparison"
    return 1
  fi
  cat "${dir}/p95.txt"
}
# UE-V's ping p95 from a ping transcript; nan without replies.            FILE
d441a_p95() {
  python3 - "$1" <<'PY'
import re, sys
rtts = sorted(float(m) for m in re.findall(r"time=([\d.]+) ms", open(sys.argv[1]).read()))
if not rtts:
    print("nan"); sys.exit()
print(f"{rtts[min(len(rtts)-1, int(0.95*len(rtts)))]:.1f}")
PY
}
# The loop-mode chain over the scenario captures in DIR. T_STOP is when UE-B's
# load ended (RFC 3339 UTC); QUIET_SECS is restore_after_polls x poll_ms and
# MIN_HOLD_SECS min_hold_secs, in seconds.
#                             DIR CELL UE_V UE_B KIND T_STOP QUIET_SECS MIN_HOLD_SECS
d441a_chain() {
  python3 - "$@" "${D441A_RESTORE_SLACK_SECS}" <<'PY'
import re, sys
from datetime import datetime, timedelta
d, cell, ue_v, ue_b, kind, t_stop_arg = sys.argv[1:7]
quiet, min_hold, slack = map(float, sys.argv[7:10])
def stamp(ts):
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$", ts)
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    return datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f")
def load(name):
    out = []
    for l in open(f"{d}/{name}").read().splitlines():
        ts, _, msg = l.partition(" ")
        t = stamp(ts)
        if t:
            out.append((t, msg))
    return out
def fail(msg):
    raise SystemExit(f"[scenario] FAIL: {msg}")
t_stop = stamp(t_stop_arg)
if t_stop is None:
    fail(f"UE-B's stop time {t_stop_arg!r} is not an RFC 3339 UTC stamp")
nw, pcf, smf, upf, ueb = (load(f) for f in
    ("nwdaf-chain.txt", "pcf-chain.txt", "smf-chain.txt", "upf-chain.txt", "ue-b-chain.txt"))
# Accepted reports only: the refused tokenless POST logs "ran-ingest refused".
INGEST = re.compile(rf"ran-ingest cell={re.escape(cell)} ")
ingests = [(t, m) for t, m in nw if INGEST.search(m)]
def first(rows, pat, after=None, what=None):
    for t, m in rows:
        if (after is None or t >= after) and re.search(pat, m):
            return t, m
    fail(f"no {what or pat} after {after}")
if not ingests:
    fail("no ran-ingest")
t1 = ingests[0][0]
t2, _ = first(nw, rf"udc GET USER_DATA_CONGESTION kind={kind} cell=\S+ congLevel=\d+.* → 200", t1, "UDC 200")
throttles = [(t, m) for t, m in pcf if "action=throttle(" in m]
restores = [(t, m) for t, m in pcf if "action=restore(" in m]
if any(ue_v in m for _, m in throttles + restores):
    fail("UE-V was throttled or restored")
if len(throttles) != 1 or ue_b not in throttles[0][1]:
    fail(f"expected exactly one throttle of {ue_b}, got {[m for _, m in throttles]}")
if len(restores) != 1 or ue_b not in restores[0][1]:
    fail(f"expected exactly one restore of {ue_b}, got {[m for _, m in restores]}")
t3 = throttles[0][0]
if t3 < t2:
    fail("the throttle precedes the UDC answer")
t4, _ = first(smf, r"AMBR UL/DL=1000000/1000000 bps", t3, "smfd capped policy")
t5, _ = first(upf, r"Installed 1 QERs for SEID=", t4, "upfd QER")
t7 = restores[0][0]
if t7 < t5:
    fail("the restore precedes the QER install")
# The restore is for the load's end (nextgcore#1480, #1484): after UE-B stopped, and no
# later than the slack after the earliest pcfd could restore (restore_after_polls
# quiet polls after the stop, min_hold_secs after the throttle).
if t7 < t_stop:
    fail(f"the restore at {t7} precedes UE-B's stop at {t_stop}: a mid-load restore")
by = max(t_stop + timedelta(seconds=quiet), t3 + timedelta(seconds=min_hold)) + timedelta(seconds=slack)
if t7 > by:
    fail(f"the restore at {t7} comes {(t7 - t_stop).total_seconds():.1f} s after UE-B stopped, later than {by} "
         f"({quiet:g} s of quiet polls or {min_hold:g} s of hold, plus {slack:g} s)")
# UE-B's N1 Session-AMBR for the THROTTLE lies between the throttle and the
# restore; the restore's own N1 comes after it and cannot stand in.
t6, _ = first(ueb, r"network set Session-AMBR", t3, "UE-B N1 Session-AMBR")
if t6 > t7:
    fail("UE-B's first Session-AMBR after the throttle comes after the restore: the throttle's N1 is missing")
first(smf, r"Applying PCF-updated policy", t7, "smfd restore policy")
print(f"[scenario] chain: ingest {t1} → udc {t2} → throttle {t3} → smf {t4} → upf {t5} → ue-b {t6} → restore {t7} "
      f"({(t7 - t_stop).total_seconds():.1f} s after UE-B stopped)")
# AMF cross-check: the last ACCEPTED report names amf_ues_in_area equal to connected_ues.
last = ingests[-1][1]
cu = re.search(r"connected_ues=(\d+)", last); au = re.search(r"amf_ues_in_area=(\d+)", last)
if not (cu and au and cu.group(1) == au.group(1)):
    fail(f"AMF numberOfUes does not match the gNB's connected UEs: {last}")
print(f"[scenario] connected_ues={cu.group(1)} amf_ues_in_area={au.group(1)}")
if kind == "prediction":
    hot = []
    for t, m in ingests:
        o = re.search(r"occupancy=([\d.]+)%", m)
        if o and float(o.group(1)) >= 80.0:
            hot.append(t)
    lead = (hot[0] - t3).total_seconds() if hot else float("nan")
    print(f"[scenario] prediction lead time over measured >= 80%: {lead:.1f} s (reported, not asserted)")
    open(f"{d}/lead-time.txt", "w").write(f"{lead:.1f}\n")
PY
}

# The numeric value of `key: N` in FILE (first match); empty when absent. FILE KEY
d441a_knob() { sed -nE "s/^[[:space:]]+$2:[[:space:]]*([0-9.]+)[[:space:]]*(#.*)?$/\1/p" "$1" | head -1; }
# The pcf.congestion_loop restore knobs in PCF_CFG against the throttled band the
# gNB block in GNB_CFG implies. Prints the verdict; fails with every reason.  PCF_CFG GNB_CFG
d441a_restore_hysteresis() {
  local tk rb rp pm mh cap win
  tk="$(d441a_knob "$1" throttle_kbps)" rb="$(d441a_knob "$1" restore_below)"
  rp="$(d441a_knob "$1" restore_after_polls)" pm="$(d441a_knob "$1" poll_ms)"
  mh="$(d441a_knob "$1" min_hold_secs)" cap="$(d441a_knob "$2" cell_capacity_mbps)"
  win="$(d441a_knob "$2" window_ms)"
  [[ -n "${tk}" && -n "${rb}" && -n "${rp}" && -n "${pm}" && -n "${mh}" && -n "${cap}" && -n "${win}" ]] \
    || { echo "restore knobs or the gNB capacity/window not found (throttle_kbps=${tk} restore_below=${rb} restore_after_polls=${rp} poll_ms=${pm} min_hold_secs=${mh} cell_capacity_mbps=${cap} window_ms=${win})"; return 1; }
  python3 - "${tk}" "${rb}" "${rp}" "${pm}" "${mh}" "${cap}" "${win}" \
    "${D441A_RESTORE_BELOW_FRAC}" "${D441A_INLOAD_LOW_RUN_POLLS}" "${D441A_RESTORE_WAIT_SECS}" \
    "${D441A_RESTORE_SLACK_SECS}" <<'PY'
import sys
tk, rb, rp, pm, mh, cap, win, frac, run, wait, slack = map(float, sys.argv[1:])
ceiling = 100.0 * tk / (cap * 1000.0)          # % of C a throttled UE-B can fill
bound = frac * ceiling                          # restore_below's upper bound
bad = []
need = 2 * run * win
if rp * pm < need:
    bad.append(f"restore_after_polls x poll_ms = {rp * pm:g} ms < {need:g} ms (twice the longest in-load dip, {run:g} windows of {win:g} ms)")
if rb > bound:
    bad.append(f"restore_below {rb:g} > {bound:g} ({frac:g} x the {ceiling:g} % throttled ceiling): not near the idle level")
if max(rp * pm / 1000.0, mh) + slack > wait:
    bad.append(f"the restore needs {max(rp * pm / 1000.0, mh) + slack:g} s > the scenario's {wait:g} s restore wait")
if bad:
    print("restore hysteresis: " + "; ".join(bad)); sys.exit(1)
print(f"restore hysteresis ok: {rp:g} polls x {pm:g} ms >= {need:g} ms, restore_below {rb:g} <= {bound:g}, ceiling {ceiling:g} %")
PY
}
# restore_after_polls x poll_ms in PCF_CFG, in seconds; empty without them. PCF_CFG
d441a_quiet_secs() {
  local rp pm
  rp="$(d441a_knob "$1" restore_after_polls)" pm="$(d441a_knob "$1" poll_ms)"
  [[ -n "${rp}" && -n "${pm}" ]] && awk -v r="${rp}" -v p="${pm}" 'BEGIN { print r * p / 1000 }'
}
# UE-B is not throttled now: pcfd logged at least one throttle and as many restores. LOG
d441a_unthrottled() {
  local t r
  t="$(grep -c 'action=throttle(' "$1" || true)" r="$(grep -c 'action=restore(' "$1" || true)"
  [[ "${t}" -gt 0 && "${r}" -ge "${t}" ]]
}
# UE-B's load through kubectl: the ramp, then the hold, into S/ue-b-ramp.txt (one
# stamped `=== ` header per step and per hold ping). Prints one line per kubectl
# exec that failed and returns 1 if any did: a failed exec is a load gap
# (nextgcore#1484).                                                    S TARGET
d441a_ue_b_load() {
  local S="$1" target="$2" i=0 m rc fails=0 p
  local K=(kubectl -n "${NAMESPACE}") pids=()
  for m in ${D441A_RAMP_SIZES}; do
    i=$((i+1)) rc=0
    printf '=== step %d: -s %d (%d-byte IP packets) at %s\n' "${i}" "${m}" "$((m+28))" "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >>"${S}/ue-b-ramp.txt"
    "${K[@]}" exec deploy/ue-b -c ue -- ping -I uesimtun0 -q -s "${m}" -i 0.001 -l 8 -w 4 "${target}" \
      >>"${S}/ue-b-ramp.txt" 2>&1 || rc=$?
    (( rc == 0 )) || { echo "ramp step ${i} (-s ${m}): kubectl exec exited ${rc}"; fails=1; }
  done
  printf '=== hold: %d x -s %d for 12 s at %s\n' "${D441A_HOLD_PINGS}" "${D441A_HOLD_SIZE}" "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >>"${S}/ue-b-ramp.txt"
  for ((i = 1; i <= D441A_HOLD_PINGS; i++)); do
    "${K[@]}" exec deploy/ue-b -c ue -- ping -I uesimtun0 -q -s "${D441A_HOLD_SIZE}" -i 0.001 -l 8 -w 12 "${target}" \
      >"${S}/ue-b-hold-${i}.txt" 2>&1 &
    pids+=($!)
  done
  i=0
  for p in "${pids[@]}"; do
    i=$((i+1)) rc=0
    wait "${p}" || rc=$?
    (( rc == 0 )) || { echo "hold ping ${i}: kubectl exec exited ${rc}"; fails=1; }
  done
  for ((i = 1; i <= D441A_HOLD_PINGS; i++)); do
    printf '=== hold ping %d\n' "${i}" >>"${S}/ue-b-ramp.txt"
    cat "${S}/ue-b-hold-${i}.txt" >>"${S}/ue-b-ramp.txt"
  done
  return "${fails}"
}
# Every load step in the ramp transcript FILE carried traffic: each ramp step and
# each hold ping has its ping summary, sent at least D441A_MIN_STEP_PPS requests
# a second of its deadline, and got replies. A stalled step lets pcfd restore
# UE-B mid-load; this names it, so it does not read as a restore defect. Prints
# one line per such step; returns 1 if any.                                 FILE
d441a_load_traffic() {
  python3 - "$1" "${D441A_RAMP_SIZES}" "${D441A_HOLD_PINGS}" "${D441A_MIN_STEP_PPS}" <<'PY'
import re, sys
path, sizes, holds, pps = sys.argv[1], sys.argv[2].split(), int(sys.argv[3]), float(sys.argv[4])
steps, cur = {}, None
for line in open(path).read().splitlines():
    if line.startswith("=== "):
        m = re.match(r"=== (step \d+|hold ping \d+)\b", line)
        cur = m.group(1) if m else None
        if cur:
            steps[cur] = []
    elif cur:
        steps[cur].append(line)
want = [(f"step {i}", 4) for i in range(1, len(sizes) + 1)] + [(f"hold ping {i}", 12) for i in range(1, holds + 1)]
bad = []
for name, deadline in want:
    if name not in steps:
        bad.append(f"load {name}: not in the transcript"); continue
    m = re.search(r"(\d+) packets transmitted, (\d+) received", "\n".join(steps[name]))
    if not m:
        said = next((l.strip() for l in steps[name] if l.strip()), "no output")
        bad.append(f"load {name} produced no traffic: no ping summary ({said})"); continue
    tx, rx = int(m.group(1)), int(m.group(2))
    if tx < pps * deadline:
        bad.append(f"load {name} produced no traffic: {tx} requests in {deadline} s < {pps * deadline:g}")
    elif rx == 0:
        bad.append(f"load {name} produced no traffic: {tx} requests and no replies (no downlink load)")
print("\n".join(bad), end="\n" if bad else "")
sys.exit(1 if bad else 0)
PY
}

d441a_main() {
  set -uo pipefail
  : "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
  local K=(kubectl -n "${NAMESPACE}")
  local S="${OUT}/scenario"
  mkdir -p "${S}"
  local UE_V="imsi-999700000000001" UE_B="imsi-999700000000002" CELL="${D441A_CELL}"
  local TARGET="10.45.0.1"
  local EXPORTER_ID="6b1d7e3c-0000-4000-8000-00000000465a"
  local JWK_PATH="/tmp/d441a-cca/${EXPORTER_ID}.jwk"
  local FAILS=0 MONGO_POD GNB_POD UPF_POD NODE T0 T_STOP PING_PID POLL_PID=''
  local THROTTLES_BEFORE THROTTLES_AFTER P95 PEAK BASE f rc need KIND
  say()  { printf '[scenario] %s\n' "$*"; }
  bad()  { printf '[scenario] FAIL: %s\n' "$*"; FAILS=$((FAILS+1)); }
  wait_for() {
    local t="$1"; shift
    local end=$(( $(date +%s) + t ))
    until "$@" >/dev/null 2>&1; do
      [[ $(date +%s) -ge ${end} ]] && return 1
      sleep 3
    done
  }

  # --- 0. the restore knobs (nextgcore#1480) -------------------------------------
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  d441a_restore_hysteresis "${here}/core-configs.yaml" "${here}/gnb-config.yaml" >"${S}/restore-hysteresis.txt" 2>&1 \
    || bad "$(cat "${S}/restore-hysteresis.txt")"
  say "$(cat "${S}/restore-hysteresis.txt")"

  # --- 1. the exporter's CCA key -----------------------------------------------
  wait_for 180 "${K[@]}" exec deploy/gnb -c gnb -- test -s "${JWK_PATH}" \
    || bad "the gNB published no CCA JWK at ${JWK_PATH} within 180 s"
  "${K[@]}" exec deploy/gnb -c gnb -- cat "${JWK_PATH}" >"${S}/exporter.jwk" 2>/dev/null
  "${K[@]}" create configmap d441a-cca-trusted --from-file="${EXPORTER_ID}.jwk=${S}/exporter.jwk" \
    --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null || bad "trusted-key ConfigMap"
  say "exporter JWK published to the NRF trust store (kubelet sync can take ~60 s)"

  # --- 2. UE-B -----------------------------------------------------------------
  MONGO_POD="$("${K[@]}" get pod -l app.kubernetes.io/name=mongodb -o jsonpath='{.items[0].metadata.name}')"
  # shellcheck disable=SC2016  # `$set` is mongosh's operator, not a shell expansion
  "${K[@]}" exec "${MONGO_POD}" -- mongosh --quiet nextgcore --eval '
    const s = db.subscribers.findOne({imsi: "999700000000001"}, {_id: 0});
    s.imsi = "999700000000002"; s.msisdn = ["821000000002"];
    db.subscribers.updateOne({imsi: s.imsi}, {$set: s}, {upsert: true});
    print("seeded " + s.imsi);' >"${S}/seed-ue-b.txt" 2>&1 || bad "UE-B subscriber seed"
  "${K[@]}" scale deployment/ue-b --replicas=1 >/dev/null
  "${K[@]}" rollout status deployment/ue-b --timeout=300s >/dev/null || bad "UE-B rollout"
  tun_ip() { "${K[@]}" exec "deploy/$1" -c ue -- sh -c "ip -4 -o addr show uesimtun0 | awk '{print \$4}' | cut -d/ -f1"; }
  wait_for 180 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/ue-b -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
    || bad "UE-B has no PDU session (uesimtun0) within 180 s"
  wait_for 120 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/ue -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
    || bad "UE-V has no PDU session (uesimtun0)"
  say "UE-V $(tun_ip ue) UE-B $(tun_ip ue-b)"
  # The exporter's token needs the trusted key; wait for its first accepted export
  # (or, in no-loop, nothing to wait for).
  if [[ "${DEMO_MODE}" != no-loop ]]; then
    wait_for 180 sh -c "kubectl -n ${NAMESPACE} logs deploy/nwdaf -c nwdaf | grep -qE 'ran-ingest cell=${CELL} '" \
      || bad "no accepted cell report at nwdafd within 180 s"
  fi

  # The gNB's nr-cli node, for congestion-status (patches/gnb-d441a.yaml).
  GNB_POD="$("${K[@]}" get pod -l app.kubernetes.io/name=gnb -o jsonpath='{.items[0].metadata.name}')"
  NODE="$("${K[@]}" exec "${GNB_POD}" -c gnb -- /opt/d441a/nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')"
  [[ -n "${NODE}" ]] || bad "nr-cli --dump found no gNB node in ${GNB_POD}: congestion-status is unreadable"
  sleep 10

  # --- 3. the load -------------------------------------------------------------
  T0="$(date -u -d '-2 seconds' +%Y-%m-%dT%H:%M:%S.%NZ)"   # 2 s early, for clock skew
  : >"${S}/gnb-status.txt"
  if [[ -n "${NODE}" ]]; then
    ( while [[ ! -e "${S}/.load-done" ]]; do
        printf '=== %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
        "${K[@]}" exec "${GNB_POD}" -c gnb -- /opt/d441a/nr-cli "${NODE}" -e congestion-status 2>&1
        sleep 1
      done ) >>"${S}/gnb-status.txt" &
    POLL_PID=$!
  fi
  "${K[@]}" exec deploy/ue -c ue -- ping -I uesimtun0 -i 0.1 -c 900 -W 2 "${TARGET}" \
    >"${S}/ue-v-ping.txt" 2>&1 &
  PING_PID=$!
  sleep 10
  : >"${S}/ue-b-ramp.txt"
  d441a_ue_b_load "${S}" "${TARGET}" >"${S}/load-exec.txt"
  T_STOP="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  say "UE-B stopped at ${T_STOP}"
  while IFS= read -r f; do bad "${f}"; done <"${S}/load-exec.txt"
  d441a_load_traffic "${S}/ue-b-ramp.txt" >"${S}/load-traffic.txt"
  while IFS= read -r f; do bad "${f}"; done <"${S}/load-traffic.txt"
  wait "${PING_PID}"
  touch "${S}/.load-done"
  [[ -z "${POLL_PID}" ]] || wait "${POLL_PID}"
  rm -f "${S}/.load-done"

  # The restore needs restore_after_polls quiet polls after UE-B stops, which can
  # outlast UE-V's ping: wait for it, so the captures below hold it.
  if [[ "${DEMO_MODE}" != no-loop ]]; then
    local end=$(( $(date +%s) + D441A_RESTORE_WAIT_SECS ))
    until "${K[@]}" logs deploy/pcf -c pcf >"${S}/.pcf-now.log" 2>/dev/null && d441a_unthrottled "${S}/.pcf-now.log"; do
      [[ $(date +%s) -ge ${end} ]] && { say "UE-B not restored within ${D441A_RESTORE_WAIT_SECS} s of the load's end"; break; }
      sleep 2
    done
    rm -f "${S}/.pcf-now.log"
  fi

  # --- 4. the tokenless POST ----------------------------------------------------
  THROTTLES_BEFORE="$("${K[@]}" logs deploy/pcf -c pcf 2>/dev/null | grep -c 'action=throttle(' || true)"
  "${K[@]}" exec deploy/nwdaf -c nwdaf -- sh -c "curl -s --http2-prior-knowledge --max-time 10 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' --data '{}' http://127.0.0.1:7777/nnwdaf-randata/v1/cell-reports" \
    >"${S}/tokenless-post.status" 2>/dev/null
  sleep 3
  THROTTLES_AFTER="$("${K[@]}" logs deploy/pcf -c pcf 2>/dev/null | grep -c 'action=throttle(' || true)"

  # --- captures -------------------------------------------------------------------
  # Whole container logs, then the chains from them. A log that does not reach
  # back to the load's start was rotated: a chain from it would be incomplete.
  UPF_POD="$("${K[@]}" get pod -l app.kubernetes.io/name=upf -o jsonpath='{.items[0].metadata.name}')"
  "${K[@]}" logs deploy/nwdaf -c nwdaf --timestamps >"${S}/nwdaf.log" 2>/dev/null
  "${K[@]}" logs deploy/pcf   -c pcf   --timestamps >"${S}/pcf.log"   2>/dev/null
  "${K[@]}" logs deploy/gnb   -c gnb   --timestamps >"${S}/gnb.log"   2>/dev/null
  "${K[@]}" logs deploy/smf   -c smf   --timestamps >"${S}/smf.log"   2>/dev/null
  "${K[@]}" logs "${UPF_POD}" -c upf   --timestamps >"${S}/upf.log"   2>/dev/null
  "${K[@]}" logs deploy/ue-b  -c ue    --timestamps >"${S}/ue-b.log"  2>/dev/null
  for f in nwdaf pcf gnb smf upf ue-b; do
    d441a_covers "${S}/${f}.log" "${T0}" \
      || bad "the ${f} log does not reach back to the load start ${T0} (first line: $(d441a_first_ts "${S}/${f}.log")): empty, or rotated by kubelet"
  done
  grep -E '\[demo:d441a-congestion-loop\]' "${S}/nwdaf.log" >"${S}/nwdaf-chain.txt"
  grep -E '\[demo:d441a-congestion-loop\]' "${S}/pcf.log"   >"${S}/pcf-chain.txt"
  grep -E '\[demo:d441a-congestion-loop\]' "${S}/gnb.log"   >"${S}/gnb-chain.txt"
  grep -E 'Applying PCF-updated policy' "${S}/smf.log"      >"${S}/smf-chain.txt"
  grep -E 'Installed [0-9]+ QERs for SEID' "${S}/upf.log"   >"${S}/upf-chain.txt"
  grep -E 'network set Session-AMBR' "${S}/ue-b.log"        >"${S}/ue-b-chain.txt"
  need="nwdaf-chain pcf-chain gnb-chain"
  [[ "${DEMO_MODE}" == no-loop ]] || need+=" smf-chain upf-chain ue-b-chain"
  for f in ${need}; do
    [[ -s "${S}/${f}.txt" ]] || bad "empty capture: scenario/${f}.txt"
  done
  P95="$(d441a_p95 "${S}/ue-v-ping.txt")"
  echo "${P95}" >"${S}/p95.txt"
  PEAK="$(d441a_peak_occupancy "${S}/gnb-status.txt")"
  if d441a_saturated "${PEAK}"; then
    printf 'peak_occupancy_pct=%s\nsaturated=yes\n' "${PEAK}" >"${S}/saturation.txt"
  else
    printf 'peak_occupancy_pct=%s\nsaturated=no\n' "${PEAK:-none}" >"${S}/saturation.txt"
  fi
  say "UE-V ping p95 = ${P95} ms; peak measured occupancy = ${PEAK:-none} %; tokenless POST = $(cat "${S}/tokenless-post.status")"

  # --- assertions -------------------------------------------------------------------
  [[ "$(cat "${S}/tokenless-post.status")" == 401 ]] || bad "tokenless POST is not 401"
  [[ "${THROTTLES_AFTER}" == "${THROTTLES_BEFORE}" ]] || bad "the tokenless POST was followed by a throttle"
  if [[ "${DEMO_MODE}" == no-loop ]]; then
    d441a_ingests "${S}/nwdaf-chain.txt" >/dev/null && bad "no-loop: nwdafd ingested a cell report"
    grep -q 'export: off (mode=no-loop)' "${S}/gnb-chain.txt" || bad "no-loop: no 'export: off' gNB line"
    grep -q 'hold(no-ran-data)' "${S}/pcf-chain.txt" || bad "no-loop: no pcfd hold(no-ran-data)"
    [[ -s "${S}/smf-chain.txt" ]] && bad "no-loop: smfd applied a PCF-updated policy"
    if ! d441a_saturated "${PEAK}"; then
      bad "load did not saturate: peak measured occupancy ${PEAK:-none} % < ${D441A_SATURATION_PCT} % (scenario/gnb-status.txt); no p95 comparison"
    else
      python3 -c "import sys; sys.exit(0 if float('${P95}') >= 100 else 1)" \
        || bad "no-loop: UE-V p95 ${P95} ms < 100 ms with the cell saturated (peak ${PEAK} %)"
    fi
  else
    KIND="statistics"; [[ "${DEMO_MODE}" == prediction ]] && KIND="prediction"
    d441a_chain "${S}" "${CELL}" "${UE_V}" "${UE_B}" "${KIND}" "${T_STOP}" \
      "$(d441a_quiet_secs "${here}/core-configs.yaml")" "$(d441a_knob "${here}/core-configs.yaml" min_hold_secs)" \
      || FAILS=$((FAILS+1))
    rc=0
    BASE="$(d441a_baseline "$(dirname "$(dirname "${OUT}")")")" || rc=$?
    case "${rc}" in
      0) python3 -c "import sys; sys.exit(0 if float('${P95}') <= 0.25*float('${BASE}') else 1)" \
           || bad "UE-V p95 ${P95} ms > 0.25 x no-loop ${BASE} ms"
         say "UE-V p95 ${P95} ms vs no-loop ${BASE} ms" ;;
      2) say "${BASE}: p95 ${P95} ms recorded, ratio not checked (run the no-loop arm first)" ;;
      *) bad "${BASE}" ;;
    esac
  fi

  say "T0=${T0} FAILS=${FAILS}"
  [[ ${FAILS} -eq 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  d441a_main
  exit $?
fi
