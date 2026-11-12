#!/usr/bin/env bash
# Self-test of the D444A scenario checks (nextgsim#477). No cluster, no network.
#
#   deploy/eks/overlays/demo-d444a-ambr-adapt/test-scenario.sh
#
# Every check passes on a complete fixture and FAILS on the same fixture with
# its line removed or its value wrong, so no assertion in scenario.sh can be
# vacuous; the chain also fails out of order.
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

ts='2026-11-12T10:00:00.000000Z'
smf="${ts} [INFO] ref=1: network-requested PDU Session Modification (AMBR UL/DL 1000000000/1000000000 -> 64000/1000000000 bps, 5QI 9 -> 9, ARP PL 8 -> 8)"
req="${ts}  INFO nextgsim_gnb: PDU Session Resource Modify Request: amf_ue_ngap_id=1, ran_ue_ngap_id=1, 1 items"
rsp="${ts}  INFO nextgsim_gnb: PDU Session Resource Modify Response sent to AMF"
cmp="${ts}  INFO nextgsim_ue: Sending PDU Session Modification Complete: PSI=1, PTI=0"
rate="${ts}  INFO nextgsim_ue: [demo:d444a-ambr-adapt] rate target 51200 bps from session-AMBR (PSI 1), keep 128->40 (UL Session-AMBR 64000 bps, 50 Hz, 124 B per datagram)"
raw="${ts}  INFO nextgsim_ue: [demo:d444a-ambr-adapt] session-AMBR (PSI 1) UL 64000 bps not followed: mode raw, keep 128"
rowa="${ts}  INFO semantic_sink: [demo:d444a-ambr-adapt] epoch=7 mode=semantic encoder=pca keep=128..40 received=500 lost=0 ip_bytes=100000 ul_kbps=80.0 acc=0.960 baseline top-variance-raw acc=0.900 mean-pool acc=0.800 (equal bytes) margin=+0.060/+0.160"
rowb="${ts}  INFO semantic_sink: [demo:d444a-ambr-adapt] epoch=8 mode=semantic encoder=pca keep=40 received=500 lost=1 ip_bytes=62000 ul_kbps=49.6 acc=0.966 baseline top-variance-raw acc=0.832 mean-pool acc=0.661 (equal bytes) margin=+0.134/+0.305"
rawb="${ts}  INFO semantic_sink: [demo:d444a-ambr-adapt] epoch=8 mode=raw encoder=raw keep=128 received=270 lost=230 ip_bytes=81000 ul_kbps=64.8 acc=0.971"

full="$(put full.log "${smf}" "${req}" "${rsp}" "${cmp}" "${rate}" "${rowa}" "${rowb}")"
holds "semantic chain" d444a_chain "${full}" semantic
for drop in "${smf}" "${req}" "${rsp}" "${cmp}" "${rate}"; do
  f="$(put drop.log "${smf}" "${req}" "${rsp}" "${cmp}" "${rate}")"
  grep -vxF -- "${drop}" "${f}" >"${f}.x" || true
  breaks "semantic chain without: ${drop:30:50}" d444a_chain "${f}.x" semantic
done
breaks "chain out of order (COMPLETE before the smfd line)" d444a_chain "$(put ooo.log "${cmp}" "${smf}" "${req}" "${rsp}" "${rate}")" semantic
holds "raw chain" d444a_chain "$(put raw.log "${smf}" "${req}" "${rsp}" "${cmp}" "${raw}")" raw
breaks "raw chain needs the not-followed line" d444a_chain "$(put raw2.log "${smf}" "${req}" "${rsp}" "${cmp}" "${rate}")" raw
holds "raw: no rate target" d444a_no_rate_target "$(put r.log "${raw}")"
breaks "raw: a rate target line fails" d444a_no_rate_target "$(put r2.log "${rate}")"

[[ "$(d444a_field "${rowb}" acc)" == 0.966 ]] && ok "field takes the first acc=" || not_ok "field acc"
[[ "$(d444a_baseline "${rowb}" top-variance-raw)" == 0.832 ]] && ok "baseline top" || not_ok "baseline top"
[[ "$(d444a_baseline "${rowb}" mean-pool)" == 0.661 ]] && ok "baseline pool" || not_ok "baseline pool"
# Timestamped: the slices are by kubelet stamp, so a log whose head was rotated
# away between two collects selects the same lines (the devtest1 failure). The
# epoch-A rows (keep 128, before the throttle) are what tell "after the UE
# line" from "after some line number": without them every slice agrees.
st() { local s; s="$(printf '%02d' "$1")"; printf '%s' "${2/T10:00:00./T10:00:${s}.}"; }   # SECOND LINE
row5="${rowa/epoch=7/epoch=5}"; row5="${row5/keep=128..40/keep=128}"
row6="${row5/epoch=5/epoch=6}"
t_ue="$(st 7 "${rate}")"
tue="${t_ue%% *}"
tlog="$(put t.log "$(st 1 "${row5}")" "$(st 2 "${smf}")" "$(st 3 "${req}")" "$(st 4 "${row6}")" \
  "$(st 5 "${rsp}")" "$(st 6 "${cmp}")" "${t_ue}" "$(st 8 "${rowa}")" "$(st 9 "${rowb}")" "$(st 10 "${rowa}")")"
rot="$(put rot.log "$(sed -n '2,$p' "${tlog}")")"   # the epoch=5 row rotated away
[[ "$(d444a_epoch_b "${tlog}" "${tue}")" == "$(st 9 "${rowb}")" ]] && ok "epoch B is the second row after the UE line" || not_ok "epoch B"
[[ "$(d444a_epoch_b "${rot}" "${tue}")" == "$(st 9 "${rowb}")" ]] && ok "epoch B survives a rotated-away log head" || not_ok "epoch B rotated"
[[ -z "$(d444a_epoch_b "${tlog}" "")" ]] && ok "epoch B: no UE stamp selects nothing" || not_ok "epoch B empty stamp"
[[ "$(d444a_since "${tlog}" "2026-11-12T10:00:08.5Z" | wc -l)" == 2 ]] && ok "since: only lines stamped after TS" || not_ok "since"
[[ "$(d444a_since "${rot}" "2026-11-12T10:00:03.5Z")" == "$(d444a_since "${tlog}" "2026-11-12T10:00:03.5Z")" ]] \
  && ok "since: a rotated-away head does not shift the slice" || not_ok "since rotated"
[[ -z "$(d444a_since "${tlog}" "2026-11-12T10:00:11Z")" ]] && ok "since: nothing after the last stamp" || not_ok "since empty"
breaks "since: an empty TS fails (never selects every line)" d444a_since "${tlog}" ""

# The restore chain over a since-slice, end to end: the throttle part of the log
# is before the stamp, the restore after it, and the head is rotated away.
rsmf="${ts} [INFO] ref=1: network-requested PDU Session Modification (AMBR UL/DL 64000/1000000000 -> 1000000000/1000000000 bps, 5QI 9 -> 9, ARP PL 8 -> 8)"
rrate="${ts}  INFO nextgsim_ue: [demo:d444a-ambr-adapt] rate target 800000000 bps from session-AMBR (PSI 1), keep 40->128 (UL Session-AMBR 1000000000 bps, 50 Hz, 300 B per datagram)"
rlog="$(put rl.log "$(st 1 "${smf}")" "$(st 2 "${cmp}")" "$(st 3 "${rate}")" "$(st 4 "${rowb}")" \
  "$(st 6 "${rsmf}")" "$(st 7 "${cmp}")" "$(st 8 "${rrate}")" "$(st 9 "${rowa}")")"
rrot="$(put rrot.log "$(sed -n '4,$p' "${rlog}")")"
since_ts="2026-11-12T10:00:05.000000000Z"
d444a_since "${rlog}" "${since_ts}" >"${work}/rs.log"
d444a_since "${rrot}" "${since_ts}" >"${work}/rrs.log"
holds "restore chain over the since-slice (semantic)" d444a_restore_chain "${work}/rs.log" semantic
holds "restore chain over the slice of a rotated-head log" d444a_restore_chain "${work}/rrs.log" semantic
holds "restore chain (raw) needs no keep line" d444a_restore_chain "${work}/rrs.log" raw
breaks "restore chain: an empty slice fails" d444a_restore_chain "$(put empty.log)" semantic
d444a_since "${rlog}" "2026-11-12T10:00:00Z" | sed -n '1,4p' >"${work}/pre.log"
breaks "restore chain: the throttle lines alone do not satisfy it" d444a_restore_chain "${work}/pre.log" semantic
breaks "restore chain: no keep 40->128 line fails (semantic)" d444a_restore_chain "$(put nr.log "$(st 6 "${rsmf}")" "$(st 7 "${cmp}")")" semantic

holds "semantic epoch B" d444a_semantic_row "${rowb}" 0
breaks "semantic: keep 128..40 is not epoch B" d444a_semantic_row "${rowa}" 0
breaks "semantic: qer_gate drops" d444a_semantic_row "${rowb}" 3
breaks "semantic: losses" d444a_semantic_row "${rowb/lost=1/lost=9}" 0
breaks "semantic: below the floor" d444a_semantic_row "${rowb/acc=0.966/acc=0.850}" 0
breaks "semantic: a baseline wins" d444a_semantic_row "${rowb/top-variance-raw acc=0.832/top-variance-raw acc=0.990}" 0
breaks "semantic: no baselines" d444a_semantic_row "${rowb%% baseline*}" 0
breaks "semantic: no row" d444a_semantic_row "" 0
holds "raw epoch B" d444a_raw_row "${rawb}" 230
breaks "raw: no qer_gate drops" d444a_raw_row "${rawb}" 0
breaks "raw: a pca row" d444a_raw_row "${rowb}" 230

prom="$(put m.prom '# HELP x' 'upf_dataplane_dropped_packets_by_reason_total{reason="far_drop"} 4' 'upf_dataplane_dropped_packets_by_reason_total{reason="qer_gate"} 17')"
[[ "$(d444a_qer_gate "${prom}")" == 17 ]] && ok "qer_gate counter" || not_ok "qer_gate counter"
breaks "absent qer_gate series fails (a failed scrape is not zero drops)" d444a_qer_gate "$(put m2.prom 'x 1')"
breaks "an empty scrape fails" d444a_qer_gate "$(put m3.prom)"
[[ "$(d444a_qer_gate "$(put m4.prom 'upf_dataplane_dropped_packets_by_reason_total{reason="qer_gate"} 0')")" == 0 ]] \
  && ok "a present zero reads 0" || not_ok "present zero"

[[ "$(d444a_ul_value "$(put ul.json '{"value":1,"unit":3}')")" == "1 3" ]] && ok "UL AMBR original parsed" || not_ok "UL parse"
[[ -z "$(d444a_ul_value "$(put ul2.json 'MongoServerError: x')")" ]] && ok "an error is not a UL value" || not_ok "UL error"
orig="$(put sm.json '{"smPolicySnssaiData":{"1":{"snssai":{"sst":1},"smPolicyDnnData":{"internet":{"dnn":"internet","online":true}}}}}')"
[[ "$(d444a_flip_online "${orig}")" == '{"smPolicySnssaiData":{"1":{"snssai":{"sst":1},"smPolicyDnnData":{"internet":{"dnn":"internet","online":false}}}}}' ]] \
  && ok "throttle flips online on the original document" || not_ok "flip online"
bare="$(put sm2.json '{"smPolicySnssaiData":{"1":{"snssai":{"sst":1}}}}')"
d444a_flip_online "${bare}" | grep -qF '"internet":{"dnn":"internet","online":true}' \
  && ok "throttle adds the internet entry when absent" || not_ok "flip adds entry"
breaks "flip refuses a non-SmPolicyData body" d444a_flip_online "$(put sm3.json '{"cause":"DATA_NOT_FOUND"}')"
holds "metric" d444a_metric "$(put d.prom 'nextg_demo_enabled{demo="d444a-ambr-adapt",mode="raw"} 1')" raw
breaks "metric, other mode" d444a_metric "$(put d2.prom 'nextg_demo_enabled{demo="d444a-ambr-adapt",mode="raw"} 1')" semantic
echo "1..${n}"
