#!/usr/bin/env bash
# D444A acceptance run on EKS (nextgsim#477), called by k8s/demo-check.sh after
# the base e2e with NAMESPACE, DEMO_KEY, DEMO_MODE, OUT and KUBECONFIG set.
#
# The throttle. nextgsim#465's pcfd Session-AMBR controller is the ticket's
# throttle source and is not merged yet, so this run uses the operator path the
# core already has: it lowers the subscriber's session AMBR (UL 64 Kbps) in the
# UDR's database and re-provisions the UE's SM policy data on the UDR, whose
# PolicyDataChangeNotification makes pcfd re-authorise the live session from
# that database (TS 29.512 §4.2.3.2, nextgcore#299). The re-provisioning flips
# `online` in SmPolicyDnnData so the PCF sees a changed document; that flag
# only maps to the charging decision. When #465 merges, THROTTLE=pcf-controller
# is the swap-in (not implemented here).
#
# Chain asserted, in order, across the smfd, gNB, UE and sink logs:
#   smfd  network-requested PDU Session Modification (AMBR UL/DL <x>/<y> -> 64000/<y> bps ...)
#   gNB   PDU Session Resource Modify Request ... then Modify Response sent to AMF
#   UE    Sending PDU Session Modification Complete: PSI=1, PTI=0
#   UE    [demo:d444a-ambr-adapt] rate target 51200 bps from session-AMBR (PSI 1), keep 128->40  (semantic)
#         [demo:d444a-ambr-adapt] session-AMBR (PSI 1) UL 64000 bps not followed: mode raw  (raw)
# then epoch B, the second sink row after the UE line (the first one wholly
# after the throttle):
#   semantic  encoder=pca keep=40, lost <= 0.5 % of the datagrams, acc >= 0.90,
#             both baselines present and <= acc (the margin is reported);
#             upfd qer_gate delta over the epoch <= 0.5 % of the datagrams
#   raw       encoder=raw keep=128, upfd qer_gate delta > 0
# and the restore chain (UL back to the provisioned value; semantic: keep 40->128).
#
# Artefacts under OUT/d444a/: the per-container logs, chain.txt, sink-rows.txt,
# qer-gate.txt; OUT/metrics/<ue-pod>-nr-cli.prom is `demo metrics`.
#
# Revert arms (manual, see the docs page): `follow_session_ambr: false` and no
# `device:` in patches/ue-d444a-config.yaml; the smfd step 3b patch-out.
#
# The checks are the d444a_* functions below, over files and values only, so
# test-scenario.sh proves each one FAILS on input missing its line. Sourcing
# this file defines them and runs nothing.
# pass() and fail() always return 0, so `a && pass || fail` is an if-else here.
# shellcheck disable=SC2015

D444A_IMSI="${D444A_IMSI:-999700000000001}"
# The provisioned session AMBR the restore returns to (k8s/manifests/mongodb-init.yaml:
# value 1, unit 3 = 1 Gbps in the subscriber document's units).
D444A_RESTORE_VALUE="${D444A_RESTORE_VALUE:-1}"
D444A_RESTORE_UNIT="${D444A_RESTORE_UNIT:-3}"
# An epoch is 500 datagrams (the UE's and the sink's epoch_datagrams).
D444A_LOSS_MAX=2       # 0.5 % of an epoch
D444A_ACC_FLOOR=0.90   # nextgsim-semantic PINNED_ACCURACY_FLOOR_KEEP40

D444A_SMF_THROTTLE_RE='network-requested PDU Session Modification \(AMBR UL/DL [0-9]+/[0-9]+ -> 64000/[0-9]+ bps'
D444A_GNB_MODREQ_RE='PDU Session Resource Modify Request: '
D444A_GNB_MODRSP_RE='PDU Session Resource Modify Response sent to AMF'
D444A_UE_COMPLETE_RE='Sending PDU Session Modification Complete: PSI=1, PTI=0'
D444A_UE_RATE_RE='\[demo:d444a-ambr-adapt\] rate target 51200 bps from session-AMBR \(PSI 1\), keep 128->40'
D444A_UE_RAW_RE='\[demo:d444a-ambr-adapt\] session-AMBR \(PSI 1\) UL 64000 bps not followed: mode raw'
D444A_UE_RESTORE_RE='\[demo:d444a-ambr-adapt\] rate target [0-9]+ bps from session-AMBR \(PSI 1\), keep 40->128'
D444A_ROW_RE='\[demo:d444a-ambr-adapt\] epoch=[0-9]+ '

# Ordered chain over one merged, time-sorted log: each ERE must match a line
# strictly after the previous match. The ERE goes through the environment, never
# as an awk operand or -v (see the d440b scenario). Prints the matched lines.
d444a_order() {
  local file="$1" after=0 re hit
  shift
  [[ -f "${file}" ]] || { echo "no log ${file}"; return 1; }
  for re in "$@"; do
    hit="$(D444A_RE="${re}" awk -v after="${after}" \
      'NR > after && $0 ~ ENVIRON["D444A_RE"] { print NR; exit }' "${file}")"
    [[ -n "${hit}" ]] || { echo "missing or out of order: /${re}/"; return 1; }
    sed -n "${hit}p" "${file}"
    after="${hit}"
  done
}

d444a_chain() {                                                         # LOG MODE
  local adapt="${D444A_UE_RATE_RE}"
  [[ "$2" == raw ]] && adapt="${D444A_UE_RAW_RE}"
  d444a_order "$1" "${D444A_SMF_THROTTLE_RE}" "${D444A_GNB_MODREQ_RE}" \
    "${D444A_GNB_MODRSP_RE}" "${D444A_UE_COMPLETE_RE}" "${adapt}"
}
d444a_no_rate_target() { [[ -f "$1" ]] && ! grep -qF 'rate target' "$1"; }  # LOG

# The FIRST `key=value` token of a sink row; empty when absent. First, because
# `acc=` appears three times (pca, then each baseline).
d444a_field() {
  awk -v k="$2=" '{ for (i = 1; i <= NF; i++) if (index($i, k) == 1) { print substr($i, length(k) + 1); exit } }' <<<"$1"
}
# Epoch B: the second sink row after line AFTER of the merged log.   LOG AFTER
d444a_epoch_b() { awk -v after="$2" 'NR > after && /\[demo:d444a-ambr-adapt\] epoch=[0-9]+ /' "$1" | sed -n 2p; }
# Baseline accuracies, as the row prints them.
d444a_baseline() { sed -nE "s/.* $2 acc=([0-9.]+).*/\\1/p" <<<"$1" | head -1; }
d444a_le() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 <= b + 0) }'; }

d444a_semantic_row() {                                                  # ROW QER_DELTA
  local row="$1" acc top pool lost
  [[ -n "${row}" ]] || { echo "no epoch-B row"; return 1; }
  [[ "$(d444a_field "${row}" encoder)" == pca && "$(d444a_field "${row}" keep)" == 40 ]] \
    || { echo "epoch B is not pca at keep 40: ${row}"; return 1; }
  lost="$(d444a_field "${row}" lost)"
  [[ "${lost}" =~ ^[0-9]+$ && "${lost}" -le "${D444A_LOSS_MAX}" ]] || { echo "lost=${lost}"; return 1; }
  [[ "$2" =~ ^[0-9]+$ && "$2" -le "${D444A_LOSS_MAX}" ]] || { echo "qer_gate delta=$2"; return 1; }
  acc="$(d444a_field "${row}" acc)"
  top="$(d444a_baseline "${row}" top-variance-raw)"
  pool="$(d444a_baseline "${row}" mean-pool)"
  [[ -n "${acc}" && -n "${top}" && -n "${pool}" ]] || { echo "missing accuracy or a baseline"; return 1; }
  d444a_le "${D444A_ACC_FLOOR}" "${acc}" || { echo "acc ${acc} < ${D444A_ACC_FLOOR}"; return 1; }
  d444a_le "${top}" "${acc}" && d444a_le "${pool}" "${acc}" \
    || { echo "a baseline beats pca: acc=${acc} top=${top} pool=${pool}"; return 1; }
  echo "acc=${acc} top-variance-raw=${top} mean-pool=${pool} lost=${lost} qer_gate=$2"
}
d444a_raw_row() {                                                       # ROW QER_DELTA
  [[ -n "$1" ]] || { echo "no epoch-B row"; return 1; }
  [[ "$(d444a_field "$1" encoder)" == raw && "$(d444a_field "$1" keep)" == 128 ]] \
    || { echo "epoch B is not raw at keep 128: $1"; return 1; }
  [[ "$2" =~ ^[0-9]+$ && "$2" -gt 0 ]] || { echo "qer_gate delta=$2, want > 0"; return 1; }
  echo "lost=$(d444a_field "$1" lost) qer_gate=$2"
}
d444a_metric() {                                                        # PROMFILE MODE
  grep -qF "nextg_demo_enabled{demo=\"d444a-ambr-adapt\",mode=\"$2\"} 1" "$1"
}
# upfd's qer_gate drop counter out of a /metrics body; 0 when the series is absent.
d444a_qer_gate() {
  awk '/^upf_dataplane_dropped_packets_by_reason_total\{.*reason="qer_gate".*\} / { v = $NF } END { print v + 0 }' "$1"
}

d444a_main() {
  set -uo pipefail
  : "${NAMESPACE:?}" "${DEMO_KEY:?}" "${DEMO_MODE:?}" "${OUT:?}"
  local K=(kubectl -n "${NAMESPACE}") D="${OUT}/d444a" FAILS=() UE UPF SMF GNB PCF MONGO NODE
  local s before after row line_no q0 q1 t
  mkdir -p "${D}" "${OUT}/metrics"
  fail() { echo "FAIL: $*"; FAILS+=("$*"); }
  pass() { echo "ok:   $*"; }
  pod() { "${K[@]}" get pods -l "app.kubernetes.io/name=$1" -o jsonpath='{.items[0].metadata.name}'; }
  UE="$(pod ue)" UPF="$(pod upf)" SMF="$(pod smf)" GNB="$(pod gnb)" PCF="$(pod pcf)" MONGO="$(pod mongodb)"
  for s in UE UPF SMF GNB PCF MONGO; do [[ -n "${!s}" ]] || { echo "no ${s} pod"; return 1; }; done

  collect() {   # merged, time-sorted log of the four ends
    "${K[@]}" logs "${SMF}" -c smf --timestamps >"${D}/smf.log" 2>&1
    "${K[@]}" logs "${GNB}" -c gnb --timestamps >"${D}/gnb.log" 2>&1
    "${K[@]}" logs "${UE}" -c ue --timestamps >"${D}/ue.log" 2>&1
    "${K[@]}" logs "${UPF}" -c semantic-sink --timestamps >"${D}/sink.log" 2>&1
    cat "${D}"/{smf,gnb,ue,sink}.log | sort -s -k1,1 >"${D}/merged.log"
  }
  rows() { collect; grep -cE "${D444A_ROW_RE}" "${D}/sink.log"; }
  wait_rows() {   # until the sink has logged more than $1 rows, at most $2 s
    local deadline=$((SECONDS + $2))
    while (( SECONDS < deadline )); do (( $(rows) > $1 )) && return 0; sleep 5; done
    return 1
  }
  qer() { "${K[@]}" exec "${UPF}" -c upf -- sh -c 'curl -s --max-time 5 http://127.0.0.1:9090/metrics' >"${D}/upf.prom" 2>/dev/null; d444a_qer_gate "${D}/upf.prom"; }
  set_ul() {    # VALUE UNIT ONLINE: the subscriber's session UL AMBR, then the re-authorisation
    "${K[@]}" exec "${MONGO}" -- mongosh --quiet nextgcore --eval \
      "db.subscribers.updateOne({imsi:'${D444A_IMSI}'},{\$set:{'slice.0.session.0.ambr.uplink':{value:$1,unit:$2}}}).matchedCount" \
      >"${D}/mongo-$1-$2.txt" 2>&1
    grep -qx 1 "${D}/mongo-$1-$2.txt" || { echo "subscriber ${D444A_IMSI} not updated: $(head -c 200 "${D}/mongo-$1-$2.txt")"; return 1; }
    "${K[@]}" exec "${PCF}" -c pcf -- curl -s --http2-prior-knowledge --max-time 10 -o /dev/null -w '%{http_code}' \
      -X PUT -H 'content-type: application/json' \
      --data "{\"smPolicySnssaiData\":{\"1\":{\"snssai\":{\"sst\":1},\"smPolicyDnnData\":{\"internet\":{\"dnn\":\"internet\",\"online\":$3}}}}}" \
      "http://udr:7777/nudr-dr/v2/policy-data/ues/imsi-${D444A_IMSI}/sm-data" >"${D}/udr-put-$1.txt" 2>&1
    grep -qE '^20[14]$' "${D}/udr-put-$1.txt" || { echo "UDR sm-data PUT: $(cat "${D}/udr-put-$1.txt")"; return 1; }
  }

  # The stream is running: the sink has scored at least one epoch.
  wait_rows 0 120 && pass "the sink is scoring the UE's stream" || { fail "no sink row in 120 s"; return 1; }
  NODE="$("${K[@]}" exec "${UE}" -c ue -- nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')"
  if [[ -n "${NODE}" ]]; then
    "${K[@]}" exec "${UE}" -c ue -- nr-cli "${NODE}" -e "demo metrics" >"${OUT}/metrics/${UE}-nr-cli.prom" 2>&1
    d444a_metric "${OUT}/metrics/${UE}-nr-cli.prom" "${DEMO_MODE}" \
      && pass "nextg_demo_enabled series via nr-cli" || fail "no nextg_demo_enabled series via nr-cli"
  else
    fail "nr-cli --dump found no UE node"
  fi

  # Throttle.
  set_ul 64 1 true && pass "UL session AMBR 64 Kbps provisioned and re-authorised" || fail "throttle"
  t=$((SECONDS + 60))
  until d444a_chain "${D}/merged.log" "${DEMO_MODE}" >"${D}/chain.txt" 2>&1 || (( SECONDS > t )); do sleep 5; collect; done
  d444a_chain "${D}/merged.log" "${DEMO_MODE}" >"${D}/chain.txt" \
    && pass "ordered smfd -> gNB -> UE chain ($(wc -l <"${D}/chain.txt") steps)" || fail "chain: $(tail -1 "${D}/chain.txt")"
  [[ "${DEMO_MODE}" == raw ]] && { d444a_no_rate_target "${D}/ue.log" && pass "raw: no rate target line" || fail "raw: a rate target line"; }

  # Epoch B, with the upfd qer_gate counter read at its two ends.
  line_no="$(grep -nE "${D444A_UE_RATE_RE}|${D444A_UE_RAW_RE}" "${D}/merged.log" | head -1 | cut -d: -f1)"
  before="$(rows)"
  wait_rows "${before}" 40 || fail "no sink row after the throttle"
  q0="$(qer)"
  wait_rows "$((before + 1))" 40 || fail "no second sink row after the throttle"
  q1="$(qer)"
  echo "qer_gate ${q0} -> ${q1}" >"${D}/qer-gate.txt"
  grep -E "${D444A_ROW_RE}" "${D}/sink.log" >"${D}/sink-rows.txt"
  row="$(d444a_epoch_b "${D}/merged.log" "${line_no:-0}")"
  if [[ "${DEMO_MODE}" == semantic ]]; then
    s="$(d444a_semantic_row "${row}" "$((q1 - q0))")" && pass "epoch B: ${s}" || fail "epoch B: ${s}"
  else
    s="$(d444a_raw_row "${row}" "$((q1 - q0))")" && pass "epoch B: ${s}" || fail "epoch B: ${s}"
  fi

  # Restore.
  after="$(wc -l <"${D}/merged.log")"
  set_ul "${D444A_RESTORE_VALUE}" "${D444A_RESTORE_UNIT}" false && pass "UL session AMBR restored" || fail "restore"
  sleep 20; collect
  tail -n "+$((after + 1))" "${D}/merged.log" >"${D}/restore.log"
  if [[ "${DEMO_MODE}" == semantic ]]; then
    d444a_order "${D}/restore.log" 'network-requested PDU Session Modification \(AMBR UL/DL 64000/' \
      "${D444A_UE_COMPLETE_RE}" "${D444A_UE_RESTORE_RE}" >"${D}/restore-chain.txt" \
      && pass "restore chain" || fail "restore chain: $(tail -1 "${D}/restore-chain.txt")"
  else
    d444a_order "${D}/restore.log" 'network-requested PDU Session Modification \(AMBR UL/DL 64000/' \
      "${D444A_UE_COMPLETE_RE}" >"${D}/restore-chain.txt" \
      && pass "restore chain" || fail "restore chain: $(tail -1 "${D}/restore-chain.txt")"
  fi

  if [[ ${#FAILS[@]} -eq 0 ]]; then echo "d444a scenario: PASS"; return 0; fi
  echo "d444a scenario: FAIL (${#FAILS[@]})"; return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  d444a_main
  exit $?
fi
