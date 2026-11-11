#!/usr/bin/env bash
# D446A seeded acceptance run on EKS (nextgsim#483), called by k8s/demo-check.sh
# with NAMESPACE, DEMO_KEY, DEMO_MODE and OUT set, after the base e2e.
#
# The chains are the compose check's (nextgsim scripts/demo/d446a-check.sh):
#   load-balancing  amf: HandoverRequired ... source_gnb_id=2
#                   cause=RadioNetwork(ReduceLoadInServingCell) (exactly once) ->
#                   UE <n> relocated to target gNB; gnb (gNB-B): IntentSubmitted
#                   (energy-1) -> InboundIntent (lb-1@gnb-2) -> ConflictDetected
#                   ... Cell:16 -> Resolved ... winner lb-1 -> Deferred (energy-1)
#                   -> GuardrailHold ... ues=1
#   energy-saving   gnb: ... Resolved ... winner energy-1 -> Agent switch-off: cell
#                   16 off the air; amf: HandoverFailure ... gnb_id=1; gnb-a:
#                   Handover Preparation Failure -> ActuationFailed (lb-1)
# Also captured: gNB-B's `nr-cli agent-audit --json` and `demo metrics` (the gNB
# has no /metrics listener), the latter as $OUT/metrics/gnb-b.prom, which
# demo-check.sh reads with the NF scrapes. NR_CLI names the nr-cli binary to
# copy into the pod (default: ../nextgsim/target/release/nr-cli).
# Nothing is port-forwarded; everything is read with kubectl logs/exec/cp.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
core="$(cd "${here}/../../../.." && pwd)"
nr_cli="${NR_CLI:-${core}/../nextgsim/target/release/nr-cli}"
K=(kubectl -n "${NAMESPACE}")
TIMEOUT="${D446A_TIMEOUT:-420}"
mkdir -p "${OUT}/d446a" "${OUT}/metrics"
fails=0
fail() { echo "DEMO CHECK FAILED: $*"; fails=$((fails + 1)); }

logs() { "${K[@]}" logs "deploy/$1" -c "$1" 2>/dev/null > "${OUT}/d446a/$2.log"; }
wait_for() {   # wait_for DEPLOY NAME ERE
    local t=0
    while (( t < TIMEOUT )); do
        logs "$1" "$2"
        grep -qE "$3" "${OUT}/d446a/$2.log" && return 0
        sleep 5; t=$((t + 5))
    done
    return 1
}
# In-order ERE chain in FILE (each on a later line than the one before).
in_order() {
    local file="$1" label="$2"; shift 2
    local from=0 n=0 re line
    for re in "$@"; do
        n=$((n + 1))
        line="$(awk -v from="${from}" 'NR > from && $0 ~ ENVIRON["RE"] { print NR; exit }' RE="${re}" "${file}")"
        if [[ -z "${line}" ]]; then fail "[${label}] step ${n}/$# missing: ${re}"; return; fi
        from="${line}"
    done
    echo "[${label}] chain of $# in order"
}
lb_required='HandoverRequired \(amf_ue_ngap_id=[0-9]+, ran_ue_ngap_id=[0-9]+, type=Intra5gs\) source_gnb_id=2 cause=RadioNetwork\(ReduceLoadInServingCell\)'

case "${DEMO_MODE}" in
    load-balancing) wait_for gnb gnb-b 'audit #[0-9]+: GuardrailHold' || fail "no GuardrailHold in ${TIMEOUT}s" ;;
    energy-saving)  wait_for gnb gnb-b 'off the air: [0-9]+ heartbeat' || fail "no dropped heartbeat in ${TIMEOUT}s" ;;
    *) echo "unknown mode ${DEMO_MODE}"; exit 2 ;;
esac
logs gnb gnb-b; logs gnb-a gnb-a; logs amf amf
west="${OUT}/d446a/gnb-b.log" east="${OUT}/d446a/gnb-a.log" amf="${OUT}/d446a/amf.log"

case "${DEMO_MODE}" in
load-balancing)
    in_order "${amf}" amf "${lb_required}" 'UE [0-9]+ relocated to target gNB' \
        'UE Context Release Command sent to SOURCE association'
    [[ "$(grep -cE "${lb_required}" "${amf}")" == 1 ]] || fail "[amf] not exactly one load-balancing HandoverRequired"
    in_order "${west}" gnb-b 'audit #[0-9]+: IntentSubmitted \(energy-1\)' \
        'Handover Request received \(target gNB\):.*cause=RadioNetwork\(ReduceLoadInServingCell\)' \
        'audit #[0-9]+: InboundIntent \(lb-1@gnb-2\)' 'audit #[0-9]+: ConflictDetected \(lb-1@gnb-2\) .*Cell:16' \
        'audit #[0-9]+: Resolved \(lb-1@gnb-2\) winner lb-1' 'audit #[0-9]+: Deferred \(energy-1\)' \
        'handback hold: UE\[[0-9]+\] is not handed back to its source cell PCI 32' \
        'audit #[0-9]+: GuardrailHold \(energy-1\) SwitchOffWithConnectedUes: ues=1'
    ! grep -q 'Sent Handover Required' "${west}" || fail "[gnb-b] a HANDOVER REQUIRED during the hold"
    ;;
energy-saving)
    in_order "${west}" gnb-b 'audit #[0-9]+: IntentSubmitted \(energy-1\)' 'audit #[0-9]+: InboundIntent \(lb-1@gnb-2\)' \
        'audit #[0-9]+: ConflictDetected \(lb-1@gnb-2\) .*Cell:16' 'audit #[0-9]+: Resolved \(lb-1@gnb-2\) winner energy-1' \
        'Agent switch-off: cell 16 off the air' 'off the air: [1-9][0-9]* heartbeat\(s\) dropped'
    in_order "${amf}" amf "${lb_required}" \
        'HandoverFailure from association [0-9]+ \(amf_ue_ngap_id=[0-9]+, cause=RadioNetwork\(CellNotAvailable\)\) gnb_id=1'
    in_order "${east}" gnb-a 'Sent Handover Required: amf_ue_ngap_id=' \
        'Handover Preparation Failure: .*CellNotAvailable' 'audit #[0-9]+: ActuationFailed \(lb-1\)'
    ! grep -qE 'UE [0-9]+ relocated to target gNB' "${amf}" || fail "[amf] relocated although refused"
    ;;
esac

# gNB-B's own view through nr-cli, copied into the pod (the image ships nr-gnb only).
pod="$("${K[@]}" get pod -l app.kubernetes.io/name=gnb -o jsonpath='{.items[0].metadata.name}')"
if [[ -x "${nr_cli}" ]] && "${K[@]}" cp "${nr_cli}" "${pod}:/tmp/nr-cli" -c gnb >/dev/null 2>&1; then
    node="$("${K[@]}" exec "${pod}" -c gnb -- /tmp/nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')"
    "${K[@]}" exec "${pod}" -c gnb -- /tmp/nr-cli "${node}" -e "agent-audit --json" > "${OUT}/d446a/agent-audit.json" 2>&1
    "${K[@]}" exec "${pod}" -c gnb -- /tmp/nr-cli "${node}" -e "demo metrics" > "${OUT}/metrics/gnb-b.prom" 2>&1
    grep -qF "nextg_demo_enabled{demo=\"d446a-agent-conflict\",mode=\"${DEMO_MODE}\"} 1" "${OUT}/metrics/gnb-b.prom" \
        || fail "[gnb-b] demo metrics lack the ${DEMO_MODE} series"
else
    fail "no nr-cli at ${nr_cli} (or kubectl cp failed): agent audit and demo metrics not captured"
fi

(( fails == 0 )) && echo "D446A ${DEMO_MODE}: every assertion holds"
(( fails == 0 ))
