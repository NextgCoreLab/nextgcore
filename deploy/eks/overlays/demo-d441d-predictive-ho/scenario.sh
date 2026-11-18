#!/usr/bin/env bash
# D441D seeded acceptance run on EKS (nextgsim#467), called by k8s/demo-check.sh
# with NAMESPACE, DEMO_KEY, DEMO_MODE, DEMO_VARIANT and OUT set, after the base
# e2e. Decision 2026-11-18 (nextgcore DECISIONS 2026-11-18-083000): the K-seed
# table comes from nextgsim's compose job; this run validates the overlay and
# the chain on EKS on 3 seeds per arm (D441D_SEEDS, default "1 2 3").
#
# The deploy's UE has its route parked (configs-patch.yaml). Per seed:
#   1. write the seed into both gNB configs' shadowing block and the committed
#      start_after_secs 40 into the UE's (nextgsim-configs), then restart gnb
#      and gnb-east, then the UE;
#   2. wait for the route to start (`Simulated motion started`), then for
#      amfd's HandoverNotify, at most D441D_EPISODE_S (120) after it, then
#      D441D_SETTLE_S (15) more;
#   3. capture gnb (gnb-west), gnb-east and amf since the restart, with kubelet
#      timestamps, and score the episode with nextgsim's
#      scripts/demo/d441d_score.py (the same scorer as the compose job).
# Each seed also checks the two gNBs logged the same `RLS: seeded log-normal
# shadowing on:` line with this seed, and gnb-west's banner for the mode.
#
# Arms (DEMO_MODE, DEMO_VARIANT):
#   a3 | lsq | onnx    K seeds; pass: every arm chained on all K (lsq/onnx take
#                      K-2 only for K >= 10: the 24-seed compose table; the
#                      coordinator's ruling on the operator's decision, 2026-11-18)
#   off                demo-check's demo-off arm: one seed, the base A3 handover
#                      and no demo line (demo-check asserts the rest)
#   lsq + invalid      gnb-west restarted with mode bogus: it must log UnknownMode
#                      and not become Ready; the deployed config is then restored
#   lsq + conflict     gnb-west restarted with D446A's block too: it must log
#                      HandoverDemoConflict and not become Ready; then restored
#   a3 + runtime-switch  one seed: before the route starts, `set mode=bogus` is
#                      rejected and audited and `show` stays a3, then `set
#                      mode=lsq` is audited; the seed must score as lsq
# Also captured: gnb-west's `nr-cli nwdaf-status`, `demo ... show` and `demo
# metrics` (the gNB has no /metrics listener), the last as $OUT/metrics/gnb.prom,
# which demo-check.sh reads with the NF scrapes (runtime-switch: taken before
# the switch, so it carries the deployed mode). The image ships nr-cli
# (build-images.sh). Nothing is port-forwarded.
#
# A HandoverNotify more than D441D_EPISODE_S after the route start, or none, is a
# failure (decision Q4); a `HandoverNotify ... rejected` does not end the wait.
# Environment: D441D_SEEDS, D441D_EPISODE_S, D441D_SETTLE_S, D441D_PINGPONG_MS,
# D441D_A3_SLACK_MS (a3: report vs the replica's range, default 250),
# D441D_SCORE (default ../nextgsim/scripts/demo/d441d_score.py).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
core="$(cd "${here}/../../../.." && pwd)"
score_py="${D441D_SCORE:-${core}/../nextgsim/scripts/demo/d441d_score.py}"
K=(kubectl -n "${NAMESPACE}")
EPISODE_S="${D441D_EPISODE_S:-120}"
SETTLE_S="${D441D_SETTLE_S:-15}"
PINGPONG_MS="${D441D_PINGPONG_MS:-5000}"
A3_SLACK_MS="${D441D_A3_SLACK_MS:-250}"
ROUTE_START_SECS=40   # nextgsim config/demo-predictive-ho/ue.yaml (test-scenario.sh checks)
D="${OUT}/d441d"
mkdir -p "${D}" "${OUT}/metrics"
fails=0
fail() { echo "DEMO CHECK FAILED: $*"; fails=$((fails + 1)); }
die() { echo "DEMO CHECK FAILED: $*"; exit 1; }
say() { echo "[d441d] $*"; }

# d441d_rewrite IN OUT SEED [VARIANT]: nextgsim-configs as JSON on IN, rewritten
# to OUT for one episode: the seed in both gNB configs, the route unparked, and
# for a variant its edit to gnb.yaml (gnb-west). Every edit must match exactly
# once, so a config that drifted fails here instead of running unseeded.
d441d_rewrite() {
    python3 -I - "$1" "$2" "$3" "${4:-}" "${ROUTE_START_SECS}" <<'PY'
import json, re, sys
src, dst, seed, variant, start = sys.argv[1:]
cm = json.load(open(src))
d = cm["data"]
def sub(key, pattern, repl):
    text, n = re.subn(pattern, repl, d[key], flags=re.M)
    if n != 1:
        sys.exit(f"d441d_rewrite: {key}: /{pattern}/ matched {n} time(s), expected 1")
    d[key] = text
for key in ("gnb.yaml", "gnb-east.yaml"):
    sub(key, r"^  seed: [0-9]+$", f"  seed: {seed}")
sub("ue.yaml", r"^(\s*start_after_secs:)\s*[0-9]+\b.*$", r"\g<1> " + start)
if variant == "invalid":
    sub("gnb.yaml", r"^    mode: [a-z0-9]+$", "    mode: bogus")
elif variant == "conflict":
    sub("gnb.yaml", r"^(  d441d-predictive-ho:\n(?:    .*\n)*)",
        r"\g<1>  d446a-agent-conflict:\n    enabled: true\n    mode: load-balancing\n")
elif variant not in ("", "runtime-switch"):
    sys.exit(f"d441d_rewrite: unknown variant {variant!r}")
for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields"):
    cm["metadata"].pop(k, None)
json.dump(cm, open(dst, "w"))
PY
}

# d441d_shadowing_agrees WEST_LOG EAST_LOG SEED: both gNBs logged the same
# shadowing line, naming this seed (the replica needs both blocks equal).
d441d_shadowing_agrees() {
    local w e
    w="$(grep -oE 'RLS: seeded log-normal shadowing on: [^(]*' "$1" | head -1)"
    e="$(grep -oE 'RLS: seeded log-normal shadowing on: [^(]*' "$2" | head -1)"
    [[ -n "${w}" ]] || { fail "[gnb-west] no 'RLS: seeded log-normal shadowing on:' line"; return 1; }
    [[ "${w}" == "${e}" ]] || { fail "the gNBs' shadowing lines differ: west '${w}', east '${e}'"; return 1; }
    [[ "${w}" == *" seed=$3 "* ]] || { fail "the shadowing line names another seed: '${w}'"; return 1; }
}

# d441d_banner LOG MODE: the banner names this demo in MODE (it lists every
# active demo, comma-separated: d440b too in onnx).
d441d_banner() {
    grep -qE "DEMO MODE ACTIVE: ([^ ]*,)?d441d-predictive-ho=$2(,| |\$)" "$1" \
        || { fail "[gnb-west] no 'DEMO MODE ACTIVE: d441d-predictive-ho=$2' banner"; return 1; }
}

# Sourced by test-scenario.sh for the functions above; run, the checks below.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi

[[ -f "${score_py}" ]] || die "no scorer at ${score_py} (nextgsim checked out beside nextgcore?)"
VARIANT="${DEMO_VARIANT:-}"
case "${DEMO_MODE}:${VARIANT}" in
    a3: | lsq: | onnx: | off: | lsq:invalid | lsq:conflict | a3:runtime-switch) ;;
    *) echo "unsupported arm mode=${DEMO_MODE} variant=${VARIANT}"; exit 2 ;;
esac
read -r -a SEEDS <<< "${D441D_SEEDS:-1 2 3}"
case "${DEMO_MODE}:${VARIANT}" in a3: | lsq: | onnx:) ;; *) SEEDS=("${SEEDS[0]}") ;; esac
N="${#SEEDS[@]}"
case "${DEMO_MODE}:${VARIANT}" in
    lsq: | onnx:) MIN=$(( N >= 10 ? N - 2 : N )) ;;
    *) MIN="${N}" ;;
esac

pod_of() {   # the newest pod of a Deployment's label
    "${K[@]}" get pods -l "app.kubernetes.io/name=$1" --sort-by=.metadata.creationTimestamp \
        -o jsonpath='{.items[-1:].metadata.name}' 2>/dev/null
}
logs_since() {   # POD CONTAINER SINCE OUT (previous instance too, for a crash loop)
    { "${K[@]}" logs "$1" -c "$2" --timestamps --previous 2>/dev/null || true
      "${K[@]}" logs "$1" -c "$2" --timestamps --since-time="$3" 2>/dev/null || true; } > "$4"
}
wait_log() {   # POD CONTAINER SINCE ERE SECS OUT
    local t=0
    while (( t < $5 )); do
        logs_since "$1" "$2" "$3" "$6"
        grep -qE -- "$4" "$6" && return 0
        sleep 5; t=$((t + 5))
    done
    return 1
}
cli_west() {   # OUT ARGS...: nr-cli inside the gnb-west pod
    local out="$1"; shift
    local pod node
    pod="$(pod_of gnb)"
    node="$("${K[@]}" exec "${pod}" -c gnb -- nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')"
    "${K[@]}" exec "${pod}" -c gnb -- nr-cli "${node}" -e "$*" > "${out}" 2>&1 || true
}

# The gNB nodes' traffic-control modules, before and after (DECISIONS
# 2026-11-17-160209: demo arms stay within the approved modules and record their
# state). This scenario loads none: it uses no tc or netem.
modules() {   # OUT
    local pod
    for pod in "$(pod_of gnb)" "$(pod_of gnb-east)"; do
        echo "## ${pod} node $("${K[@]}" get pod "${pod}" -o jsonpath='{.spec.nodeName}' 2>/dev/null)"
        "${K[@]}" exec "${pod}" -c gnb -- cat /proc/modules 2>/dev/null | grep -E '^(sch|cls|act)_' || echo "(no sch_/cls_/act_ module)"
    done > "$1"
}
modules "${D}/modules-before.txt"

"${K[@]}" get configmap nextgsim-configs -o json > "${D}/nextgsim-configs.deployed.json" \
    || die "cannot read nextgsim-configs"
restore_configs() {
    modules "${D}/modules-after.txt"
    "${K[@]}" replace -f "${D}/nextgsim-configs.deployed.json" >/dev/null 2>&1 \
        || "${K[@]}" apply -f "${D}/nextgsim-configs.deployed.json" >/dev/null 2>&1 || true
}
# The run leaves the deployed configs as it found them, on every exit path.
trap restore_configs EXIT

# --- invalid, conflict: a refused restart of gnb-west ---------------------------
if [[ "${VARIANT}" == invalid || "${VARIANT}" == conflict ]]; then
    seed="${SEEDS[0]}"
    S="${D}/${VARIANT}"; mkdir -p "${S}"
    d441d_rewrite "${D}/nextgsim-configs.deployed.json" "${S}/nextgsim-configs.json" "${seed}" "${VARIANT}" \
        || die "cannot stage the ${VARIANT} config"
    since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "${K[@]}" replace -f "${S}/nextgsim-configs.json" >/dev/null || die "cannot replace nextgsim-configs"
    "${K[@]}" rollout restart deployment/gnb >/dev/null
    if [[ "${VARIANT}" == invalid ]]; then
        re='unknown mode "bogus" for demo "d441d-predictive-ho"'
    else
        re='HandoverDemoConflict: demos d441d-predictive-ho and d446a-agent-conflict both trigger handovers'
    fi
    sleep 10
    wait_log "$(pod_of gnb)" gnb "${since}" "${re}" 180 "${S}/gnb-west.log" \
        || fail "[gnb-west] never logged /${re}/ within 180 s"
    ready="$("${K[@]}" get pod "$(pod_of gnb)" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)"
    [[ "${ready}" != true ]] || fail "[gnb-west] became Ready with a refused config"
    ! grep -q 'Sent Handover Required' "${S}/gnb-west.log" || fail "[gnb-west] handed a UE over with a refused config"
    say "gnb-west refused the ${VARIANT} config (ready=${ready:-false}); restoring the deployed config"
    restore_configs
    "${K[@]}" rollout restart deployment/gnb >/dev/null
    "${K[@]}" rollout status deployment/gnb --timeout=300s >/dev/null || fail "gnb-west did not come back after the restore"
    (( fails == 0 )) && echo "D441D ${VARIANT}: every assertion holds"
    (( fails == 0 )); exit
fi

# --- seeded episodes -------------------------------------------------------------
SCORE_ARM="${DEMO_MODE}"
[[ "${VARIANT}" == runtime-switch ]] && SCORE_ARM=lsq
rows="${D}/rows.tsv"; : > "${rows}"
for seed in "${SEEDS[@]}"; do
    S="${D}/seed-${seed}"; rm -rf "${S}"; mkdir -p "${S}"
    d441d_rewrite "${D}/nextgsim-configs.deployed.json" "${S}/nextgsim-configs.json" "${seed}" \
        || die "cannot stage seed ${seed}"
    since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "${K[@]}" replace -f "${S}/nextgsim-configs.json" >/dev/null || die "cannot replace nextgsim-configs"
    "${K[@]}" rollout restart deployment/gnb deployment/gnb-east >/dev/null
    "${K[@]}" rollout status deployment/gnb --timeout=300s >/dev/null || die "seed ${seed}: gnb-west rollout"
    "${K[@]}" rollout status deployment/gnb-east --timeout=300s >/dev/null || die "seed ${seed}: gnb-east rollout"
    wait_log "$(pod_of gnb)" gnb "${since}" 'Received NG Setup Response' 120 "${S}/gnb-west.log" \
        || die "seed ${seed}: gnb-west has no NG Setup"
    wait_log "$(pod_of gnb-east)" gnb "${since}" 'Received NG Setup Response' 120 "${S}/gnb-east.log" \
        || die "seed ${seed}: gnb-east has no NG Setup"
    "${K[@]}" rollout restart deployment/ue >/dev/null
    "${K[@]}" rollout status deployment/ue --timeout=300s >/dev/null || die "seed ${seed}: UE rollout"
    UE="$(pod_of ue)"
    wait_log "${UE}" ue "${since}" 'is now ACTIVE' 150 "${S}/ue.log" || fail "seed ${seed}: no PDU session"

    if [[ "${VARIANT}" == runtime-switch ]]; then
        # demo metrics in the deployed mode, before the switch (demo-check reads it).
        cli_west "${OUT}/metrics/gnb.prom" demo metrics
        cli_west "${S}/set-bogus.txt" demo d441d-predictive-ho set mode=bogus
        cli_west "${S}/show-after-bogus.txt" demo d441d-predictive-ho show
        grep -q 'demo=d441d-predictive-ho active=true mode=a3 ' "${S}/show-after-bogus.txt" \
            || fail "[gnb-west] the mode changed on a rejected set: $(cat "${S}/show-after-bogus.txt")"
        cli_west "${S}/set-lsq.txt" demo d441d-predictive-ho set mode=lsq
        logs_since "$(pod_of gnb)" gnb "${since}" "${S}/gnb-west.log"
        grep -qF 'audit: rejected set mode="bogus" from nr-cli' "${S}/gnb-west.log" \
            || fail "[gnb-west] set mode=bogus not audited as rejected"
        grep -qF 'audit: mode a3 -> lsq from nr-cli' "${S}/gnb-west.log" \
            || fail "[gnb-west] set mode=lsq not audited"
    fi

    wait_log "${UE}" ue "${since}" 'Simulated motion started' 120 "${S}/ue.log" \
        || fail "seed ${seed}: the UE's route never started"
    wait_log "$(pod_of amf)" amf "${since}" 'HandoverNotify from association [0-9]+ \(amf_ue_ngap_id=' "${EPISODE_S}" "${S}/amf.log" \
        || say "seed ${seed}: no HandoverNotify within ${EPISODE_S}s (scored as a failure)"
    sleep "${SETTLE_S}"
    logs_since "$(pod_of gnb)" gnb "${since}" "${S}/gnb-west.log"
    logs_since "$(pod_of gnb-east)" gnb "${since}" "${S}/gnb-east.log"
    logs_since "$(pod_of amf)" amf "${since}" "${S}/amf.log"
    logs_since "${UE}" ue "${since}" "${S}/ue.log"
    for f in gnb-west gnb-east amf; do
        [[ -s "${S}/${f}.log" ]] || fail "seed ${seed}: [${f}] captured log is empty"
    done
    cli_west "${S}/nwdaf-status.json" nwdaf-status
    cli_west "${S}/demo-show.txt" demo d441d-predictive-ho show
    [[ "${VARIANT}" == runtime-switch ]] || cli_west "${OUT}/metrics/gnb.prom" demo metrics

    d441d_shadowing_agrees "${S}/gnb-west.log" "${S}/gnb-east.log" "${seed}" || true
    if [[ "${DEMO_MODE}" == off ]]; then
        grep -q 'demo=d441d-predictive-ho active=false ' "${S}/demo-show.txt" \
            || fail "[gnb-west] demo show is not disabled: $(cat "${S}/demo-show.txt")"
    else
        d441d_banner "${S}/gnb-west.log" "${DEMO_MODE}" || true
    fi
    if [[ "${DEMO_MODE}" == onnx ]]; then
        grep -q 'NWDAF: model verified' "${S}/gnb-west.log" || fail "[gnb-west] onnx without 'NWDAF: model verified'"
    fi
    # bash 4.2 (the cloud desktop) treats "${header[@]}" of an empty array as unbound under set -u.
    header=(); [[ -s "${rows}" ]] || header=(--header)
    python3 -I "${score_py}" score --arm "${SCORE_ARM}" --seed "${seed}" ${header[@]+"${header[@]}"} \
        --west "${S}/gnb-west.log" --east "${S}/gnb-east.log" --amf "${S}/amf.log" \
        --ue "${S}/ue.log" --window-ms "$((EPISODE_S * 1000))" \
        --pingpong-ms "${PINGPONG_MS}" --a3-slack-ms "${A3_SLACK_MS}" | tee -a "${rows}"
done

python3 -I "${score_py}" table --arm "${SCORE_ARM}" --seeds "${SEEDS[*]}" --min-chains "${MIN}" "${rows}" > "${D}/table.md" \
    || fail "[${SCORE_ARM}] fewer than ${MIN} of ${N} seeds held the chain"
cat "${D}/table.md"
(( fails == 0 )) && echo "D441D ${DEMO_MODE}${VARIANT:++${VARIANT}}: every assertion holds"
(( fails == 0 ))
