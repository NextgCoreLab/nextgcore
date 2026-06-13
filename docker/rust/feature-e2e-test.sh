#!/bin/bash
# NextG Rel-17/18 Feature E2E Test
#
# Exercises the integrated Rel-17/18 features (RedCap, XR 5QI, SNPN, MINT, UAV)
# end-to-end against a running stack and asserts on the exact log signatures
# each feature emits. Unlike e2e-test.sh (which drives a plain null-scheme UE),
# this script swaps the UE (and, for SNPN, the gNB + AMF) config per scenario
# via docker-compose.features.yml and config/features/*.yaml, then greps the
# relevant container logs.
#
# PREREQUISITE: the baseline stack must already be built and UP, e.g.
#   ./e2e-test.sh --keep
# This script only recreates the containers each scenario needs; it never
# rebuilds images.
#
# Usage:
#   ./feature-e2e-test.sh                 # run all scenarios
#   ./feature-e2e-test.sh redcap xr       # run only the named scenarios
#   ./feature-e2e-test.sh --down          # tear the stack down after running
#
# Scenario names: redcap xr uav-allow uav-deny mint snpn-accept snpn-reject
#
# Exit codes: 0 all asserted, 1 one or more assertions failed, 2 stack not up.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE=(docker compose -f "$SCRIPT_DIR/docker-compose.yml" -f "$SCRIPT_DIR/docker-compose.features.yml")
FEATURE_CFG="/etc/nextgsim/features"   # in-container path (config dir is mounted at /etc/nextgsim)

WAIT_TIMEOUT=75        # seconds to wait for a scenario's key log to appear
SETTLE=4               # seconds to let a freshly recreated container boot before polling

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0
TEARDOWN=false
# Unix epoch set at each scenario start; assertions only look at logs since then,
# so a stale line from an earlier scenario (core NFs are not recreated between
# UE-only scenarios) can't produce a false match. Epoch is unambiguous for
# `docker logs --since` (a naive RFC3339 string would be read in the host TZ).
SCN_SINCE=""
begin_scenario() { SCN_SINCE="$(date +%s)"; }

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_scn()   { echo; echo -e "${BLUE}========== Scenario: $* ==========${NC}"; }

# log_has <container> <fixed-pattern> — true if pattern is in the container's logs.
# NOTE: we capture to a temp file and grep the FILE rather than piping
# `docker logs | grep -q`. With `set -o pipefail`, grep -q exits on the first
# match and closes the pipe, docker logs then dies with SIGPIPE (141), and
# pipefail reports the whole pipeline as failed — turning a real match into a
# false negative. Grepping a file avoids the pipe entirely.
log_has() {
    local container="$1" pattern="$2" tmp rc
    tmp="$(mktemp)"
    if [ -n "$SCN_SINCE" ]; then
        docker logs --since "$SCN_SINCE" "$container" >"$tmp" 2>&1 || true
    else
        docker logs "$container" >"$tmp" 2>&1 || true
    fi
    grep -qF -- "$pattern" "$tmp"; rc=$?
    rm -f "$tmp"
    return $rc
}

# assert_log <container> <fixed-pattern> <description>
assert_log() {
    local container="$1" pattern="$2" desc="$3"
    TOTAL=$((TOTAL + 1))
    if log_has "$container" "$pattern"; then
        log_pass "$desc"
        PASS=$((PASS + 1))
        return 0
    fi
    log_fail "$desc (pattern not found in $container logs: '$pattern')"
    FAIL=$((FAIL + 1))
    return 1
}

# refute_log <container> <fixed-pattern> <description>  — asserts pattern is ABSENT
refute_log() {
    local container="$1" pattern="$2" desc="$3"
    TOTAL=$((TOTAL + 1))
    if log_has "$container" "$pattern"; then
        log_fail "$desc (unexpected pattern present in $container: '$pattern')"
        FAIL=$((FAIL + 1))
        return 1
    fi
    log_pass "$desc"
    PASS=$((PASS + 1))
    return 0
}

# wait_for_log <container> <fixed-pattern> — poll up to WAIT_TIMEOUT
wait_for_log() {
    local container="$1" pattern="$2" waited=0
    sleep "$SETTLE"
    while [ "$waited" -lt "$WAIT_TIMEOUT" ]; do
        if log_has "$container" "$pattern"; then
            return 0
        fi
        sleep 3; waited=$((waited + 3))
    done
    log_warn "timed out (${WAIT_TIMEOUT}s) waiting for '$pattern' in $container"
    return 1
}

# recreate <service...> — force-recreate the given services with current env exported
recreate() {
    "${COMPOSE[@]}" up -d --force-recreate --no-deps "$@" >/dev/null 2>&1
}

ensure_stack_up() {
    if ! docker ps --format '{{.Names}}' | grep -q '^nextgcore-amf$'; then
        log_fail "baseline stack is not up (nextgcore-amf not running)."
        echo "       Run './e2e-test.sh --keep' first, then re-run this script."
        exit 2
    fi
}

# Reset AMF/gNB to baseline (no SNPN/UAV env, baseline gNB config). Called
# before UE-only scenarios in case a prior SNPN scenario mutated them.
reset_core_baseline() {
    export FEATURE_GNB_CONFIG="/etc/nextgsim/gnb.yaml"
    export AMF_SNPN_ALLOWED_NIDS=""
    export AMF_UAV_GEOFENCE=""
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

scn_redcap() {
    log_scn "RedCap (Rel-17, TS 38.101) — reduced bandwidth + reduced session-AMBR"
    reset_core_baseline
    export FEATURE_UE_CONFIG="$FEATURE_CFG/ue-redcap.yaml"
    recreate gnb ue
    wait_for_log nextgcore-smf "RedCap UE: session-AMBR reduced from UL/DL"
    # RedCap rides the NAS Registration Request (IEI 0xA9) in the simulator's
    # runtime path. The RRCSetupComplete AS signalling + gNB scheduler
    # bandwidth restriction live only in the library RrcTask, which the runtime
    # binary's inline run_rrc_task() does not exercise (it sends raw NAS on
    # UL-DCCH) — so the gNB BW-restriction is a documented architectural gap,
    # not asserted here.
    assert_log nextgsim-ue   "RedCap registration: including reduced-capability indication" "UE signals RedCap (NAS Reg Request, IEI 0xA9)"
    assert_log nextgcore-amf "UE indicates RedCap (Reduced Capability) device"               "AMF parses RedCap indication"
    assert_log nextgcore-amf "redcap=true"                                                   "AMF forwards redcap=true to SMF (N11)"
    assert_log nextgcore-smf "RedCap UE: session-AMBR reduced from UL/DL"                     "SMF applies reduced session-AMBR"
    log_warn "RedCap gNB bandwidth restriction (RRC-layer) is NOT exercised by the runtime RRC path — documented limitation"
}

scn_xr() {
    log_scn "XR 5QI (Rel-18, TS 23.501 5.7.4) — delay-critical GBR flow 5QI 82"
    reset_core_baseline
    export FEATURE_UE_CONFIG="$FEATURE_CFG/ue-xr.yaml"
    recreate gnb ue
    wait_for_log nextgcore-upf "Installed XR QER"
    assert_log nextgsim-ue   "XR PDU session requested"      "UE requests XR 5QI session"
    assert_log nextgcore-smf "XR QoS flow bound: 5QI="       "SMF binds XR QoS flow (process_xr_qos_flow_binding)"
    assert_log nextgcore-smf "PFCP: installing XR QER"       "SMF installs XR GBR QER via PFCP"
    assert_log nextgcore-upf "Installed XR QER"              "UPF installs XR GBR QER in data plane"
}

scn_uav_allow() {
    log_scn "UAV geofence ALLOW (Rel-18, TS 23.256) — altitude 100m within 120m ceiling"
    reset_core_baseline
    export FEATURE_UE_CONFIG="$FEATURE_CFG/ue-uav-allow.yaml"
    recreate gnb ue
    wait_for_log nextgcore-amf "[UAV Tracking] Geofence ALLOW: UAV"
    assert_log nextgsim-ue   "UAV registration: including aerial-UE indication (CAA-ID=" "UE includes UAV indication (IEI 0xA8)"
    assert_log nextgcore-amf "UAV registration: aerial UE authorized (CAA-ID="           "AMF authorizes aerial UE + geofence"
    assert_log nextgsim-ue   "UAV tracking report: CAA-ID="                              "UE sends UAV tracking report (0x6A)"
    assert_log nextgcore-amf "[UAV Tracking] Geofence ALLOW: UAV"                         "AMF allows in-zone position"
}

scn_uav_deny() {
    log_scn "UAV geofence DENY (Rel-18, TS 23.256) — altitude 200m above 120m ceiling"
    reset_core_baseline
    export FEATURE_UE_CONFIG="$FEATURE_CFG/ue-uav-deny.yaml"
    recreate gnb ue
    wait_for_log nextgcore-amf "[UAV Tracking] Geofence DENY: UAV"
    assert_log nextgsim-ue   "UAV registration: including aerial-UE indication (CAA-ID=" "UE includes UAV indication (IEI 0xA8)"
    assert_log nextgcore-amf "[UAV Tracking] Altitude violation:"                         "AMF detects altitude violation"
    assert_log nextgcore-amf "[UAV Tracking] Geofence DENY: UAV"                          "AMF denies out-of-bounds flight + revokes"
}

scn_mint() {
    log_scn "MINT / disaster roaming (Rel-18, TS 23.761) — secondary SUPI 999700000000002"
    reset_core_baseline
    export FEATURE_UE_CONFIG="$FEATURE_CFG/ue-mint.yaml"
    recreate gnb ue
    wait_for_log nextgcore-amf "MINT disaster-roaming indication present"
    assert_log nextgsim-ue   "MINT task spawned"                                       "UE spawns MINT task (Rel-18)"
    assert_log nextgsim-ue   "MINT enabled:"                                           "UE MINT secondary subscription active"
    assert_log nextgsim-ue   "MINT registration: including disaster-roaming indication" "UE sets disaster-roaming (IEI 0xA7)"
    assert_log nextgcore-amf "MINT disaster-roaming indication present"                 "AMF accepts disaster-roaming registration"
    assert_log nextgcore-udm "AMF Registration: SUPI=imsi-999700000000002"              "UDM registers secondary SUPI (UECM)"
}

scn_snpn_accept() {
    log_scn "SNPN accept (Rel-17, TS 23.501 §5.30) — served NID 7AB01234567"
    export FEATURE_GNB_CONFIG="$FEATURE_CFG/gnb-snpn-accept.yaml"
    export AMF_SNPN_ALLOWED_NIDS="7AB01234567"
    export AMF_UAV_GEOFENCE=""
    export FEATURE_UE_CONFIG="$FEATURE_CFG/ue-snpn-accept.yaml"
    recreate amf
    wait_for_log nextgcore-amf "NGAP server listening"
    recreate gnb
    wait_for_log nextgcore-amf "NG Setup"
    recreate ue
    wait_for_log nextgcore-amf "SNPN registration authorized for NID="
    assert_log nextgsim-ue   "SNPN registration: including NID=7AB01234567" "UE includes served NID (IEI 0xA6)"
    assert_log nextgcore-amf "SNPN registration authorized for NID=7AB01234567" "AMF authorizes the served NID"
}

scn_snpn_reject() {
    log_scn "SNPN reject (Rel-17, TS 23.501 §5.30) — NID 00000000000 not in allowed list"
    export FEATURE_GNB_CONFIG="$FEATURE_CFG/gnb-snpn-reject.yaml"
    export AMF_SNPN_ALLOWED_NIDS="7AB01234567"
    export AMF_UAV_GEOFENCE=""
    export FEATURE_UE_CONFIG="$FEATURE_CFG/ue-snpn-reject.yaml"
    recreate amf
    wait_for_log nextgcore-amf "NGAP server listening"
    recreate gnb
    wait_for_log nextgcore-amf "NG Setup"
    recreate ue
    wait_for_log nextgcore-amf "SNPN registration rejected: NID="
    assert_log nextgsim-ue   "SNPN registration: including NID=00000000000" "UE includes unknown NID (IEI 0xA6)"
    assert_log nextgcore-amf "SNPN registration rejected: NID=00000000000"  "AMF rejects the unknown NID (cause #75)"
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
declare -a REQUESTED=()
for arg in "$@"; do
    case "$arg" in
        --down) TEARDOWN=true ;;
        redcap|xr|uav-allow|uav-deny|mint|snpn-accept|snpn-reject) REQUESTED+=("$arg") ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done
# Default order runs UE-only scenarios first, SNPN (mutates amf+gnb) last.
if [ "${#REQUESTED[@]}" -eq 0 ]; then
    REQUESTED=(redcap xr uav-allow uav-deny mint snpn-accept snpn-reject)
fi

ensure_stack_up

for scn in "${REQUESTED[@]}"; do
    begin_scenario
    case "$scn" in
        redcap)      scn_redcap ;;
        xr)          scn_xr ;;
        uav-allow)   scn_uav_allow ;;
        uav-deny)    scn_uav_deny ;;
        mint)        scn_mint ;;
        snpn-accept) scn_snpn_accept ;;
        snpn-reject) scn_snpn_reject ;;
    esac
done

echo
echo "========================================"
echo "  Rel-17/18 feature assertions"
echo "  Total:  $TOTAL"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "========================================"

if [ "$TEARDOWN" = true ]; then
    log_info "Tearing down stack (--down)..."
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
else
    log_warn "Leaving stack running. Re-run baseline check with: ./e2e-test.sh --no-build"
    log_warn "To restore the baseline UE/gNB/AMF: ./e2e-test.sh --no-build --keep"
fi

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
