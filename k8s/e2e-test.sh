#!/bin/bash
# NextGCore Kubernetes E2E Test Script
#
# Verifies the full 5G stack deployed on Kind cluster:
# NF startup, UE registration, PDU session, data plane ping.
#
# Usage:
#   ./e2e-test.sh           # Run full E2E test
#   ./e2e-test.sh --deploy  # Deploy first, then test
#
# Exit codes:
#   0 - All tests passed
#   1 - Test failure
#   2 - Infrastructure failure (pods not ready, timeout)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAMESPACE="nextg-system"
TIMEOUT_PODS=180      # seconds to wait for all pods ready
TIMEOUT_REGISTER=90   # seconds to wait for UE registration
TIMEOUT_PING=30       # seconds to wait for ping success

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

RUN_DEPLOY=false
PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --deploy) RUN_DEPLOY=true; shift ;;
        *)        echo "Unknown option: $1"; exit 2 ;;
    esac
done

# ============================================================================
# Helpers
# ============================================================================
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[FAIL]${NC}  $*"; }

assert_pass() {
    TOTAL=$((TOTAL + 1))
    if eval "$1" >/dev/null 2>&1; then
        PASSED=$((PASSED + 1))
        log_info "PASS: $2"
    else
        FAILED=$((FAILED + 1))
        log_error "FAIL: $2"
    fi
}

assert_log_contains() {
    local deployment="$1"
    local pattern="$2"
    local desc="$3"
    TOTAL=$((TOTAL + 1))
    local tmplog
    tmplog=$(mktemp)
    kubectl logs "deployment/${deployment}" -n "${NAMESPACE}" --all-containers >"$tmplog" 2>&1 || true
    if grep -q "$pattern" "$tmplog"; then
        PASSED=$((PASSED + 1))
        log_info "PASS: $desc"
    else
        FAILED=$((FAILED + 1))
        log_error "FAIL: $desc (pattern '$pattern' not found in $deployment logs)"
    fi
    rm -f "$tmplog"
}

# ============================================================================
# Step 0: Deploy (optional)
# ============================================================================
if [ "$RUN_DEPLOY" = true ]; then
    log_info "Running deployment first..."
    bash "${SCRIPT_DIR}/deploy.sh"
fi

# ============================================================================
# Step 1: Wait for all pods to be ready
# ============================================================================
log_info "Waiting for all pods to be Ready (timeout: ${TIMEOUT_PODS}s)..."

DEPLOYMENTS="nrf ausf udm udr pcf nssf bsf amf smf upf gnb ue"
all_ready=true
for dep in $DEPLOYMENTS; do
    if ! kubectl wait --for=condition=Available "deployment/${dep}" -n "${NAMESPACE}" --timeout="${TIMEOUT_PODS}s" 2>/dev/null; then
        log_error "Deployment ${dep} not ready"
        all_ready=false
    fi
done

if [ "$all_ready" = false ]; then
    log_error "Not all deployments are ready"
    kubectl get pods -n "${NAMESPACE}"
    exit 2
fi
log_info "All 12 deployments ready"

# ============================================================================
# Step 2: Wait for UE registration + PDU session
# ============================================================================
log_info "Waiting for UE registration (timeout: ${TIMEOUT_REGISTER}s)..."

deadline=$((SECONDS + TIMEOUT_REGISTER))
registered=false
while [ $SECONDS -lt $deadline ]; do
    if kubectl logs deployment/ue -n "${NAMESPACE}" 2>&1 | grep -q "Registration Accept"; then
        registered=true
        break
    fi
    sleep 2
done

if [ "$registered" = false ]; then
    log_warn "UE registration not detected in logs (may still work)"
else
    log_info "UE registration detected"
fi

# Wait for PDU session establishment
log_info "Waiting for PDU session establishment..."
deadline=$((SECONDS + 30))
pdu_done=false
while [ $SECONDS -lt $deadline ]; do
    if kubectl logs deployment/ue -n "${NAMESPACE}" 2>&1 | grep -q "PDU Session.*ACTIVE"; then
        pdu_done=true
        break
    fi
    sleep 2
done

if [ "$pdu_done" = false ]; then
    log_warn "PDU session not detected in UE logs (may still work)"
else
    log_info "PDU session established"
fi

# Give extra time for logs to flush
sleep 5

# ============================================================================
# Step 3: Test assertions
# ============================================================================
echo ""
log_info "=== E2E Test Results ==="
echo ""

# --- NF startup assertions ---
assert_log_contains "nrf" "NextGCore NRF ready" \
    "NRF started successfully"

assert_log_contains "ausf" "NextGCore AUSF ready" \
    "AUSF started successfully"

assert_log_contains "udm" "NextGCore UDM ready" \
    "UDM started successfully"

assert_log_contains "udr" "NextGCore UDR ready" \
    "UDR started successfully"

assert_log_contains "pcf" "NextGCore PCF ready" \
    "PCF started successfully"

assert_log_contains "nssf" "NextGCore NSSF ready" \
    "NSSF started successfully"

assert_log_contains "bsf" "NextGCore BSF ready" \
    "BSF started successfully"

assert_log_contains "upf" "NextGCore UPF ready" \
    "UPF started successfully"

assert_log_contains "udr" "MongoDB connected" \
    "UDR connected to MongoDB"

# --- AMF NGAP setup ---
assert_log_contains "amf" "Configured GUAMI" \
    "AMF GUAMI configured"

assert_log_contains "amf" "Configured TAI" \
    "AMF TAI configured"

assert_log_contains "amf" "NGAP server listening" \
    "AMF NGAP server listening"

assert_log_contains "amf" "NG Setup Request" \
    "AMF received NG Setup Request from gNB"

assert_log_contains "amf" "NG Setup successful" \
    "AMF NG Setup successful"

# --- AMF Registration flow ---
assert_log_contains "amf" "Initial UE Message" \
    "AMF received Initial UE Message"

assert_log_contains "amf" "Sending Identity Request" \
    "AMF sent Identity Request"

assert_log_contains "amf" "Received Identity Response" \
    "AMF received Identity Response"

assert_log_contains "amf" "SUCI:" \
    "AMF extracted SUCI from Identity Response"

assert_log_contains "amf" "Calling AUSF authenticate" \
    "AMF called AUSF SBI for authentication"

assert_log_contains "amf" "AUSF auth.*success" \
    "AMF got AUSF auth success"

assert_log_contains "amf" "Authentication Request sent" \
    "AMF sent Authentication Request to UE"

assert_log_contains "amf" "Received Authentication Response" \
    "AMF received Authentication Response from UE"

assert_log_contains "amf" "HXRES.*verification passed" \
    "AMF HXRES* verification passed"

assert_log_contains "amf" "AUTHENTICATION_SUCCESS" \
    "AUSF 5G-AKA authentication succeeded"

assert_log_contains "amf" "NAS security context established" \
    "AMF NAS security context established"

assert_log_contains "amf" "Security Mode Command sent" \
    "AMF sent Security Mode Command"

assert_log_contains "amf" "Security Mode Complete" \
    "AMF received Security Mode Complete"

assert_log_contains "amf" "Registration Accept" \
    "AMF sent Registration Accept"

# --- AMF PDU Session flow ---
assert_log_contains "amf" "PDU Session Establishment Request" \
    "AMF received PDU Session Establishment Request"

assert_log_contains "amf" "Calling SMF SM Context Create" \
    "AMF called SMF SM Context Create (N11 SBI)"

assert_log_contains "amf" "SMF SM Context Created" \
    "AMF received SMF SM Context response"

assert_log_contains "amf" "PDU Session Establishment Accept sent" \
    "AMF sent PDU Session Accept to UE"

assert_log_contains "amf" "PDU Session Resource Setup Request sent" \
    "AMF sent NGAP PDU Session Resource Setup to gNB"

assert_log_contains "amf" "PDU Session Resource Setup Response" \
    "AMF received PDU Session Resource Setup Response"

assert_log_contains "amf" "Extracted gNB TEID" \
    "AMF extracted gNB TEID from Setup Response"

assert_log_contains "amf" "Calling SMF SM Context Update" \
    "AMF called SMF Update with gNB TEID (N11 SBI)"

assert_log_contains "amf" "SMF SM Context Updated" \
    "AMF SMF Update completed"

# --- AUSF authentication ---
assert_log_contains "ausf" "UE Authentication Request" \
    "AUSF received UE Authentication Request"

assert_log_contains "ausf" "5G-AKA Confirmation" \
    "AUSF received 5G-AKA Confirmation"

assert_log_contains "ausf" "authentication succeeded" \
    "AUSF authentication succeeded"

# --- UDM auth data generation ---
assert_log_contains "udm" "Generate Auth Data" \
    "UDM generated authentication data"

# --- UDR subscription data ---
assert_log_contains "udr" "Converted SUCI.*SUPI" \
    "UDR converted SUCI to SUPI"

assert_log_contains "udr" "GET authentication-subscription" \
    "UDR retrieved auth subscription"

assert_log_contains "udr" "Returning auth subscription data" \
    "UDR returned auth subscription data"

assert_log_contains "udr" "PATCH authentication-subscription" \
    "UDR patched auth subscription (SQN update)"

# --- SMF session management ---
assert_log_contains "smf" "PFCP Session Establishment" \
    "SMF sent PFCP Session Establishment to UPF"

# --- Detect UPF data plane mode ---
UPF_NO_DATAPLANE=false
if kubectl logs deployment/upf -n "${NAMESPACE}" --all-containers 2>&1 | grep -q "no-dataplane\|control-plane-only\|TUN creation failed"; then
    UPF_NO_DATAPLANE=true
    log_warn "UPF running in no-dataplane mode (Kind/macOS nested containers)"
fi

if [ "$UPF_NO_DATAPLANE" = true ]; then
    # Skip data plane tests in no-dataplane mode
    for skip_desc in \
        "SMF sent PFCP Session Modification (DL FAR with gNB TEID)" \
        "UPF created TUN device" \
        "UPF configured TUN IP 10.45.0.1/16" \
        "UPF NAT configured for UE subnet" \
        "UPF PFCP session established" \
        "UPF added data plane session" \
        "UPF PFCP session modified with gNB TEID" \
        "UPF updated DL TEID to gNB"; do
        SKIPPED=$((SKIPPED + 1))
        log_warn "SKIP: $skip_desc (no-dataplane mode)"
    done
else
    assert_log_contains "smf" "PFCP Session Modification successful" \
        "SMF sent PFCP Session Modification (DL FAR with gNB TEID)"

    assert_log_contains "upf" "Created TUN device" \
        "UPF created TUN device"

    assert_log_contains "upf" "Configured TUN device.*10.45.0.1" \
        "UPF configured TUN IP 10.45.0.1/16"

    assert_log_contains "upf" "NAT configured" \
        "UPF NAT configured for UE subnet"

    assert_log_contains "upf" "Session established.*UPF_SEID" \
        "UPF PFCP session established"

    assert_log_contains "upf" "Added data plane session" \
        "UPF added data plane session"

    assert_log_contains "upf" "Session.*modified" \
        "UPF PFCP session modified with gNB TEID"

    assert_log_contains "upf" "Updated data plane session.*DL_TEID" \
        "UPF updated DL TEID to gNB"
fi

# --- UPF control plane (always runs) ---
assert_log_contains "upf" "PFCP path opened" \
    "UPF PFCP path opened"

assert_log_contains "upf" "GTP-U path opened" \
    "UPF GTP-U path opened"

# --- gNB NGAP + GTP ---
assert_log_contains "gnb" "Sent NG Setup Request" \
    "gNB sent NG Setup Request"

assert_log_contains "gnb" "NG Setup Response" \
    "gNB received NG Setup Response"

assert_log_contains "gnb" "Sending Initial UE Message" \
    "gNB sent Initial UE Message to AMF"

assert_log_contains "gnb" "GTP-U socket bound" \
    "gNB GTP-U socket bound"

assert_log_contains "gnb" "PDU Session Resource Setup Request" \
    "gNB received PDU Session Resource Setup Request"

assert_log_contains "gnb" "GTP session created" \
    "gNB created GTP-U session"

assert_log_contains "gnb" "PDU Session Resource Setup Response sent" \
    "gNB sent PDU Session Resource Setup Response"

# --- UE NAS + session ---
assert_log_contains "ue" "Cell discovered" \
    "UE discovered cell"

assert_log_contains "ue" "Sending Registration Request" \
    "UE sent Registration Request"

assert_log_contains "ue" "Identity Request" \
    "UE received Identity Request"

assert_log_contains "ue" "Sending Identity Response" \
    "UE sent Identity Response"

assert_log_contains "ue" "Authentication Request received" \
    "UE received Authentication Request"

assert_log_contains "ue" "AUTN MAC verified" \
    "UE verified AUTN MAC"

assert_log_contains "ue" "Sending Authentication Response" \
    "UE sent Authentication Response"

assert_log_contains "ue" "Security Mode Command" \
    "UE received Security Mode Command"

assert_log_contains "ue" "Sending Security Mode Complete" \
    "UE sent Security Mode Complete"

assert_log_contains "ue" "Received Registration Accept" \
    "UE received Registration Accept"

assert_log_contains "ue" "Sending PDU Session Establishment Request" \
    "UE sent PDU Session Establishment Request"

assert_log_contains "ue" "PDU Session Establishment Accept" \
    "UE received PDU Session Establishment Accept"

assert_log_contains "ue" "PDU Session 1 established with IP" \
    "UE PDU Session 1 got IP address"

assert_log_contains "ue" "PDU Session.*ACTIVE" \
    "UE PDU session is ACTIVE"

assert_log_contains "ue" "Creating TUN interface" \
    "UE creating TUN interface"

# --- Data plane ping tests ---
if [ "$UPF_NO_DATAPLANE" = true ]; then
    SKIPPED=$((SKIPPED + 1))
    log_warn "SKIP: Ping 10.45.0.1 via UE tunnel (no-dataplane mode)"
else
    log_info "Testing data plane (ping through GTP-U tunnel)..."
    TOTAL=$((TOTAL + 1))
    UE_POD=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=ue -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -z "$UE_POD" ]; then
        FAILED=$((FAILED + 1))
        log_error "FAIL: UE pod not found"
    else
        if kubectl exec "$UE_POD" -n "${NAMESPACE}" -- ping -c 3 -W 5 10.45.0.1 >/dev/null 2>&1; then
            PASSED=$((PASSED + 1))
            log_info "PASS: Ping 10.45.0.1 via UE tunnel (UPF gateway)"
        else
            FAILED=$((FAILED + 1))
            log_error "FAIL: Ping 10.45.0.1 via UE tunnel"
        fi
    fi
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "========================================"
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo "========================================"
echo ""

if [ $FAILED -gt 0 ]; then
    log_error "$FAILED test(s) failed"
    exit 1
else
    if [ $SKIPPED -gt 0 ]; then
        log_info "All $PASSED tests passed ($SKIPPED skipped - UPF no-dataplane mode)"
    else
        log_info "All $PASSED tests passed"
    fi
    exit 0
fi
