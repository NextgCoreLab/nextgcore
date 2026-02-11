#!/bin/bash
# NextGCore E2E Test Script
#
# Starts the full 5G stack, waits for all services to be healthy,
# triggers UE registration + PDU session, verifies data plane with ping.
#
# Usage:
#   ./e2e-test.sh              # Run full E2E test
#   ./e2e-test.sh --no-build   # Skip Docker image build
#   ./e2e-test.sh --keep       # Don't tear down after test
#
# Exit codes:
#   0 - All tests passed
#   1 - Test failure
#   2 - Infrastructure failure (build, startup, timeout)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
TIMEOUT_HEALTH=120    # seconds to wait for all services healthy
TIMEOUT_REGISTER=60   # seconds to wait for UE registration
TIMEOUT_PING=30       # seconds to wait for ping success

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SKIP_BUILD=false
KEEP_RUNNING=false
PASSED=0
FAILED=0
TOTAL=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build) SKIP_BUILD=true; shift ;;
        --keep)     KEEP_RUNNING=true; shift ;;
        *)          echo "Unknown option: $1"; exit 2 ;;
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
    local container="$1"
    local pattern="$2"
    local desc="$3"
    TOTAL=$((TOTAL + 1))
    # Capture logs to temp file to avoid pipe buffering issues with pipefail
    local tmplog
    tmplog=$(mktemp)
    docker logs "$container" >"$tmplog" 2>&1 || true
    if grep -q "$pattern" "$tmplog"; then
        PASSED=$((PASSED + 1))
        log_info "PASS: $desc"
    else
        FAILED=$((FAILED + 1))
        log_error "FAIL: $desc (pattern '$pattern' not found in $container logs)"
    fi
    rm -f "$tmplog"
}

cleanup() {
    if [ "$KEEP_RUNNING" = false ]; then
        log_info "Tearing down..."
        docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    else
        log_warn "Keeping containers running (--keep)"
    fi
}
trap cleanup EXIT

# ============================================================================
# Step 1: Build (optional)
# ============================================================================
if [ "$SKIP_BUILD" = false ]; then
    log_info "Building Docker images..."
    "$SCRIPT_DIR/build.sh" || { log_error "Build failed"; exit 2; }
fi

# ============================================================================
# Step 2: Start services
# ============================================================================
log_info "Starting 5G core stack..."
docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d

# ============================================================================
# Step 3: Wait for all services to be healthy
# ============================================================================
log_info "Waiting for all services to be healthy (timeout: ${TIMEOUT_HEALTH}s)..."

SERVICES="mongodb nrf udr udm ausf pcf nssf bsf smf amf upf gnb ue"
deadline=$((SECONDS + TIMEOUT_HEALTH))

all_healthy=false
while [ $SECONDS -lt $deadline ]; do
    unhealthy=0
    for svc in $SERVICES; do
        container="nextgcore-$svc"
        [ "$svc" = "gnb" ] && container="nextgsim-gnb"
        [ "$svc" = "ue" ] && container="nextgsim-ue"
        [ "$svc" = "mongodb" ] && container="nextgcore-mongodb"

        status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "missing")
        if [ "$status" != "healthy" ]; then
            unhealthy=$((unhealthy + 1))
        fi
    done

    if [ $unhealthy -eq 0 ]; then
        all_healthy=true
        break
    fi

    sleep 2
done

if [ "$all_healthy" = false ]; then
    log_error "Not all services became healthy within ${TIMEOUT_HEALTH}s"
    for svc in $SERVICES; do
        container="nextgcore-$svc"
        [ "$svc" = "gnb" ] && container="nextgsim-gnb"
        [ "$svc" = "ue" ] && container="nextgsim-ue"
        [ "$svc" = "mongodb" ] && container="nextgcore-mongodb"

        status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "missing")
        if [ "$status" != "healthy" ]; then
            log_error "  $container: $status"
        fi
    done
    exit 2
fi
log_info "All $( echo $SERVICES | wc -w | tr -d ' ') services healthy"

# ============================================================================
# Step 4: Wait for UE registration + PDU session
# ============================================================================
log_info "Waiting for UE registration (timeout: ${TIMEOUT_REGISTER}s)..."

deadline=$((SECONDS + TIMEOUT_REGISTER))
registered=false
while [ $SECONDS -lt $deadline ]; do
    if docker logs nextgsim-ue 2>&1 | grep -q "Registration Accept"; then
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

# Wait for PDU session establishment to complete (SMF→UPF PFCP + gNB GTP)
log_info "Waiting for PDU session establishment..."
deadline=$((SECONDS + 30))
pdu_done=false
while [ $SECONDS -lt $deadline ]; do
    if docker logs nextgsim-ue 2>&1 | grep -q "PDU Session.*ACTIVE"; then
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

# Give extra time for all logs to flush to Docker log driver
sleep 10

# ============================================================================
# Step 5: Test assertions
# ============================================================================
echo ""
log_info "=== E2E Test Results ==="
echo ""

# --- NF process assertions (use sh -c since kill binary not in debian slim) ---
for svc in nrf ausf udm udr pcf nssf bsf amf smf; do
    assert_pass \
        "docker exec nextgcore-$svc sh -c 'kill -0 1'" \
        "NF process running: $svc"
done

# --- Log assertions ---
# AMF logs "Initial UE Message" (not "Registration Request")
assert_log_contains "nextgcore-amf" "Initial UE Message" \
    "AMF received Initial UE Message (Registration Request)"

assert_log_contains "nextgcore-amf" "AUSF" \
    "AMF called AUSF for authentication"

assert_log_contains "nextgcore-amf" "AUTHENTICATION_SUCCESS" \
    "AUSF authentication succeeded"

assert_log_contains "nextgcore-amf" "Security Mode Command" \
    "AMF sent Security Mode Command"

assert_log_contains "nextgcore-amf" "Registration Accept" \
    "AMF sent Registration Accept"

assert_log_contains "nextgcore-amf" "PDU Session Establishment Request" \
    "AMF received PDU Session Establishment Request"

assert_log_contains "nextgcore-amf" "SMF SM Context Created" \
    "AMF called SMF via SBI (N11)"

assert_log_contains "nextgcore-amf" "PDU Session Resource Setup Request sent" \
    "AMF sent NGAP PDU Session Resource Setup to gNB"

assert_log_contains "nextgcore-amf" "PDU Session Resource Setup Response" \
    "AMF received PDU Session Resource Setup Response from gNB"

assert_log_contains "nextgcore-amf" "SMF SM Context Updated" \
    "AMF called SMF Update with gNB TEID"

assert_log_contains "nextgcore-smf" "PFCP Session Establishment" \
    "SMF sent PFCP Session Establishment to UPF"

assert_log_contains "nextgcore-smf" "PFCP Session Modification successful" \
    "SMF sent PFCP Session Modification (DL FAR with gNB TEID)"

assert_log_contains "nextgsim-gnb" "PDU Session Resource Setup Request" \
    "gNB received PDU Session Resource Setup Request"

assert_log_contains "nextgsim-gnb" "GTP session created" \
    "gNB created GTP-U session"

assert_log_contains "nextgsim-gnb" "PDU Session Resource Setup Response" \
    "gNB sent PDU Session Resource Setup Response"

assert_log_contains "nextgsim-ue" "Registration Accept" \
    "UE received Registration Accept"

assert_log_contains "nextgsim-ue" "PDU Session.*ACTIVE" \
    "UE PDU session is ACTIVE"

assert_log_contains "nextgsim-ue" "TUN interface created" \
    "UE TUN interface created"

# --- Data plane ping test ---
log_info "Testing data plane (ping through GTP-U tunnel)..."
TOTAL=$((TOTAL + 1))
if docker exec nextgsim-ue ping -c 3 -W 5 10.45.0.1 >/dev/null 2>&1; then
    PASSED=$((PASSED + 1))
    log_info "PASS: Ping 10.45.0.1 via UE tunnel (UPF gateway)"
else
    FAILED=$((FAILED + 1))
    log_error "FAIL: Ping 10.45.0.1 via UE tunnel"
fi

TOTAL=$((TOTAL + 1))
if docker exec nextgsim-ue ping -c 3 -W 5 172.23.0.1 >/dev/null 2>&1; then
    PASSED=$((PASSED + 1))
    log_info "PASS: Ping 172.23.0.1 via UE tunnel (Docker gateway)"
else
    FAILED=$((FAILED + 1))
    log_error "FAIL: Ping 172.23.0.1 via UE tunnel"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "========================================"
echo "  Total:  $TOTAL"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"
echo "========================================"
echo ""

if [ $FAILED -gt 0 ]; then
    log_error "$FAILED test(s) failed"
    exit 1
else
    log_info "All $PASSED tests passed"
    exit 0
fi
