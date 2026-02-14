#!/bin/bash
# NextGCore Multi-UE Stress Test Script (G38)
#
# Tests 5 concurrent UE registrations and PDU sessions.
# Verifies that multiple UEs can successfully register and establish
# independent PDU sessions without interference.
#
# Usage:
#   ./test-multi-ue.sh              # Run multi-UE stress test
#   ./test-multi-ue.sh --ue-count 10  # Test with 10 UEs
#   ./test-multi-ue.sh --no-build   # Skip Docker image build
#   ./test-multi-ue.sh --keep       # Keep containers running after test
#
# Exit codes:
#   0 - All tests passed
#   1 - Test failure
#   2 - Infrastructure failure (build, startup, timeout)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
TIMEOUT_HEALTH=120
TIMEOUT_REGISTER=90
UE_COUNT=5

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
        --ue-count) UE_COUNT="$2"; shift 2 ;;
        *)          echo "Unknown option: $1"; exit 2 ;;
    esac
done

# ============================================================================
# Helpers
# ============================================================================
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[FAIL]${NC}  $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

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

cleanup() {
    if [ "$KEEP_RUNNING" = false ]; then
        log_info "Tearing down..."
        docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true

        # Remove any leftover UE containers
        for i in $(seq 1 "$UE_COUNT"); do
            docker rm -f "nextgsim-ue${i}" 2>/dev/null || true
        done
    else
        log_warn "Keeping containers running (--keep)"
    fi
}
trap cleanup EXIT

echo -e "${GREEN}=== NextGCore Multi-UE Stress Test ===${NC}"
echo "UE count: $UE_COUNT"
echo ""

# ============================================================================
# Step 1: Build (optional)
# ============================================================================
if [ "$SKIP_BUILD" = false ]; then
    log_step "Building Docker images..."
    "$SCRIPT_DIR/build.sh" || { log_error "Build failed"; exit 2; }
fi

# ============================================================================
# Step 2: Start 5GC + gNB (without default UE)
# ============================================================================
log_step "Starting 5G core + gNB..."
docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true

# Start all except UE
docker compose -f "$COMPOSE_FILE" up -d mongodb nrf udr udm ausf pcf nssf bsf amf smf upf gnb

# ============================================================================
# Step 3: Wait for core + gNB to be healthy
# ============================================================================
log_step "Waiting for 5GC + gNB to be healthy (timeout: ${TIMEOUT_HEALTH}s)..."

SERVICES="mongodb nrf udr udm ausf pcf nssf bsf smf amf upf gnb"
deadline=$((SECONDS + TIMEOUT_HEALTH))

all_healthy=false
while [ $SECONDS -lt $deadline ]; do
    unhealthy=0
    for svc in $SERVICES; do
        container="nextgcore-$svc"
        [ "$svc" = "gnb" ] && container="nextgsim-gnb"
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
    exit 2
fi
log_info "All infrastructure services healthy"

# ============================================================================
# Step 4: Create UE configs with different SUPI/IMSI
# ============================================================================
log_step "Generating UE configurations..."

mkdir -p "$SCRIPT_DIR/configs/ue-multi"

BASE_IMSI="999700000000001"
BASE_IP=101

for i in $(seq 1 "$UE_COUNT"); do
    # Generate unique IMSI by adding to base
    IMSI=$((BASE_IMSI + i - 1))
    UE_IP="172.23.0.$((BASE_IP + i - 1))"

    cat > "$SCRIPT_DIR/configs/ue-multi/ue${i}.yaml" <<EOF
# UE ${i} Configuration (Multi-UE Stress Test)
supi: imsi-${IMSI}
mcc: '999'
mnc: '70'
key: '465B5CE8B199B49FAA5F0A2EE238A6BC'
op: 'E8ED289DEBA952E4283B54E88E6183CA'
opType: OP

gnb:
  host: 172.23.0.100
  port: 9487

sessions:
  - type: IPv4
    apn: internet
    slice:
      sst: 1
      sd: '0x010203'

configured-nssai:
  - sst: 1
    sd: '0x010203'

default-nssai:
  - sst: 1
    sd: '0x010203'

integrity:
  IA1: true
  IA2: true
  IA3: true

ciphering:
  EA1: true
  EA2: true
  EA3: true
EOF

    log_info "Created config for UE${i} (IMSI: ${IMSI})"
done

# ============================================================================
# Step 5: Launch all UEs concurrently
# ============================================================================
log_step "Launching ${UE_COUNT} UEs concurrently..."

for i in $(seq 1 "$UE_COUNT"); do
    UE_IP="172.23.0.$((BASE_IP + i - 1))"

    docker run -d \
        --name "nextgsim-ue${i}" \
        --network nextgcore-docker-rust_core \
        --ip "$UE_IP" \
        --cap-add NET_ADMIN \
        --device /dev/net/tun \
        -e RUST_LOG=info,nextgsim_ue=debug,nextgsim_nas=debug \
        -v "$SCRIPT_DIR/configs/ue-multi/ue${i}.yaml:/etc/nextgsim/ue.yaml:ro" \
        nextgsim-ue:latest \
        -c /etc/nextgsim/ue.yaml

    log_info "Launched UE${i} (${UE_IP})"
done

# ============================================================================
# Step 6: Wait for all UEs to register and establish PDU sessions
# ============================================================================
log_step "Waiting for all UEs to register (timeout: ${TIMEOUT_REGISTER}s)..."

deadline=$((SECONDS + TIMEOUT_REGISTER))
ue_registered=()
ue_pdu_active=()

for i in $(seq 1 "$UE_COUNT"); do
    ue_registered[$i]=false
    ue_pdu_active[$i]=false
done

while [ $SECONDS -lt $deadline ]; do
    all_done=true

    for i in $(seq 1 "$UE_COUNT"); do
        # Check registration
        if [ "${ue_registered[$i]}" = false ]; then
            if docker logs "nextgsim-ue${i}" 2>&1 | grep -q "Registration Accept"; then
                ue_registered[$i]=true
                log_info "UE${i}: Registration complete"
            else
                all_done=false
            fi
        fi

        # Check PDU session
        if [ "${ue_pdu_active[$i]}" = false ]; then
            if docker logs "nextgsim-ue${i}" 2>&1 | grep -q "PDU Session.*ACTIVE"; then
                ue_pdu_active[$i]=true
                log_info "UE${i}: PDU session active"
            else
                all_done=false
            fi
        fi
    done

    if [ "$all_done" = true ]; then
        break
    fi

    sleep 2
done

# Give logs time to flush
sleep 5

# ============================================================================
# Step 7: Verify all UEs registered and got PDU sessions
# ============================================================================
echo ""
log_step "=== Multi-UE Test Results ==="
echo ""

for i in $(seq 1 "$UE_COUNT"); do
    # Registration test
    TOTAL=$((TOTAL + 1))
    if [ "${ue_registered[$i]}" = true ]; then
        PASSED=$((PASSED + 1))
        log_info "PASS: UE${i} registration"
    else
        FAILED=$((FAILED + 1))
        log_error "FAIL: UE${i} registration (timeout)"
    fi

    # PDU session test
    TOTAL=$((TOTAL + 1))
    if [ "${ue_pdu_active[$i]}" = true ]; then
        PASSED=$((PASSED + 1))
        log_info "PASS: UE${i} PDU session established"
    else
        FAILED=$((FAILED + 1))
        log_error "FAIL: UE${i} PDU session (timeout)"
    fi

    # Extract IP address
    TOTAL=$((TOTAL + 1))
    ip_addr=$(docker logs "nextgsim-ue${i}" 2>&1 | grep -oP 'PDU Session 1 established with IP \K[0-9.]+' | head -1 || echo "")
    if [ -n "$ip_addr" ]; then
        PASSED=$((PASSED + 1))
        log_info "PASS: UE${i} got IP address: $ip_addr"
    else
        FAILED=$((FAILED + 1))
        log_error "FAIL: UE${i} did not get IP address"
    fi
done

# ============================================================================
# Step 8: Test data plane for each UE
# ============================================================================
echo ""
log_step "Testing data plane (ping from each UE)..."

for i in $(seq 1 "$UE_COUNT"); do
    TOTAL=$((TOTAL + 1))
    if docker exec "nextgsim-ue${i}" ping -c 2 -W 3 10.45.0.1 >/dev/null 2>&1; then
        PASSED=$((PASSED + 1))
        log_info "PASS: UE${i} ping 10.45.0.1 (UPF gateway)"
    else
        FAILED=$((FAILED + 1))
        log_error "FAIL: UE${i} ping 10.45.0.1"
    fi
done

# ============================================================================
# Step 9: Verify AMF handled multiple UE contexts
# ============================================================================
echo ""
log_step "Verifying AMF multi-UE handling..."

TOTAL=$((TOTAL + 1))
amf_ue_count=$(docker logs nextgcore-amf 2>&1 | grep -c "Registration Accept" || echo "0")
if [ "$amf_ue_count" -ge "$UE_COUNT" ]; then
    PASSED=$((PASSED + 1))
    log_info "PASS: AMF sent ${amf_ue_count} Registration Accept messages"
else
    FAILED=$((FAILED + 1))
    log_error "FAIL: AMF only sent ${amf_ue_count}/${UE_COUNT} Registration Accept messages"
fi

# ============================================================================
# Step 10: Verify SMF handled multiple PDU sessions
# ============================================================================
TOTAL=$((TOTAL + 1))
smf_session_count=$(docker logs nextgcore-smf 2>&1 | grep -c "PFCP Session Establishment" || echo "0")
if [ "$smf_session_count" -ge "$UE_COUNT" ]; then
    PASSED=$((PASSED + 1))
    log_info "PASS: SMF created ${smf_session_count} PFCP sessions"
else
    FAILED=$((FAILED + 1))
    log_error "FAIL: SMF only created ${smf_session_count}/${UE_COUNT} PFCP sessions"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "========================================"
echo "  Multi-UE Stress Test Summary"
echo "========================================"
echo "  UE Count:     $UE_COUNT"
echo "  Total Tests:  $TOTAL"
echo "  Passed:       $PASSED"
echo "  Failed:       $FAILED"
echo "========================================"
echo ""

if [ $FAILED -gt 0 ]; then
    log_error "$FAILED test(s) failed"
    exit 1
else
    log_info "All $PASSED tests passed - ${UE_COUNT} concurrent UEs working correctly"
    exit 0
fi
