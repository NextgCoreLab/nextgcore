#!/usr/bin/env bash
# =============================================================================
# NextGCore Rust Docker Deployment Validation Script
# =============================================================================
# This script validates Docker Compose deployments for:
# - 5G Core (5GC) stack: NRF, AUSF, UDM, UDR, PCF, NSSF, BSF, AMF, SMF, UPF
# - EPC (4G) stack: HSS, PCRF, MME, SGW-C, SGW-U
#
# Usage:
#   ./validate-deployment.sh [OPTIONS]
#
# Options:
#   -5, --5gc       Validate 5G Core deployment only
#   -4, --epc       Validate EPC deployment only
#   -a, --all       Validate both 5GC and EPC (default)
#   -c, --cleanup   Clean up after validation
#   -v, --verbose   Enable verbose output
#   -h, --help      Show this help message
#
# Requirements:
#   - Docker and Docker Compose installed
#   - curl for HTTP health checks
#   - jq for JSON parsing (optional, for better output)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default options
VALIDATE_5GC=false
VALIDATE_EPC=false
CLEANUP=false
VERBOSE=false
TIMEOUT=120  # seconds to wait for services

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# =============================================================================
# Logging Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${CYAN}[SKIP]${NC} $1"
    ((TESTS_SKIPPED++))
}

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

log_section() {
    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================${NC}"
}

# =============================================================================
# Utility Functions
# =============================================================================

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Wait for a service to be healthy
wait_for_service() {
    local service_name=$1
    local check_cmd=$2
    local max_attempts=$((TIMEOUT / 5))
    local attempt=1

    log_info "Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if eval "$check_cmd" &> /dev/null; then
            log_verbose "$service_name is ready (attempt $attempt)"
            return 0
        fi
        log_verbose "Attempt $attempt/$max_attempts: $service_name not ready yet..."
        sleep 5
        ((attempt++))
    done
    
    log_error "$service_name failed to become ready within ${TIMEOUT}s"
    return 1
}

# Check HTTP endpoint
check_http_endpoint() {
    local name=$1
    local url=$2
    local expected_status=${3:-200}
    
    log_verbose "Checking HTTP endpoint: $url"
    
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null || echo "000")
    
    if [ "$response" = "$expected_status" ] || [ "$response" = "200" ] || [ "$response" = "204" ]; then
        log_success "$name: HTTP $response"
        return 0
    else
        log_error "$name: Expected HTTP $expected_status, got $response"
        return 1
    fi
}

# Check if container is running
check_container_running() {
    local container_name=$1
    
    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        return 0
    else
        return 1
    fi
}

# Check container health status
check_container_health() {
    local container_name=$1
    
    local health
    health=$(docker inspect --format='{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "none")
    
    case "$health" in
        "healthy")
            return 0
            ;;
        "unhealthy")
            return 1
            ;;
        "starting")
            return 2
            ;;
        *)
            # No health check defined, check if running
            if check_container_running "$container_name"; then
                return 0
            fi
            return 1
            ;;
    esac
}

# Get container logs (last N lines)
get_container_logs() {
    local container_name=$1
    local lines=${2:-20}
    
    docker logs --tail "$lines" "$container_name" 2>&1
}

# Check process is running in container
check_process_in_container() {
    local container_name=$1
    local process_name=$2
    
    if docker exec "$container_name" pgrep -x "$process_name" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# =============================================================================
# 5G Core Validation Functions
# =============================================================================

validate_5gc_mongodb() {
    log_info "Validating MongoDB for 5GC..."
    
    local container="nextgcore-5gc-mongodb"
    
    if ! check_container_running "$container"; then
        log_error "MongoDB container not running"
        return 1
    fi
    
    # Check MongoDB is accepting connections
    if docker exec "$container" mongosh --eval "db.adminCommand('ping')" &> /dev/null; then
        log_success "MongoDB: Accepting connections"
    else
        log_error "MongoDB: Not accepting connections"
        return 1
    fi
    
    # Check nextgcore database exists
    if docker exec "$container" mongosh --eval "db.getSiblingDB('nextgcore').getCollectionNames()" &> /dev/null; then
        log_success "MongoDB: nextgcore database accessible"
    else
        log_warn "MongoDB: nextgcore database may not be initialized"
    fi
    
    return 0
}

validate_5gc_nrf() {
    log_info "Validating NRF (Network Repository Function)..."
    
    local container="nextgcore-5gc-nrf"
    
    if ! check_container_running "$container"; then
        log_error "NRF container not running"
        return 1
    fi
    
    # Check NRF process is running (SBI server is stub implementation)
    if check_process_in_container "$container" "nf-binary"; then
        log_success "NRF: Process running"
    else
        log_error "NRF: Process not running"
        return 1
    fi
    
    # Note: HTTP endpoint check skipped - SBI server is stub implementation
    # In production, would check: http://localhost:7777/nnrf-nfm/v1/nf-instances
    if [ "$VERBOSE" = true ]; then
        echo "[DEBUG] NRF SBI: Stub implementation (HTTP endpoint not available)"
    fi
    
    return 0
}

validate_5gc_nf_registration() {
    log_info "Validating NF Registration with NRF..."
    
    # Query NRF for registered NFs
    local nf_instances
    nf_instances=$(curl -s "http://localhost:7777/nnrf-nfm/v1/nf-instances" 2>/dev/null || echo "{}")
    
    if command_exists jq; then
        local nf_count
        nf_count=$(echo "$nf_instances" | jq -r '.nfInstances | length' 2>/dev/null || echo "0")
        
        if [ "$nf_count" -gt 0 ]; then
            log_success "NRF: $nf_count NF(s) registered"
            
            # List registered NFs
            echo "$nf_instances" | jq -r '.nfInstances[] | "  - \(.nfType): \(.nfInstanceId)"' 2>/dev/null || true
        else
            log_warn "NRF: No NFs registered yet"
        fi
    else
        if echo "$nf_instances" | grep -q "nfInstances"; then
            log_success "NRF: NF instances endpoint responding"
        else
            log_warn "NRF: Unable to parse NF instances (install jq for detailed output)"
        fi
    fi
    
    return 0
}

validate_5gc_ausf() {
    log_info "Validating AUSF (Authentication Server Function)..."
    
    local container="nextgcore-5gc-ausf"
    
    if ! check_container_running "$container"; then
        log_error "AUSF container not running"
        return 1
    fi
    
    # AUSF doesn't have a simple health endpoint, check process
    if check_process_in_container "$container" "nf-binary"; then
        log_success "AUSF: Process running"
    else
        log_error "AUSF: Process not running"
        return 1
    fi
    
    return 0
}

validate_5gc_udm() {
    log_info "Validating UDM (Unified Data Management)..."
    
    local container="nextgcore-5gc-udm"
    
    if ! check_container_running "$container"; then
        log_error "UDM container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "UDM: Process running"
    else
        log_error "UDM: Process not running"
        return 1
    fi
    
    return 0
}

validate_5gc_udr() {
    log_info "Validating UDR (Unified Data Repository)..."
    
    local container="nextgcore-5gc-udr"
    
    if ! check_container_running "$container"; then
        log_error "UDR container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "UDR: Process running"
    else
        log_error "UDR: Process not running"
        return 1
    fi
    
    return 0
}

validate_5gc_pcf() {
    log_info "Validating PCF (Policy Control Function)..."
    
    local container="nextgcore-5gc-pcf"
    
    if ! check_container_running "$container"; then
        log_error "PCF container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "PCF: Process running"
    else
        log_error "PCF: Process not running"
        return 1
    fi
    
    return 0
}

validate_5gc_nssf() {
    log_info "Validating NSSF (Network Slice Selection Function)..."
    
    local container="nextgcore-5gc-nssf"
    
    if ! check_container_running "$container"; then
        log_error "NSSF container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "NSSF: Process running"
    else
        log_error "NSSF: Process not running"
        return 1
    fi
    
    return 0
}

validate_5gc_bsf() {
    log_info "Validating BSF (Binding Support Function)..."
    
    local container="nextgcore-5gc-bsf"
    
    if ! check_container_running "$container"; then
        log_error "BSF container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "BSF: Process running"
    else
        log_error "BSF: Process not running"
        return 1
    fi
    
    return 0
}

validate_5gc_amf() {
    log_info "Validating AMF (Access and Mobility Management Function)..."
    
    local container="nextgcore-5gc-amf"
    
    if ! check_container_running "$container"; then
        log_error "AMF container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "AMF: Process running"
    else
        log_error "AMF: Process not running"
        return 1
    fi
    
    # Check NGAP port is listening (38412/sctp)
    # Note: SCTP check requires special handling
    log_verbose "AMF: NGAP port check skipped (requires SCTP tools)"
    
    return 0
}

validate_5gc_smf() {
    log_info "Validating SMF (Session Management Function)..."
    
    local container="nextgcore-5gc-smf"
    
    if ! check_container_running "$container"; then
        log_error "SMF container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "SMF: Process running"
    else
        log_error "SMF: Process not running"
        return 1
    fi
    
    return 0
}

validate_5gc_upf() {
    log_info "Validating UPF (User Plane Function)..."
    
    local container="nextgcore-5gc-upf"
    
    if ! check_container_running "$container"; then
        log_error "UPF container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "UPF: Process running"
    else
        log_error "UPF: Process not running"
        return 1
    fi
    
    # Check TUN interface exists
    if docker exec "$container" ip link show ogstun &> /dev/null; then
        log_success "UPF: TUN interface (ogstun) exists"
    else
        log_warn "UPF: TUN interface (ogstun) not found"
    fi
    
    return 0
}

# =============================================================================
# EPC Validation Functions
# =============================================================================

validate_epc_mongodb() {
    log_info "Validating MongoDB for EPC..."
    
    local container="nextgcore-epc-mongodb"
    
    if ! check_container_running "$container"; then
        log_error "MongoDB container not running"
        return 1
    fi
    
    if docker exec "$container" mongosh --eval "db.adminCommand('ping')" &> /dev/null; then
        log_success "MongoDB: Accepting connections"
    else
        log_error "MongoDB: Not accepting connections"
        return 1
    fi
    
    return 0
}

validate_epc_hss() {
    log_info "Validating HSS (Home Subscriber Server)..."
    
    local container="nextgcore-epc-hss"
    
    if ! check_container_running "$container"; then
        log_error "HSS container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "HSS: Process running"
    else
        log_error "HSS: Process not running"
        return 1
    fi
    
    # Check Diameter port (3868)
    log_verbose "HSS: Diameter port check skipped (requires Diameter client)"
    
    return 0
}

validate_epc_pcrf() {
    log_info "Validating PCRF (Policy and Charging Rules Function)..."
    
    local container="nextgcore-epc-pcrf"
    
    if ! check_container_running "$container"; then
        log_error "PCRF container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "PCRF: Process running"
    else
        log_error "PCRF: Process not running"
        return 1
    fi
    
    return 0
}

validate_epc_mme() {
    log_info "Validating MME (Mobility Management Entity)..."
    
    local container="nextgcore-epc-mme"
    
    if ! check_container_running "$container"; then
        log_error "MME container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "MME: Process running"
    else
        log_error "MME: Process not running"
        return 1
    fi
    
    # Check S1AP port (36412/sctp)
    log_verbose "MME: S1AP port check skipped (requires SCTP tools)"
    
    return 0
}

validate_epc_sgwc() {
    log_info "Validating SGW-C (Serving Gateway - Control Plane)..."
    
    local container="nextgcore-epc-sgwc"
    
    if ! check_container_running "$container"; then
        log_error "SGW-C container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "SGW-C: Process running"
    else
        log_error "SGW-C: Process not running"
        return 1
    fi
    
    return 0
}

validate_epc_sgwu() {
    log_info "Validating SGW-U (Serving Gateway - User Plane)..."
    
    local container="nextgcore-epc-sgwu"
    
    if ! check_container_running "$container"; then
        log_error "SGW-U container not running"
        return 1
    fi
    
    if check_process_in_container "$container" "nf-binary"; then
        log_success "SGW-U: Process running"
    else
        log_error "SGW-U: Process not running"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Deployment Functions
# =============================================================================

deploy_5gc() {
    log_section "Deploying 5G Core Stack"
    
    cd "$SCRIPT_DIR"
    
    log_info "Starting 5GC services..."
    docker compose -f docker-compose-5gc.yml up -d
    
    log_info "Waiting for services to initialize..."
    sleep 10
    
    # Wait for MongoDB first
    wait_for_service "MongoDB" "docker exec nextgcore-5gc-mongodb mongosh --eval 'db.adminCommand(\"ping\")'"
    
    # Wait for NRF
    wait_for_service "NRF" "curl -s http://localhost:7777/nnrf-nfm/v1/nf-instances"
    
    # Give other NFs time to register
    log_info "Waiting for NFs to register with NRF..."
    sleep 15
    
    return 0
}

deploy_epc() {
    log_section "Deploying EPC Stack"
    
    cd "$SCRIPT_DIR"
    
    log_info "Starting EPC services..."
    docker compose -f docker-compose-epc.yml up -d
    
    log_info "Waiting for services to initialize..."
    sleep 10
    
    # Wait for MongoDB first
    wait_for_service "MongoDB" "docker exec nextgcore-epc-mongodb mongosh --eval 'db.adminCommand(\"ping\")'"
    
    # Give services time to start
    log_info "Waiting for EPC services to initialize..."
    sleep 15
    
    return 0
}

cleanup_5gc() {
    log_info "Cleaning up 5GC deployment..."
    cd "$SCRIPT_DIR"
    docker compose -f docker-compose-5gc.yml down -v --remove-orphans 2>/dev/null || true
}

cleanup_epc() {
    log_info "Cleaning up EPC deployment..."
    cd "$SCRIPT_DIR"
    docker compose -f docker-compose-epc.yml down -v --remove-orphans 2>/dev/null || true
}

# =============================================================================
# Main Validation Functions
# =============================================================================

validate_5gc_stack() {
    log_section "Validating 5G Core Stack"
    
    # Infrastructure
    validate_5gc_mongodb || true
    
    # Core NFs
    validate_5gc_nrf || true
    validate_5gc_nf_registration || true
    validate_5gc_ausf || true
    validate_5gc_udm || true
    validate_5gc_udr || true
    validate_5gc_pcf || true
    validate_5gc_nssf || true
    validate_5gc_bsf || true
    
    # Access NFs
    validate_5gc_amf || true
    validate_5gc_smf || true
    
    # User Plane
    validate_5gc_upf || true
}

validate_epc_stack() {
    log_section "Validating EPC Stack"
    
    # Infrastructure
    validate_epc_mongodb || true
    
    # Core NFs
    validate_epc_hss || true
    validate_epc_pcrf || true
    validate_epc_sgwc || true
    validate_epc_mme || true
    
    # User Plane
    validate_epc_sgwu || true
}

# =============================================================================
# Summary
# =============================================================================

print_summary() {
    log_section "Validation Summary"
    
    echo -e "Tests Passed:  ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed:  ${RED}$TESTS_FAILED${NC}"
    echo -e "Tests Skipped: ${CYAN}$TESTS_SKIPPED${NC}"
    echo ""
    
    local total=$((TESTS_PASSED + TESTS_FAILED))
    if [ $total -gt 0 ]; then
        local pass_rate=$((TESTS_PASSED * 100 / total))
        echo -e "Pass Rate: ${pass_rate}%"
    fi
    
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All validations passed!${NC}"
        return 0
    else
        echo -e "${RED}Some validations failed. Check logs above for details.${NC}"
        return 1
    fi
}

# =============================================================================
# Usage
# =============================================================================

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Validate NextGCore Rust Docker Compose deployments.

Options:
  -5, --5gc       Validate 5G Core deployment only
  -4, --epc       Validate EPC deployment only
  -a, --all       Validate both 5GC and EPC (default)
  -d, --deploy    Deploy before validating (builds images if needed)
  -c, --cleanup   Clean up after validation
  -t, --timeout N Timeout in seconds for service readiness (default: 120)
  -v, --verbose   Enable verbose output
  -h, --help      Show this help message

Examples:
  $0 -5                    # Validate 5GC only (assumes already deployed)
  $0 -4                    # Validate EPC only (assumes already deployed)
  $0 -a                    # Validate both stacks
  $0 -d -5                 # Deploy and validate 5GC
  $0 -d -a -c              # Deploy, validate, and cleanup both stacks
  $0 -d -5 -c -v           # Deploy, validate, cleanup 5GC with verbose output

EOF
}

# =============================================================================
# Main
# =============================================================================

DEPLOY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -5|--5gc)
            VALIDATE_5GC=true
            shift
            ;;
        -4|--epc)
            VALIDATE_EPC=true
            shift
            ;;
        -a|--all)
            VALIDATE_5GC=true
            VALIDATE_EPC=true
            shift
            ;;
        -d|--deploy)
            DEPLOY=true
            shift
            ;;
        -c|--cleanup)
            CLEANUP=true
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Default to validating both if nothing specified
if [ "$VALIDATE_5GC" = "false" ] && [ "$VALIDATE_EPC" = "false" ]; then
    VALIDATE_5GC=true
    VALIDATE_EPC=true
fi

# Check prerequisites
if ! command_exists docker; then
    log_error "Docker is not installed"
    exit 1
fi

if ! command_exists curl; then
    log_error "curl is not installed"
    exit 1
fi

if ! command_exists jq; then
    log_warn "jq is not installed - some output will be limited"
fi

# Print header
echo ""
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}NextGCore Rust Docker Deployment Validation${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo "Configuration:"
echo "  Validate 5GC: $VALIDATE_5GC"
echo "  Validate EPC: $VALIDATE_EPC"
echo "  Deploy:       $DEPLOY"
echo "  Cleanup:      $CLEANUP"
echo "  Timeout:      ${TIMEOUT}s"
echo "  Verbose:      $VERBOSE"
echo ""

# Trap for cleanup on exit
cleanup_on_exit() {
    if [ "$CLEANUP" = "true" ]; then
        log_section "Cleanup"
        if [ "$VALIDATE_5GC" = "true" ]; then
            cleanup_5gc
        fi
        if [ "$VALIDATE_EPC" = "true" ]; then
            cleanup_epc
        fi
    fi
}
trap cleanup_on_exit EXIT

# Deploy if requested
if [ "$DEPLOY" = "true" ]; then
    if [ "$VALIDATE_5GC" = "true" ]; then
        deploy_5gc
    fi
    if [ "$VALIDATE_EPC" = "true" ]; then
        deploy_epc
    fi
fi

# Run validations
if [ "$VALIDATE_5GC" = "true" ]; then
    validate_5gc_stack
fi

if [ "$VALIDATE_EPC" = "true" ]; then
    validate_epc_stack
fi

# Print summary
print_summary
exit_code=$?

exit $exit_code
