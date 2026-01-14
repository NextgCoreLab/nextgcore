#!/usr/bin/env bash
# Fast Docker Build Script for NextGCore Rust
# Builds Linux binaries in a container, then creates minimal Docker images
#
# This is MUCH faster than building inside each Dockerfile because:
# 1. Binaries are built once and shared across all images
# 2. No 15GB context transfer per image
# 3. Cargo cache is preserved between builds

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 5GC Network Functions
NFS_5GC=(
    "nextgcore-nrfd"
    "nextgcore-ausfd"
    "nextgcore-udmd"
    "nextgcore-udrd"
    "nextgcore-pcfd"
    "nextgcore-nssfd"
    "nextgcore-bsfd"
    "nextgcore-amfd"
    "nextgcore-smfd"
    "nextgcore-upfd"
)

# EPC Network Functions
NFS_EPC=(
    "nextgcore-hssd"
    "nextgcore-pcrfd"
    "nextgcore-mmed"
    "nextgcore-sgwcd"
    "nextgcore-sgwud"
)

BUILD_5GC=false
BUILD_EPC=false
SKIP_COMPILE=false

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Fast build Docker images using pre-compiled binaries.

Options:
  -5, --5gc         Build 5G Core NFs only
  -4, --epc         Build EPC NFs only  
  -a, --all         Build all NFs (default)
  -s, --skip-compile Skip compilation (use existing binaries)
  -h, --help        Show this help

Examples:
  $0 -5             # Build 5GC images
  $0 -s -5          # Build 5GC images using existing binaries
  $0 -a             # Build all images
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -5|--5gc) BUILD_5GC=true; shift ;;
        -4|--epc) BUILD_EPC=true; shift ;;
        -a|--all) BUILD_5GC=true; BUILD_EPC=true; shift ;;
        -s|--skip-compile) SKIP_COMPILE=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Default to all if nothing specified
if [ "$BUILD_5GC" = "false" ] && [ "$BUILD_EPC" = "false" ]; then
    BUILD_5GC=true
    BUILD_EPC=true
fi

# Build list
BUILD_LIST=()
[ "$BUILD_5GC" = "true" ] && BUILD_LIST+=("${NFS_5GC[@]}")
[ "$BUILD_EPC" = "true" ] && BUILD_LIST+=("${NFS_EPC[@]}")

log_info "Building: ${BUILD_LIST[*]}"

# Step 1: Compile binaries in Linux container
if [ "$SKIP_COMPILE" = "false" ]; then
    log_info "Step 1: Compiling Rust binaries in Linux container..."
    
    # Create cargo cache volume if it doesn't exist
    docker volume create nextgcore-cargo-cache 2>/dev/null || true
    
    # Build all binaries
    docker run --rm \
        -v "${PROJECT_ROOT}:/app" \
        -v "nextgcore-cargo-cache:/usr/local/cargo/registry" \
        -w /app/rust_src \
        -e CARGO_HOME=/usr/local/cargo \
        rust:1.85-bookworm \
        bash -c "
            apt-get update && apt-get install -y --no-install-recommends \
                pkg-config libssl-dev libsctp-dev libyaml-dev clang libclang-dev && \
            cargo build --release --workspace && \
            echo 'Build complete!'
        "
    
    log_success "Binaries compiled successfully"
else
    log_info "Step 1: Skipping compilation (using existing binaries)"
fi

# Step 2: Build Docker images
log_info "Step 2: Building Docker images..."

for nf in "${BUILD_LIST[@]}"; do
    # Map NF binary name to image name (e.g., nextgcore-nrfd -> nrf)
    image_suffix="${nf#nextgcore-}"  # Remove 'nextgcore-' prefix
    image_suffix="${image_suffix%d}"  # Remove trailing 'd'
    image_name="nextgcore-rust/${image_suffix}:latest"
    
    log_info "Building image: $image_name"
    
    docker build \
        -f "$SCRIPT_DIR/Dockerfile.prebuilt" \
        --build-arg NF_NAME="$nf" \
        -t "$image_name" \
        "$PROJECT_ROOT"
    
    log_success "Built: $image_name"
done

log_info "Step 3: Listing built images..."
docker images | grep "nextgcore-rust" | head -20

log_success "All images built successfully!"
echo ""
echo "To deploy 5GC stack:"
echo "  docker compose -f docker/rust/docker-compose-5gc.yml up -d"
echo ""
echo "To validate deployment:"
echo "  ./docker/rust/validate-deployment.sh -5 -v"
