#!/bin/bash
# NextGCore + NextGSim Docker Build
#
# Builds Rust binaries inside Docker, then creates lightweight runtime images.
#
# Architecture:
#   1. Dockerfile.builder → Builds all binaries inside Docker
#   2. Dockerfile.core    → Shared runtime base (Debian slim + libs)
#   3. Dockerfile.nf      → Per-NF image (FROM core + binary)
#
# Usage:
#   ./build.sh                # Full build (compile + images)
#   ./build.sh --skip-rust    # Only rebuild Docker images (use existing binaries)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NEXTGSIM_DIR="$PROJECT_ROOT/nextgsim"
BINARIES_DIR="$SCRIPT_DIR/binaries"

SKIP_RUST=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-rust) SKIP_RUST=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "=== NextGCore Docker Build ==="
echo "Project root: $PROJECT_ROOT"
echo ""

# ============================================================================
# Step 1: Build Rust binaries inside Docker
# ============================================================================
if [ "$SKIP_RUST" = false ]; then
    mkdir -p "$BINARIES_DIR"

    echo "=== Building all Rust binaries in Docker ==="
    echo "(This builds both nextgcore and nextgsim inside a Rust container)"
    echo ""

    # Build using Docker builder
    docker build \
        -f "$SCRIPT_DIR/Dockerfile.builder" \
        -t nextg-builder:latest \
        "$PROJECT_ROOT" \
        2>&1

    # Extract binaries from builder image
    echo ""
    echo "=== Extracting binaries ==="
    docker rm -f nextg-builder-extract 2>/dev/null || true
    docker create --name nextg-builder-extract nextg-builder:latest /bin/true
    docker cp nextg-builder-extract:/out/. "$BINARIES_DIR/"
    docker rm -f nextg-builder-extract >/dev/null

    echo "=== Built binaries ==="
    ls -lh "$BINARIES_DIR/" | grep -v "^total" | grep -v "\.d$"
fi

# ============================================================================
# Step 2: Build Docker images
# ============================================================================
echo ""
echo "=== Building core runtime image ==="
docker build -f "$SCRIPT_DIR/Dockerfile.core" -t nextgcore-core:latest "$SCRIPT_DIR"

echo ""
echo "=== Building NF images (from core) ==="
for nf in amfd ausfd bsfd nrfd nssfd pcfd smfd udmd udrd upfd; do
    if [ -f "$BINARIES_DIR/nextgcore-$nf" ]; then
        tag="${nf%d}"
        echo "  nextgcore-rust/$tag"
        docker build -q \
            -f "$SCRIPT_DIR/Dockerfile.nf" \
            --build-arg NF_NAME="nextgcore-$nf" \
            -t "nextgcore-rust/$tag:latest" \
            "$SCRIPT_DIR" >/dev/null
    fi
done

# Build gNB/UE images
if [ -f "$BINARIES_DIR/nr-gnb" ]; then
    echo "  nextgsim-gnb"
    mkdir -p "$NEXTGSIM_DIR/binaries"
    cp "$BINARIES_DIR/nr-gnb" "$NEXTGSIM_DIR/binaries/"
    docker build -q -f "$NEXTGSIM_DIR/Dockerfile.gnb-local" -t nextgsim-gnb:latest "$NEXTGSIM_DIR" >/dev/null
fi
if [ -f "$BINARIES_DIR/nr-ue" ]; then
    echo "  nextgsim-ue"
    mkdir -p "$NEXTGSIM_DIR/binaries"
    cp "$BINARIES_DIR/nr-ue" "$NEXTGSIM_DIR/binaries/"
    docker build -q -f "$NEXTGSIM_DIR/Dockerfile.ue-local" -t nextgsim-ue:latest "$NEXTGSIM_DIR" >/dev/null
fi

echo ""
echo "=== Done ==="
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep -E "nextgcore|nextgsim"
