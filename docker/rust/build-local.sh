#!/bin/bash
# Build all NextGCore binaries in a single Docker container
# Then create lightweight runtime images

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Building NextGCore binaries in Docker ==="
echo "Project root: $PROJECT_ROOT"

# Build all binaries in a single container
docker build \
    -f "$SCRIPT_DIR/Dockerfile.builder" \
    -t nextgcore-builder:latest \
    "$PROJECT_ROOT"

# Create a temporary container to extract binaries
echo "=== Extracting binaries ==="
CONTAINER_ID=$(docker create nextgcore-builder:latest)
mkdir -p "$SCRIPT_DIR/binaries"

# Extract all NF binaries
for nf in amfd ausfd bsfd hssd mmed nrfd nssfd pcfd pcrfd scpd seppd sgwcd sgwud smfd udmd udrd upfd; do
    echo "Extracting nextgcore-$nf..."
    docker cp "$CONTAINER_ID:/app/target/release/nextgcore-$nf" "$SCRIPT_DIR/binaries/" 2>/dev/null || echo "  (not found, skipping)"
done

docker rm "$CONTAINER_ID"

echo "=== Building runtime images ==="
# Build runtime images for each NF
for nf in amfd ausfd bsfd nrfd nssfd pcfd smfd udmd udrd upfd; do
    if [ -f "$SCRIPT_DIR/binaries/nextgcore-$nf" ]; then
        echo "Building nextgcore-rust/$nf:latest..."
        docker build \
            -f "$SCRIPT_DIR/Dockerfile.runtime-local" \
            --build-arg NF_NAME="nextgcore-$nf" \
            -t "nextgcore-rust/${nf%d}:latest" \
            "$SCRIPT_DIR"
    fi
done

echo "=== Done ==="
docker images | grep nextgcore-rust
