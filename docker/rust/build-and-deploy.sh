#!/bin/bash
# Build all binaries once and deploy 5GC containers
#
# Usage: ./build-and-deploy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Step 1: Building all binaries in Docker ==="
docker build -f Dockerfile.all-in-one -t nextgcore-builder:latest ../../..

echo "=== Step 2: Extracting binaries from builder ==="
mkdir -p binaries

# Create a temporary container and extract binaries
CONTAINER_ID=$(docker create nextgcore-builder:latest)
docker cp "$CONTAINER_ID:/nextgcore-amfd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-ausfd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-bsfd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-nrfd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-nssfd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-pcfd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-smfd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-udmd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-udrd" binaries/
docker cp "$CONTAINER_ID:/nextgcore-upfd" binaries/
docker rm "$CONTAINER_ID"

echo "=== Step 3: Deploying 5GC containers ==="
docker compose -f docker-compose-5gc-optimized.yml up -d --build

echo "=== Done! ==="
echo "Check containers: docker compose -f docker-compose-5gc-optimized.yml ps"
