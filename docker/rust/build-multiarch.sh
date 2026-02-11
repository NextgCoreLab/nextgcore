#!/bin/bash
# NextGCore + NextGSim Multi-Architecture Docker Build (Item #204)
#
# Builds images for linux/amd64 and linux/arm64 using Docker Buildx.
# Supports both local build and registry push.
#
# Prerequisites:
#   docker buildx create --name nextg-builder --use (first time only)
#
# Usage:
#   ./build-multiarch.sh                    # Build for local platform only
#   ./build-multiarch.sh --push REGISTRY    # Build + push multi-arch to registry
#   ./build-multiarch.sh --platform linux/amd64,linux/arm64
#   ./build-multiarch.sh --push ghcr.io/nextg --platform linux/amd64,linux/arm64

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NEXTGSIM_DIR="$PROJECT_ROOT/nextgsim"
BINARIES_DIR="$SCRIPT_DIR/binaries"

PLATFORMS="linux/amd64,linux/arm64"
REGISTRY=""
PUSH=false
TAG="latest"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --push)
            PUSH=true
            REGISTRY="$2"
            shift 2
            ;;
        --platform)
            PLATFORMS="$2"
            shift 2
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--push REGISTRY] [--platform PLATFORMS] [--tag TAG]"
            exit 1
            ;;
    esac
done

echo "=== NextGCore Multi-Architecture Docker Build ==="
echo "Platforms: $PLATFORMS"
echo "Tag: $TAG"
if [ "$PUSH" = true ]; then
    echo "Registry: $REGISTRY"
fi
echo ""

# ============================================================================
# Ensure buildx builder exists
# ============================================================================
if ! docker buildx inspect nextg-multiarch >/dev/null 2>&1; then
    echo "Creating buildx builder 'nextg-multiarch'..."
    docker buildx create --name nextg-multiarch \
        --driver docker-container \
        --platform "$PLATFORMS" \
        --use
    docker buildx inspect --bootstrap
fi

docker buildx use nextg-multiarch

# ============================================================================
# Build multi-arch builder image (compiles all binaries)
# ============================================================================
echo "=== Building multi-arch builder image ==="
echo "(This cross-compiles Rust binaries for all target platforms)"

BUILD_ARGS="--platform $PLATFORMS -f $SCRIPT_DIR/Dockerfile.builder"

if [ "$PUSH" = true ]; then
    # Build and push builder
    docker buildx build $BUILD_ARGS \
        -t "${REGISTRY}/nextg-builder:${TAG}" \
        --push \
        "$PROJECT_ROOT"
else
    # Build for local platform only (--load requires single platform)
    LOCAL_PLATFORM="linux/$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')"
    docker buildx build --platform "$LOCAL_PLATFORM" \
        -f "$SCRIPT_DIR/Dockerfile.builder" \
        -t nextg-builder:${TAG} \
        --load \
        "$PROJECT_ROOT"
fi

# ============================================================================
# Build multi-arch runtime images
# ============================================================================
if [ "$PUSH" = false ]; then
    # Local build: extract binaries and build normally (single platform)
    echo ""
    echo "=== Local build: extracting binaries ==="
    mkdir -p "$BINARIES_DIR"
    docker rm -f nextg-builder-extract 2>/dev/null || true
    docker create --name nextg-builder-extract nextg-builder:${TAG} /bin/true
    docker cp nextg-builder-extract:/out/. "$BINARIES_DIR/"
    docker rm -f nextg-builder-extract >/dev/null

    echo "=== Building core runtime image ==="
    docker build -f "$SCRIPT_DIR/Dockerfile.core" -t nextgcore-core:${TAG} "$SCRIPT_DIR"

    echo ""
    echo "=== Building NF images ==="
    for nf in amfd ausfd bsfd nrfd nssfd pcfd smfd udmd udrd upfd; do
        if [ -f "$BINARIES_DIR/nextgcore-$nf" ]; then
            tag_name="${nf%d}"
            echo "  nextgcore-rust/$tag_name"
            docker build -q \
                -f "$SCRIPT_DIR/Dockerfile.nf" \
                --build-arg NF_NAME="nextgcore-$nf" \
                -t "nextgcore-rust/$tag_name:${TAG}" \
                "$SCRIPT_DIR" >/dev/null
        fi
    done
else
    # Multi-arch push: build and push core + per-NF images
    echo ""
    echo "=== Building and pushing multi-arch core image ==="
    docker buildx build --platform "$PLATFORMS" \
        -f "$SCRIPT_DIR/Dockerfile.core" \
        -t "${REGISTRY}/nextgcore-core:${TAG}" \
        --push \
        "$SCRIPT_DIR"

    echo ""
    echo "=== Building and pushing multi-arch NF images ==="
    for nf in amfd ausfd bsfd nrfd nssfd pcfd smfd udmd udrd upfd; do
        tag_name="${nf%d}"
        echo "  ${REGISTRY}/nextgcore-rust/$tag_name:${TAG}"
        docker buildx build --platform "$PLATFORMS" \
            -f "$SCRIPT_DIR/Dockerfile.nf" \
            --build-arg CORE_IMAGE="${REGISTRY}/nextgcore-core:${TAG}" \
            --build-arg NF_NAME="nextgcore-$nf" \
            -t "${REGISTRY}/nextgcore-rust/$tag_name:${TAG}" \
            --push \
            "$SCRIPT_DIR"
    done

    # Build gNB/UE images
    echo ""
    echo "=== Building and pushing multi-arch RAN images ==="
    for sim in gnb ue; do
        dockerfile="$NEXTGSIM_DIR/Dockerfile.${sim}-local"
        if [ -f "$dockerfile" ]; then
            echo "  ${REGISTRY}/nextgsim-${sim}:${TAG}"
            docker buildx build --platform "$PLATFORMS" \
                -f "$dockerfile" \
                -t "${REGISTRY}/nextgsim-${sim}:${TAG}" \
                --push \
                "$NEXTGSIM_DIR"
        fi
    done
fi

echo ""
echo "=== Multi-arch build complete ==="
echo "Platforms: $PLATFORMS"
if [ "$PUSH" = true ]; then
    echo "Images pushed to: $REGISTRY"
fi
