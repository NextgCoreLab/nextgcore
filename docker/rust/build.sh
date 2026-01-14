#!/usr/bin/env bash
# NextGCore Rust Docker Build Script
# Builds Docker images for all network functions
#
# This script supports:
# - Individual Dockerfiles (default): Uses dedicated Dockerfile per NF
# - Template mode (-T): Uses Dockerfile.nf-template with build args
# - Semantic versioning with git-based auto-versioning
# - Multi-platform builds (amd64, arm64)
# - Parallel builds for faster execution
# - Build caching with BuildKit
# - Image tagging with multiple tags (version, latest, git sha)

set -e

# Enable BuildKit for better caching and parallel builds
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TAG="${TAG:-latest}"
REGISTRY="${REGISTRY:-}"
PUSH="${PUSH:-false}"
USE_TEMPLATE="${USE_TEMPLATE:-false}"
PARALLEL="${PARALLEL:-false}"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"
NO_CACHE="${NO_CACHE:-false}"
PLATFORMS="${PLATFORMS:-}"
BUILD_BASE="${BUILD_BASE:-false}"
DRY_RUN="${DRY_RUN:-false}"
VERBOSE="${VERBOSE:-false}"
AUTO_VERSION="${AUTO_VERSION:-false}"
EXTRA_TAGS=()
BUILD_ARGS=()

# Network function list - 5G Core
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
    "nextgcore-scpd"
    "nextgcore-seppd"
)

# Network function list - EPC (4G)
NFS_EPC=(
    "nextgcore-hssd"
    "nextgcore-pcrfd"
    "nextgcore-mmed"
    "nextgcore-sgwcd"
    "nextgcore-sgwud"
)

# All network functions
NFS=("${NFS_5GC[@]}" "${NFS_EPC[@]}")

# Build tracking (using simple arrays for portability)
FAILED_BUILDS=()
SUCCESSFUL_BUILDS=()
BUILD_TIMES_NFS=()
BUILD_TIMES_DURATIONS=()
START_TIME=$(date +%s)

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Get version from git
get_git_version() {
    local version=""
    
    # Try to get version from git tag
    if version=$(git describe --tags --exact-match 2>/dev/null); then
        echo "$version"
    elif version=$(git describe --tags 2>/dev/null); then
        echo "$version"
    else
        # Fallback to commit hash
        echo "dev-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    fi
}

# Get git commit SHA
get_git_sha() {
    git rev-parse --short HEAD 2>/dev/null || echo "unknown"
}

# Get git branch
get_git_branch() {
    git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown"
}

# Validate NF name
validate_nf_name() {
    local nf_name=$1
    for nf in "${NFS[@]}"; do
        if [ "$nf" = "$nf_name" ]; then
            return 0
        fi
    done
    return 1
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS] [NF_NAME...]

Build Docker images for NextGCore Rust network functions.

Options:
  -t, --tag TAG           Image tag (default: latest)
  -r, --registry REG      Registry prefix (e.g., ghcr.io/nextgcore)
  -p, --push              Push images after building
  -a, --all               Build all network functions
  -5, --5gc               Build only 5G Core NFs
  -4, --epc               Build only EPC (4G) NFs
  -T, --template          Use template Dockerfile instead of individual ones
  -P, --parallel          Build images in parallel
  -j, --jobs N            Number of parallel jobs (default: 4)
  --no-cache              Build without using cache
  --platforms PLATFORMS   Build for multiple platforms (e.g., linux/amd64,linux/arm64)
  --build-base            Build base image first
  --build-arg ARG=VALUE   Pass build argument to Docker
  --extra-tag TAG         Add additional tag to images (can be used multiple times)
  --auto-version          Auto-generate version from git tags/commits
  --dry-run               Show what would be built without building
  -v, --verbose           Enable verbose output
  -h, --help              Show this help message

Environment Variables:
  TAG                     Default image tag
  REGISTRY                Default registry prefix
  PUSH                    Set to 'true' to push by default
  PARALLEL_JOBS           Number of parallel build jobs
  DOCKER_BUILDKIT         Enable BuildKit (default: 1)

Examples:
  $0 -a                                    # Build all NFs
  $0 -5                                    # Build only 5G Core NFs
  $0 -4                                    # Build only EPC NFs
  $0 -T -a                                 # Build all using template Dockerfile
  $0 nextgcore-amfd nextgcore-smfd             # Build specific NFs
  $0 -t v1.0.0 -p -a                       # Build all, tag v1.0.0, and push
  $0 --auto-version -p -a                  # Auto-version from git and push
  $0 -P -j 8 -a                            # Parallel build with 8 jobs
  $0 --platforms linux/amd64,linux/arm64 -a  # Multi-platform build
  $0 -r ghcr.io/nextgcore --extra-tag latest -t v2.0.0 -a  # Multiple tags
  $0 --build-base -a                       # Build base image first, then all NFs

Network Functions:
  5G Core: ${NFS_5GC[*]}
  EPC:     ${NFS_EPC[*]}

EOF
}

# Build base image
build_base_image() {
    local base_tag="${REGISTRY:+$REGISTRY/}nextgcore-rust-base:${TAG}"
    
    log_info "Building base image: $base_tag"
    
    local build_cmd="docker build"
    build_cmd+=" -f $SCRIPT_DIR/Dockerfile.base"
    build_cmd+=" -t $base_tag"
    
    if [ "$NO_CACHE" = "true" ]; then
        build_cmd+=" --no-cache"
    fi
    
    # Add build args
    for arg in "${BUILD_ARGS[@]}"; do
        build_cmd+=" --build-arg $arg"
    done
    
    build_cmd+=" $PROJECT_ROOT"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY RUN] Would execute: $build_cmd"
        return 0
    fi
    
    log_verbose "Executing: $build_cmd"
    
    if eval "$build_cmd"; then
        log_success "Base image built: $base_tag"
        
        # Add extra tags
        for extra_tag in "${EXTRA_TAGS[@]}"; do
            local extra_image="${REGISTRY:+$REGISTRY/}nextgcore-rust-base:${extra_tag}"
            docker tag "$base_tag" "$extra_image"
            log_info "Tagged: $extra_image"
        done
        
        if [ "$PUSH" = "true" ]; then
            log_info "Pushing base image..."
            docker push "$base_tag"
            for extra_tag in "${EXTRA_TAGS[@]}"; do
                docker push "${REGISTRY:+$REGISTRY/}nextgcore-rust-base:${extra_tag}"
            done
        fi
        
        return 0
    else
        log_error "Failed to build base image"
        return 1
    fi
}

# Build single NF
build_nf() {
    local nf_name=$1
    local build_start=$(date +%s)
    local image_name="${REGISTRY:+$REGISTRY/}${nf_name}:${TAG}"
    local dockerfile
    local build_cmd
    
    log_info "Building: $image_name"
    
    # Determine Dockerfile to use
    if [ "$USE_TEMPLATE" = "true" ]; then
        dockerfile="$SCRIPT_DIR/Dockerfile.nf-template"
    else
        dockerfile="$SCRIPT_DIR/$nf_name/Dockerfile"
        if [ ! -f "$dockerfile" ]; then
            log_warn "Individual Dockerfile not found at $dockerfile, using template"
            dockerfile="$SCRIPT_DIR/Dockerfile.nf-template"
        fi
    fi
    
    # Build command construction
    if [ -n "$PLATFORMS" ]; then
        # Multi-platform build with buildx
        build_cmd="docker buildx build"
        build_cmd+=" --platform $PLATFORMS"
        if [ "$PUSH" = "true" ]; then
            build_cmd+=" --push"
        else
            build_cmd+=" --load"
        fi
    else
        build_cmd="docker build"
    fi
    
    build_cmd+=" -f $dockerfile"
    build_cmd+=" -t $image_name"
    
    # Add extra tags
    for extra_tag in "${EXTRA_TAGS[@]}"; do
        build_cmd+=" -t ${REGISTRY:+$REGISTRY/}${nf_name}:${extra_tag}"
    done
    
    # Add NF_NAME build arg for template
    if [ "$dockerfile" = "$SCRIPT_DIR/Dockerfile.nf-template" ]; then
        build_cmd+=" --build-arg NF_NAME=$nf_name"
    fi
    
    # Add custom build args
    for arg in "${BUILD_ARGS[@]}"; do
        build_cmd+=" --build-arg $arg"
    done
    
    if [ "$NO_CACHE" = "true" ]; then
        build_cmd+=" --no-cache"
    fi
    
    # Add labels
    build_cmd+=" --label org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    build_cmd+=" --label org.opencontainers.image.revision=$(get_git_sha)"
    build_cmd+=" --label org.opencontainers.image.version=$TAG"
    
    build_cmd+=" $PROJECT_ROOT"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_info "[DRY RUN] Would execute: $build_cmd"
        return 0
    fi
    
    log_verbose "Executing: $build_cmd"
    
    # Execute build
    if eval "$build_cmd"; then
        local build_end=$(date +%s)
        local build_duration=$((build_end - build_start))
        BUILD_TIMES_NFS+=("$nf_name")
        BUILD_TIMES_DURATIONS+=("$build_duration")
        SUCCESSFUL_BUILDS+=("$nf_name")
        
        log_success "Built $image_name in ${build_duration}s"
        
        # Push if requested (and not multi-platform, which pushes during build)
        if [ "$PUSH" = "true" ] && [ -z "$PLATFORMS" ]; then
            log_info "Pushing: $image_name"
            docker push "$image_name"
            for extra_tag in "${EXTRA_TAGS[@]}"; do
                docker push "${REGISTRY:+$REGISTRY/}${nf_name}:${extra_tag}"
            done
        fi
        
        return 0
    else
        FAILED_BUILDS+=("$nf_name")
        log_error "Failed to build $nf_name"
        return 1
    fi
}

# Parallel build function
build_parallel() {
    local nfs=("$@")
    local pids=()
    local running=0
    local idx=0
    local total=${#nfs[@]}
    
    log_info "Starting parallel build with $PARALLEL_JOBS jobs for $total images"
    
    # Create temp directory for build logs
    local log_dir=$(mktemp -d)
    
    while [ $idx -lt $total ] || [ $running -gt 0 ]; do
        # Start new jobs if we have capacity
        while [ $running -lt $PARALLEL_JOBS ] && [ $idx -lt $total ]; do
            local nf="${nfs[$idx]}"
            log_info "Starting build [$((idx+1))/$total]: $nf"
            
            # Run build in background
            (build_nf "$nf" > "$log_dir/$nf.log" 2>&1) &
            pids[$idx]=$!
            ((running++))
            ((idx++))
        done
        
        # Wait for any job to complete
        if [ $running -gt 0 ]; then
            for i in "${!pids[@]}"; do
                if [ -n "${pids[$i]}" ]; then
                    if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                        # Job completed
                        wait "${pids[$i]}" || true
                        local nf="${nfs[$i]}"
                        
                        # Show log output
                        if [ -f "$log_dir/$nf.log" ]; then
                            if [ "$VERBOSE" = "true" ]; then
                                cat "$log_dir/$nf.log"
                            fi
                        fi
                        
                        unset "pids[$i]"
                        ((running--))
                    fi
                fi
            done
            sleep 1
        fi
    done
    
    # Cleanup
    rm -rf "$log_dir"
}

# Helper function to get build duration for an NF
get_build_duration() {
    local nf_name=$1
    local i
    for i in "${!BUILD_TIMES_NFS[@]}"; do
        if [ "${BUILD_TIMES_NFS[$i]}" = "$nf_name" ]; then
            echo "${BUILD_TIMES_DURATIONS[$i]}"
            return
        fi
    done
    echo "?"
}

# Print build summary
print_summary() {
    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))
    
    echo ""
    echo "============================================"
    echo "Build Summary"
    echo "============================================"
    echo "Total time: ${total_duration}s"
    echo "Successful: ${#SUCCESSFUL_BUILDS[@]}"
    echo "Failed: ${#FAILED_BUILDS[@]}"
    echo ""
    
    if [ ${#SUCCESSFUL_BUILDS[@]} -gt 0 ]; then
        echo "Successful builds:"
        for nf in "${SUCCESSFUL_BUILDS[@]}"; do
            local duration=$(get_build_duration "$nf")
            echo "  ✓ $nf (${duration}s)"
        done
        echo ""
    fi
    
    if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
        echo "Failed builds:"
        for nf in "${FAILED_BUILDS[@]}"; do
            echo "  ✗ $nf"
        done
        echo ""
    fi
    
    echo "============================================"
}

# List available images
list_images() {
    echo "Available Network Functions:"
    echo ""
    echo "5G Core:"
    for nf in "${NFS_5GC[@]}"; do
        echo "  - $nf"
    done
    echo ""
    echo "EPC (4G):"
    for nf in "${NFS_EPC[@]}"; do
        echo "  - $nf"
    done
}

# Parse arguments
BUILD_LIST=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -r|--registry)
            REGISTRY="$2"
            shift 2
            ;;
        -p|--push)
            PUSH="true"
            shift
            ;;
        -a|--all)
            BUILD_LIST=("${NFS[@]}")
            shift
            ;;
        -5|--5gc)
            BUILD_LIST=("${NFS_5GC[@]}")
            shift
            ;;
        -4|--epc)
            BUILD_LIST=("${NFS_EPC[@]}")
            shift
            ;;
        -T|--template)
            USE_TEMPLATE="true"
            shift
            ;;
        -P|--parallel)
            PARALLEL="true"
            shift
            ;;
        -j|--jobs)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE="true"
            shift
            ;;
        --platforms)
            PLATFORMS="$2"
            shift 2
            ;;
        --build-base)
            BUILD_BASE="true"
            shift
            ;;
        --build-arg)
            BUILD_ARGS+=("$2")
            shift 2
            ;;
        --extra-tag)
            EXTRA_TAGS+=("$2")
            shift 2
            ;;
        --auto-version)
            AUTO_VERSION="true"
            shift
            ;;
        --dry-run)
            DRY_RUN="true"
            shift
            ;;
        -v|--verbose)
            VERBOSE="true"
            shift
            ;;
        --list)
            list_images
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            if validate_nf_name "$1"; then
                BUILD_LIST+=("$1")
            else
                log_error "Unknown network function: $1"
                echo "Use --list to see available network functions"
                exit 1
            fi
            shift
            ;;
    esac
done

# Auto-version from git
if [ "$AUTO_VERSION" = "true" ]; then
    TAG=$(get_git_version)
    log_info "Auto-detected version: $TAG"
    
    # Add git SHA as extra tag
    EXTRA_TAGS+=("sha-$(get_git_sha)")
fi

# Validate build list
if [ ${#BUILD_LIST[@]} -eq 0 ]; then
    log_error "No network functions specified."
    echo "Use -a to build all, -5 for 5G Core, -4 for EPC, or specify NF names."
    echo "Use --list to see available network functions."
    usage
    exit 1
fi

# Check for multi-platform build requirements
if [ -n "$PLATFORMS" ]; then
    if ! docker buildx version &>/dev/null; then
        log_error "Docker buildx is required for multi-platform builds"
        log_info "Install with: docker buildx install"
        exit 1
    fi
    
    # Create/use buildx builder
    if ! docker buildx inspect nextgcore-builder &>/dev/null; then
        log_info "Creating buildx builder: nextgcore-builder"
        docker buildx create --name nextgcore-builder --use
    else
        docker buildx use nextgcore-builder
    fi
fi

# Print build configuration
echo "============================================"
echo "NextGCore Rust Docker Build"
echo "============================================"
echo "Version:      $TAG"
echo "Registry:     ${REGISTRY:-<local>}"
echo "Push:         $PUSH"
echo "Template:     $USE_TEMPLATE"
echo "Parallel:     $PARALLEL (jobs: $PARALLEL_JOBS)"
echo "No Cache:     $NO_CACHE"
echo "Platforms:    ${PLATFORMS:-<native>}"
echo "Build Base:   $BUILD_BASE"
echo "Dry Run:      $DRY_RUN"
echo "Git SHA:      $(get_git_sha)"
echo "Git Branch:   $(get_git_branch)"
echo "Extra Tags:   ${EXTRA_TAGS[*]:-<none>}"
echo "Build Args:   ${BUILD_ARGS[*]:-<none>}"
echo "Building:     ${BUILD_LIST[*]}"
echo "============================================"
echo ""

# Build base image if requested
if [ "$BUILD_BASE" = "true" ]; then
    if ! build_base_image; then
        log_error "Base image build failed, aborting"
        exit 1
    fi
    echo ""
fi

# Build NFs
if [ "$PARALLEL" = "true" ]; then
    build_parallel "${BUILD_LIST[@]}"
else
    for nf in "${BUILD_LIST[@]}"; do
        build_nf "$nf" || true
    done
fi

# Print summary
print_summary

# Exit with error if any builds failed
if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
    exit 1
fi

log_success "All builds completed successfully!"
