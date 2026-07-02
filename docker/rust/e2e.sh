#!/bin/bash
# NextGCore one-command Docker E2E entrypoint (Wave-6 H10)
#
# Composes: disk preflight (preflight.sh, hazard #269) -> image build
# (build.sh) -> matched-sim E2E run (e2e-test.sh, our gNB/UE vs our 5GC,
# NO Open5GS) -> optional overlay selection -> artifact capture on failure.
# Propagates a clean exit code so CI can consume it.
#
# Usage:
#   ./e2e.sh                         # preflight + full build + baseline E2E
#   ./e2e.sh --quick                 # reuse existing binaries (build.sh --skip-rust)
#   ./e2e.sh --overlay oauth2        # baseline suite with OAuth2 enforcement overlay
#   ./e2e.sh --overlay kernel-sctp   # baseline suite over native kernel SCTP N2
#   ./e2e.sh --overlay features      # baseline E2E, then the Rel-17/18 feature
#                                    # harness (feature-e2e-test.sh, all scenarios)
#   ./e2e.sh --keep                  # leave the stack running afterwards
#   ./e2e.sh --no-build              # stack images already built
#   ./e2e.sh --no-preflight          # skip the disk preflight (not recommended)
#   ./e2e.sh --artifacts DIR         # where to write failure artifacts
#                                    # (default: <script-dir>/artifacts)
#
# Overlay names map to docker-compose.<name>.yml ("w6" is accepted as an alias
# for "features" — the harness was renamed from w6-feature-test.sh).
#
# On any failure the logs of every nextgcore-*/nextgsim-* container are saved
# under the artifacts directory (captured BEFORE teardown).
#
# Exit codes:
#   0 - everything passed
#   1 - one or more test assertions failed
#   2 - infrastructure failure (preflight refusal, build, startup)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
BINARIES_DIR="$SCRIPT_DIR/binaries"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_info()  { echo -e "${GREEN}[E2E]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[E2E]${NC}  $*"; }
log_error() { echo -e "${RED}[E2E]${NC}  $*" >&2; }

OVERLAY=""
QUICK=false
KEEP=false
NO_BUILD=false
NO_PREFLIGHT=false
ARTIFACT_DIR="$SCRIPT_DIR/artifacts"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --overlay)      OVERLAY="$2"; shift 2 ;;
        --quick)        QUICK=true; shift ;;
        --keep)         KEEP=true; shift ;;
        --no-build)     NO_BUILD=true; shift ;;
        --no-preflight) NO_PREFLIGHT=true; shift ;;
        --artifacts)    ARTIFACT_DIR="$2"; shift 2 ;;
        -h|--help)      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)              log_error "Unknown option: $1"; exit 2 ;;
    esac
done

# "w6" was the harness's original name; the files are now feature-*/features.
[ "$OVERLAY" = "w6" ] && OVERLAY="features"

case "$OVERLAY" in
    ""|features) COMPOSE_ARGS=(-f "$COMPOSE_FILE") ;;
    *)
        OVERLAY_FILE="$SCRIPT_DIR/docker-compose.$OVERLAY.yml"
        if [ ! -f "$OVERLAY_FILE" ]; then
            log_error "Unknown overlay '$OVERLAY' (no $OVERLAY_FILE)"
            exit 2
        fi
        COMPOSE_ARGS=(-f "$COMPOSE_FILE" -f "$OVERLAY_FILE")
        ;;
esac

# ---------------------------------------------------------------------------
# Failure artifact capture (docker logs per NF; must run BEFORE teardown)
# ---------------------------------------------------------------------------
capture_artifacts() {
    local dest
    dest="$ARTIFACT_DIR/e2e-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dest"
    local containers
    containers=$(docker ps -a --format '{{.Names}}' | grep -E '^(nextgcore-|nextgsim-)' || true)
    for c in $containers; do
        docker logs "$c" >"$dest/$c.log" 2>&1 || true
    done
    docker ps -a >"$dest/docker-ps.txt" 2>&1 || true
    docker system df >"$dest/docker-system-df.txt" 2>&1 || true
    log_warn "failure artifacts saved to: $dest"
}

teardown() {
    if [ "$KEEP" = true ]; then
        log_warn "keeping the stack running (--keep)"
        return 0
    fi
    log_info "tearing down..."
    docker compose "${COMPOSE_ARGS[@]}" down -v --remove-orphans 2>/dev/null || true
}

fail() {
    # $1 = exit code, $2 = message
    log_error "$2"
    capture_artifacts
    teardown
    exit "$1"
}

# ---------------------------------------------------------------------------
# Step 1: preflight (disk headroom + builder-cache trim, hazard #269)
# ---------------------------------------------------------------------------
if [ "$NO_PREFLIGHT" = false ]; then
    "$SCRIPT_DIR/preflight.sh" || {
        log_error "preflight refused - not building (use --no-preflight to override)"
        exit 2
    }
fi

# ---------------------------------------------------------------------------
# Step 2: build images (preflight already done above)
# ---------------------------------------------------------------------------
if [ "$NO_BUILD" = false ]; then
    if [ "$QUICK" = true ]; then
        if [ ! -f "$BINARIES_DIR/nextgcore-amfd" ] || [ ! -f "$BINARIES_DIR/nr-gnb" ]; then
            log_error "--quick requested but no prebuilt binaries in $BINARIES_DIR (run a full build first)"
            exit 2
        fi
        log_info "quick build: reusing existing binaries (build.sh --skip-rust)"
        "$SCRIPT_DIR/build.sh" --skip-rust --no-preflight || exit 2
    else
        log_info "full build (compile + images)"
        "$SCRIPT_DIR/build.sh" --no-preflight || exit 2
    fi
fi

# ---------------------------------------------------------------------------
# Step 3: baseline (or overlaid) E2E suite
# e2e-test.sh always gets --keep: e2e.sh owns teardown so that failure
# artifacts can be captured before the containers disappear.
# ---------------------------------------------------------------------------
E2E_ARGS=(--no-build --no-preflight --keep)
if [ -n "$OVERLAY" ] && [ "$OVERLAY" != "features" ]; then
    E2E_ARGS+=(--overlay "$OVERLAY")
fi

log_info "running E2E suite${OVERLAY:+ (overlay: $OVERLAY)}..."
"$SCRIPT_DIR/e2e-test.sh" "${E2E_ARGS[@]}"
rc=$?
if [ $rc -ne 0 ]; then
    fail $rc "E2E suite failed (exit $rc)"
fi

# ---------------------------------------------------------------------------
# Step 4: feature harness (only for --overlay features)
# ---------------------------------------------------------------------------
if [ "$OVERLAY" = "features" ]; then
    log_info "running Rel-17/18 feature harness (feature-e2e-test.sh)..."
    "$SCRIPT_DIR/feature-e2e-test.sh"
    rc=$?
    if [ $rc -ne 0 ]; then
        # The feature harness layers docker-compose.features.yml itself;
        # include it in our teardown set so down removes everything.
        COMPOSE_ARGS+=(-f "$SCRIPT_DIR/docker-compose.features.yml")
        fail $rc "feature harness failed (exit $rc)"
    fi
    COMPOSE_ARGS+=(-f "$SCRIPT_DIR/docker-compose.features.yml")
fi

teardown
log_info "E2E green${OVERLAY:+ (overlay: $OVERLAY)}"
exit 0
