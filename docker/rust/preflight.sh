#!/bin/bash
# NextGCore Docker build/E2E disk preflight (Wave-6 H10, hazard #269 mitigation)
#
# WHY: on 2026-06-12 a full Docker rebuild (~20GB needed) ran under disk
# pressure and Docker Desktop wiped its ENTIRE image store mid-build. This
# script refuses to let a build start without headroom, and trims the BuildKit
# cache so it cannot grow unbounded between runs.
#
# What it does, in order:
#   1. Verifies the Docker daemon is reachable.
#   2. `docker builder prune --force --keep-storage=<keep>` (default 20GB):
#      trims build cache ABOVE the threshold but keeps recent layers so
#      iteration stays fast (an unconditional full prune would force cold
#      rebuilds).
#   3. Prints `docker system df` (post-prune usage snapshot for the log).
#   4. Checks free disk on the HOST filesystem that holds the Docker data
#      (macOS: ~/Library/Containers/com.docker.docker; Linux: /var/lib/docker;
#      falls back to this script's filesystem).
#   5. Checks free disk INSIDE the Docker VM: a throwaway container's `/`
#      overlay reflects the VM data volume. On macOS the host df alone is NOT
#      sufficient — the Docker.raw VM disk is sparse and grows into host free
#      space, and the VM can be full while the host looks fine (and vice
#      versa). Best effort: skipped with a warning if the probe image cannot
#      run (the host check still gates).
#   6. Exits 2 if any free-space reading is below the minimum (default 25GB).
#
# APFS GOTCHA (macOS): `df` may show almost no free space although most of it
# is reclaimable — APFS local snapshots (Time Machine) pin deleted data. If
# this preflight refuses on a mac that "should" have space:
#   tmutil listlocalsnapshots /        # see the snapshots
#   tmutil deletelocalsnapshots <date> # or just free space and re-run
# Conversely df can OVER-report usable space while Docker.raw is near its
# configured cap — that is what the in-VM check (step 5) catches.
#
# Usage:
#   ./preflight.sh [--min-free-gb N] [--keep-storage SIZE] [--no-prune]
#
# Environment overrides:
#   NEXTG_MIN_FREE_GB           minimum free GB required (default 25)
#   NEXTG_BUILDER_KEEP_STORAGE  builder cache to keep (default 20GB)
#   NEXTG_PREFLIGHT_PROBE_IMAGE image for the in-VM df probe (default alpine:3)
#
# Exit codes:
#   0 - enough disk everywhere, safe to build
#   2 - refused: low disk or Docker unavailable (do NOT start a build)

set -euo pipefail

MIN_FREE_GB="${NEXTG_MIN_FREE_GB:-25}"
KEEP_STORAGE="${NEXTG_BUILDER_KEEP_STORAGE:-20GB}"
PROBE_IMAGE="${NEXTG_PREFLIGHT_PROBE_IMAGE:-alpine:3}"
DO_PRUNE=true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log_info()  { echo -e "${GREEN}[PREFLIGHT]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[PREFLIGHT]${NC} $*"; }
log_error() { echo -e "${RED}[PREFLIGHT]${NC} $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --min-free-gb)  MIN_FREE_GB="$2"; shift 2 ;;
        --keep-storage) KEEP_STORAGE="$2"; shift 2 ;;
        --no-prune)     DO_PRUNE=false; shift ;;
        -h|--help)      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)              log_error "Unknown option: $1"; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# 1. Docker daemon reachable?
# ---------------------------------------------------------------------------
if ! docker info >/dev/null 2>&1; then
    log_error "Docker daemon is not reachable. Start Docker (Desktop) and re-run."
    exit 2
fi

# ---------------------------------------------------------------------------
# 2. Trim the BuildKit cache (keep recent layers), 3. usage snapshot
# ---------------------------------------------------------------------------
if [ "$DO_PRUNE" = true ]; then
    log_info "docker builder prune --force --keep-storage=${KEEP_STORAGE}"
    if ! docker builder prune --force --keep-storage="$KEEP_STORAGE"; then
        # Older/newer CLIs may rename the flag; a failed prune must not block
        # the build by itself — the disk checks below still gate.
        log_warn "builder prune failed (flag drift?); continuing with disk checks"
    fi
else
    log_warn "builder prune skipped (--no-prune)"
fi

log_info "docker system df (post-prune):"
docker system df || log_warn "docker system df failed (non-fatal)"

# ---------------------------------------------------------------------------
# 4. Host free-disk check (filesystem holding the Docker data)
# ---------------------------------------------------------------------------
free_kb_of() {
    # POSIX df: available KiB of the filesystem containing $1
    df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'
}

HOST_PATH=""
for candidate in \
    "$HOME/Library/Containers/com.docker.docker" \
    /var/lib/docker \
    "$(cd "$(dirname "$0")" && pwd)"; do
    if [ -e "$candidate" ]; then HOST_PATH="$candidate"; break; fi
done

MIN_FREE_KB=$((MIN_FREE_GB * 1024 * 1024))
FAILED=false

HOST_FREE_KB="$(free_kb_of "$HOST_PATH")"
if [ -z "$HOST_FREE_KB" ]; then
    log_warn "could not read host df for $HOST_PATH; skipping host check"
else
    HOST_FREE_GB=$((HOST_FREE_KB / 1024 / 1024))
    if [ "$HOST_FREE_KB" -lt "$MIN_FREE_KB" ]; then
        log_error "HOST disk too low: ${HOST_FREE_GB}GB free at $HOST_PATH (need >= ${MIN_FREE_GB}GB)."
        log_error "A full rebuild needs ~20GB; building under disk pressure risks a"
        log_error "Docker Desktop image-store WIPE (hazard #269, seen 2026-06-12)."
        log_error "NOTE (macOS/APFS): df may under-report reclaimable space pinned by"
        log_error "APFS local snapshots — 'tmutil listlocalsnapshots /' and delete them,"
        log_error "or free space, then re-run."
        FAILED=true
    else
        log_info "host disk OK: ${HOST_FREE_GB}GB free at $HOST_PATH (need >= ${MIN_FREE_GB}GB)"
    fi
fi

# ---------------------------------------------------------------------------
# 5. In-VM free-disk check (Docker Desktop VM data volume), best effort
# ---------------------------------------------------------------------------
VM_FREE_KB="$(docker run --rm "$PROBE_IMAGE" df -Pk / 2>/dev/null | awk '$6=="/" {print $4; exit}')" || VM_FREE_KB=""
if [ -z "$VM_FREE_KB" ]; then
    log_warn "in-VM df probe unavailable ($PROBE_IMAGE could not run); relying on the host check only"
else
    VM_FREE_GB=$((VM_FREE_KB / 1024 / 1024))
    if [ "$VM_FREE_KB" -lt "$MIN_FREE_KB" ]; then
        log_error "Docker VM disk too low: ${VM_FREE_GB}GB free inside the VM (need >= ${MIN_FREE_GB}GB)."
        log_error "The VM data volume (Docker.raw) is near its cap even though the host"
        log_error "may look fine. Prune images/volumes ('docker system prune', review"
        log_error "'docker system df' above) or raise the Docker Desktop disk limit, then re-run."
        FAILED=true
    else
        log_info "Docker VM disk OK: ${VM_FREE_GB}GB free inside the VM (need >= ${MIN_FREE_GB}GB)"
    fi
fi

# ---------------------------------------------------------------------------
# 6. Verdict
# ---------------------------------------------------------------------------
if [ "$FAILED" = true ]; then
    log_error "preflight REFUSED: fix disk space before building (exit 2)"
    exit 2
fi
log_info "preflight OK"
exit 0
