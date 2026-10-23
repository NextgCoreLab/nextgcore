#!/usr/bin/env bash
# Build the NextG workload images (12 for PROFILE=5g, 9 for epc) and push them to ECR.
#
# Replaces the `kind load docker-image` step in nextgcore/k8s/deploy.sh, which
# has no equivalent on EKS - without a registry every pod lands in
# ErrImagePull.
#
# Packages prebuilt binaries. They are NOT committed (both binaries/ dirs are
# gitignored); build them first (README "Prerequisites"):
#   nextgcore/binaries/nextgcore-*         (the workspace builds 28 NF daemons
#                                          plus webui; 5g packages 10, epc 7)
#   nextgsim/docker/binaries/nr-gnb,nr-ue  (5g)
#   nextgsim/binaries/lte-enb,lte-ue       (epc)
#
# Images are tagged by the git SHA of the repository they are built from, not
# :latest. See lib/image-tag.sh for why a mutable tag makes the deploy a silent
# no-op. IMAGE_TAG still overrides, for a release tag or to reproduce an old
# deploy.
#
# Usage:
#   ./build-and-push.sh                        # infer registry from STS
#   REGISTRY=<acct>.dkr.ecr.<region>.amazonaws.com ./build-and-push.sh
#   REPO_PREFIX=nextg IMAGE_TAG=v1 ./build-and-push.sh
#   FORCE_PUSH=true ./build-and-push.sh        # re-push tags already in ECR
#   PROFILE=epc ./build-and-push.sh            # another profile's images (default 5g)
#   CORE_BIN_DIR=/path/to/bins ./build-and-push.sh  # core binaries from elsewhere
#
# The image lists, tag suffix and cargo features come from
# profiles/$PROFILE/profile.env (see lib/profile.sh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"

# shellcheck source=lib/image-tag.sh
source "${SCRIPT_DIR}/lib/image-tag.sh"
# shellcheck source=lib/profile.sh
source "${SCRIPT_DIR}/lib/profile.sh"
nextg_load_profile "${PROFILE:-5g}" || exit 1

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"

# NF -> binary name. The image name is the short NF name; the binary is the
# daemon name. Dockerfile.nf symlinks it to /usr/local/bin/nf-binary.
CORE_NFS=("${PROFILE_CORE_NFS[@]}")
# Where the core binaries are read from. The default is the repo's binaries/;
# a feature build (6G) points this at its own output dir instead of
# overwriting the shared one.
DEFAULT_CORE_BIN_DIR="${CORE_DIR}/binaries"
CORE_BIN_DIR="${CORE_BIN_DIR:-${DEFAULT_CORE_BIN_DIR}}"
NUM_IMAGES=$(( ${#CORE_NFS[@]} + ${#PROFILE_SIM_IMAGES[@]} ))

log()  { printf '\033[0;32m[build]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[fail ]\033[0m %s\n' "$*" >&2; exit 1; }

# --- image tags ------------------------------------------------------------

# Two repositories, two tags: the core NFs are built from nextgcore and the
# gnb/ue from the sibling nextgsim, which sits at its own commit. Tagging both
# groups with one SHA would label an image with a commit that does not describe
# it. An explicit IMAGE_TAG overrides both.
if [[ -n "${IMAGE_TAG:-}" ]]; then
  CORE_TAG="${IMAGE_TAG}"
  SIM_TAG="${IMAGE_TAG}"
  if [[ "${IMAGE_TAG}" == "latest" ]]; then
    warn "IMAGE_TAG=latest is MUTABLE: deploy-eks.sh's kubectl apply becomes a"
    warn "no-op because the Deployment spec text never changes, so pods keep"
    warn "running the old image while the deploy reports success."
  fi
else
  CORE_TAG="$(nextg_image_tag "${CORE_DIR}")" || die "cannot derive nextgcore image tag"
  SIM_TAG="$(nextg_image_tag "${SIM_DIR}")"   || die "cannot derive nextgsim image tag"
  CORE_TAG="${CORE_TAG}${PROFILE_TAG_SUFFIX}"
  SIM_TAG="${SIM_TAG}${PROFILE_TAG_SUFFIX}"
fi

for repo_tag in "nextgcore:${CORE_TAG}" "nextgsim:${SIM_TAG}"; do
  if [[ "${repo_tag#*:}" == *-dirty ]]; then
    warn "${repo_tag%%:*} tree is dirty; tagging ${repo_tag#*:} (not reproducible from the SHA)"
  fi
done

# --- binaries --------------------------------------------------------------

# Fail early and loudly if the binaries are missing, rather than producing
# images that crash on start. This runs before any AWS call (#716): with
# expired credentials the STS check below would otherwise fail first and hide
# which binaries are missing. They are build artifacts and no longer tracked in
# git, so a fresh clone has none until you build.
MISSING=()
# Bare binary names, for profile_build_hint (it prints only their steps).
MISSING_CORE_BINS=()
MISSING_SIM_BINS=()
for entry in "${CORE_NFS[@]}"; do
  bin="${entry#*:}"
  [[ -f "${CORE_BIN_DIR}/${bin}" ]] && continue
  MISSING_CORE_BINS+=("${bin}")
  if [[ "${CORE_BIN_DIR}" == "${DEFAULT_CORE_BIN_DIR}" ]]; then
    MISSING+=("nextgcore/binaries/${bin}")
  else
    MISSING+=("${CORE_BIN_DIR}/${bin}")
  fi
done
for entry in "${PROFILE_SIM_IMAGES[@]}"; do
  IFS=: read -r _node _dockerfile ctx bins <<<"${entry}"
  IFS=, read -r -a _bins <<<"${bins}"
  for bin in "${_bins[@]}"; do
    if [[ "${ctx}" == . ]]; then
      [[ -f "${SIM_DIR}/binaries/${bin}" ]] && continue
      MISSING+=("nextgsim/binaries/${bin}")
    else
      [[ -f "${SIM_DIR}/${ctx}/binaries/${bin}" ]] && continue
      MISSING+=("nextgsim/${ctx}/binaries/${bin}")
    fi
    MISSING_SIM_BINS+=("${bin}")
  done
done
if (( ${#MISSING[@]} )); then
  printf 'missing prebuilt binaries:\n'; printf '  %s\n' "${MISSING[@]}"
  printf 'build them with (PROFILE=%s):\n' "${PROFILE_NAME}"
  profile_build_hint
  die "no binaries to package"
fi

# --- preflight -------------------------------------------------------------

for c in aws docker; do
  command -v "$c" >/dev/null || die "$c not found"
done

log "verifying AWS credentials..."
if ! ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"; then
  die "AWS credentials invalid or expired. Refresh them and retry."
fi

REGISTRY="${REGISTRY:-${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com}"
[[ "${PROFILE_NAME}" == 5g ]] || log "profile:  ${PROFILE_NAME} (cargo features: ${PROFILE_CARGO_FEATURES:-none})"
log "registry: ${REGISTRY}"
log "prefix:   ${REPO_PREFIX}    core tag: ${CORE_TAG}    gnb/ue tag: ${SIM_TAG}"

# --- ECR login + repos -----------------------------------------------------

log "authenticating docker to ECR..."
aws ecr get-login-password --region "${REGION}" \
  | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null \
  || die "ECR login failed"

ensure_repo() {
  local name="${REPO_PREFIX}/$1"
  if ! aws ecr describe-repositories --repository-names "${name}" \
        --region "${REGION}" >/dev/null 2>&1; then
    log "creating ECR repository ${name}"
    aws ecr create-repository --repository-name "${name}" \
      --region "${REGION}" --image-scanning-configuration scanOnPush=true \
      >/dev/null
  fi
}

# A clean SHA tag names one commit, so once it is in ECR it must not move
# (#436). The repos are MUTABLE and image builds are not byte-reproducible, so
# re-running this script used to re-push every tag with a NEW digest. A pod whose
# spec did not change (gnb/ue when only the core moved) then kept running the
# previous digest under the same tag -- a move the deploy's spec-based verifier
# cannot see, so the only defence is not to move the tag.
# Skip an image whose tag already exists, unless the tag is one that is MEANT to
# move: a -dirty tree, `latest`, or FORCE_PUSH=true.
PUSHED=0
SKIPPED=0
already_pushed() {
  local repo="${REPO_PREFIX}/$1" tag="$2"
  [[ "${tag}" != *-dirty && "${tag}" != latest && "${FORCE_PUSH:-false}" != true ]] \
    || return 1
  aws ecr describe-images --repository-name "${repo}" --image-ids imageTag="${tag}" \
    --region "${REGION}" >/dev/null 2>&1
}

# --- base image ------------------------------------------------------------

# Dockerfile.nf does FROM ${CORE_IMAGE}, so the shared core image (which
# carries iproute2/iptables and the nextgcore user) must exist locally first.
log "building base core image..."
docker build \
  -f "${CORE_DIR}/docker/rust/Dockerfile.core" \
  -t nextgcore-core:latest \
  "${CORE_DIR}/docker/rust" \
  || die "core image build failed"

# --- core NFs --------------------------------------------------------------

for entry in "${CORE_NFS[@]}"; do
  nf="${entry%%:*}"
  bin="${entry#*:}"
  remote="${REGISTRY}/${REPO_PREFIX}/${nf}:${CORE_TAG}"

  ensure_repo "${nf}"
  if already_pushed "${nf}" "${CORE_TAG}"; then
    log "${nf}:${CORE_TAG} is already in ECR; not re-pushing (FORCE_PUSH=true to override)"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi
  log "building ${nf} (${bin})"
  # Build context is the repo root so COPY binaries/<bin> resolves. A
  # CORE_BIN_DIR elsewhere gets a throwaway context holding just that binary,
  # since Dockerfile.nf only ever reads binaries/<bin>.
  context="${CORE_DIR}"
  if [[ "${CORE_BIN_DIR}" != "${DEFAULT_CORE_BIN_DIR}" ]]; then
    context="$(mktemp -d -t nextg-nf-ctx-XXXXXX)"
    mkdir -p "${context}/binaries"
    cp "${CORE_BIN_DIR}/${bin}" "${context}/binaries/${bin}"
  fi
  docker build \
    -f "${CORE_DIR}/docker/rust/Dockerfile.nf" \
    --build-arg CORE_IMAGE=nextgcore-core:latest \
    --build-arg "NF_NAME=${bin}" \
    -t "${remote}" \
    "${context}" \
    || die "${nf} build failed"
  if [[ "${context}" != "${CORE_DIR}" ]]; then
    rm -f "${context}/binaries/${bin}"
    rmdir "${context}/binaries" "${context}"
  fi

  log "pushing ${remote}"
  docker push "${remote}" >/dev/null || die "${nf} push failed"
  PUSHED=$((PUSHED + 1))
done

# --- simulator -------------------------------------------------------------

for entry in "${PROFILE_SIM_IMAGES[@]}"; do
  IFS=: read -r node dockerfile ctx _bins <<<"${entry}"
  remote="${REGISTRY}/${REPO_PREFIX}/${node}:${SIM_TAG}"

  ensure_repo "${node}"
  if already_pushed "${node}" "${SIM_TAG}"; then
    log "${node}:${SIM_TAG} is already in ECR; not re-pushing (FORCE_PUSH=true to override)"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi
  log "building ${node}"
  # For gnb/ue the context is nextgsim/docker, NOT nextgsim: those Dockerfiles
  # do `COPY binaries/nr-gnb`, and the binaries live in
  # nextgsim/docker/binaries/. The LTE Dockerfiles also COPY config/ and
  # scripts/, so their context is the repo root (with nextgsim/binaries/).
  docker build \
    -f "${SIM_DIR}/${dockerfile}" \
    -t "${remote}" \
    "${SIM_DIR}/${ctx}" \
    || die "${node} build failed"

  log "pushing ${remote}"
  docker push "${remote}" >/dev/null || die "${node} push failed"
  PUSHED=$((PUSHED + 1))
done

# --- summary ---------------------------------------------------------------

cat <<EOF

All ${NUM_IMAGES} images are in ECR: ${PUSHED} pushed, ${SKIPPED} already present.

  registry:      ${REGISTRY}
  prefix:        ${REPO_PREFIX}
  core NF tag:   ${CORE_TAG}
  gnb/ue tag:    ${SIM_TAG}

Next (deploy-eks.sh derives the SAME tags from the same two repos, so it needs
no tag argument -- commit either repo in between and it will fail fast on a
missing ECR tag rather than deploying a stale image):

  $([[ "${PROFILE_NAME}" == 5g ]] || printf 'PROFILE=%s ' "${PROFILE_NAME}")REGISTRY=${REGISTRY} REPO_PREFIX=${REPO_PREFIX} ./deploy-eks.sh
EOF
