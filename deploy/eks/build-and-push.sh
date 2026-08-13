#!/usr/bin/env bash
# Build the 12 NextG workload images and push them to ECR.
#
# Replaces the `kind load docker-image` step in nextgcore/k8s/deploy.sh, which
# has no equivalent on EKS - without a registry every pod lands in
# ErrImagePull.
#
# Uses the prebuilt binaries committed in the repo:
#   nextgcore/binaries/nextgcore-*d       (17 NF binaries, 10 used here)
#   nextgsim/docker/binaries/nr-gnb,nr-ue
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
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"

# shellcheck source=lib/image-tag.sh
source "${SCRIPT_DIR}/lib/image-tag.sh"

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"

# NF -> binary name. The image name is the short NF name; the binary is the
# daemon name. Dockerfile.nf symlinks it to /usr/local/bin/nf-binary.
CORE_NFS=(
  "nrf:nextgcore-nrfd"
  "amf:nextgcore-amfd"
  "smf:nextgcore-smfd"
  "upf:nextgcore-upfd"
  "ausf:nextgcore-ausfd"
  "udm:nextgcore-udmd"
  "udr:nextgcore-udrd"
  "pcf:nextgcore-pcfd"
  "nssf:nextgcore-nssfd"
  "bsf:nextgcore-bsfd"
)

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
fi

for repo_tag in "nextgcore:${CORE_TAG}" "nextgsim:${SIM_TAG}"; do
  if [[ "${repo_tag#*:}" == *-dirty ]]; then
    warn "${repo_tag%%:*} tree is dirty; tagging ${repo_tag#*:} (not reproducible from the SHA)"
  fi
done

# --- preflight -------------------------------------------------------------

for c in aws docker; do
  command -v "$c" >/dev/null || die "$c not found"
done

log "verifying AWS credentials..."
if ! ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"; then
  die "AWS credentials invalid or expired. Refresh them and retry."
fi

REGISTRY="${REGISTRY:-${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com}"
log "registry: ${REGISTRY}"
log "prefix:   ${REPO_PREFIX}    tag: ${IMAGE_TAG}"

# Fail early and loudly if the binaries are missing, rather than producing
# images that crash on start. They are build artifacts and no longer tracked in
# git, so a fresh clone has none until you build.
MISSING=()
for entry in "${CORE_NFS[@]}"; do
  bin="${entry#*:}"
  [[ -f "${CORE_DIR}/binaries/${bin}" ]] || MISSING+=("nextgcore/binaries/${bin}")
done
[[ -f "${SIM_DIR}/docker/binaries/nr-gnb" ]] || MISSING+=("nextgsim/docker/binaries/nr-gnb")
[[ -f "${SIM_DIR}/docker/binaries/nr-ue"  ]] || MISSING+=("nextgsim/docker/binaries/nr-ue")
if (( ${#MISSING[@]} )); then
  printf 'missing prebuilt binaries:\n'; printf '  %s\n' "${MISSING[@]}"
  printf 'build them with:\n'
  printf '  cd %s/src && cargo build --release && \\\n' "${CORE_DIR}"
  printf '    cp target/release/nextgcore-*d ../binaries/\n'
  printf '  cd %s && cargo build --release && \\\n' "${SIM_DIR}"
  printf '    cp target/release/nr-gnb target/release/nr-ue docker/binaries/\n'
  die "no binaries to package"
fi

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
  log "building ${nf} (${bin})"
  # Build context is the repo root so COPY binaries/<bin> resolves.
  docker build \
    -f "${CORE_DIR}/docker/rust/Dockerfile.nf" \
    --build-arg CORE_IMAGE=nextgcore-core:latest \
    --build-arg "NF_NAME=${bin}" \
    -t "${remote}" \
    "${CORE_DIR}" \
    || die "${nf} build failed"

  log "pushing ${remote}"
  docker push "${remote}" >/dev/null || die "${nf} push failed"
done

# --- simulator -------------------------------------------------------------

for pair in "gnb:Dockerfile.gnb-local" "ue:Dockerfile.ue-local"; do
  node="${pair%%:*}"
  dockerfile="${pair#*:}"
  remote="${REGISTRY}/${REPO_PREFIX}/${node}:${SIM_TAG}"

  ensure_repo "${node}"
  log "building ${node}"
  # Context is nextgsim/docker, NOT nextgsim: the Dockerfiles do
  # `COPY binaries/nr-gnb`, and the binaries live in nextgsim/docker/binaries/.
  # There is no nextgsim/binaries/, so building from the repo root fails.
  docker build \
    -f "${SIM_DIR}/${dockerfile}" \
    -t "${remote}" \
    "${SIM_DIR}/docker" \
    || die "${node} build failed"

  log "pushing ${remote}"
  docker push "${remote}" >/dev/null || die "${node} push failed"
done

# --- summary ---------------------------------------------------------------

cat <<EOF

All 12 images pushed.

  registry:      ${REGISTRY}
  prefix:        ${REPO_PREFIX}
  core NF tag:   ${CORE_TAG}
  gnb/ue tag:    ${SIM_TAG}

Next (deploy-eks.sh derives the SAME tags from the same two repos, so it needs
no tag argument -- commit either repo in between and it will fail fast on a
missing ECR tag rather than deploying a stale image):

  REGISTRY=${REGISTRY} REPO_PREFIX=${REPO_PREFIX} ./deploy-eks.sh
EOF
