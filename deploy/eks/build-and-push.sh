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
# Usage:
#   ./build-and-push.sh                        # infer registry from STS
#   REGISTRY=<acct>.dkr.ecr.<region>.amazonaws.com ./build-and-push.sh
#   REPO_PREFIX=nextg IMAGE_TAG=v1 ./build-and-push.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

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

# Fail early and loudly if the committed binaries are missing, rather than
# producing images that crash on start.
MISSING=()
for entry in "${CORE_NFS[@]}"; do
  bin="${entry#*:}"
  [[ -f "${CORE_DIR}/binaries/${bin}" ]] || MISSING+=("nextgcore/binaries/${bin}")
done
[[ -f "${SIM_DIR}/docker/binaries/nr-gnb" ]] || MISSING+=("nextgsim/docker/binaries/nr-gnb")
[[ -f "${SIM_DIR}/docker/binaries/nr-ue"  ]] || MISSING+=("nextgsim/docker/binaries/nr-ue")
if (( ${#MISSING[@]} )); then
  printf 'missing prebuilt binaries:\n'; printf '  %s\n' "${MISSING[@]}"
  die "build them first, or check out the committed binaries"
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
  remote="${REGISTRY}/${REPO_PREFIX}/${nf}:${IMAGE_TAG}"

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
  remote="${REGISTRY}/${REPO_PREFIX}/${node}:${IMAGE_TAG}"

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

  registry: ${REGISTRY}
  prefix:   ${REPO_PREFIX}
  tag:      ${IMAGE_TAG}

Next:
  REGISTRY=${REGISTRY} REPO_PREFIX=${REPO_PREFIX} IMAGE_TAG=${IMAGE_TAG} \\
    ./deploy-eks.sh
EOF
