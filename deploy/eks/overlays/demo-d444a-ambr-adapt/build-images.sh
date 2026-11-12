#!/usr/bin/env bash
# Build and push the D444A UE image for an EKS run (nextgsim#477).
#
#   deploy/eks/overlays/demo-d444a-ambr-adapt/build-images.sh
#
# Images, both tagged demo-d444a-ambr-adapt-<nextgsim short sha>:
#   nextg/ue    nextgsim's own Dockerfile.ue-local over nr-ue built with
#               `6g,demo-d444a-ambr-adapt`, plus nr-cli and semantic-sink
#               (Dockerfile.ue-local copies both when binaries/ has them). The
#               upf pod's semantic-sink container runs this same image.
#   nextg/gnb   nextgsim's Dockerfile.gnb-local over the 6g nr-gnb, so the gNB
#               and UE share one SIM_IMAGE_TAG.
# A tag that already exists in ECR is never overwritten: the script stops.
# These are demo images for devtest1 only, never published.
#
# Then: SIM_IMAGE_TAG=<tag> CORE_IMAGE_TAG=<an existing -6g core tag> \
#         flock /tmp/eks-nextg-demo.lock k8s/demo-check.sh d444a-ambr-adapt <mode>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"
REGION="${AWS_REGION:-us-west-2}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
TAG="demo-d444a-ambr-adapt-$(git -C "${SIM_DIR}" rev-parse --short=12 HEAD)"
# Tracked changes would make the tag lie about what was built.
[[ -z "$(git -C "${SIM_DIR}" status --porcelain --untracked-files=no)" ]] \
  || { echo "nextgsim tree has uncommitted changes" >&2; exit 1; }
# The cargo target dir is outside the source tree. The binaries are then copied
# into nextgsim's binaries/ (gitignored), the build context Dockerfile.*-local expect.
TARGET_DIR="${D444A_TARGET_DIR:-/tmp/nextg-d444a-target}"
mkdir -p "${TARGET_DIR}"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
for repo in gnb ue; do
  if aws ecr describe-images --region "${REGION}" --repository-name "${REPO_PREFIX}/${repo}" \
      --image-ids imageTag="${TAG}" >/dev/null 2>&1; then
    echo "${REPO_PREFIX}/${repo}:${TAG} already exists; not overwriting" >&2; exit 1
  fi
done

# The binaries, in the pinned toolchain image the other demo builds use
# (bookworm glibc, matching the runtime image).
docker run --rm -v "${SIM_DIR}:/src:ro" -v "${TARGET_DIR}:/tgt" -w /src -e CARGO_TARGET_DIR=/tgt \
  rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 \
  sh -c 'cargo build --release --locked -p nextgsim-gnb --features 6g --bin nr-gnb &&
         cargo build --release --locked -p nextgsim-ue --features 6g,demo-d444a-ambr-adapt --bin nr-ue &&
         cargo build --release --locked -p nextgsim-semantic --features demo-d444a-ambr-adapt --bin semantic-sink &&
         cargo build --release --locked -p nextgsim-cli --bin nr-cli'
mkdir -p "${SIM_DIR}/binaries"
for b in nr-gnb nr-ue semantic-sink nr-cli; do cp "${TARGET_DIR}/release/${b}" "${SIM_DIR}/binaries/"; done

docker build -f "${SIM_DIR}/Dockerfile.gnb-local" -t "${REGISTRY}/${REPO_PREFIX}/gnb:${TAG}" "${SIM_DIR}"
docker build -f "${SIM_DIR}/Dockerfile.ue-local" -t "${REGISTRY}/${REPO_PREFIX}/ue:${TAG}" "${SIM_DIR}"
# The UE image must carry the sink, or the upf pod's second container cannot start.
docker run --rm --entrypoint sh "${REGISTRY}/${REPO_PREFIX}/ue:${TAG}" -c 'command -v semantic-sink && command -v nr-cli' \
  || { echo "ue image lacks semantic-sink or nr-cli" >&2; exit 1; }

aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}"
docker push "${REGISTRY}/${REPO_PREFIX}/gnb:${TAG}"
docker push "${REGISTRY}/${REPO_PREFIX}/ue:${TAG}"
echo "SIM_IMAGE_TAG=${TAG}"
