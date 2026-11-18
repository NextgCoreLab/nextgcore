#!/usr/bin/env bash
# Push the D440A images for an EKS run (nextgsim#462), on top of an existing
# demo-profile core tag.
#
#   BASE_CORE_IMAGE_TAG=<an existing -6g core tag> \
#     deploy/eks/overlays/demo-d440a-ai-paging/build-images.sh
#
# Only amfd and the simulator change for this demo, so only they are built. One
# new tag, demo-d440a-ai-paging-<nextgcore sha8>-<nextgsim sha8>, the HEADs of
# the two trees:
#   nextg/amf    amfd built with the demo profile's amfd features plus
#                demo-d440a-ai-paging;
#   nextg/{nrf,smf,upf,ausf,udm,udr,pcf,nssf,bsf}
#                the new tag added to BASE_CORE_IMAGE_TAG's image manifest
#                (same digest, nothing rebuilt);
#   nextg/gnb    nr-gnb with demo-d440a-ai-paging (it implies 6g);
#   nextg/ue     the default nr-ue.
# nr-cli is built beside them into nextgsim's binaries/ (gitignored), where
# scenario.sh copies it into each gNB for the release; no image carries it.
#
# It refuses to start when a tree has uncommitted changes, when a nextg/<repo>
# is missing (it never creates one), when BASE_CORE_IMAGE_TAG is absent from a
# core repo, or when the new tag already exists in any repo (a tag is never
# overwritten). These are devtest1 demo images only.
#
# Then:
#   CORE_IMAGE_TAG=<tag> SIM_IMAGE_TAG=<tag> SIM_SHA=<nextgsim sha> \
#     flock /tmp/eks-nextg-demo.lock k8s/demo-check.sh d440a-ai-paging <mode>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
SIM_DIR="$(cd "${NEXTGSIM_DIR:-${CORE_DIR}/../nextgsim}" && pwd)"
REGION="${AWS_REGION:-us-west-2}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
BASE="${BASE_CORE_IMAGE_TAG:?set BASE_CORE_IMAGE_TAG to an existing demo-profile core tag}"
for d in "${CORE_DIR}" "${SIM_DIR}"; do
  [[ -z "$(git -C "${d}" status --porcelain --untracked-files=no)" ]] \
    || { echo "${d} has uncommitted changes" >&2; exit 1; }
done
TAG="demo-d440a-ai-paging-$(git -C "${CORE_DIR}" rev-parse --short=8 HEAD)-$(git -C "${SIM_DIR}" rev-parse --short=8 HEAD)"
TARGET_DIR="${D440A_TARGET_DIR:-/tmp/nextg-d440a-target}"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
RETAGGED=(nrf smf upf ausf udm udr pcf nssf bsf)
for repo in amf "${RETAGGED[@]}" gnb ue; do
  aws ecr describe-repositories --region "${REGION}" --repository-names "${REPO_PREFIX}/${repo}" \
    >/dev/null 2>&1 || { echo "ECR repository ${REPO_PREFIX}/${repo} is missing; not creating it" >&2; exit 1; }
  if aws ecr describe-images --region "${REGION}" --repository-name "${REPO_PREFIX}/${repo}" \
      --image-ids imageTag="${TAG}" >/dev/null 2>&1; then
    echo "${REPO_PREFIX}/${repo}:${TAG} already exists; not overwriting" >&2; exit 1
  fi
done
manifest_of() {   # <repo> <tag>: the image manifest, or nothing
  aws ecr batch-get-image --region "${REGION}" --repository-name "${REPO_PREFIX}/$1" \
    --image-ids imageTag="$2" --query 'images[0].imageManifest' --output text 2>/dev/null
}
for repo in "${RETAGGED[@]}"; do
  m="$(manifest_of "${repo}" "${BASE}")"
  [[ -n "${m}" && "${m}" != None ]] || { echo "${REPO_PREFIX}/${repo}:${BASE} does not exist" >&2; exit 1; }
done

# amfd: the demo profile's amfd features (they include demo-d440a-ai-paging
# for this overlay), and nothing else of the profile.
# shellcheck disable=SC1091  # deploy/eks/lib/profile.sh, resolved at run time
source "${CORE_DIR}/deploy/eks/lib/profile.sh"
export DEMO_OVERLAY=demo-d440a-ai-paging
nextg_load_profile demo
feats=()
for f in ${PROFILE_CARGO_FEATURES}; do [[ "${f}" == nextgcore-amfd/* ]] && feats+=(--features "${f}"); done
printf '%s\n' "${feats[@]}" | grep -qx 'nextgcore-amfd/demo-d440a-ai-paging' \
  || { echo "the demo profile does not build amfd with demo-d440a-ai-paging" >&2; exit 1; }
(cd "${CORE_DIR}/src" && CARGO_TARGET_DIR="${TARGET_DIR}/core" cargo build --release --locked -p nextgcore-amfd "${feats[@]}")

(cd "${SIM_DIR}" && CARGO_TARGET_DIR="${TARGET_DIR}/sim" sh -c '
  cargo build --release --locked -p nextgsim-gnb --features demo-d440a-ai-paging --bin nr-gnb &&
  cargo build --release --locked -p nextgsim-ue --bin nr-ue &&
  cargo build --release --locked -p nextgsim-cli --bin nr-cli')
mkdir -p "${SIM_DIR}/binaries"
for b in nr-gnb nr-ue nr-cli; do cp "${TARGET_DIR}/sim/release/${b}" "${SIM_DIR}/binaries/"; done

aws ecr get-login-password --region "${REGION}" \
  | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null
docker build -f "${CORE_DIR}/docker/rust/Dockerfile.core" -t nextgcore-core:latest "${CORE_DIR}/docker/rust"
CTX="$(mktemp -d -t nextg-d440a-amf-XXXXXX)"
trap 'rm -rf -- "${CTX}"' EXIT
mkdir -p "${CTX}/binaries"
cp "${TARGET_DIR}/core/release/nextgcore-amfd" "${CTX}/binaries/"
docker build -f "${CORE_DIR}/docker/rust/Dockerfile.nf" --build-arg CORE_IMAGE=nextgcore-core:latest \
  --build-arg NF_NAME=nextgcore-amfd -t "${REGISTRY}/${REPO_PREFIX}/amf:${TAG}" "${CTX}"
docker push "${REGISTRY}/${REPO_PREFIX}/amf:${TAG}" >/dev/null
for entry in "${PROFILE_SIM_IMAGES[@]}"; do
  IFS=: read -r node dockerfile ctx _bins <<<"${entry}"
  docker build -f "${SIM_DIR}/${dockerfile}" -t "${REGISTRY}/${REPO_PREFIX}/${node}:${TAG}" "${SIM_DIR}/${ctx}"
  docker push "${REGISTRY}/${REPO_PREFIX}/${node}:${TAG}" >/dev/null
done
# The unchanged NFs: the new tag on the base tag's manifest. put-image refuses
# nothing here (the tag was checked absent above); it adds a tag, moves none.
for repo in "${RETAGGED[@]}"; do
  aws ecr put-image --region "${REGION}" --repository-name "${REPO_PREFIX}/${repo}" \
    --image-tag "${TAG}" --image-manifest "$(manifest_of "${repo}" "${BASE}")" >/dev/null
done
echo "CORE_IMAGE_TAG=${TAG} SIM_IMAGE_TAG=${TAG} SIM_SHA=$(git -C "${SIM_DIR}" rev-parse --short=12 HEAD) BASE_CORE_IMAGE_TAG=${BASE}"
