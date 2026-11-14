#!/usr/bin/env bash
# Build and push the D440C images for an EKS run (nextgsim#464).
#
#   deploy/eks/overlays/demo-d440c-nwdaf-paging/build-images.sh
#
# One tag for every image, demo-d440c-nwdaf-paging-<nextgcore sha8>-<nextgsim sha8>,
# the HEADs of the two trees the binaries are built from:
#   nextg/{nrf,amf,smf,upf,ausf,udm,udr,pcf,nssf,bsf,nwdaf}
#            the demo profile's NFs (PROFILE=demo DEMO_OVERLAY=this overlay):
#            the 6G features plus amfd demo-d440c-nwdaf-paging and nwdafd
#            amf-mobility, from build-and-push.sh;
#   nextg/gnb  nr-gnb with demo-d440c-nwdaf-paging (it implies 6g);
#   nextg/ue   the default nr-ue.
# nr-cli is built beside them into nextgsim's binaries/ (gitignored), where
# scenario.sh copies it into gNB A for the release; no image carries it.
#
# It refuses to start when a tree has uncommitted changes, when a nextg/<repo>
# is missing (it never creates one), or when the tag already exists in any of
# them (a tag is never overwritten). These are devtest1 demo images only.
#
# Then:
#   CORE_IMAGE_TAG=<tag> SIM_IMAGE_TAG=<tag> SIM_SHA=<nextgsim sha> \
#     flock /tmp/eks-nextg-demo.lock k8s/demo-check.sh d440c-nwdaf-paging <mode>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"
REGION="${AWS_REGION:-us-west-2}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
for d in "${CORE_DIR}" "${SIM_DIR}"; do
  [[ -z "$(git -C "${d}" status --porcelain --untracked-files=no)" ]] \
    || { echo "${d} has uncommitted changes" >&2; exit 1; }
done
TAG="demo-d440c-nwdaf-paging-$(git -C "${CORE_DIR}" rev-parse --short=8 HEAD)-$(git -C "${SIM_DIR}" rev-parse --short=8 HEAD)"
TARGET_DIR="${D440C_TARGET_DIR:-/tmp/nextg-d440c-target}"
CORE_BIN_DIR="${D440C_CORE_BIN_DIR:-${TARGET_DIR}/core-bin}"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPOS=(nrf amf smf upf ausf udm udr pcf nssf bsf nwdaf gnb ue)
for repo in "${REPOS[@]}"; do
  aws ecr describe-repositories --region "${REGION}" --repository-names "${REPO_PREFIX}/${repo}" \
    >/dev/null 2>&1 || { echo "ECR repository ${REPO_PREFIX}/${repo} is missing; not creating it" >&2; exit 1; }
  if aws ecr describe-images --region "${REGION}" --repository-name "${REPO_PREFIX}/${repo}" \
      --image-ids imageTag="${TAG}" >/dev/null 2>&1; then
    echo "${REPO_PREFIX}/${repo}:${TAG} already exists; not overwriting" >&2; exit 1
  fi
done

# The core binaries: exactly the demo profile's NFs and cargo features.
# shellcheck disable=SC1091  # deploy/eks/lib/profile.sh, resolved at run time
source "${CORE_DIR}/deploy/eks/lib/profile.sh"
export DEMO_OVERLAY=demo-d440c-nwdaf-paging
nextg_load_profile demo
pkgs=(); feats=()
for e in "${PROFILE_CORE_NFS[@]}"; do pkgs+=(-p "${e#*:}"); done
for f in ${PROFILE_CARGO_FEATURES}; do feats+=(--features "${f}"); done
(cd "${CORE_DIR}/src" && CARGO_TARGET_DIR="${TARGET_DIR}/core" cargo build --release --locked "${pkgs[@]}" "${feats[@]}")
mkdir -p "${CORE_BIN_DIR}"
for e in "${PROFILE_CORE_NFS[@]}"; do cp "${TARGET_DIR}/core/release/${e#*:}" "${CORE_BIN_DIR}/"; done

# The simulator binaries, into nextgsim's binaries/ (the Dockerfiles' context).
(cd "${SIM_DIR}" && CARGO_TARGET_DIR="${TARGET_DIR}/sim" sh -c '
  cargo build --release --locked -p nextgsim-gnb --features demo-d440c-nwdaf-paging --bin nr-gnb &&
  cargo build --release --locked -p nextgsim-ue --bin nr-ue &&
  cargo build --release --locked -p nextgsim-cli --bin nr-cli')
mkdir -p "${SIM_DIR}/binaries"
for b in nr-gnb nr-ue nr-cli; do cp "${TARGET_DIR}/sim/release/${b}" "${SIM_DIR}/binaries/"; done

# build-and-push.sh never re-pushes an existing tag; every repo exists (above),
# so its ensure_repo creates nothing.
PROFILE=demo DEMO_OVERLAY=demo-d440c-nwdaf-paging IMAGE_TAG="${TAG}" CORE_BIN_DIR="${CORE_BIN_DIR}" \
  REGISTRY="${REGISTRY}" REPO_PREFIX="${REPO_PREFIX}" "${CORE_DIR}/deploy/eks/build-and-push.sh"
echo "CORE_IMAGE_TAG=${TAG} SIM_IMAGE_TAG=${TAG} SIM_SHA=$(git -C "${SIM_DIR}" rev-parse --short=12 HEAD)"
