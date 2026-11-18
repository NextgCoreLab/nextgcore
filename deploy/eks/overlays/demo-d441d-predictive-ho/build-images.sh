#!/usr/bin/env bash
# Build and push the D441D images for an EKS run (nextgsim#467).
#
#   deploy/eks/overlays/demo-d441d-predictive-ho/build-images.sh <onnxruntime wheel>
#
# The wheel is onnxruntime 1.23.2 for cp311 manylinux_2_27 x86_64, from PyPI
# (`pip download onnxruntime==1.23.2 --no-deps --only-binary=:all:
#  --platform manylinux_2_27_x86_64 --python-version 3.11`); its sha256 and that
# of the libonnxruntime it carries are checked (the D440B pins). Only the C
# library is used.
#
# One tag for every image, demo-d441d-predictive-ho-<nextgcore sha8>-<nextgsim sha8>,
# the HEADs of the two trees the binaries are built from (the D440C scheme):
#   nextg/{nrf,amf,smf,upf,ausf,udm,udr,pcf,nssf,bsf}
#            the demo profile's NFs and features (PROFILE=demo, this overlay):
#            stock 6G core, D441D changes no core NF; from build-and-push.sh.
#   nextg/gnb  nextgsim's Dockerfile.gnb-local over nr-gnb built with
#            `demo-d441d-predictive-ho,demo-d446a-agent-conflict` (one image for
#            every arm; the D446A key is set only in the conflict variant), plus
#            ONE layer adding nr-cli (scenario.sh reads the gNB through it) and
#            libonnxruntime at /usr/local/lib/onnxruntime/ (mode onnx). Pushed
#            first, so build-and-push.sh finds the tag and does not build its own.
#   nextg/ue   the default nr-ue, from build-and-push.sh.
#
# It refuses to start when a tree has uncommitted changes, when a nextg/<repo>
# is missing (it never creates one), or when the tag already exists in any of
# them (a tag is never overwritten). These are devtest1 demo images only.
# Every build goes to one target directory, D441D_TARGET_DIR (default
# /tmp/nextg-d441d-target), core/ and sim/ beneath it.
#
# Then:
#   CORE_IMAGE_TAG=<tag> SIM_IMAGE_TAG=<tag> SIM_SHA=<nextgsim sha> \
#     flock /tmp/eks-nextg-demo.lock k8s/demo-check.sh d441d-predictive-ho <mode>
set -euo pipefail
WHEEL="${1:?usage: $0 <onnxruntime-1.23.2 cp311 manylinux_2_27 x86_64 wheel>}"
WHEEL_SHA256=da44b99206e77734c5819aa2142c69e64f3b46edc3bd314f6a45a932defc0b3e
LIB_SHA256=718c3fb0785d5ea06061b92c32ce4ad35be1bd4c71ae6192efe06f1ab21f0f8a
LIB=libonnxruntime.so.1.23.2
OVERLAY=demo-d441d-predictive-ho

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"
REGION="${AWS_REGION:-us-west-2}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
for d in "${CORE_DIR}" "${SIM_DIR}"; do
  [[ -z "$(git -C "${d}" status --porcelain --untracked-files=no)" ]] \
    || { echo "${d} has uncommitted changes" >&2; exit 1; }
done
TAG="${OVERLAY}-$(git -C "${CORE_DIR}" rev-parse --short=8 HEAD)-$(git -C "${SIM_DIR}" rev-parse --short=8 HEAD)"
TARGET_DIR="${D441D_TARGET_DIR:-/tmp/nextg-d441d-target}"
CORE_BIN_DIR="${TARGET_DIR}/core-bin"

echo "${WHEEL_SHA256}  ${WHEEL}" | sha256sum -c -
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
python3 -I - "${WHEEL}" "${STAGE}/${LIB}" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
open(sys.argv[2], 'wb').write(z.read('onnxruntime/capi/libonnxruntime.so.1.23.2'))
PY
echo "${LIB_SHA256}  ${STAGE}/${LIB}" | sha256sum -c -

# The demo profile's NF list and features, for this overlay.
# shellcheck disable=SC1091  # deploy/eks/lib/profile.sh, resolved at run time
source "${CORE_DIR}/deploy/eks/lib/profile.sh"
export DEMO_OVERLAY="${OVERLAY}"
nextg_load_profile demo

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
REPOS=(gnb ue)
for e in "${PROFILE_CORE_NFS[@]}"; do REPOS+=("${e%%:*}"); done
for repo in "${REPOS[@]}"; do
  aws ecr describe-repositories --region "${REGION}" --repository-names "${REPO_PREFIX}/${repo}" \
    >/dev/null 2>&1 || { echo "ECR repository ${REPO_PREFIX}/${repo} is missing; not creating it" >&2; exit 1; }
  if aws ecr describe-images --region "${REGION}" --repository-name "${REPO_PREFIX}/${repo}" \
      --image-ids imageTag="${TAG}" >/dev/null 2>&1; then
    echo "${REPO_PREFIX}/${repo}:${TAG} already exists; not overwriting" >&2; exit 1
  fi
done

# The core binaries: exactly the demo profile's NFs and cargo features.
pkgs=(); feats=()
for e in "${PROFILE_CORE_NFS[@]}"; do pkgs+=(-p "${e#*:}"); done
for f in ${PROFILE_CARGO_FEATURES}; do feats+=(--features "${f}"); done
(cd "${CORE_DIR}/src" && CARGO_TARGET_DIR="${TARGET_DIR}/core" cargo build --release --locked "${pkgs[@]}" "${feats[@]}")
mkdir -p "${CORE_BIN_DIR}"
for e in "${PROFILE_CORE_NFS[@]}"; do cp "${TARGET_DIR}/core/release/${e#*:}" "${CORE_BIN_DIR}/"; done

# The simulator binaries, into nextgsim's binaries/ (gitignored; the Dockerfiles' context).
(cd "${SIM_DIR}" && CARGO_TARGET_DIR="${TARGET_DIR}/sim" sh -c '
  cargo build --release --locked -p nextgsim-gnb --features demo-d441d-predictive-ho,demo-d446a-agent-conflict --bin nr-gnb &&
  cargo build --release --locked -p nextgsim-ue --bin nr-ue &&
  cargo build --release --locked -p nextgsim-cli --bin nr-cli')
mkdir -p "${SIM_DIR}/binaries"
for b in nr-gnb nr-ue; do cp "${TARGET_DIR}/sim/release/${b}" "${SIM_DIR}/binaries/"; done
cp "${TARGET_DIR}/sim/release/nr-cli" "${STAGE}/"

aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}"
# The gNB first, with nr-cli and ONNX Runtime: build-and-push.sh then skips gnb.
docker build -f "${SIM_DIR}/Dockerfile.gnb-local" -t "d441d-gnb-base:${TAG}" "${SIM_DIR}"
docker build -t "${REGISTRY}/${REPO_PREFIX}/gnb:${TAG}" -f - "${STAGE}" <<DOCKERFILE
FROM d441d-gnb-base:${TAG}
COPY nr-cli /usr/local/bin/nr-cli
COPY ${LIB} /usr/local/lib/onnxruntime/${LIB}
ENV ORT_DYLIB_PATH=/usr/local/lib/onnxruntime/${LIB}
DOCKERFILE
docker push "${REGISTRY}/${REPO_PREFIX}/gnb:${TAG}"

# The core NFs and the UE. build-and-push.sh never re-pushes an existing tag, and
# every repo exists (above), so its ensure_repo creates nothing.
PROFILE=demo DEMO_OVERLAY="${OVERLAY}" IMAGE_TAG="${TAG}" CORE_BIN_DIR="${CORE_BIN_DIR}" \
  REGISTRY="${REGISTRY}" REPO_PREFIX="${REPO_PREFIX}" "${CORE_DIR}/deploy/eks/build-and-push.sh"
echo "CORE_IMAGE_TAG=${TAG} SIM_IMAGE_TAG=${TAG} SIM_SHA=$(git -C "${SIM_DIR}" rev-parse --short=12 HEAD)"
