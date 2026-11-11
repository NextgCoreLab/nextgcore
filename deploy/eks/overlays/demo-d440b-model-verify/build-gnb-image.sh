#!/usr/bin/env bash
# Build and push the D440B gNB/UE images for an EKS run (nextgsim#463).
#
#   deploy/eks/overlays/demo-d440b-model-verify/build-gnb-image.sh <onnxruntime wheel>
#
# The wheel is onnxruntime 1.23.2 for cp311 manylinux_2_27 x86_64, from PyPI
# (`pip download onnxruntime==1.23.2 --no-deps --only-binary=:all:
#  --platform manylinux_2_27_x86_64 --python-version 3.11`); its sha256 and that
# of the libonnxruntime it carries are checked below. Only the C library is
# used.
#
# Images, both tagged demo-d440b-model-verify-<nextgsim short sha>:
#   nextg/gnb   nextgsim's own Dockerfile.gnb-local over nr-gnb built with
#               `6g,model-registry`, then ONE layer on top adding nr-cli (the
#               scenario reads the gNB through it) and libonnxruntime at
#               /usr/local/lib/onnxruntime/. There is no second gNB Dockerfile.
#   nextg/ue    nextgsim's Dockerfile.ue-local over the default nr-ue.
# A tag that already exists in ECR is never overwritten: the script stops.
# These are demo images for devtest1 only, never published.
#
# Then: SIM_IMAGE_TAG=<tag> CORE_IMAGE_TAG=<an existing -6g core tag> \
#         k8s/demo-check.sh d440b-model-verify <mode>
set -euo pipefail
WHEEL="${1:?usage: $0 <onnxruntime-1.23.2 cp311 manylinux_2_27 x86_64 wheel>}"
WHEEL_SHA256=da44b99206e77734c5819aa2142c69e64f3b46edc3bd314f6a45a932defc0b3e
LIB_SHA256=718c3fb0785d5ea06061b92c32ce4ad35be1bd4c71ae6192efe06f1ab21f0f8a
LIB=libonnxruntime.so.1.23.2

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"
REGION="${AWS_REGION:-us-west-2}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
TAG="demo-d440b-model-verify-$(git -C "${SIM_DIR}" rev-parse --short=12 HEAD)"
# Tracked changes would make the tag lie about what was built.
[[ -z "$(git -C "${SIM_DIR}" status --porcelain --untracked-files=no)" ]] \
  || { echo "nextgsim tree has uncommitted changes" >&2; exit 1; }
# Outside the source tree, so the build leaves nextgsim untouched.
TARGET_DIR="${D440B_TARGET_DIR:-/tmp/nextg-d440b-target}"
mkdir -p "${TARGET_DIR}"

echo "${WHEEL_SHA256}  ${WHEEL}" | sha256sum -c -
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
python3 -I - "${WHEEL}" "${STAGE}/${LIB}" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
open(sys.argv[2], 'wb').write(z.read('onnxruntime/capi/libonnxruntime.so.1.23.2'))
PY
echo "${LIB_SHA256}  ${STAGE}/${LIB}" | sha256sum -c -

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
for repo in gnb ue; do
  if aws ecr describe-images --region "${REGION}" --repository-name "${REPO_PREFIX}/${repo}" \
      --image-ids imageTag="${TAG}" >/dev/null 2>&1; then
    echo "${REPO_PREFIX}/${repo}:${TAG} already exists; not overwriting" >&2; exit 1
  fi
done

# The binaries, in the same pinned toolchain image nextgcore's builder and the
# nextgsim 6G nightly use (bookworm glibc, matching the runtime image).
docker run --rm -v "${SIM_DIR}:/src:ro" -v "${TARGET_DIR}:/tgt" -w /src -e CARGO_TARGET_DIR=/tgt \
  rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 \
  sh -c 'cargo build --release --locked -p nextgsim-gnb --features 6g,model-registry --bin nr-gnb &&
         cargo build --release --locked -p nextgsim-ue --bin nr-ue &&
         cargo build --release --locked -p nextgsim-cli --bin nr-cli'
mkdir -p "${SIM_DIR}/binaries"
cp "${TARGET_DIR}/release/nr-gnb" "${TARGET_DIR}/release/nr-ue" "${SIM_DIR}/binaries/"
cp "${TARGET_DIR}/release/nr-cli" "${STAGE}/"

docker build -f "${SIM_DIR}/Dockerfile.gnb-local" -t "d440b-gnb-base:${TAG}" "${SIM_DIR}"
docker build -f "${SIM_DIR}/Dockerfile.ue-local" -t "${REGISTRY}/${REPO_PREFIX}/ue:${TAG}" "${SIM_DIR}"
docker build -t "${REGISTRY}/${REPO_PREFIX}/gnb:${TAG}" -f - "${STAGE}" <<DOCKERFILE
FROM d440b-gnb-base:${TAG}
COPY nr-cli /usr/local/bin/nr-cli
COPY ${LIB} /usr/local/lib/onnxruntime/${LIB}
ENV ORT_DYLIB_PATH=/usr/local/lib/onnxruntime/${LIB}
DOCKERFILE

aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}"
docker push "${REGISTRY}/${REPO_PREFIX}/gnb:${TAG}"
docker push "${REGISTRY}/${REPO_PREFIX}/ue:${TAG}"
echo "SIM_IMAGE_TAG=${TAG}"
