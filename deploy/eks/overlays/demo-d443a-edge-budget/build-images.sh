#!/usr/bin/env bash
# Build and push the images of demo d443a-edge-budget (nextgsim#471) for an EKS run.
#
#   CORE_BIN_DIR=<dir> SIM_BIN_DIR=<dir> \
#     deploy/eks/overlays/demo-d443a-edge-budget/build-images.sh
#
# Prebuilt binaries, from clean trees at the commits the tags name (CORE_SRC,
# SIM_SRC; their HEAD names the tag):
#   CORE_BIN_DIR   nextgcore, the 6G profile's features plus eesd's and smfd's
#       demo feature:
#       cd src && cargo build --release --locked -p nextgcore-{nrfd,amfd,smfd,upfd,
#         ausfd,udmd,udrd,pcfd,nssfd,bsfd,eesd} --features nextgcore-amfd/ntn
#         --features nextgcore-smfd/compute-aware-upf
#         --features nextgcore-upfd/compute-aware-upf
#         --features nextgcore-pcfd/intent-loop --features nextgcore-udmd/nes
#         --features nextgcore-eesd/demo-d443a-edge-budget
#         --features nextgcore-smfd/demo-d443a-edge-budget
#   SIM_BIN_DIR    nextgsim: nr-gnb (default), nr-cli, nr-ue (--features
#       demo-d443a-edge-budget) and nr-she-eas (nextgsim-she --features
#       demo-d443a-edge-budget).
# Each binary is checked for a string its feature compiles in, so a default
# build cannot be packaged by mistake.
#
# Tags: demo-d443a-edge-budget-<nextgcore short sha> on every core NF (nextg/<nf>,
# ees included) and demo-d443a-edge-budget-<nextgsim short sha> on nextg/gnb and
# nextg/ue (Dockerfile.ue-d443a). A tag that already exists in ECR is never
# overwritten: the script stops before building anything. The repos must
# exist; this script creates none. Demo images for devtest1 only.
#
# Then:
#   CORE_IMAGE_TAG=<core tag> SIM_IMAGE_TAG=<sim tag> YES=true \
#     flock /tmp/eks-nextg-demo.lock k8s/demo-check.sh d443a-edge-budget <mode>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"
REGION="${AWS_REGION:-us-west-2}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
: "${CORE_BIN_DIR:?set CORE_BIN_DIR}" "${SIM_BIN_DIR:?set SIM_BIN_DIR}"
die() { echo "build-images: $*" >&2; exit 1; }

# The source trees the binaries were built from (default: this checkout and its
# sibling nextgsim). Run from a branch that only adds deploy files, point
# CORE_SRC at a clean worktree of the built commit. Each tag is that tree's HEAD,
# asserted again right before the push.
CORE_SRC="$(cd "${CORE_SRC:-${CORE_DIR}}" && pwd)"; SIM_SRC="$(cd "${SIM_SRC:-${SIM_DIR}}" && pwd)"
for dir in "${CORE_SRC}" "${SIM_SRC}"; do
  # Untracked files too: docker/rust and the sim tree are build contexts.
  [[ -z "$(git -C "${dir}" status --porcelain)" ]] \
    || die "${dir} has uncommitted or untracked files: the tag would not describe the build"
done
CORE_SHA="$(git -C "${CORE_SRC}" rev-parse --short=12 HEAD)"
SIM_SHA="$(git -C "${SIM_SRC}" rev-parse --short=12 HEAD)"
CORE_TAG="demo-d443a-edge-budget-${CORE_SHA}"
SIM_TAG="demo-d443a-edge-budget-${SIM_SHA}"
# The tag's SHA is the tree's HEAD, now and at push time.                 TAG DIR
assert_tag() {
  [[ "${1##*-}" == "$(git -C "$2" rev-parse --short=12 HEAD)" ]] \
    || die "tag $1 is not $2 at HEAD ($(git -C "$2" rev-parse --short=12 HEAD)); not pushing"
}
CORE_NFS=(nrf:nextgcore-nrfd amf:nextgcore-amfd smf:nextgcore-smfd upf:nextgcore-upfd
          ausf:nextgcore-ausfd udm:nextgcore-udmd udr:nextgcore-udrd pcf:nextgcore-pcfd
          nssf:nextgcore-nssfd bsf:nextgcore-bsfd ees:nextgcore-eesd)
SIM_BINS=(nr-gnb nr-cli nr-ue nr-she-eas)
for e in "${CORE_NFS[@]}"; do [[ -x "${CORE_BIN_DIR}/${e#*:}" ]] || die "missing ${CORE_BIN_DIR}/${e#*:}"; done
# Provenance: each bin dir carries BUILT_FROM, the full commit its binaries were
# built from (run-arms.sh writes it: HEAD read before the build, checked unchanged
# after). It must be the HEAD the tag names.                          BIN_DIR TREE
built_from() {
  [[ -s "$1/BUILT_FROM" ]] || die "$1/BUILT_FROM is missing: no record of what built these binaries"
  [[ "$(cat "$1/BUILT_FROM")" == "$(git -C "$2" rev-parse HEAD)" ]] \
    || die "$1 was built from $(cat "$1/BUILT_FROM"), not $2 at HEAD $(git -C "$2" rev-parse HEAD)"
}
built_from "${CORE_BIN_DIR}" "${CORE_SRC}"
built_from "${SIM_BIN_DIR}" "${SIM_SRC}"
for b in "${SIM_BINS[@]}"; do [[ -x "${SIM_BIN_DIR}/${b}" ]] || die "missing ${SIM_BIN_DIR}/${b}"; done
# Feature checks: each string exists only in the feature build.     BIN STRING
has() { grep -aqF "$2" "$1" || die "$1 lacks '$2': wrong feature set"; }
has "${CORE_BIN_DIR}/nextgcore-eesd" "edge-budget: on (mode="
has "${CORE_BIN_DIR}/nextgcore-eesd" "OAuth2 callback exemption (TS 33.501"
has "${CORE_BIN_DIR}/nextgcore-smfd" "+n6Delays upf="
has "${SIM_BIN_DIR}/nr-ue" "no EEC client in this UE"
has "${SIM_BIN_DIR}/nr-she-eas" "nr-she-eas runs only with demo"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
# Fail closed: a tag is "absent" only on ImageNotFoundException; any other error
# (throttling, an expired session, the network) stops the run, since the repos are
# MUTABLE and a push over an existing tag would move it.                REPO TAG
absent() {
  local err rc=0
  err="$(aws ecr describe-images --region "${REGION}" --repository-name "${REPO_PREFIX}/$1" \
           --image-ids imageTag="$2" 2>&1 >/dev/null)" || rc=$?
  (( rc != 0 )) || die "${REPO_PREFIX}/$1:$2 already exists; not overwriting"
  # The CLI's service-error exit (254) with that exact error code, nothing looser.
  [[ "${rc}" == 254 && "${err}" == *"(ImageNotFoundException)"* ]] \
    || die "describe-images ${REPO_PREFIX}/$1:$2 failed (rc ${rc}): ${err}"
}
repo() {   # REPO: must exist; only RepositoryNotFoundException means it does not
  local err
  err="$(aws ecr describe-repositories --region "${REGION}" --repository-names "${REPO_PREFIX}/$1" 2>&1 >/dev/null)" && return
  [[ "${err}" == *RepositoryNotFoundException* ]] \
    && die "ECR repository ${REPO_PREFIX}/$1 does not exist (this script creates none)"
  die "describe-repositories ${REPO_PREFIX}/$1 failed: ${err}"
}
for e in "${CORE_NFS[@]}"; do repo "${e%%:*}"; absent "${e%%:*}" "${CORE_TAG}"; done
for r in gnb ue; do repo "${r}"; absent "${r}" "${SIM_TAG}"; done

ctx="$(mktemp -d -t d443a-ctx-XXXXXX)"
# A local base tag of this run only: nextgcore-core:latest is shared with every
# other build on the host.
BASE="nextgcore-core:d443a-${CORE_SHA}-$$"
trap 'rm -rf "${ctx}"; docker rmi "${BASE}" >/dev/null 2>&1 || true' EXIT
docker build -f "${CORE_SRC}/docker/rust/Dockerfile.core" -t "${BASE}" "${CORE_SRC}/docker/rust"
mkdir -p "${ctx}/core/binaries"
for e in "${CORE_NFS[@]}"; do
  cp "${CORE_BIN_DIR}/${e#*:}" "${ctx}/core/binaries/"
  docker build -f "${CORE_SRC}/docker/rust/Dockerfile.nf" --build-arg "CORE_IMAGE=${BASE}" \
    --build-arg "NF_NAME=${e#*:}" -t "${REGISTRY}/${REPO_PREFIX}/${e%%:*}:${CORE_TAG}" "${ctx}/core"
done
mkdir -p "${ctx}/sim/binaries"
cp "${SIM_BIN_DIR}/nr-gnb" "${ctx}/sim/binaries/"
docker build -f "${SIM_SRC}/Dockerfile.gnb-local" -t "${REGISTRY}/${REPO_PREFIX}/gnb:${SIM_TAG}" "${ctx}/sim"
mkdir -p "${ctx}/ue"
for b in nr-ue nr-cli nr-she-eas; do cp "${SIM_BIN_DIR}/${b}" "${ctx}/ue/"; done
docker build -f "${HERE}/Dockerfile.ue-d443a" -t "${REGISTRY}/${REPO_PREFIX}/ue:${SIM_TAG}" "${ctx}/ue"
docker run --rm --entrypoint sh "${REGISTRY}/${REPO_PREFIX}/ue:${SIM_TAG}" -c \
  'for c in nr-ue nr-cli nr-she-eas ip tc iptables curl setpriv; do command -v $c >/dev/null || { echo "missing $c"; exit 1; }; done' \
  || die "ue image is incomplete"

assert_tag "${CORE_TAG}" "${CORE_SRC}"
assert_tag "${SIM_TAG}" "${SIM_SRC}"
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null
# Each push re-checks that its tag is still absent, right before it.   REPO TAG
push() { assert_tag "$2" "$3"; absent "$1" "$2"; docker push "${REGISTRY}/${REPO_PREFIX}/$1:$2" >/dev/null; }
for e in "${CORE_NFS[@]}"; do push "${e%%:*}" "${CORE_TAG}" "${CORE_SRC}"; done
push gnb "${SIM_TAG}" "${SIM_SRC}"
push ue "${SIM_TAG}" "${SIM_SRC}"
echo "CORE_IMAGE_TAG=${CORE_TAG}"
echo "SIM_IMAGE_TAG=${SIM_TAG}"
