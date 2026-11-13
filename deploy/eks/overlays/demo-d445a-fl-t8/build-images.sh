#!/usr/bin/env bash
# Build and push the images of demo d445a-fl-t8 (nextgsim#480) for an EKS run.
#
#   CORE_BIN_DIR=<dir> SIM_BIN_DIR=<dir> \
#     deploy/eks/overlays/demo-d445a-fl-t8/build-images.sh
#
# Prebuilt binaries, from clean trees at the commits the tags name (CORE_REV,
# SIM_REV; default HEAD):
#   CORE_BIN_DIR   nextgcore, the 6G profile's features plus nefd's demo feature:
#       cd src && cargo build --release --locked -p nextgcore-{nrfd,amfd,smfd,upfd,
#         ausfd,udmd,udrd,pcfd,nssfd,bsfd,nefd} --features nextgcore-amfd/ntn
#         --features nextgcore-smfd/compute-aware-upf
#         --features nextgcore-upfd/compute-aware-upf
#         --features nextgcore-pcfd/intent-loop --features nextgcore-udmd/nes
#         --features nextgcore-nefd/demo-d445a-fl-t8
#   SIM_BIN_DIR    nextgsim: nr-gnb (default), nr-cli, nr-ue and nr-fl-server
#       (--features demo-d445a-fl-t8), and nr-ue-revert-hooks and
#       nr-fl-server-revert-hooks (the same binaries with --features revert-hooks).
# Each binary is checked for a string its feature compiles in, so a default
# build cannot be packaged by mistake.
#
# Tags: demo-d445a-fl-t8-<nextgcore short sha> on every core NF (nextg/<nf>,
# nef included) and demo-d445a-fl-t8-<nextgsim short sha> on nextg/gnb and
# nextg/ue (Dockerfile.ue-d445a). A tag that already exists in ECR is never
# overwritten: the script stops before building anything. The repos must
# exist; this script creates none. Demo images for devtest1 only.
#
# Then:
#   CORE_IMAGE_TAG=<core tag> SIM_IMAGE_TAG=<sim tag> YES=true \
#     flock /tmp/eks-nextg-demo.lock k8s/demo-check.sh d445a-fl-t8 <mode>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
SIM_DIR="$(cd "${CORE_DIR}/../nextgsim" && pwd)"
REGION="${AWS_REGION:-us-west-2}"
REPO_PREFIX="${REPO_PREFIX:-nextg}"
: "${CORE_BIN_DIR:?set CORE_BIN_DIR}" "${SIM_BIN_DIR:?set SIM_BIN_DIR}"
die() { echo "build-images: $*" >&2; exit 1; }

# The commits the binaries were built from (default HEAD), e.g. CORE_REV=origin/main
# when this script runs from a branch that only adds deploy files: the tag names
# that commit, so its sources and Dockerfiles must equal this tree's.
CORE_REV="${CORE_REV:-HEAD}"; SIM_REV="${SIM_REV:-HEAD}"
for d in "${CORE_DIR}:${CORE_REV}" "${SIM_DIR}:${SIM_REV}"; do
  dir="${d%%:*}" rev="${d#*:}"
  [[ -z "$(git -C "${dir}" status --porcelain --untracked-files=no -- src docker 'Dockerfile*' 'nextgsim-*' scripts)" ]] \
    || die "${dir} has uncommitted source changes: the tag would not describe the build"
  git -C "${dir}" diff --quiet "${rev}" HEAD -- src docker 'Dockerfile*' 'nextgsim-*' scripts Cargo.lock \
    || die "${dir}: sources differ between ${rev} and HEAD"
done
CORE_TAG="demo-d445a-fl-t8-$(git -C "${CORE_DIR}" rev-parse --short=12 "${CORE_REV}")"
SIM_TAG="demo-d445a-fl-t8-$(git -C "${SIM_DIR}" rev-parse --short=12 "${SIM_REV}")"

CORE_NFS=(nrf:nextgcore-nrfd amf:nextgcore-amfd smf:nextgcore-smfd upf:nextgcore-upfd
          ausf:nextgcore-ausfd udm:nextgcore-udmd udr:nextgcore-udrd pcf:nextgcore-pcfd
          nssf:nextgcore-nssfd bsf:nextgcore-bsfd nef:nextgcore-nefd)
SIM_BINS=(nr-gnb nr-cli nr-ue nr-ue-revert-hooks nr-fl-server nr-fl-server-revert-hooks)
for e in "${CORE_NFS[@]}"; do [[ -x "${CORE_BIN_DIR}/${e#*:}" ]] || die "missing ${CORE_BIN_DIR}/${e#*:}"; done
for b in "${SIM_BINS[@]}"; do [[ -x "${SIM_BIN_DIR}/${b}" ]] || die "missing ${SIM_BIN_DIR}/${b}"; done
# Feature checks: each string exists only in the feature build.     BIN STRING
has() { grep -aqF "$2" "$1" || die "$1 lacks '$2': wrong feature set"; }
has "${CORE_BIN_DIR}/nextgcore-nefd" "T8 delivery sub="
has "${SIM_BIN_DIR}/nr-ue" "no FL client in this UE"
has "${SIM_BIN_DIR}/nr-ue" "fl.leak_raw is a revert arm and needs a revert-hooks build"
has "${SIM_BIN_DIR}/nr-ue-revert-hooks" "no FL client in this UE"
! grep -aqF "fl.leak_raw is a revert arm and needs" "${SIM_BIN_DIR}/nr-ue-revert-hooks" \
  || die "nr-ue-revert-hooks is not a revert-hooks build"
has "${SIM_BIN_DIR}/nr-fl-server" "nr-fl-server runs only with demo"
# The AF's knobs: refused by the demo build, accepted by the revert-hooks one.
"${SIM_BIN_DIR}/nr-fl-server" -c /nonexistent --no-t8 2>&1 | grep -q "needs a revert-hooks build" \
  || die "nr-fl-server accepts --no-t8: it is a revert-hooks build"
"${SIM_BIN_DIR}/nr-fl-server-revert-hooks" -c /nonexistent --no-t8 2>&1 | grep -q "No such file" \
  || die "nr-fl-server-revert-hooks refuses --no-t8: not a revert-hooks build"

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com"
exists() { aws ecr describe-images --region "${REGION}" --repository-name "${REPO_PREFIX}/$1" \
             --image-ids imageTag="$2" >/dev/null 2>&1; }
for e in "${CORE_NFS[@]}"; do
  aws ecr describe-repositories --region "${REGION}" --repository-names "${REPO_PREFIX}/${e%%:*}" >/dev/null 2>&1 \
    || die "ECR repository ${REPO_PREFIX}/${e%%:*} does not exist (this script creates none)"
  ! exists "${e%%:*}" "${CORE_TAG}" || die "${REPO_PREFIX}/${e%%:*}:${CORE_TAG} already exists; not overwriting"
done
for r in gnb ue; do
  ! exists "${r}" "${SIM_TAG}" || die "${REPO_PREFIX}/${r}:${SIM_TAG} already exists; not overwriting"
done

ctx="$(mktemp -d -t d445a-ctx-XXXXXX)"
trap 'rm -rf "${ctx}"' EXIT
docker build -f "${CORE_DIR}/docker/rust/Dockerfile.core" -t nextgcore-core:latest "${CORE_DIR}/docker/rust"
mkdir -p "${ctx}/core/binaries"
for e in "${CORE_NFS[@]}"; do
  cp "${CORE_BIN_DIR}/${e#*:}" "${ctx}/core/binaries/"
  docker build -f "${CORE_DIR}/docker/rust/Dockerfile.nf" --build-arg CORE_IMAGE=nextgcore-core:latest \
    --build-arg "NF_NAME=${e#*:}" -t "${REGISTRY}/${REPO_PREFIX}/${e%%:*}:${CORE_TAG}" "${ctx}/core"
done
mkdir -p "${ctx}/sim/binaries"
cp "${SIM_BIN_DIR}/nr-gnb" "${ctx}/sim/binaries/"
docker build -f "${SIM_DIR}/Dockerfile.gnb-local" -t "${REGISTRY}/${REPO_PREFIX}/gnb:${SIM_TAG}" "${ctx}/sim"
mkdir -p "${ctx}/ue"
for b in nr-ue nr-ue-revert-hooks nr-cli nr-fl-server nr-fl-server-revert-hooks; do cp "${SIM_BIN_DIR}/${b}" "${ctx}/ue/"; done
cp "${SIM_DIR}/scripts/nr-ue-deregister.sh" "${ctx}/ue/"
docker build -f "${HERE}/Dockerfile.ue-d445a" -t "${REGISTRY}/${REPO_PREFIX}/ue:${SIM_TAG}" "${ctx}/ue"
docker run --rm --entrypoint sh "${REGISTRY}/${REPO_PREFIX}/ue:${SIM_TAG}" -c \
  'for c in nr-ue nr-cli nr-fl-server nr-fl-server-revert-hooks nr-ue-revert-hooks nr-ue-deregister ip iptables tcpdump; do command -v $c >/dev/null || { echo "missing $c"; exit 1; }; done' \
  || die "ue image is incomplete"

aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null
for e in "${CORE_NFS[@]}"; do docker push "${REGISTRY}/${REPO_PREFIX}/${e%%:*}:${CORE_TAG}" >/dev/null; done
docker push "${REGISTRY}/${REPO_PREFIX}/gnb:${SIM_TAG}" >/dev/null
docker push "${REGISTRY}/${REPO_PREFIX}/ue:${SIM_TAG}" >/dev/null
echo "CORE_IMAGE_TAG=${CORE_TAG}"
echo "SIM_IMAGE_TAG=${SIM_TAG}"
