#!/usr/bin/env bash
# Build, push and run every arm of demo d443a-edge-budget on devtest1 (nextgsim#471).
#
#   CORE_SRC=<clean nextgcore worktree> SIM_SRC=<clean nextgsim worktree> \
#     deploy/eks/overlays/demo-d443a-edge-budget/run-arms.sh [ARM:MODE ...]
#   With CORE_IMAGE_TAG and SIM_IMAGE_TAG set (an earlier run's tags, which must
#   name those trees' HEADs and be in ECR), nothing is built or pushed.
#
# Arms (scenario.sh's header says what each does):
#   off:off  main:measured-budget  static:static
#   no-kpi-patch:measured-budget (revert)  gates:measured-budget (bogus mode)
#
# Prerequisites: the ECR repos nextg/<nf> for every core NF, ees included, plus
# nextg/gnb and nextg/ue (this script creates none); the tags
# demo-d443a-edge-budget-<CORE_SRC HEAD> and -<SIM_SRC HEAD> not yet in ECR
# (build-images.sh never overwrites one); AWS credentials and a kubeconfig context
# KUBE_CONTEXT (default devtest1) that may deploy; python3 with `cryptography` and
# PyYAML; docker; the toolchains of both repos.
#
# 1. release binaries from CORE_SRC and SIM_SRC (TARGET_DIR, default a fresh
#    mktemp dir; cargo clean it afterwards);
# 2. build-images.sh (the tags come from the two trees' HEADs);
# 3. every arm, one demo-check.sh run per hold of /tmp/eks-nextg-demo.lock;
#    artefacts under /tmp/eks-val/demos/d443a-<arm>/. Default arms: all.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
KEY=d443a-edge-budget
: "${CORE_SRC:?}" "${SIM_SRC:?}"
T="${TARGET_DIR:-$(mktemp -d -t tgt-d443a-XXXXXX)}"
echo "run-arms: target dir ${T} (cargo clean it afterwards)"
ARMS=("$@")
[[ ${#ARMS[@]} -gt 0 ]] || ARMS=(off:off main:measured-budget static:static
  no-kpi-patch:measured-budget gates:measured-budget)
CORE_NFS=(nrf amf smf upf ausf udm udr pcf nssf bsf ees)
set -e
if [[ -n "${CORE_IMAGE_TAG:-}" && -n "${SIM_IMAGE_TAG:-}" ]]; then
  [[ "${CORE_IMAGE_TAG}" == "demo-${KEY}-$(git -C "${CORE_SRC}" rev-parse --short=12 HEAD)" \
     && "${SIM_IMAGE_TAG}" == "demo-${KEY}-$(git -C "${SIM_SRC}" rev-parse --short=12 HEAD)" ]] \
    || { echo "run-arms: the given tags do not name CORE_SRC/SIM_SRC at HEAD" >&2; exit 1; }
  for r in "${CORE_NFS[@]}"; do
    aws ecr describe-images --repository-name "nextg/${r}" --image-ids imageTag="${CORE_IMAGE_TAG}" >/dev/null \
      || { echo "run-arms: nextg/${r}:${CORE_IMAGE_TAG} is not in ECR" >&2; exit 1; }
  done
  for r in gnb ue; do
    aws ecr describe-images --repository-name "nextg/${r}" --image-ids imageTag="${SIM_IMAGE_TAG}" >/dev/null \
      || { echo "run-arms: nextg/${r}:${SIM_IMAGE_TAG} is not in ECR" >&2; exit 1; }
  done
  SKIP_BUILD=true
fi
if [[ "${SKIP_BUILD:-}" != true ]]; then
CORE_HEAD="$(git -C "${CORE_SRC}" rev-parse HEAD)"; SIM_HEAD="$(git -C "${SIM_SRC}" rev-parse HEAD)"
for d in "${CORE_SRC}" "${SIM_SRC}"; do
  [[ -z "$(git -C "${d}" status --porcelain)" ]] || { echo "run-arms: ${d} is not clean" >&2; exit 1; }
done
(cd "${CORE_SRC}/src" && CARGO_TARGET_DIR="${T}/core" cargo build --release --locked \
  -p nextgcore-nrfd -p nextgcore-amfd -p nextgcore-smfd -p nextgcore-upfd -p nextgcore-ausfd \
  -p nextgcore-udmd -p nextgcore-udrd -p nextgcore-pcfd -p nextgcore-nssfd -p nextgcore-bsfd \
  -p nextgcore-eesd --features nextgcore-amfd/ntn --features nextgcore-smfd/compute-aware-upf \
  --features nextgcore-upfd/compute-aware-upf --features nextgcore-pcfd/intent-loop \
  --features nextgcore-udmd/nes --features nextgcore-eesd/demo-d443a-edge-budget \
  --features nextgcore-smfd/demo-d443a-edge-budget)
mkdir -p "${T}/simbin"
(cd "${SIM_SRC}" && export CARGO_TARGET_DIR="${T}/sim" &&
  cargo build --release --locked -p nextgsim-gnb --bin nr-gnb &&
  cargo build --release --locked -p nextgsim-cli --bin nr-cli &&
  cargo build --release --locked -p nextgsim-ue --features demo-d443a-edge-budget --bin nr-ue &&
  cargo build --release --locked -p nextgsim-she --features demo-d443a-edge-budget --bin nr-she-eas &&
  cp "${T}/sim/release/"{nr-gnb,nr-cli,nr-ue,nr-she-eas} "${T}/simbin/")
[[ "$(git -C "${CORE_SRC}" rev-parse HEAD)" == "${CORE_HEAD}" && "$(git -C "${SIM_SRC}" rev-parse HEAD)" == "${SIM_HEAD}" ]] \
  || { echo "run-arms: a source tree moved during the build" >&2; exit 1; }
echo "${CORE_HEAD}" >"${T}/core/release/BUILT_FROM"
echo "${SIM_HEAD}" >"${T}/simbin/BUILT_FROM"
tags="$(CORE_SRC="${CORE_SRC}" SIM_SRC="${SIM_SRC}" CORE_BIN_DIR="${T}/core/release" \
  SIM_BIN_DIR="${T}/simbin" "${HERE}/build-images.sh" | grep -E '^(CORE|SIM)_IMAGE_TAG=')"
eval "${tags}"
fi
set +e
SIM_SHA="$(git -C "${SIM_SRC}" rev-parse --short=12 HEAD)"
export CORE_IMAGE_TAG SIM_IMAGE_TAG SIM_SHA YES=true
rc=0
for am in "${ARMS[@]}"; do
  arm="${am%%:*}" mode="${am#*:}"
  echo "=== $(date -u +%FT%TZ) arm=${arm} mode=${mode}"
  variant=""
  case "${arm}" in main|static|off) ;; *) variant="${arm}" ;; esac
  DEMO_VARIANT="${variant}" OUT_ROOT="/tmp/eks-val/demos/d443a-${arm}" \
    flock /tmp/eks-nextg-demo.lock "${CORE_DIR}/k8s/demo-check.sh" "${KEY}" "${mode}" || rc=1
done
exit "${rc}"
