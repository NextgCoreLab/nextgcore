#!/usr/bin/env bash
# Build, push and run every arm of demo d445a-fl-t8 on devtest1 (nextgsim#480).
#
#   CORE_SRC=<clean nextgcore worktree> SIM_SRC=<clean nextgsim worktree> \
#     deploy/eks/overlays/demo-d445a-fl-t8/run-arms.sh [ARM:MODE ...]
#
# Prerequisites: the ECR repos nextg/<nf> for every core NF, nef included, plus
# nextg/gnb and nextg/ue (this script creates none); the tags
# demo-d445a-fl-t8-<CORE_SRC HEAD> and demo-d445a-fl-t8-<SIM_SRC HEAD> not yet
# in ECR (build-images.sh never overwrites one); AWS credentials and a
# kubeconfig context KUBE_CONTEXT (default devtest1) that may deploy; python3
# with `cryptography` and PyYAML; docker; the toolchains of both repos.
#
# 1. release binaries from CORE_SRC and SIM_SRC (TARGET_DIR, default
#    /tmp/tgt-d445a; the revert-hooks builds are copied aside);
# 2. build-images.sh (the tags come from the two trees' HEADs);
# 3. every arm, one demo-check.sh run per hold of /tmp/eks-nextg-demo.lock;
#    artefacts under /tmp/eks-val/demos/d445a-<arm>/. Default arms: all.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "${HERE}/../../../.." && pwd)"
: "${CORE_SRC:?}" "${SIM_SRC:?}"
T="${TARGET_DIR:-/tmp/tgt-d445a}"
ARMS=("$@")
[[ ${#ARMS[@]} -gt 0 ]] || ARMS=(off:off main:t8-exclusion poisoned:poisoned-ue probe:t8-exclusion
  gates:t8-exclusion no-t8:t8-exclusion freeze-global:t8-exclusion leak-raw:t8-exclusion
  nat-on:t8-exclusion nefd-down:t8-exclusion udm-fallback:t8-exclusion eth0:t8-exclusion)
set -e
# What the binaries are built from, read BEFORE the build and checked unchanged
# after it; build-images.sh refuses bin dirs whose BUILT_FROM is not the HEAD its
# tag names.
CORE_HEAD="$(git -C "${CORE_SRC}" rev-parse HEAD)"; SIM_HEAD="$(git -C "${SIM_SRC}" rev-parse HEAD)"
for d in "${CORE_SRC}" "${SIM_SRC}"; do
  [[ -z "$(git -C "${d}" status --porcelain)" ]] || { echo "run-arms: ${d} is not clean" >&2; exit 1; }
done
(cd "${CORE_SRC}/src" && CARGO_TARGET_DIR="${T}/core" cargo build --release --locked \
  -p nextgcore-nrfd -p nextgcore-amfd -p nextgcore-smfd -p nextgcore-upfd -p nextgcore-ausfd \
  -p nextgcore-udmd -p nextgcore-udrd -p nextgcore-pcfd -p nextgcore-nssfd -p nextgcore-bsfd \
  -p nextgcore-nefd --features nextgcore-amfd/ntn --features nextgcore-smfd/compute-aware-upf \
  --features nextgcore-upfd/compute-aware-upf --features nextgcore-pcfd/intent-loop \
  --features nextgcore-udmd/nes --features nextgcore-nefd/demo-d445a-fl-t8)
mkdir -p "${T}/simbin"
(cd "${SIM_SRC}" && export CARGO_TARGET_DIR="${T}/sim" &&
  cargo build --release --locked -p nextgsim-gnb --bin nr-gnb &&
  cargo build --release --locked -p nextgsim-cli --bin nr-cli &&
  cargo build --release --locked -p nextgsim-ue --features demo-d445a-fl-t8 --bin nr-ue &&
  cargo build --release --locked -p nextgsim-fl --features demo-d445a-fl-t8 --bin nr-fl-server &&
  cp "${T}/sim/release/"{nr-gnb,nr-cli,nr-ue,nr-fl-server} "${T}/simbin/" &&
  cargo build --release --locked -p nextgsim-ue --features revert-hooks --bin nr-ue &&
  cargo build --release --locked -p nextgsim-fl --features revert-hooks --bin nr-fl-server &&
  cp "${T}/sim/release/nr-ue" "${T}/simbin/nr-ue-revert-hooks" &&
  cp "${T}/sim/release/nr-fl-server" "${T}/simbin/nr-fl-server-revert-hooks")
[[ "$(git -C "${CORE_SRC}" rev-parse HEAD)" == "${CORE_HEAD}" && "$(git -C "${SIM_SRC}" rev-parse HEAD)" == "${SIM_HEAD}" ]] \
  || { echo "run-arms: a source tree moved during the build" >&2; exit 1; }
echo "${CORE_HEAD}" >"${T}/core/release/BUILT_FROM"
echo "${SIM_HEAD}" >"${T}/simbin/BUILT_FROM"
tags="$(CORE_SRC="${CORE_SRC}" SIM_SRC="${SIM_SRC}" CORE_BIN_DIR="${T}/core/release" \
  SIM_BIN_DIR="${T}/simbin" "${HERE}/build-images.sh" | grep -E '^(CORE|SIM)_IMAGE_TAG=')"
eval "${tags}"
set +e
SIM_SHA="$(git -C "${SIM_SRC}" rev-parse --short=12 HEAD)"
export CORE_IMAGE_TAG SIM_IMAGE_TAG SIM_SHA YES=true
rc=0
for am in "${ARMS[@]}"; do
  arm="${am%%:*}" mode="${am#*:}"
  echo "=== $(date -u +%FT%TZ) arm=${arm} mode=${mode}"
  if [[ "${arm}" == off ]]; then
    flock /tmp/eks-nextg-demo.lock "${CORE_DIR}/k8s/demo-check.sh" off off || rc=1
  else
    D445A_ARM="${arm}" OUT_ROOT="/tmp/eks-val/demos/d445a-${arm}" \
      flock /tmp/eks-nextg-demo.lock "${CORE_DIR}/k8s/demo-check.sh" d445a-fl-t8 "${mode}" || rc=1
  fi
done
exit "${rc}"
