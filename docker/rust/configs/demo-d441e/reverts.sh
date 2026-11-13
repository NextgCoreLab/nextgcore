#!/usr/bin/env bash
# The revert arms of demo d441e-model-retrain (nextgsim#468): each one patches
# nwdafd, rebuilds it, and passes only if `check.sh retrain` then FAILS at the
# step the patch takes away, with the patch's own evidence in the logs.
#
#   flip-v2-byte      the MTLF serves v2 with one byte flipped (manifest
#                     unchanged) -> the AnLF logs "model refused (sha256
#                     mismatch) ...; keeping v1" and the check fails at S12
#   no-feedback-feed  the MTLF's MLModelMonitor notify handler never feeds the
#                     FeedbackRegistry -> the AnLF still reports the drop, the
#                     MTLF never requests a retrain, the check fails at S8
#
# The patch is applied only for the build and reversed right after it (and by
# the EXIT trap), so the arm itself runs against a clean tree; the script fails
# if the tree is not back to HEAD. ARMS="a b" runs a subset.
#
# Environment: CARGO_TARGET_DIR (cargo's), D441E_CARGO (the cargo command,
# default cargo; CI runs it in a bookworm container so the binary matches the
# image's glibc), D441E_CORE_IMAGE (the base image
# Dockerfile.nf extends, default nextgcore-core:latest), D441E_NRF_IMAGE and
# D441E_COMPOSE as check.sh, DEMO_ARTEFACTS root (default /tmp/demo-artefacts/d441e).
# Exit 0 when every arm fails as it must.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(git -C "${here}" rev-parse --show-toplevel)"
target="${CARGO_TARGET_DIR:-${root}/src/target}"
art_root="${DEMO_ARTEFACTS:-/tmp/demo-artefacts/d441e}"
read -r -a CARGO <<<"${D441E_CARGO:-cargo}"
declare -A expect=([flip-v2-byte]='step S12' [no-feedback-feed]='step S8')
cd "${root}"
git diff --quiet HEAD -- || { echo "reverts: tracked files differ from HEAD" >&2; exit 2; }

applied=""
restore() {
  if [[ -n "${applied}" ]]; then git apply -R "${applied}"; applied=""; fi
}
trap restore EXIT

for arm in ${ARMS:-flip-v2-byte no-feedback-feed}; do
  patch="${here}/reverts/${arm}.patch"
  want="${expect[${arm}]:?unknown arm ${arm}}"
  art="${art_root}/revert-${arm}"
  mkdir -p "${art}"
  echo "[d441e] revert arm ${arm}: check.sh retrain must fail with '${want}'"
  git apply --check "${patch}" || { echo "reverts: ${arm}.patch does not apply; refresh it" >&2; exit 2; }
  git apply "${patch}"; applied="${patch}"
  (cd src && "${CARGO[@]}" build --release -p nextgcore-nwdafd --features demo-d441e-model-retrain) >"${art}/build.log" 2>&1 \
    || { tail -30 "${art}/build.log" >&2; echo "reverts: ${arm} build failed" >&2; exit 2; }
  restore
  git diff --quiet HEAD -- || { echo "reverts: tree not restored after ${arm}" >&2; exit 3; }
  ctx="$(mktemp -d)"; mkdir -p "${ctx}/binaries"
  cp "${target}/release/nextgcore-nwdafd" "${ctx}/binaries/"
  image="nextgcore-rust/nwdaf-d441e:revert-${arm}"
  docker build -q -f "${root}/docker/rust/Dockerfile.nf" \
    --build-arg "CORE_IMAGE=${D441E_CORE_IMAGE:-nextgcore-core:latest}" \
    --build-arg NF_NAME=nextgcore-nwdafd -t "${image}" "${ctx}" >/dev/null
  rm -f "${ctx}/binaries/nextgcore-nwdafd"; rmdir "${ctx}/binaries" "${ctx}"

  set +e
  D441E_NWDAF_IMAGE="${image}" DEMO_ARTEFACTS="${art}" D441E_PROJECT="nextg-d441e-revert-${arm}" \
    "${here}/check.sh" retrain >"${art}/check.out" 2>&1
  rc=$?
  set -e
  if [[ ${rc} == 0 ]]; then
    echo "reverts: ARM BROKEN: check.sh retrain PASSED under ${arm}" >&2; exit 1
  fi
  grep -F "DEMO CHECK FAILED" "${art}/check.out" | grep -qF "${want}" \
    || { tail -20 "${art}/check.out" >&2; echo "reverts: ARM BROKEN: ${arm} failed, but not with '${want}'" >&2; exit 1; }
  case "${arm}" in
    flip-v2-byte)
      grep -E 'model refused \(sha256 mismatch\) from \S+: .*; keeping v1' "${art}/nwdaf-anlf.log" >"${art}/evidence.txt" \
        || { echo "reverts: ARM BROKEN: no 'model refused (sha256 mismatch) ...; keeping v1' line" >&2; exit 1; }
      ;;
    no-feedback-feed)
      # The drop happened (the AnLF reported it) and nothing asked for a retrain.
      if grep -q 'retrain requested' "${art}/nwdaf-mtlf.log"; then
        echo "reverts: ARM BROKEN: the MTLF requested a retrain without the feed" >&2; exit 1
      fi
      grep -E 'accuracy 0\.[0-6][0-9] \(n=[0-9]+\) reported' "${art}/nwdaf-anlf.log" | tail -3 >"${art}/evidence.txt" \
        || { echo "reverts: ARM BROKEN: the AnLF never reported the drop" >&2; exit 1; }
      ;;
  esac
  echo "[d441e] revert arm ${arm} holds: $(grep -F 'DEMO CHECK FAILED' "${art}/check.out" | head -1)"
  sed 's/^/[d441e]   evidence: /' "${art}/evidence.txt"
done
echo "[d441e] every revert arm failed as it must"
