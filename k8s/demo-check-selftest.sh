#!/usr/bin/env bash
# Self-test of k8s/demo-check.sh against a fake cluster (nextgcore#1395).
#
# Copies demo-check.sh into a throwaway tree whose deploy-eks.sh, e2e-internet.sh
# and kubectl are stubs, then checks the paths a real cluster run cannot easily
# force:
#   1. aborted at the prompt          -> exit 2, private kubeconfig removed
#   2. namespace already exists       -> exit 2, kubeconfig removed, namespace kept
#   3. a run whose deploy/e2e logs and pod log carry a Bearer token and a JWT
#                                     -> every artefact scrubbed, VERDICT: PASS,
#                                        teardown=ok, artefacts mode 600
#   4. the same run with scrubbing disabled -> VERDICT: FAIL naming the leak
# Needs bash, python3 and coreutils only. Exit 0 when all hold.
# shellcheck disable=SC2016,SC2317  # check() evals its single-quoted conditions
set -uo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demo-check.sh"
T="$(mktemp -d -t demo-check-selftest-XXXXXX)"
trap 'rm -rf -- "${T}"' EXIT
mkdir -p "${T}/k8s" "${T}/deploy/eks/overlays/demo" "${T}/bin" "${T}/out" "${T}/tmp"
cp "${SRC}" "${T}/k8s/demo-check.sh"
: > "${T}/deploy/eks/overlays/demo/kustomization.yaml"
cat > "${T}/deploy/eks/deploy-eks.sh" <<'EOF'
#!/bin/bash
echo "deploying; Authorization: Bearer abcdefghijklmnop123456"
EOF
cat > "${T}/deploy/eks/e2e-internet.sh" <<'EOF'
#!/bin/bash
echo "token eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"; echo "e2e PASS"
EOF
cat > "${T}/bin/kubectl" <<'EOF'
#!/bin/bash
case "$*" in
  "config view"*) echo "apiVersion: v1" ;;
  "cluster-info") ;;
  "get namespace nextg-demo") [[ -f "${FAKE_NS}" ]] || exit 1 ;;
  "delete namespace"*) rm -f "${FAKE_NS}" ;;
  *"get pods -o jsonpath={.items[*].metadata.name}"*) echo "amf-1" ;;
  *"{.spec.initContainers[*].name} {.spec.containers[*].name}"*) echo "amf" ;;
  *"logs amf-1 -c amf"*) echo "2026-11-11T00:00:00Z amf up, Bearer zzzzzzzzzzzzzzzzzz" ;;
  *"containers[0].ports"*) echo "9090" ;;
  *"podIP"*) echo "10.0.0.1" ;;
  *"containers[0].name"*) echo "amf" ;;
  *"exec amf-1"*) echo 'nextgcore_build_info{nf="amf"} 1' ;;
esac
EOF
chmod +x "${T}/bin/kubectl" "${T}"/deploy/eks/*.sh "${T}/k8s/demo-check.sh"

run() { PATH="${T}/bin:${PATH}" FAKE_NS="${T}/ns" OUT_ROOT="${T}/out" TMPDIR="${T}/tmp" "$@"; }
kcfgs() { find "${T}/tmp" -name 'nextg-demo-kcfg-*' | wc -l; }
bad=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; bad=1; fi; }

echo n | run "${T}/k8s/demo-check.sh" off off >/dev/null 2>&1; rc=$?
check "aborted: exit 2" '[[ ${rc} == 2 ]]'
check "aborted: kubeconfig removed" '[[ $(kcfgs) == 0 ]]'

touch "${T}/ns"
YES=true run "${T}/k8s/demo-check.sh" off off >/dev/null 2>&1; rc=$?
check "namespace exists: exit 2" '[[ ${rc} == 2 ]]'
check "namespace exists: kubeconfig removed" '[[ $(kcfgs) == 0 ]]'
check "namespace exists: namespace not deleted" '[[ -f ${T}/ns ]]'
rm -f "${T}/ns"

YES=true run "${T}/k8s/demo-check.sh" off off >/dev/null 2>&1; rc=$?
L="${T}/out/off/off/latest"
check "scrubbed run: exit 0" '[[ ${rc} == 0 ]]'
check "scrubbed run: VERDICT: PASS, teardown=ok" 'grep -q "VERDICT: PASS" "${L}/verdict.txt" && grep -q "teardown=ok" "${L}/verdict.txt"'
check "scrubbed run: no token or JWT in any artefact" \
  '! grep -rqE "Bearer [A-Za-z0-9]{8,}|eyJ[A-Za-z0-9_-]+\." "${L}/"'
check "scrubbed run: artefacts mode 600" '[[ $(stat -c %a "${L}/deploy.log") == 600 ]]'

sed -i 's|  scrub <"${f}" >"${f}.scrub" \&\& mv "${f}.scrub" "${f}"|  :|' "${T}/k8s/demo-check.sh"
YES=true run "${T}/k8s/demo-check.sh" off off >/dev/null 2>&1; rc=$?
L="${T}/out/off/off/latest"
check "unscrubbed run: FAIL naming the leak" \
  '[[ ${rc} == 1 ]] && grep -q "credential pattern left in" "${L}/verdict.txt"'

[[ ${bad} == 0 ]] && echo "demo-check self-test ok"
exit "${bad}"
