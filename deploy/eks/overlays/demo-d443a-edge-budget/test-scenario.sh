#!/usr/bin/env bash
# Self-test of the D443A harness (nextgsim#471). No cluster, no network.
#
#   deploy/eks/overlays/demo-d443a-edge-budget/test-scenario.sh
#
# 1. analyze.py --self-test: every check passes on a complete fixture, FAILS on
#    each of its negative controls (one per condition), and, forced to PASS,
#    makes the arm's verdict hold on that control (so the check alone catches
#    it). The revert arm's target fails on its fixture and passes on main's.
# 2. gate(): run 20261116T011728Z's real eesd `mode: bogus` output (its
#    OpenTelemetry preamble puts the error past character 1100) through
#    scenario.sh's d443a_gate: the gate line keeps the error and rc.
# 3. The sidecar's restart guard: eas.yaml's sidecar.sh, with stub `ip` and
#    `sleep` that report an existing dn, stops with its FATAL line before
#    touching anything (a real run needs a netns and NET_ADMIN).
# 4. cca.py --self-test (with `cryptography`): a generated key and its JWK agree.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
t="$(mktemp -d)"; trap 'rm -rf "${t}"' EXIT
bash -n "${here}/scenario.sh"
python3 "${here}/analyze.py" --self-test

# 2. gate()
# shellcheck source=/dev/null
source "${here}/scenario.sh"
raw="$(cat "${here}/fixture-eesd-bogus-20261116T011728Z.txt"; echo "rc=1")"
pos="$(python3 -c 'import sys; print(sys.stdin.read().find("unknown mode"))' <<<"${raw}")"
[[ "${pos}" -gt 400 ]] || { echo "not ok - the fixture no longer exercises a long preamble (${pos})"; exit 1; }
d443a_gate "${t}" "${t}/gates.txt" eesd bogus "${raw}"
line="$(cat "${t}/gates.txt")"
[[ "${line}" == "eesd bogus: "*'unknown mode "bogus" for demo "d443a-edge-budget"'*"rc=1"* ]] \
  || { echo "not ok - gate() lost the error or rc: ${line:0:300}"; exit 1; }
[[ -s "${t}/gates-out/eesd-bogus.txt" ]] || { echo "not ok - gate() kept no full output"; exit 1; }
echo "ok - gate() keeps the error past the preamble (at ${pos})"

# 3. The restart guard
python3 - "${here}/eas.yaml" "${t}/sidecar.sh" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], 'w').write(d['data']['sidecar.sh'])
PY
mkdir -p "${t}/bin"
cat >"${t}/bin/ip" <<'STUB'
#!/bin/sh
echo "ip $*" >>"${STUB_LOG}"
[ "$1 $2 $3" = "link show eas-br" ] && exit 0
exit 1
STUB
printf '#!/bin/sh\necho "sleep $*" >>"${STUB_LOG}"\n' >"${t}/bin/sleep"
chmod +x "${t}/bin/ip" "${t}/bin/sleep"
out="$(cd "${t}" && STUB_LOG="${t}/calls" PATH="${t}/bin:${PATH}" D443A_EASES='eas-local 10.60.0.11 10 50 x 4' \
  sh "${t}/sidecar.sh" 2>&1 || true)"
grep -q 'FATAL: dn already exists' <<<"${out}" || { echo "not ok - no restart guard: ${out}"; exit 1; }
! grep -q '^ip link add' "${t}/calls" || { echo "not ok - the guard ran after dn was touched"; exit 1; }
grep -q '^sleep infinity' "${t}/calls" || { echo "not ok - the guard does not idle"; exit 1; }
echo "ok - a restarted sidecar stops at the guard and idles"

if python3 -c 'import cryptography' 2>/dev/null; then
  python3 "${here}/cca.py" --self-test
else
  echo "cca.py self-test skipped: no python3 cryptography"
fi
