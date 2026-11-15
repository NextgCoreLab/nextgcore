#!/usr/bin/env bash
# Self-test of the D443A harness (nextgsim#471). No cluster, no network.
#
#   deploy/eks/overlays/demo-d443a-edge-budget/test-scenario.sh
#
# analyze.py --self-test: every check passes on a complete fixture, FAILS on its
# negative control, and, forced to PASS, makes the arm's verdict hold on that
# control (so each check is what catches it). The revert arm's target fails on
# its fixture and passes on main's.
# cca.py --self-test (with `cryptography`): a generated key and its JWK agree.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash -n "${here}/scenario.sh"
python3 "${here}/analyze.py" --self-test
if python3 -c 'import cryptography' 2>/dev/null; then
  python3 "${here}/cca.py" --self-test
else
  echo "cca.py self-test skipped: no python3 cryptography"
fi
