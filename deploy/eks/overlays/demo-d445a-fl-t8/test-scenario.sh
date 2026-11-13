#!/usr/bin/env bash
# Self-test of the D445A checks (nextgsim#480). No cluster, no network.
#
#   deploy/eks/overlays/demo-d445a-fl-t8/test-scenario.sh
#
# checks.py --self-test: every check passes on a complete fixture and FAILS (and
# only that check) on the same fixture with a line removed, out of order or a
# value wrong; each revert arm holds only when its target check fails.
# cca.py --self-test: the per-arm AF configs, and (with `cryptography`) that a
# generated CCA verifies against its JWK.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash -n "${here}/scenario.sh"
python3 "${here}/checks.py" --self-test
python3 "${here}/cca.py" --self-test
