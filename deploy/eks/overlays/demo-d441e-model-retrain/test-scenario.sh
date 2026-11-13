#!/usr/bin/env bash
# Self-test of demo d441e-model-retrain's checks (CI runs every overlay's): the
# chain.py that scenario.sh and the compose check.sh share passes a good log of
# each mode in both log formats, and fails on every needed line taken out, a
# reordering, a v2 below threshold, a refused model and both revert arms' logs.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$(cd "${here}/../../../.." && pwd)/docker/rust/configs/demo-d441e/chain.py" --self-test
bash -n "${here}/scenario.sh"
