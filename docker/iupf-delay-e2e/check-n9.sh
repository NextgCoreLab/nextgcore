#!/usr/bin/env bash
# #2222 R43: the N9 part, differentially. The pass arm's DL less the no-N9 arm's
# DL (NETEM_N9_MS=0) is what the PSA added for N9, and must be N9_MS within
# BAND_MS. Independent of how loaded the runner is, since both arms share it.
# Usage: check-n9.sh <pass results.txt> <no-N9 results.txt>
set -euo pipefail
N9_MS="${N9_MS:-15}"
BAND_MS="${BAND_MS:-3}"
dl() { sed -nE 's/^RESULT DL ([0-9]+) ms.*/\1/p' "$1" | head -n 1; }
pass="$(dl "${1:?pass results}")"
none="$(dl "${2:?no-N9 results}")"
if [ -z "$pass" ] || [ -z "$none" ]; then
  echo "no DL in $1 or $2" >&2
  exit 1
fi
d=$((pass - none))
echo "N9 part: DL $pass - $none = $d ms (want $N9_MS +/- $BAND_MS)"
[ "$d" -ge $((N9_MS - BAND_MS)) ] && [ "$d" -le $((N9_MS + BAND_MS)) ]
