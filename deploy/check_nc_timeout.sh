#!/usr/bin/env bash
# #1506: every `nc` port probe that scans (`-z`, in any flag cluster) must set a
# connect timeout (`-w N`, N >= 1) in the same command. Without one, a single
# dropped SYN blocks the probe for the kernel's SYN-retransmit budget (~130 s),
# and the pod starts after deploy-eks.sh's readiness window.
#
#   deploy/check_nc_timeout.sh             scan the repo (git grep), fail on a hit
#   deploy/check_nc_timeout.sh --self-test check the pattern against known spellings
#
# The pattern, per `nc` invocation (a command segment ends at ; | & or newline):
#   (?<![\w.-])nc\b                  the word nc, not the tail of rsync / foo-nc
#   (?=[^;|&\n]*\s-[a-zA-Z]*z)       a flag cluster with z (-z, -zv, -vz, -nz ...)
#   (?![^;|&\n]*\s-[a-zA-Z]*w\s*[1-9])  and no -w N (or -zvwN) with N >= 1
# (#1572 review supplied the shape; -w 0 rejected per the same review.)
set -euo pipefail

PATTERN='(?<![\w.-])nc\b(?=[^;|&\n]*\s-[a-zA-Z]*z)(?![^;|&\n]*\s-[a-zA-Z]*w\s*[1-9])'

self_test() {
  local bad=0 line want got
  # want: 1 = must be flagged, 0 = must pass.
  while IFS='|' read -r want line; do
    [[ -z "$want" ]] && continue
    if printf '%s\n' "$line" | grep -qP "$PATTERN"; then got=1; else got=0; fi
    if [[ "$got" != "$want" ]]; then
      echo "self-test: expected $([[ $want == 1 ]] && echo flagged || echo pass): $line"
      bad=1
    fi
  done <<'CASES'
1|until nc -z nrf 7777; do sleep 2; done
1|nc -zv nrf 7777
1|nc -vz nrf 7777
1|nc -v -z nrf 7777
1|nc -nz nrf 7777
1|busybox nc -z nrf 7777
1|nc -z -w 0 nrf 7777
1|until nc -z h 1; do nc -w 2 -z other 2; done
0|until nc -z -w 2 nrf 7777; do sleep 2; done
0|nc -w2 -z nrf 7777
0|nc -z -v -w 2 nrf 7777
0|nc -zvw2 nrf 7777
0|nc -w 10 -z nrf 7777
0|rsync -z a b
0|nc -l -p 7777
0|echo sync done
CASES
  if [[ "$bad" != 0 ]]; then
    exit 1
  fi
  echo "self-test: ok"
}

scan() {
  # git grep exits 0 on a match, 1 on none (the pass case) and >1 on an error,
  # which must fail rather than read as "no match".
  local rc=0
  git grep -nIP "$PATTERN" -- ':!*.rs' ':!deploy/check_nc_timeout.sh' || rc=$?
  case "$rc" in
    1) echo "every nc -z probe sets -w N" ;;
    0) echo "nc -z probe without a connect timeout (above); use 'nc -z -w 2' (#1506)"; exit 1 ;;
    *) echo "git grep failed (rc=$rc)"; exit 1 ;;
  esac
}

case "${1:-}" in
  --self-test) self_test ;;
  "") scan ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
