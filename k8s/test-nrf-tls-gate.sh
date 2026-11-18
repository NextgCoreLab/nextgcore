#!/usr/bin/env bash
# Tests of k8s/nrf-tls-gate.sh (nextgcore#1617) against a fake kubectl whose
# `exec ... curl .../metrics` prints the next of a sequence of scrapes.
#
#   1. every type REGISTERED and 0 unverified, at both reads: pass
#   2. a type never REGISTERED: fail, naming it
#   3. unverified > 0 at the first read: fail
#   4. unverified 0 at the first read and > 0 after the settle: fail (a heartbeat
#      without a certificate)
#   5. the counter absent: fail
#   6. the NRF unreachable: fail
#   7. a type REGISTERED only on a later read: pass (the bounded wait)
#   8. a SUSPENDED instance does not count as REGISTERED
#   9. usage: no namespace, a malformed type: exit 2
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT="${HERE}/nrf-tls-gate.sh"
T="$(mktemp -d -t nrf-tls-gate-test-XXXXXX)"
trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin"
cat > "${T}/bin/kubectl" <<'SH'
#!/usr/bin/env bash
# Fake kubectl: `-n <ns> exec deploy/nrf -c nrf -- curl ... /metrics` prints
# $FAKE_DIR/<n> for the nth call (the last one again once they run out); a
# missing $FAKE_DIR/<n> with no earlier one fails like an unreachable pod.
[ "$1 $3 $4" = "-n exec deploy/nrf" ] || { echo "fake kubectl: unexpected $*" >&2; exit 1; }
n=$(( $(cat "$FAKE_DIR/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$FAKE_DIR/count"
while [ "$n" -gt 0 ] && [ ! -f "$FAKE_DIR/$n" ]; do n=$((n - 1)); done
[ "$n" -gt 0 ] || { echo "error: unable to upgrade connection" >&2; exit 1; }
cat "$FAKE_DIR/$n"
SH
chmod +x "${T}/bin/kubectl"
export PATH="${T}/bin:${PATH}" NRF_TLS_GATE_TRIES=3 NRF_TLS_GATE_SETTLE=0

pass=0
ok()   { pass=$((pass + 1)); echo "ok ${pass} - $*"; }
fail() { echo "not ok - $*" >&2; exit 1; }
scrape() {  # scrape <file> <unverified|-> <type>... : a metrics exposition
  local f="$1" u="$2"; shift 2
  { for t in "$@"; do
      printf 'nrf_registered_nf_instances{nf_type="%s",nf_status="REGISTERED"} 1\n' "${t}"
    done
    printf 'nrf_registered_nf_instances{nf_type="UPF",nf_status="SUSPENDED"} 1\n'
    [[ "${u}" == - ]] || printf 'nrf_nf_management_unverified_total %s\n' "${u}"
  } > "${f}"
}
case_dir() { rm -rf "${T}/s"; mkdir -p "${T}/s"; export FAKE_DIR="${T}/s"; }
gate() { "${SUT}" ns "$@" > "${T}/out" 2> "${T}/err"; }
expect_fail() {  # expect_fail <needle> <case>
  local rc=0
  gate AMF SMF || rc=$?
  [[ "${rc}" == 1 ]] || fail "$2: exit ${rc}, not 1"
  grep -q -- "$1" "${T}/err" || fail "$2: the reason is not '$1': $(cat "${T}/err")"
}

case_dir; scrape "${T}/s/1" 0 AMF SMF
gate AMF SMF || fail "1: $(cat "${T}/err")"
grep -q "AMF SMF REGISTERED over TLS; 0 unverified" "${T}/out" || fail "1: no verdict: $(cat "${T}/out")"
ok "every type REGISTERED and 0 unverified passes"

case_dir; scrape "${T}/s/1" 0 AMF
expect_fail "not REGISTERED at the NRF over TLS: SMF" 2
ok "a type never REGISTERED fails, naming it"

case_dir; scrape "${T}/s/1" 2 AMF SMF
expect_fail "2 NF-management requests reached the NRF without a verified client certificate (at registration)" 3
ok "unverified > 0 at registration fails"

case_dir; scrape "${T}/s/1" 0 AMF SMF; scrape "${T}/s/2" 1 AMF SMF
expect_fail "(after 0 s of heartbeats)" 4
ok "an unverified heartbeat after the settle fails"

case_dir; scrape "${T}/s/1" - AMF SMF
expect_fail "does not expose nrf_nf_management_unverified_total" 5
ok "an absent counter fails"

case_dir
expect_fail "could not read the NRF's /metrics" 6
ok "an unreachable NRF fails"

case_dir; scrape "${T}/s/1" 0 AMF; scrape "${T}/s/2" 0 AMF SMF
gate AMF SMF || fail "7: $(cat "${T}/err")"
ok "a type REGISTERED on a later read passes"

case_dir; scrape "${T}/s/1" 0 AMF SMF
rc=0; gate AMF SMF UPF || rc=$?
if [[ "${rc}" != 1 ]] || ! grep -q "not REGISTERED at the NRF over TLS: UPF" "${T}/err"; then
  fail "8: a SUSPENDED UPF counted as REGISTERED: rc ${rc} $(cat "${T}/err")"
fi
ok "a SUSPENDED instance is not REGISTERED"

rc=0; "${SUT}" 2>/dev/null || rc=$?
[[ "${rc}" == 2 ]] || fail "9: no namespace exited ${rc}, not 2"
rc=0; "${SUT}" ns amf 2>/dev/null || rc=$?
[[ "${rc}" == 2 ]] || fail "9: a malformed type exited ${rc}, not 2"
ok "usage errors exit 2"

echo "1..${pass} all passed"
