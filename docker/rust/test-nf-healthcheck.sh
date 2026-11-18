#!/usr/bin/env bash
# Tests of docker/rust/nf-healthcheck.sh (nextgcore#1617) with a stub `curl`
# on PATH that records its arguments and exits with the next code of
# $FAKE_RC (a space-separated list, one per call). No real curl runs: the
# probe against a live h2c and TLS listener is for the final E2E.
#
#   1. the h2c probe answers: healthy, one h2c call to 127.0.0.1:7777/health
#   2. the NRF on TLS: h2c fails, the TLS call verifies nrf.crt as nrf against
#      the CA, dialled on 127.0.0.1 (--resolve), and its exit is the verdict
#   3. no TLS name for a non-NRF NF: unhealthy after the h2c call only
#   4. an unreadable CA: unhealthy, no TLS call
#   5. NF_HEALTH_ADDR / _PORT / _TLS_NAME / _TLS_CA are honoured; IPv6 is bracketed
#   6. no call ever skips verification (-k / --insecure) or speaks HTTP/1.1
#   7. Dockerfile.core installs it and its HEALTHCHECK runs it
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT="${HERE}/nf-healthcheck.sh"
T="$(mktemp -d -t nf-healthcheck-test-XXXXXX)"
trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin"
cat > "${T}/bin/curl" <<'SH'
#!/bin/sh
# Stub: one line of arguments per call in $FAKE_LOG; exit with the next $FAKE_RC.
printf '%s\n' "$*" >> "$FAKE_LOG"
n=$(wc -l < "$FAKE_LOG")
rc=$(printf '%s\n' $FAKE_RC | sed -n "${n}p")
exit "${rc:-1}"
SH
chmod +x "${T}/bin/curl"
printf 'dummy CA\n' > "${T}/ca.crt"
export PATH="${T}/bin:${PATH}" FAKE_LOG="${T}/calls"

pass=0
ok()   { pass=$((pass + 1)); echo "ok ${pass} - $*"; }
fail() { echo "not ok - $*" >&2; exit 1; }
probe() {  # probe <rc list> [VAR=value...]: the script's exit code
  : > "${FAKE_LOG}"
  local rcs="$1"; shift
  local rc=0
  env -u NF_NAME -u NF_HEALTH_ADDR -u NF_HEALTH_PORT -u NF_HEALTH_TLS_NAME -u NF_HEALTH_TLS_CA \
    FAKE_RC="${rcs}" NF_HEALTH_TLS_CA="${T}/ca.crt" "$@" sh "${SUT}" || rc=$?
  echo "${rc}"
}
calls() { wc -l < "${FAKE_LOG}" | tr -d ' '; }
call() { sed -n "$1p" "${FAKE_LOG}"; }

# 1
[[ "$(probe 0)" == 0 ]] || fail "1: an answering h2c listener is not healthy"
[[ "$(calls)" == 1 ]] || fail "1: $(calls) calls, not 1"
[[ "$(call 1)" == *"--http2-prior-knowledge"*" http://127.0.0.1:7777/health" ]] \
  || fail "1: not an h2c probe of 127.0.0.1:7777/health: $(call 1)"
[[ "$(call 1)" == *"--fail "* ]] || fail "1: the probe does not fail on an HTTP error (--fail): $(call 1)"
ok "an answering h2c listener is healthy after one h2c call"

# 2
for want in 0 1; do
  [[ "$(probe "7 ${want}" NF_NAME=nextgcore-nrfd)" == "${want}" ]] \
    || fail "2: the TLS call's exit ${want} is not the verdict"
  [[ "$(calls)" == 2 ]] || fail "2: $(calls) calls, not 2"
  c="$(call 2)"
  for part in "--http2 " "--cacert ${T}/ca.crt" "--resolve nrf:7777:127.0.0.1" " https://nrf:7777/health"; do
    [[ "${c}" == *"${part}"* ]] || fail "2: the TLS call lacks '${part}': ${c}"
  done
done
ok "the NRF on TLS: verified as nrf against the CA on 127.0.0.1, and that call decides"

# 3
[[ "$(probe "7 0" NF_NAME=nextgcore-amfd)" == 1 ]] || fail "3: a non-NRF NF without a TLS name was healthy"
[[ "$(calls)" == 1 ]] || fail "3: $(calls) calls, not the h2c one only"
ok "no TLS name: unhealthy after the h2c call alone"

# 4
[[ "$(probe "7 0" NF_NAME=nextgcore-nrfd NF_HEALTH_TLS_CA="${T}/missing.crt")" == 1 ]] \
  || fail "4: an unreadable CA was healthy"
[[ "$(calls)" == 1 ]] || fail "4: $(calls) calls with no CA"
ok "an unreadable CA: unhealthy, no TLS call"

# 5
[[ "$(probe "7 0" NF_HEALTH_ADDR=10.0.0.9 NF_HEALTH_PORT=8443 NF_HEALTH_TLS_NAME=amf)" == 0 ]] \
  || fail "5: the configured TLS probe failed"
[[ "$(call 1)" == *" http://10.0.0.9:8443/health" ]] || fail "5: h2c target: $(call 1)"
[[ "$(call 2)" == *"--resolve amf:8443:10.0.0.9"*" https://amf:8443/health" ]] || fail "5: TLS target: $(call 2)"
[[ "$(probe 0 NF_HEALTH_ADDR=fd00::7)" == 0 ]] || fail "5: IPv6 h2c probe failed"
[[ "$(call 1)" == *" http://[fd00::7]:7777/health" ]] || fail "5: IPv6 not bracketed: $(call 1)"
ok "address, port, name and CA are honoured; IPv6 is bracketed"

# 6
for args in "7 0 NF_NAME=nextgcore-nrfd" "7 1 NF_HEALTH_TLS_NAME=x"; do
  # shellcheck disable=SC2086  # args is a word list
  set -- ${args}
  probe "$1 $2" "$3" >/dev/null
  if grep -Eq -- '(^| )(-k|--insecure|--http1\.[01]|-0)( |$)' "${FAKE_LOG}"; then
    fail "6: a call skips verification or speaks HTTP/1: $(cat "${FAKE_LOG}")"
  fi
  if grep -vq -- '--http2' "${FAKE_LOG}"; then fail "6: a call is not HTTP/2: $(cat "${FAKE_LOG}")"; fi
  grep -c -- '--fail ' "${FAKE_LOG}" | grep -qx "$(wc -l < "${FAKE_LOG}" | tr -d ' ')" \
    || fail "6: a call does not fail on an HTTP error: $(cat "${FAKE_LOG}")"
done
ok "no call skips verification or speaks HTTP/1.1"

# 7
df="${HERE}/Dockerfile.core"
grep -Eq '^COPY +nf-healthcheck\.sh +/usr/local/bin/nf-healthcheck' "${df}" \
  || fail "7: Dockerfile.core does not install nf-healthcheck"
grep -A1 '^HEALTHCHECK' "${df}" | grep -q 'CMD \["\?/usr/local/bin/nf-healthcheck' \
  || fail "7: the HEALTHCHECK does not run nf-healthcheck: $(grep -A1 '^HEALTHCHECK' "${df}")"
if grep -A1 '^HEALTHCHECK' "${df}" | grep -q 'http://'; then
  fail "7: the HEALTHCHECK still probes http:// directly"
fi
ok "Dockerfile.core installs it and the HEALTHCHECK runs it"

echo "1..${pass} all passed"
