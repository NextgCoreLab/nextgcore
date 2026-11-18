#!/usr/bin/env bash
# Tests of k8s/nf-tls-secrets.sh (nextgcore#1617) against a fake kubectl that
# keeps Secrets in a directory and can fail or stall its Nth write. The
# offline kubectl subcommands (create --dry-run=client, label --local) are the
# real kubectl's.
#
#   1. a fresh namespace gets one complete version; --stamp points a manifest at it
#   2. a re-run writes nothing and prints the same version (idempotent)
#   3. a rejected request (an unknown row) writes nothing
#   4. a failure on the Nth write of a re-issue leaves the version in use
#      untouched; the next run issues a complete new version, never the partial one
#   5. an interrupt (SIGTERM) part way leaves the version in use untouched and
#      no CA key on disk
#   6. a key that is not its certificate's is not kept
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT="${HERE}/nf-tls-secrets.sh"
REAL_KUBECTL="$(command -v kubectl)" || { echo "kubectl (for its offline subcommands) not found" >&2; exit 1; }
T="$(mktemp -d -t nf-tls-test-XXXXXX)"
trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin" "${T}/store" "${T}/tmp"
export REAL_KUBECTL FAKE_STORE="${T}/store" FAKE_LOG="${T}/writes"
: > "${FAKE_LOG}"

cat > "${T}/bin/kubectl" <<'SH'
#!/usr/bin/env bash
# Fake kubectl: Secrets as JSON files in $FAKE_STORE. FAKE_FAIL_AT=N fails the
# Nth write, FAKE_HANG_AT=N stalls it (touching $FAKE_STORE.hang first).
if [ "$1 $2" = "get secrets" ]; then
  python3 - "$FAKE_STORE" <<'PY'
import json, os, sys
d = sys.argv[1]
print(json.dumps({'items': [json.load(open(os.path.join(d, f))) for f in sorted(os.listdir(d))]}))
PY
  exit 0
fi
if [ "$1" = create ] && [ "$2" = -f ]; then
  n=$(( $(wc -l < "$FAKE_LOG") + 1 ))
  echo write >> "$FAKE_LOG"
  [ "${FAKE_FAIL_AT:-0}" = "$n" ] && { echo "fake: injected failure on write $n" >&2; exit 1; }
  if [ "${FAKE_HANG_AT:-0}" = "$n" ]; then touch "$FAKE_STORE.hang"; sleep 3; fi
  exec python3 -c '
import json, os, sys, time, yaml
d = yaml.safe_load(sys.stdin)
d["metadata"]["creationTimestamp"] = "%.9f" % time.time()
p = os.path.join(sys.argv[1], d["metadata"]["name"])
if os.path.exists(p):
    sys.exit("AlreadyExists")
json.dump(d, open(p, "w"))' "$FAKE_STORE"
fi
exec "$REAL_KUBECTL" "$@"
SH
chmod +x "${T}/bin/kubectl"
export PATH="${T}/bin:${PATH}" TMPDIR="${T}/tmp"

pass=0
ok()   { pass=$((pass + 1)); echo "ok ${pass} - $*"; }
fail() { echo "not ok - $*" >&2; exit 1; }
writes() { wc -l < "${FAKE_LOG}" | tr -d ' '; }
reset_writes() { : > "${FAKE_LOG}"; }
store_sum() { cat "${FAKE_STORE}"/* | sha256sum | cut -c1-64; }
vsum() { cat "${FAKE_STORE}"/*"-$1" | sha256sum | cut -c1-64; }  # one version's Secrets
manifest() {  # manifest <file> <row>...
  local f="$1"; shift
  { for r in "$@"; do
      printf -- '---\nkind: Deployment\nmetadata: {name: %s}\nspec:\n  template:\n    spec:\n      volumes:\n        - name: nf-tls\n          secret: {secretName: nf-tls-%s, defaultMode: 0440}\n' "$r" "$r"
    done; } > "$f"
}
run() { "${SUT}" ns "$@" 2>"${T}/err"; }

manifest "${T}/base.yaml" nrf amf smf ca
manifest "${T}/plus.yaml" nwdaf
manifest "${T}/plus2.yaml" nef

# 1. fresh
V1="$(run "${T}/base.yaml" | tail -1)"
[[ "${V1}" =~ ^[0-9a-f]{16}$ ]] || fail "1: no version printed: ${V1}"
[[ "$(writes)" == 4 ]] || fail "1: $(writes) writes, not 4"
for r in nrf amf smf ca; do [[ -f "${FAKE_STORE}/nf-tls-${r}-${V1}" ]] || fail "1: nf-tls-${r}-${V1} missing"; done
"${SUT}" --stamp "${V1}" "${T}/base.yaml" > "${T}/stamped.yaml"
grep -q "secretName: nf-tls-amf-${V1}" "${T}/stamped.yaml" || fail "1: --stamp did not point amf at ${V1}"
grep -q "nextg.io/nf-tls-ca: ${V1}" "${T}/stamped.yaml" || fail "1: --stamp did not annotate"
ok "a fresh namespace gets one complete version ${V1}; --stamp points the manifests at it"

# 2. idempotent
reset_writes
[[ "$(run "${T}/base.yaml" | tail -1)" == "${V1}" ]] || fail "2: the version changed"
[[ "$(writes)" == 0 ]] || fail "2: a re-run wrote $(writes) Secrets"
ok "a re-run writes nothing and keeps ${V1}"

# 3. rejected
manifest "${T}/bogus.yaml" no-such-row
reset_writes
if run "${T}/bogus.yaml" >/dev/null; then fail "3: an unknown row was accepted"; fi
grep -q "no row no-such-row" "${T}/err" || fail "3: the refusal does not name the row: $(cat "${T}/err")"
[[ "$(writes)" == 0 ]] || fail "3: a refused request wrote $(writes) Secrets"
ok "an unknown row is refused and writes nothing"

# 4. failure on the Nth write of a re-issue (a new row forces it)
before="$(store_sum)"
reset_writes
if FAKE_FAIL_AT=3 run "${T}/base.yaml" "${T}/plus.yaml" >/dev/null; then fail "4: the injected failure was not reported"; fi
for r in nrf amf smf ca; do [[ -f "${FAKE_STORE}/nf-tls-${r}-${V1}" ]] || fail "4: ${V1} lost nf-tls-${r}"; done
vsum "${V1}" > "${T}/v1sum"
[[ "$(cat "${T}/v1sum")" == "$(printf '%s' "${before}")" ]] || fail "4: the version in use was modified"
reset_writes
V2="$(run "${T}/base.yaml" "${T}/plus.yaml" | tail -1)"
[[ "${V2}" != "${V1}" ]] || fail "4: no new version after the failed one"
[[ "$(writes)" == 5 ]] || fail "4: the new version wrote $(writes) Secrets, not its whole set of 5"
for r in nrf amf smf ca nwdaf; do [[ -f "${FAKE_STORE}/nf-tls-${r}-${V2}" ]] || fail "4: ${V2} lacks nf-tls-${r}"; done
[[ "$(vsum "${V1}")" == "$(cat "${T}/v1sum")" ]] \
  || fail "4: issuing ${V2} modified ${V1}"
ok "a failure on write 3 leaves ${V1} as it was; the next run issues complete ${V2}, not the partial set"

# 5. interrupt part way
v2sum="$(vsum "${V2}")"
reset_writes
rm -f "${FAKE_STORE}.hang"
FAKE_HANG_AT=2 "${SUT}" ns "${T}/base.yaml" "${T}/plus.yaml" "${T}/plus2.yaml" > "${T}/out5" 2>"${T}/err" &
pid=$!
for _ in $(seq 1 100); do [[ -e "${FAKE_STORE}.hang" ]] && break; sleep 0.1; done
[[ -e "${FAKE_STORE}.hang" ]] || fail "5: the run never reached its second write"
kill -TERM "${pid}"
rc=0; wait "${pid}" || rc=$?
[[ "${rc}" != 0 ]] || fail "5: an interrupted run exited 0"
[[ ! -s "${T}/out5" ]] || fail "5: an interrupted run printed a version: $(cat "${T}/out5")"
leftover="$(find "${T}/tmp" -name 'ca.key' | head -1)"
[[ -z "${leftover}" ]] || fail "5: the CA key survived the interrupt: ${leftover}"
[[ "$(vsum "${V2}")" == "${v2sum}" ]] \
  || fail "5: the interrupt modified ${V2}"
reset_writes
[[ "$(run "${T}/base.yaml" "${T}/plus.yaml" | tail -1)" == "${V2}" ]] || fail "5: ${V2} is no longer the one kept"
[[ "$(writes)" == 0 ]] || fail "5: after the interrupt a re-run wrote $(writes)"
ok "SIGTERM part way prints no version, leaves no CA key and leaves ${V2} in use"

# 6. a key that is not its certificate's
python3 - "${FAKE_STORE}" "${V2}" <<'PY'
import json, os, sys
d, v = sys.argv[1:3]
a = json.load(open(os.path.join(d, 'nf-tls-amf-' + v)))
s = json.load(open(os.path.join(d, 'nf-tls-smf-' + v)))
a['data']['amf.key'] = s['data']['smf.key']
json.dump(a, open(os.path.join(d, 'nf-tls-amf-' + v), 'w'))
PY
V3="$(run "${T}/base.yaml" "${T}/plus.yaml" | tail -1)"
[[ "${V3}" != "${V2}" ]] || fail "6: a version whose amf.key is smf's was kept"
grep -q "amf.key is not the key of amf.crt" "${T}/err" || fail "6: the reason is not named: $(cat "${T}/err")"
ok "a mismatched key is not kept (${V3} issued)"

echo "1..${pass} all passed"
