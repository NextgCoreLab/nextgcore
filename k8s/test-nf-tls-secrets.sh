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
#   7. --ids: the rows and IDs come from another table; the Helm wrapper
#      (deploy/helm/nf-tls-secrets.sh) issues each NF the ID the chart pins
#   8. --prune: a version that is not in the namespace is refused and nothing
#      is deleted; a version something still mounts is kept; the others are
#      deleted; a failure part way is finished by a re-run
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
if [ "$1 $2" = "get pods,deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs" ]; then
  if [ -s "${FAKE_USERS:-/dev/null}" ]; then cat "$FAKE_USERS"; else echo '{"items": []}'; fi
  exit 0
fi
if [ "$1 $2" = "delete secret" ]; then
  # delete secret -n <ns> -l <key>=<value>
  n=$(( $(wc -l < "$FAKE_LOG") + 1 ))
  echo delete >> "$FAKE_LOG"
  [ "${FAKE_FAIL_AT:-0}" = "$n" ] && { echo "fake: injected failure on write $n" >&2; exit 1; }
  exec python3 -c '
import json, os, sys
d, sel = sys.argv[1], sys.argv[2]
k, v = sel.split("=", 1)
for f in os.listdir(d):
    s = json.load(open(os.path.join(d, f)))
    if (s["metadata"].get("labels") or {}).get(k) == v:
        os.remove(os.path.join(d, f))' "$FAKE_STORE" "$6"
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
# Up to 60 s: issuing the PKI takes ~5 s idle and longer on a loaded runner.
for _ in $(seq 1 600); do [[ -e "${FAKE_STORE}.hang" ]] && break; sleep 0.1; done
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

# 7. --ids, and the Helm wrapper end to end
run_ids() { local ids="$1"; shift; "${SUT}" --ids "${ids}" ns "$@" 2>"${T}/err"; }
cert_of() {  # cert_of <secret file> <key>: the decoded entry
  python3 -c '
import base64, json, sys
sys.stdout.write(base64.b64decode(json.load(open(sys.argv[1]))["data"][sys.argv[2]]).decode())' "$1" "$2"
}
cat > "${T}/ids.txt" <<'IDS'
amf   AMF  0f0e0d0c-0b0a-4908-8706-050403020100  -
nrf   NRF  0f0e0d0c-0b0a-4908-8706-0504030201f0  -
IDS
manifest "${T}/ids.yaml" amf nrf
VI="$(run_ids "${T}/ids.txt" "${T}/ids.yaml" | tail -1)" || fail "7: --ids run failed: $(cat "${T}/err")"
cert_of "${FAKE_STORE}/nf-tls-amf-${VI}" amf.crt | openssl x509 -noout -text \
  | grep -q 'URI:urn:uuid:0f0e0d0c-0b0a-4908-8706-050403020100' \
  || fail "7: nf-tls-amf-${VI} does not name the --ids table's amf ID"
manifest "${T}/ids-bad.yaml" smf
if run_ids "${T}/ids.txt" "${T}/ids-bad.yaml" >/dev/null; then fail "7: a row outside the --ids table was accepted"; fi
grep -q "no row smf" "${T}/err" || fail "7: the refusal does not name the row: $(cat "${T}/err")"
command -v helm >/dev/null || fail "7: helm not found (the Helm wrapper case needs it)"
VH="$("${HERE}/../deploy/helm/nf-tls-secrets.sh" rel ns --set global.siteId=t 2>"${T}/err" | tail -1)"
[[ "${VH}" =~ ^[0-9a-f]{16}$ ]] || fail "7: the Helm wrapper printed no version: $(cat "${T}/err")"
helm template rel "${HERE}/../deploy/helm/nextgcore" -n ns --set global.siteId=t > "${T}/helm.yaml"
for nf in nrf amf smf ausf udm udr pcf nssf bsf; do
  pinned="$(python3 -c '
import sys, yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if isinstance(d, dict) and d.get("kind") == "Deployment" and d["metadata"]["name"] == "rel-" + sys.argv[2]:
        for c in d["spec"]["template"]["spec"]["containers"]:
            for e in c.get("env") or []:
                if e["name"].endswith("_INSTANCE_ID"):
                    print(e["value"])' "${T}/helm.yaml" "${nf}")"
  [[ "${pinned}" =~ ^[0-9a-f-]{36}$ ]] || fail "7: rel-${nf} pins no single ID: ${pinned}"
  cert_of "${FAKE_STORE}/nf-tls-${nf}-${VH}" "${nf}.crt" | openssl x509 -noout -text \
    | grep -q "URI:urn:uuid:${pinned}" \
    || fail "7: nf-tls-${nf}-${VH} does not name urn:uuid:${pinned}, the ID rel-${nf} pins"
done
left="$(find "${T}/tmp" -maxdepth 1 -name 'helm-nf-tls-*' | head -1)"
[[ -z "${left}" ]] || fail "7: the Helm wrapper left its render behind: ${left}"
reset_writes
VH2="$("${HERE}/../deploy/helm/nf-tls-secrets.sh" rel ns --set global.siteId=t \
  --set global.nrfTls.secretVersion="${VH}" 2>"${T}/err" | tail -1)" || true
[[ "${VH2}" == "${VH}" && "$(writes)" == 0 ]] \
  || fail "7: with secretVersion already set the wrapper printed ${VH2} after $(writes) writes, not ${VH} after 0: $(cat "${T}/err")"
ok "--ids issues the table's IDs and refuses other rows; the Helm wrapper's ${VH} names each ID the chart pins, and is kept on a re-run that names it"

# 8. --prune
prune() { "${SUT}" --prune ns "$@" 2>"${T}/err"; }
vers() { python3 -c '
import json, os, sys
d = sys.argv[1]
print(" ".join(sorted({json.load(open(os.path.join(d, f)))["metadata"]["labels"]["nextg.io/nf-tls-ca"] for f in os.listdir(d)})))' "${FAKE_STORE}"; }
all_before="$(vers)"
reset_writes
if prune 0123456789abcdef; then fail "8: a version that is not in the namespace was accepted"; fi
grep -q "refusing to prune" "${T}/err" || fail "8: the refusal is not named: $(cat "${T}/err")"
[[ "$(vers)" == "${all_before}" && "$(writes)" == 0 ]] || fail "8: a refused prune deleted something"
# A pod still mounts V2; a Deployment's template mounts V3 (projected); an old
# ReplicaSet (replicas 0) mounts V1, which does not keep it.
cat > "${T}/users.json" <<JSON
{"items": [
 {"kind": "Pod", "metadata": {"name": "amf-x"}, "spec": {"volumes": [{"name": "nf-tls", "secret": {"secretName": "nf-tls-amf-${V2}"}}]}},
 {"kind": "Deployment", "metadata": {"name": "smf"}, "spec": {"template": {"spec": {"volumes": [{"name": "nf-tls", "projected": {"sources": [{"secret": {"name": "nf-tls-smf-${V3}"}}]}}]}}}},
 {"kind": "ReplicaSet", "metadata": {"name": "amf-old"}, "spec": {"replicas": 0, "template": {"spec": {"volumes": [{"name": "nf-tls", "secret": {"secretName": "nf-tls-amf-${V1}"}}]}}}}
]}
JSON
export FAKE_USERS="${T}/users.json"
reset_writes
if FAKE_FAIL_AT=2 prune "${VH}"; then fail "8: an injected delete failure was not reported"; fi
for v in "${V2}" "${V3}" "${VH}"; do [[ " $(vers) " == *" ${v} "* ]] || fail "8: version ${v} was deleted"; done
grep -q "re-run --prune to finish" "${T}/err" || fail "8: the failure does not say how to finish: $(cat "${T}/err")"
prune "${VH}" || fail "8: the re-run failed: $(cat "${T}/err")"
want="$(printf '%s\n' "${V2}" "${V3}" "${VH}" | sort | tr '\n' ' ' | sed 's/ $//')"
[[ "$(vers)" == "${want}" ]] || fail "8: after the re-run the versions are $(vers), not ${want}"
grep -q "kept version ${V2}: still mounted by Pod/amf-x" "${T}/err" || fail "8: the pod's version is not named kept: $(cat "${T}/err")"
grep -q "kept version ${V3}: still mounted by Deployment/smf" "${T}/err" || fail "8: the Deployment's version is not named kept"
unset FAKE_USERS
ok "--prune refuses an absent version, keeps the mounted ones (${V2} pod, ${V3} template), deletes the rest, and a re-run finishes a failed one"

echo "1..${pass} all passed"
