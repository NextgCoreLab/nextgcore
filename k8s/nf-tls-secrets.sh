#!/usr/bin/env bash
# nf-tls-secrets.sh -- the NRF and its clients' TLS Secrets (nextgcore#1617).
#
# Every pod that talks to the NRF, and the NRF itself, mounts one Secret
# nf-tls-<name> at /etc/nextgcore/certs (k8s/manifests, deploy/eks overlays).
# <name> is a row of docker/rust/certs/nf-identities.txt, and the Secret holds
#   ca.crt  <name>.crt  <name>.key
# issued by docker/rust/certs/generate-dev-certs.sh with the NF TLS
# certificate profile of TS 33.310 §6.1.3c.3: subjectAltName
# urn:uuid:<nfInstanceId> and the RFC 9310 NFTypes of the row, which the NRF
# binds NFRegister / NFUpdate / NFDeregister to. nf-tls-ca holds ca.crt only,
# for a client that only discovers (it has no identity to present).
#
# Usage:
#   nf-tls-secrets.sh <namespace> <manifest>...   create or keep the Secrets;
#                                                 prints the CA version
#   nf-tls-secrets.sh --dry-run <namespace> <manifest>...
#                                                 list them; no cluster access
#   nf-tls-secrets.sh --stamp <version> <manifest>
#                                                 print the manifest pointed at
#                                                 that version (below)
#
# One CA, one version. The Secrets of a CA are named nf-tls-<name>-<version>,
# <version> being the first 16 hex digits of the sha256 of its ca.crt, and
# labelled nextg.io/nf-tls-ca=<version>. The manifests mount nf-tls-<name>;
# --stamp rewrites each such secretName to nf-tls-<name>-<version> and stamps
# the pod template with annotation nextg.io/nf-tls-ca=<version>, so applying
# the stamped manifests moves the NRF and every client to that CA together.
#
# The CA key never enters the cluster: the PKI is issued into a private
# temporary directory that is deleted on exit (also on SIGINT / SIGTERM / SIGHUP).
# So the Secrets are the state:
#   - a version that has every needed Secret, each certificate chaining to its
#     ca.crt, matching its key, naming its row's urn:uuid and valid for 30 more
#     days, is kept (the newest such version) and nothing is written;
#   - otherwise a new CA is issued and its whole set is created under the new
#     version. Nothing a running pod mounts is touched: the old version's
#     Secrets stay as they were. A failure or an interrupt part way therefore
#     leaves the running stack on its one CA, and the incomplete new version is
#     never printed, never stamped, and not kept by the next run (which issues
#     a fresh one). Older versions are left in place, unreferenced once the
#     stamped manifests are applied; the script names them, it deletes nothing.
#
# Secrets are written with kubectl create, never apply, so no
# last-applied-configuration annotation copies a private key.
# shellcheck disable=SC2086  # ${needed}: row names ([a-z0-9-]), split on purpose
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$(cd "${SCRIPT_DIR}/../docker/rust/certs" && pwd)"
TABLE="${CERTS_DIR}/nf-identities.txt"
LABEL="nextg.io/nf-tls-ca"
# Re-issue when a certificate expires within this many seconds (30 days).
MIN_VALIDITY=2592000

die() { printf 'nf-tls-secrets: %s\n' "$*" >&2; exit 1; }
say() { printf 'nf-tls-secrets: %s\n' "$*" >&2; }

if [[ "${1:-}" == --stamp ]]; then
  [[ $# -eq 3 && "$2" =~ ^[0-9a-f]{16}$ ]] || die "usage: $0 --stamp <version> <manifest>"
  exec python3 - "$2" "$3" "${LABEL}" <<'PY'
import re, sys, yaml
ver, path, key = sys.argv[1:4]
out = []
for d in yaml.safe_load_all(open(path)):
    if not d:
        continue
    tmpl = (d.get('spec') or {}).get('template') if isinstance(d, dict) else None
    stamped = False
    for v in ((tmpl or {}).get('spec') or {}).get('volumes') or []:
        s = v.get('secret') or {}
        if re.fullmatch(r'nf-tls-[a-z0-9-]+', s.get('secretName') or ''):
            s['secretName'] = '%s-%s' % (s['secretName'], ver)
            stamped = True
    if stamped:
        tmpl.setdefault('metadata', {}).setdefault('annotations', {})[key] = ver
    out.append(d)
yaml.safe_dump_all(out, sys.stdout, default_flow_style=False)
PY
fi

DRY_RUN=false
if [[ "${1:-}" == --dry-run ]]; then
  DRY_RUN=true
  shift
fi
[[ $# -ge 2 ]] || die "usage: $0 [--dry-run] <namespace> <manifest>..."
NS="$1"
shift

# The rows the manifests mount, one per line.
needed="$(python3 - "$@" <<'PY'
import re, sys, yaml
names = set()
for path in sys.argv[1:]:
    for d in yaml.safe_load_all(open(path)):
        if not isinstance(d, dict):
            continue
        tmpl = (d.get('spec') or {}).get('template') or {}
        for v in (tmpl.get('spec') or {}).get('volumes') or []:
            m = re.fullmatch(r'nf-tls-([a-z0-9-]+)',
                             (v.get('secret') or {}).get('secretName') or '')
            if m:
                names.add(m.group(1))
print('\n'.join(sorted(names)))
PY
)"
if [[ -z "${needed}" ]]; then
  # A stack without an NRF (PROFILE=epc): nothing to issue, no CA to stamp.
  say "no pod template mounts an nf-tls-* Secret; none needed"
  exit 0
fi

row_id() { awk -v n="$1" '$1 !~ /^#/ && $1 == n { print $3 }' "${TABLE}"; }
for n in ${needed}; do
  [[ "${n}" == ca || -n "$(row_id "${n}")" ]] \
    || die "Secret nf-tls-${n}: no row ${n} in ${TABLE}"
done

if [[ "${DRY_RUN}" == true ]]; then
  say "would create or keep in ${NS}: $(printf 'nf-tls-%s ' ${needed})"
  exit 0
fi

command -v kubectl >/dev/null || die "kubectl not found"
command -v openssl >/dev/null || die "openssl not found (needed to issue the dev PKI)"

WORK="$(umask 077 && mktemp -d -t nf-tls-XXXXXX)"
cleanup() { rm -rf "${WORK}"; }
# bash runs the EXIT trap on INT, TERM and HUP too (test-nf-tls-secrets.sh 5).
# Only a SIGKILL leaves WORK (0700, under TMPDIR) behind.
trap cleanup EXIT

# --- keep a complete, current version ---------------------------------------
kubectl get secrets -n "${NS}" -l "${LABEL}" -o json > "${WORK}/all.json" \
  || die "cannot list Secrets in ${NS}"
# Versions, newest first; each one's Secrets unpacked into WORK/v/<version>/.
versions="$(python3 - "${WORK}/all.json" "${WORK}/v" "${LABEL}" <<'PY'
import base64, json, os, sys
items = json.load(open(sys.argv[1])).get('items') or []
newest = {}
for s in items:
    meta = s.get('metadata') or {}
    ver = (meta.get('labels') or {}).get(sys.argv[3], '')
    name = meta.get('name', '')
    if len(ver) != 16 or not name.startswith('nf-tls-') or not name.endswith('-' + ver):
        continue
    row = name[len('nf-tls-'):-len(ver) - 1]
    d = os.path.join(sys.argv[2], ver, row)
    os.makedirs(d, mode=0o700, exist_ok=True)
    for k, b in (s.get('data') or {}).items():
        with open(os.path.join(d, k), 'wb') as f:
            f.write(base64.b64decode(b))
    newest[ver] = max(newest.get(ver, ''), meta.get('creationTimestamp', ''))
print(' '.join(sorted(newest, key=lambda v: newest[v], reverse=True)))
PY
)" || die "cannot read the nf-tls Secrets of ${NS}"

current() {  # current <version>: every needed Secret of that version is good
  local ver="$1" n d id ca
  for n in ${needed}; do
    d="${WORK}/v/${ver}/${n}"
    ca="${d}/ca.crt"
    [[ -f "${ca}" ]] || { say "version ${ver}: nf-tls-${n} is absent"; return 1; }
    [[ "$(sha256sum "${ca}" | cut -c1-16)" == "${ver}" ]] \
      || { say "version ${ver}: nf-tls-${n} carries another CA"; return 1; }
    if [[ "${n}" == ca ]]; then
      [[ "$(find "${d}" -mindepth 1 -printf '%f\n')" == ca.crt ]] || { say "version ${ver}: nf-tls-ca holds more than ca.crt"; return 1; }
      continue
    fi
    [[ "$(find "${d}" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ')" == "$(printf '%s\n' ca.crt "${n}.crt" "${n}.key" | sort | tr '\n' ' ')" ]] \
      || { say "version ${ver}: nf-tls-${n} does not hold exactly ca.crt ${n}.crt ${n}.key"; return 1; }
    id="$(row_id "${n}")"
    openssl verify -CAfile "${ca}" "${d}/${n}.crt" >/dev/null 2>&1 \
      || { say "version ${ver}: ${n}.crt does not chain to its ca.crt"; return 1; }
    openssl x509 -in "${d}/${n}.crt" -noout -checkend "${MIN_VALIDITY}" >/dev/null \
      || { say "version ${ver}: ${n}.crt expires within 30 days"; return 1; }
    openssl x509 -in "${d}/${n}.crt" -noout -text | grep -qi "URI:urn:uuid:${id}" \
      || { say "version ${ver}: ${n}.crt does not name urn:uuid:${id}"; return 1; }
    # The key is the certificate's: compare the public keys.
    [[ "$(openssl x509 -in "${d}/${n}.crt" -noout -pubkey 2>/dev/null)" \
       == "$(openssl pkey -in "${d}/${n}.key" -pubout 2>/dev/null)" ]] \
      || { say "version ${ver}: ${n}.key is not the key of ${n}.crt"; return 1; }
  done
  openssl x509 -in "${WORK}/v/${ver}/$(printf '%s\n' ${needed} | head -1)/ca.crt" -noout \
    -checkend "${MIN_VALIDITY}" >/dev/null || { say "version ${ver}: the CA expires within 30 days"; return 1; }
}

keep=""
for ver in ${versions}; do
  if current "${ver}"; then
    keep="${ver}"
    break
  fi
done

if [[ -n "${keep}" ]]; then
  say "kept version ${keep}: $(printf 'nf-tls-%s ' ${needed})(current)"
  ver="${keep}"
else
  # --- issue a new CA and create its whole set under a new version ---------
  say "issuing a new dev PKI for ${NS} (the CA key stays in ${WORK} and is deleted on exit)"
  bash "${CERTS_DIR}/generate-dev-certs.sh" --out "${WORK}/pki" >/dev/null \
    || die "generate-dev-certs.sh failed"
  ver="$(sha256sum "${WORK}/pki/ca.crt" | cut -c1-16)"
  for n in ${needed}; do
    files=(--from-file="ca.crt=${WORK}/pki/ca.crt")
    if [[ "${n}" != ca ]]; then
      files+=(--from-file="${n}.crt=${WORK}/pki/${n}.crt"
              --from-file="${n}.key=${WORK}/pki/${n}.key")
    fi
    kubectl create secret generic "nf-tls-${n}-${ver}" -n "${NS}" "${files[@]}" \
      --dry-run=client -o yaml \
      | kubectl label --local -f - -o yaml "${LABEL}=${ver}" app.kubernetes.io/part-of=nextgcore \
      | kubectl create -f - >/dev/null \
      || die "could not create Secret nf-tls-${n}-${ver}; the running stack keeps its CA (version ${ver} is incomplete and will not be used)"
    say "created nf-tls-${n}-${ver}"
  done
  say "these are DEVELOPMENT certificates. Replace them for any real use."
fi
others="$(printf '%s\n' ${versions} | grep -vx "${ver}" | tr '\n' ' ' || true)"
[[ -z "${others// /}" ]] \
  || say "older versions left in place (unreferenced once the stamped manifests are applied): ${others}"
printf '%s\n' "${ver}"
