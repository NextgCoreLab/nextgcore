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
#   nf-tls-secrets.sh <namespace> <manifest>...   create or keep the Secrets
#   nf-tls-secrets.sh --dry-run <namespace> <manifest>...
#                                                 list them; no cluster access
#   nf-tls-secrets.sh --annotate <ca-sha> <manifest>
#                                                 print the manifest with each
#                                                 pod template that mounts an
#                                                 nf-tls-* Secret annotated
#                                                 nextg.io/nf-tls-ca: <ca-sha>
#
# The Secrets needed are the nf-tls-* secretNames the manifests' pod templates
# mount. The CA key never enters the cluster: the PKI is issued into a private
# temporary directory that is deleted on exit. So the Secrets are the state:
#   - every needed Secret exists, all of them carry one ca.crt, and each
#     <name>.crt chains to it, names its row's urn:uuid and is valid for 30
#     more days: they are kept and nothing is written;
#   - otherwise a fresh CA is issued and EVERY nf-tls-* Secret of the namespace
#     (needed now or already there) is rewritten from it, so a namespace never
#     holds two CAs.
# The last line of stdout is the sha256 of the ca.crt in force (nothing when no
# manifest mounts one). The deploy
# scripts stamp it on each pod template that mounts one (--annotate), so a
# re-issue rolls the NRF and every client onto the new CA together.
#
# Secrets are written with kubectl create / replace, never apply, so no
# last-applied-configuration annotation copies a private key.
# shellcheck disable=SC2086  # ${needed} / ${existing}: row names ([a-z0-9-]), split on purpose
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$(cd "${SCRIPT_DIR}/../docker/rust/certs" && pwd)"
TABLE="${CERTS_DIR}/nf-identities.txt"
ANNOTATION="nextg.io/nf-tls-ca"
# Re-issue when a certificate expires within this many seconds (30 days).
MIN_VALIDITY=2592000

die() { printf 'nf-tls-secrets: %s\n' "$*" >&2; exit 1; }
say() { printf 'nf-tls-secrets: %s\n' "$*" >&2; }

if [[ "${1:-}" == --annotate ]]; then
  [[ $# -eq 3 ]] || die "usage: $0 --annotate <ca-sha> <manifest>"
  exec python3 - "$2" "$3" "${ANNOTATION}" <<'PY'
import re, sys, yaml
sha, path, key = sys.argv[1:4]
out = []
for d in yaml.safe_load_all(open(path)):
    if not d:
        continue
    tmpl = (d.get('spec') or {}).get('template') if isinstance(d, dict) else None
    vols = ((tmpl or {}).get('spec') or {}).get('volumes') or []
    if any(re.fullmatch(r'nf-tls-[a-z0-9-]+', (v.get('secret') or {}).get('secretName') or '')
           for v in vols):
        tmpl.setdefault('metadata', {}).setdefault('annotations', {})[key] = sha
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
trap 'rm -rf "${WORK}"' EXIT

# --- keep the Secrets when they are current --------------------------------
existing="$(kubectl get secrets -n "${NS}" -o name 2>/dev/null | sed -n 's|^secret/nf-tls-||p')" \
  || die "cannot list Secrets in ${NS}"

current() {
  local n ca="" json="${WORK}/cur.json" id
  mkdir -p "${WORK}/cur"
  for n in ${needed}; do
    kubectl get secret "nf-tls-${n}" -n "${NS}" -o json > "${json}" 2>/dev/null \
      || { say "nf-tls-${n} is absent"; return 1; }
    python3 - "${json}" "${WORK}/cur" "${n}" <<'PY' || { say "nf-tls-${n} lacks a file"; return 1; }
import base64, json, os, sys
data = json.load(open(sys.argv[1])).get('data') or {}
n = sys.argv[3]
want = ['ca.crt'] if n == 'ca' else ['ca.crt', n + '.crt', n + '.key']
if sorted(data) != sorted(want):
    sys.exit(1)
for k in want:
    if k.endswith('.key'):
        continue
    with open(os.path.join(sys.argv[2], n + '-' + k), 'wb') as f:
        f.write(base64.b64decode(data[k]))
PY
    if [[ -z "${ca}" ]]; then
      ca="${WORK}/cur/${n}-ca.crt"
    elif ! cmp -s "${ca}" "${WORK}/cur/${n}-ca.crt"; then
      say "nf-tls-${n} carries another CA"
      return 1
    fi
    [[ "${n}" == ca ]] && continue
    id="$(row_id "${n}")"
    openssl verify -CAfile "${ca}" "${WORK}/cur/${n}-${n}.crt" >/dev/null 2>&1 \
      || { say "nf-tls-${n}: ${n}.crt does not chain to its ca.crt"; return 1; }
    openssl x509 -in "${WORK}/cur/${n}-${n}.crt" -noout -checkend "${MIN_VALIDITY}" >/dev/null \
      || { say "nf-tls-${n}: ${n}.crt expires within 30 days"; return 1; }
    openssl x509 -in "${WORK}/cur/${n}-${n}.crt" -noout -text | grep -qi "URI:urn:uuid:${id}" \
      || { say "nf-tls-${n}: ${n}.crt does not name urn:uuid:${id}"; return 1; }
  done
  openssl x509 -in "${ca}" -noout -checkend "${MIN_VALIDITY}" >/dev/null \
    || { say "the CA expires within 30 days"; return 1; }
  cp "${ca}" "${WORK}/ca.crt"
}

if current; then
  say "kept $(printf 'nf-tls-%s ' ${needed})(current, one CA)"
else
  # --- issue a fresh PKI and rewrite every nf-tls-* Secret -----------------
  say "issuing a new dev PKI for ${NS} (the CA key stays in ${WORK} and is deleted on exit)"
  bash "${CERTS_DIR}/generate-dev-certs.sh" --out "${WORK}/pki" >/dev/null \
    || die "generate-dev-certs.sh failed"
  cp "${WORK}/pki/ca.crt" "${WORK}/ca.crt"
  for n in $(printf '%s\n' ${needed} ${existing} | sort -u); do
    if [[ "${n}" != ca && -z "$(row_id "${n}")" ]]; then
      say "WARN: leaving nf-tls-${n} alone: no row ${n} in ${TABLE}"
      continue
    fi
    files=(--from-file="ca.crt=${WORK}/pki/ca.crt")
    if [[ "${n}" != ca ]]; then
      files+=(--from-file="${n}.crt=${WORK}/pki/${n}.crt"
              --from-file="${n}.key=${WORK}/pki/${n}.key")
    fi
    verb=create
    printf '%s\n' ${existing} | grep -qx "${n}" && verb=replace
    kubectl create secret generic "nf-tls-${n}" -n "${NS}" "${files[@]}" \
      --dry-run=client -o yaml \
      | kubectl label --local -f - -o yaml app.kubernetes.io/part-of=nextgcore \
      | kubectl "${verb}" -f - >/dev/null \
      || die "could not ${verb} Secret nf-tls-${n}"
    say "${verb}d nf-tls-${n}"
  done
  say "these are DEVELOPMENT certificates. Replace them for any real use."
fi
sha256sum "${WORK}/ca.crt" | cut -c1-16
