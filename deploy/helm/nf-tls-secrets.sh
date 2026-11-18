#!/usr/bin/env bash
# nf-tls-secrets.sh -- the dev NRF TLS Secrets of a Helm release (nextgcore#1617).
#
# The chart (deploy/helm/nextgcore) mounts Secret nf-tls-<nf>[-<version>] into
# the NRF and every NF that dials it, and pins each NF's nfInstanceId, derived
# from global.siteId, the namespace, the release and the NF (or set per NF).
# Each certificate must name that ID (URI SAN urn:uuid:<id>) and the NF's type
# (RFC 9310 NFTypes), TS 33.310 §6.1.3c.3, or the NRF refuses the NF's
# NFRegister. This script:
#   1. renders the chart with your values (`helm template`, so no cluster
#      lookup; the IDs are those `helm install` pins with the same values);
#   2. reads the identity table from the rendered <release>-nf-identities
#      ConfigMap;
#   3. runs k8s/nf-tls-secrets.sh --ids <that table> on the render, which keeps
#      the current Secret version or issues a whole new one (the dev PKI of
#      docker/rust/certs/generate-dev-certs.sh; the CA key never enters the
#      cluster) and prints its version.
# Then install or upgrade with that version:
#   ver="$(deploy/helm/nf-tls-secrets.sh <release> <namespace> -f my-values.yaml)"
#   helm upgrade --install <release> deploy/helm/nextgcore -n <namespace> \
#     -f my-values.yaml --set global.nrfTls.secretVersion="${ver}"
# and, once the release runs on it, delete the superseded versions (each holds
# a private key) with k8s/nf-tls-secrets.sh --prune <namespace> "${ver}".
#
# Usage: nf-tls-secrets.sh [--dry-run] <release> <namespace> [helm template flags]...
#
# These are DEVELOPMENT certificates. For production issue them from your own
# PKI for the same table (see the chart README).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="${HERE}/nextgcore"
SECRETS="${HERE}/../../k8s/nf-tls-secrets.sh"

die() { printf 'helm nf-tls-secrets: %s\n' "$*" >&2; exit 1; }

dry=()
if [[ "${1:-}" == --dry-run ]]; then
  dry=(--dry-run)
  shift
fi
[[ $# -ge 2 ]] || die "usage: $0 [--dry-run] <release> <namespace> [helm template flags]..."
release="$1"
ns="$2"
shift 2
command -v helm >/dev/null || die "helm not found"

WORK="$(umask 077 && mktemp -d -t helm-nf-tls-XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

# secretVersion forced empty after the caller's flags: the render must name the
# unversioned nf-tls-<nf> Secrets, which is how nf-tls-secrets.sh finds the rows.
helm template "${release}" "${CHART}" -n "${ns}" "$@" \
  --set global.nrfTls.secretVersion= > "${WORK}/render.yaml" \
  || die "helm template failed"
python3 - "${WORK}/render.yaml" "${release}-nf-identities" > "${WORK}/ids.txt" <<'PY' \
  || die "the render has no usable ${release}-nf-identities ConfigMap"
import sys, yaml
want = sys.argv[2]
for d in yaml.safe_load_all(open(sys.argv[1])):
    if isinstance(d, dict) and d.get('kind') == 'ConfigMap' \
            and (d.get('metadata') or {}).get('name') == want:
        text = (d.get('data') or {}).get('nf-identities.txt') or ''
        if not text.strip():
            sys.exit('%s lists no NF' % want)
        sys.stdout.write(text)
        sys.exit(0)
sys.exit('no ConfigMap %s' % want)
PY
# Not exec: the EXIT trap must still remove WORK.
"${SECRETS}" --ids "${WORK}/ids.txt" ${dry[@]+"${dry[@]}"} "${ns}" "${WORK}/render.yaml"
