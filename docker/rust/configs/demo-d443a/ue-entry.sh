#!/bin/sh
# The D443A UE (nextgsim#471): nextgsim's config/ue.yaml with she_enabled, the
# eec: block (IP literals: every EEC socket is bound to uesimtun0, so names are
# not resolved) and the demo: block.
set -eu
: "${D443A_MODE:?}"
f=/tmp/ue.yaml
sed 's/^she_enabled:.*/she_enabled: true/' /etc/nextgsim/ue.yaml >"$f"
grep -q '^she_enabled: true' "$f" || echo 'she_enabled: true' >>"$f"
if grep -qE '^(eec|demo):' "$f"; then echo "ue.yaml already has eec: or demo:" >&2; exit 1; fi
cat >>"$f" <<YAML

eec:
  ees: "http://172.23.0.31:7777"
  device: uesimtun0
  eec_id: eec-d443a-ue1
  ac_id: ac-d443a
  eass: [eas-local, eas-regional, eas-cloud]
  req_comp: 100
  deadline_ms: 15
  job_port: 9471
  oauth2:
    nrf: "https://172.23.0.10:7777"
    nf_instance_id: 6b1d7e3c-0000-4000-8000-0000000471ec
    cca_key_file: /var/lib/d443a/keys/eec.key
    public_jwk_dir: /var/lib/d443a/cca
    register: true
demo:
  enabled: true
  d443a-edge-budget:
    enabled: true
    mode: ${D443A_MODE}
YAML
mkdir -p /var/lib/d443a/keys
exec nr-ue -c "$f"
