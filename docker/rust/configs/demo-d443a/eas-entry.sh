#!/bin/sh
# One EAS sidecar of the D443A compose stack (nextgsim#471): its config, a route
# back to the UEs (10.45.0.0/16) through the UPF on dn, then nr-she-eas as nobody
# with no capabilities. Its CCA key is created on first use and its public JWK
# published into the NRF's trusted directory (the d443a_cca volume).
set -eu
: "${EAS_ID:?}" "${EAS_IP:?}" "${EAS_MR:?}" "${EAS_AVL:?}" "${EAS_NF_ID:?}" "${D443A_MODE:?}"
ip route replace 10.45.0.0/16 via 10.60.0.2
mkdir -p /var/lib/d443a/keys
chown 65534:65534 /var/lib/d443a/keys /var/lib/d443a/cca
sed -e "s/@EAS@/$EAS_ID/g" -e "s/@IP@/$EAS_IP/" -e "s/@MR@/$EAS_MR/" -e "s/@AVL@/$EAS_AVL/" \
    -e "s/@ID@/$EAS_NF_ID/" -e "s/@MODE@/$D443A_MODE/" /etc/d443a/eas.yaml.in >/tmp/eas.yaml
echo $$ >/tmp/eas.pid
# shellcheck disable=SC2086  # EAS_ARGS is a flag list (--load 5, --no-kpi-patch)
exec setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all \
  --no-new-privs nr-she-eas -c /tmp/eas.yaml ${EAS_ARGS:-}
