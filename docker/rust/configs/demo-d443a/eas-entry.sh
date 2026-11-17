#!/bin/sh
# One EAS sidecar of the D443A compose stack (nextgsim#471): its config, routes
# to the UEs (10.45.0.0/16) and to core (eesd, the NRF) through the UPF on dn,
# its emulated distance (netem), then nr-she-eas as its own uid (EAS_UID: 65531,
# 65532, 65533) with no capabilities. Its CCA key is created on first use, as
# that uid, in this container's /tmp (it never leaves the container), and its
# public JWK published into the NRF's trusted directory (the d443a_cca volume).
# That directory is shared and sticky: an EAS cannot replace another's JWK, but
# one that starts first could take another's file name (labelled: compose only;
# on EKS each EAS publishes into a directory of its own).
set -eu
: "${EAS_DIST_MS:?}" "${EAS_UID:?}" "${EAS_ID:?}" "${EAS_IP:?}" "${EAS_MR:?}" "${EAS_AVL:?}" "${EAS_NF_ID:?}" "${D443A_MODE:?}"
ip route replace 10.45.0.0/16 via 10.60.0.2
# eesd and the NRF on core, through the UPF (which masquerades dn -> core).
ip route replace 172.23.0.0/24 via 10.60.0.2
# The emulated distance (labelled): netem on this EAS's egress toward the UPF,
# one way, so upfd's STAMP one-way N6 delay is half of it (local 4 -> 2 ms,
# regional 6 -> 3, cloud 40 -> 20, the plan's Act 1 values). Act 2 changes
# eas-local's to 20 ms (the header's act commands).
tc qdisc add dev eth0 root netem delay "${EAS_DIST_MS:?}ms"
# The shared JWK directory, sticky and world-writable like /tmp, so each EAS uid
# publishes its own public JWK there (no CHOWN in this container).
chmod 1777 /var/lib/d443a/cca
sed -e "s/@EAS@/$EAS_ID/g" -e "s/@IP@/$EAS_IP/" -e "s/@MR@/$EAS_MR/" -e "s/@AVL@/$EAS_AVL/" \
    -e "s/@ID@/$EAS_NF_ID/" -e "s/@MODE@/$D443A_MODE/" /etc/d443a/eas.yaml.in >/tmp/eas.yaml
echo $$ >/tmp/eas.pid
# shellcheck disable=SC2086  # EAS_ARGS is a flag list (--load 5, --no-kpi-patch)
exec setpriv --reuid="${EAS_UID}" --regid="${EAS_UID}" --clear-groups --inh-caps=-all \
  --no-new-privs nr-she-eas -c /tmp/eas.yaml ${EAS_ARGS:-}
