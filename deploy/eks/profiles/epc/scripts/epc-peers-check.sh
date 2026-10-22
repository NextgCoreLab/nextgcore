#!/bin/sh
# Liveness probe: fail when a peer recorded by epc-run.sh now resolves to a
# different pod IP. The kubelet restarts the container, and epc-run.sh then
# re-resolves. Not failing while a peer has no address at all (it is being
# replaced); that resolves on a later probe.
STATE=/run/epc/peers
[ -f "$STATE" ] || exit 0
while read -r name ip; do
  [ -n "$name" ] || continue
  cur=$(getent ahostsv4 "$name.${POD_NAMESPACE}.svc.cluster.local" | cut -d' ' -f1 | sort -u)
  [ -n "$cur" ] || continue
  if ! echo "$cur" | grep -qx "$ip"; then
    echo "peer $name moved: $ip -> $(echo "$cur" | tr '\n' ' ')"
    exit 1
  fi
done < "$STATE"
exit 0
