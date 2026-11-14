#!/bin/sh
# A D445A UE (nextgsim#480): nextgsim's config/ue.yaml with this UE's IMSI, the
# demo block and the fl: block for member $FL_MEMBER; the stack is 3 members in
# t8-exclusion, 5 in poisoned-ue.
set -eu
: "${FL_MEMBER:?}" "${D445A_MODE:?}"
case "$D445A_MODE" in t8-exclusion) clients=3 ;; poisoned-ue) clients=5 ;; *) echo "mode $D445A_MODE" >&2; exit 1 ;; esac
f=/tmp/ue.yaml
# nextgsim's ue.yaml carries `federated_learning_enabled: false`; flip it in place
# (a second key would be a duplicate the parser refuses).
sed 's/^federated_learning_enabled:.*/federated_learning_enabled: true/' /etc/nextgsim/ue.yaml >"$f"
grep -q '^federated_learning_enabled: true' "$f" || echo 'federated_learning_enabled: true' >>"$f"
if grep -qE '^(fl|demo):' "$f"; then echo "ue.yaml already has fl: or demo:" >&2; exit 1; fi
cat >>"$f" <<YAML

fl:
  server: 10.46.0.10:7480
  device: uesimtun0
  member: ${FL_MEMBER}
  clients: ${clients}
  seed: 480
demo:
  enabled: true
  d445a-fl-t8:
    enabled: true
    mode: ${D445A_MODE}
YAML
exec nr-ue -c "$f" -i "99970000000000${FL_MEMBER}"
