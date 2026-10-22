#!/bin/sh
# epc-run.sh <self> <command...>
#
# Container entrypoint for every PROFILE=epc pod. It renders the compose
# configs (docker/rust/configs/epc, nextgsim/config) for this pod, then execs
# <command>.
#
# The configs address every node by its docker-compose-epc.yml IP
# (172.24.0.0/24). Neither the nextgcore EPC configs nor the nextgsim configs
# (IpAddr fields) take hostnames, so each 172.24.0.N becomes:
#   - this pod's own IP when N is <self> (bind and advertised addresses);
#   - otherwise the peer's pod IP, from its headless Service.
#
# A pod IP is used, not a ClusterIP: GTP-C, PFCP and GTP-U peers reply to and
# initiate toward each other's ADVERTISED addresses (F-TEIDs, F-SEIDs), and
# kube-proxy's per-flow NAT on those UDP flows produces conntrack clashes.
#
# A pod IP is a one-shot literal, though. This script runs at every CONTAINER
# start, not in an init container, and records what it resolved in
# /run/epc/peers. epc-peers-check.sh (the liveness probe) restarts the
# container when a peer's IP changes, so the next start re-resolves. A
# restarted peer does not strand its dependents.
#
# Env:
#   POD_IP, POD_NAMESPACE   downward API (required)
#   EPC_EXPORT              "VAR=<node> ..." exported before exec; <node> is a
#                           name in MAP below, "self", or "dns:<node>" for the
#                           node's Service FQDN (for an NF that re-resolves a
#                           hostname itself, e.g. smfd's UPF_PFCP_ADDR since
#                           #658), which is not tracked
#   EPC_UNTRACKED           nodes not to record for the liveness probe (their
#                           consumer re-resolves them itself)
set -eu

SELF="$1"; shift
SRC=/epc/templates
OUT=/run/epc/cfg
STATE=/run/epc/peers

# docker-compose-epc.yml addressing: last octet -> Service name.
MAP="2:mongodb 3:sgwc 4:pgwc 5:mme 6:sgwu 7:pgwu 8:hss 9:pcrf 50:enb 60:lte-ue"

log() { echo "[epc-run] $*" >&2; }

case "${POD_IP:-}" in
  *[0-9].[0-9]*) ;;
  *) log "FATAL: POD_IP is not an IPv4 address: '${POD_IP:-}'"; exit 1 ;;
esac

# resolve <service> -> pod IP of its headless Service (publishNotReadyAddresses,
# so a peer resolves as soon as it has an IP; no start-order deadlock between
# HSS and MME, which name each other).
resolve() {
  _i=0
  while :; do
    _ip=$(getent hosts "$1.${POD_NAMESPACE}.svc.cluster.local" | head -n1 | cut -d' ' -f1)
    case "$_ip" in
      *[0-9].[0-9]*) echo "$_ip"; return 0 ;;
    esac
    _i=$((_i + 1))
    [ "$_i" -ge 150 ] && { log "FATAL: $1 never resolved"; return 1; }
    log "waiting for $1 ($_i/150)"
    sleep 2
  done
}

addr_of() { # <name> -> IP (self or resolved), recording peers
  if [ "$1" = "$SELF" ] || [ "$1" = self ]; then
    echo "$POD_IP"
    return 0
  fi
  _a=$(resolve "$1") || return 1
  case " ${EPC_UNTRACKED:-} " in
    *" $1 "*) ;;
    *) grep -q "^$1 " "$STATE" 2>/dev/null || echo "$1 $_a" >> "$STATE" ;;
  esac
  echo "$_a"
}

rm -rf "$OUT"
mkdir -p "$OUT"
: > "$STATE"
cp "$SRC"/* "$OUT"/
# The configs name their freeDiameter files under /etc/freeDiameter.
sed -i "s|/etc/freeDiameter/|$OUT/|g" "$OUT"/*

for pair in $MAP; do
  n=${pair%%:*}
  name=${pair#*:}
  grep -qE "172\.24\.0\.$n([^0-9]|\$)" "$OUT"/* || continue
  ip=$(addr_of "$name")
  sed -i -E "s/172\.24\.0\.$n([^0-9]|\$)/$ip\1/g" "$OUT"/*
  log "172.24.0.$n ($name) -> $ip"
done

for kv in ${EPC_EXPORT:-}; do
  var=${kv%%=*}
  case "${kv#*=}" in
    dns:*) ip="${kv#*=dns:}.${POD_NAMESPACE}.svc.cluster.local" ;;
    *) ip=$(addr_of "${kv#*=}") ;;
  esac
  export "$var=$ip"
  log "$var=$ip"
done

if grep -nE '172\.24\.0\.[0-9]' "$OUT"/*; then
  log "FATAL: compose addresses survived the rewrite (above)"
  exit 1
fi
log "peers: $(tr '\n' ' ' < "$STATE")"
exec "$@"
