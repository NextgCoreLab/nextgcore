#!/bin/sh
# nf-healthcheck -- the HEALTHCHECK of the nextgcore images (nextgcore#1617).
#
# GET /health on the NF's SBI listener over HTTP/2: the SBI server speaks h2
# only (h2c prior knowledge, or h2 over TLS), so an HTTP/1.1 probe never
# succeeds. The old `curl -sf http://localhost:7777/health` was such a probe,
# and once the NRF served TLS it could not have passed even over h2.
#
#   1. h2c:  http://<addr>:<port>/health
#   2. TLS:  https://<name>:<port>/health, the certificate verified against
#            <ca> as <name> (curl --resolve <name>:<port>:<addr>); never
#            skipped (no -k). Tried only when a name and a readable CA are known.
#
# Environment:
#   NF_HEALTH_ADDR      address to dial        (default 127.0.0.1)
#   NF_HEALTH_PORT      SBI port               (default 7777)
#   NF_HEALTH_TLS_CA    trust anchor           (default /etc/nextgcore/certs/ca.crt,
#                                               where every stack mounts it)
#   NF_HEALTH_TLS_NAME  name its certificate carries (default: nrf for the NRF,
#                       nextgcore-nrfd, whose dev nrf.crt names DNS:nrf; none
#                       otherwise)
#
# Exit 0 healthy, 1 not.
addr="${NF_HEALTH_ADDR:-127.0.0.1}"
port="${NF_HEALTH_PORT:-7777}"
case "${addr}" in *:*) host="[${addr}]" ;; *) host="${addr}" ;; esac

curl --fail --silent --max-time 3 --http2-prior-knowledge -o /dev/null \
  "http://${host}:${port}/health" && exit 0

ca="${NF_HEALTH_TLS_CA:-/etc/nextgcore/certs/ca.crt}"
name="${NF_HEALTH_TLS_NAME:-}"
if [ -z "${name}" ] && [ "${NF_NAME:-}" = nextgcore-nrfd ]; then
  name=nrf
fi
[ -n "${name}" ] && [ -r "${ca}" ] || exit 1
exec curl --fail --silent --max-time 3 --http2 --cacert "${ca}" -o /dev/null \
  --resolve "${name}:${port}:${host}" "https://${name}:${port}/health"
