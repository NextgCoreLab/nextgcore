#!/bin/sh
# eesd of the D443A compose stack (nextgsim#471).
# 1. The NRF's JWKS, fetched once the NRF is up: eesd verifies every eees-* token
#    against it (the NRF's signing key is generated at its start).
# 2. STAND-IN, labelled: the EES is not an NRF NF type (TS 29.510; TS 23.558
#    §6.2), but the NRF (#1391) grants an eees-* scope only if a producer of
#    the target type offering it is registered. A background loop registers a
#    profile with the custom nfType "EES" and the two eees-* services, and
#    re-registers it every 30 s (heartBeatTimer 60).
# Both over TLS (#1617): the NRF serves https; the stand-in presents its own
# certificate (certs/nf-identities.txt row ees-standin: this id, nfType EES),
# mounted from its volume tls-ees-standin by the sbi-tls service.
set -eu
: "${D443A_MODE:?}"
nrf=https://172.23.0.10:7777
c=/etc/nextgcore/certs
tls="--http2 --cacert $c/ca.crt --cert $c/ees-standin.crt --key $c/ees-standin.key"
# shellcheck disable=SC2086  # $tls is a flag list
until curl -s $tls --max-time 5 -o /tmp/jwks.json "$nrf/nnrf-oauth2/v1/jwks" \
  && grep -q '"keys"' /tmp/jwks.json; do echo "waiting for the NRF's JWKS"; sleep 2; done
id=6b1d7e3c-0000-4000-8000-00000000471e
svc() { printf '{"serviceInstanceId":"%s","serviceName":"%s","versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],"scheme":"http","nfServiceStatus":"REGISTERED"}' "$1" "$1"; }
body="{\"nfInstanceId\":\"$id\",\"nfType\":\"EES\",\"nfStatus\":\"REGISTERED\",\"heartBeatTimer\":60,\"ipv4Addresses\":[\"172.23.0.31\"],\"nfServices\":[$(svc eees-easregistration),$(svc eees-eecregistration)]}"
( while :; do
    # shellcheck disable=SC2086
    code="$(curl -s $tls --max-time 5 -o /dev/null -w '%{http_code}' -X PUT \
      -H 'Content-Type: application/json' -d "$body" "$nrf/nnrf-nfm/v1/nf-instances/$id")"
    echo "$(date -u +%FT%TZ) [d443a nrf-standin] stand-in EES profile $id (nfType EES, eees-easregistration, eees-eecregistration) PUT -> $code"
    sleep 30
  done ) &
sed "s/@MODE@/$D443A_MODE/" /etc/nextgcore/ees.yaml.in >/tmp/ees.yaml
exec nf-binary -c /tmp/ees.yaml --oauth2-jwks-file /tmp/jwks.json
