#!/usr/bin/env bash
# One arm of demo d441e-model-retrain (nextgsim#468) on the compose stack
# docker/rust/docker-compose.demo-d441e.yml: an NRF, an MTLF and an AnLF.
#
#   check.sh retrain        the main arm: the chain to model v2 verified
#   check.sh no-retrain     same seeded run; the MTLF never refits
#   check.sh off-absent     no demo: block
#   check.sh off-disabled   demo.enabled: false
#   check.sh off-key-only   demo.enabled: false, d441e-model-retrain.enabled: true
#   check.sh bogus-mode     mode: bogus must fail start-up
#
# retrain / no-retrain. The seeded series (nwdaf.retrain_series, the same on
# both NWDAFs) is a function of unix time: every 600 s cycle is calm for 120 s,
# then alternating. The AnLF reports accuracy as soon as the MTLF subscribes,
# over the newest 20 points, so the NWDAFs start 25-60 s into a cycle (the
# check waits for that window, at most 10 min): the first reports are on the
# calm part, and the scripted change comes 60-95 s later. Then chain.py asserts
# the ordered chain by the runtime's timestamps (its header lists the steps):
#   retrain     ... retrain requested after the change, the refit, v2 published,
#               provisioned and verified, every v2 report >= 0.70; and after v2,
#               a GET of the v1 URL still returns the v1 bytes (sha256) and the
#               v2 URL the v2 bytes;
#   no-retrain  ... the drop with "mode no-retrain, no retrain", no v2, every
#               later report < 0.70 (observed D441E_NO_RETRAIN_HOLD s more).
# Both: each NWDAF logged `DEMO MODE ACTIVE` and its /metrics has
# nextg_demo_enabled{demo="d441e-model-retrain",mode="<mode>"} 1.
#
# off-*. Same roles, no demo: no `DEMO MODE ACTIVE` or `[demo:` line, no
# nextg_demo_enabled series, the MLModelMonitor routes are 404 on both, the
# AnLF client does not start (no "subscribed to MTLF"), and the MTLF still
# publishes its model (the base MTLF behaviour).
#
# bogus-mode. Both NWDAFs exit non-zero with
# DemoConfigError::UnknownMode { demo: "d441e-model-retrain", mode: "bogus", .. }
# (the ticket writes `key:`; nextgcore-demo's field is `demo`).
#
# Environment:
#   D441E_NWDAF_IMAGE   nwdafd built with --features demo-d441e-model-retrain
#   D441E_NRF_IMAGE     nrfd
#   DEMO_ARTEFACTS      capture dir (default /tmp/demo-artefacts/d441e/<arm>)
#   D441E_COMPOSE       the compose command (default: docker compose)
#   D441E_AFTER_CHANGE  seconds the chain may take after the change (default 360)
#   D441E_NO_RETRAIN_HOLD  extra observation in no-retrain (default 90)
#
# Private: the stack publishes nothing (asserted from `docker compose config`
# before anything starts); every request goes through `exec` in a container.
# Every failure prints `DEMO CHECK FAILED: <why>`. Exit 0 PASS, 1 FAIL, 2 usage.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rust_dir="$(cd "${here}/../.." && pwd)"
ARM="${1:-}"
case "${ARM}" in
  retrain | no-retrain | off-absent | off-disabled | off-key-only | bogus-mode) ;;
  *) sed -n '2,40p' "$0" >&2; exit 2 ;;
esac
KEY=d441e-model-retrain
ART="${DEMO_ARTEFACTS:-/tmp/demo-artefacts/d441e/${ARM}}"
mkdir -p "${ART}/config" || exit 2
read -r -a COMPOSE <<<"${D441E_COMPOSE:-docker compose}"
COMPOSE+=(-f "${rust_dir}/docker-compose.demo-d441e.yml" -p "${D441E_PROJECT:-nextg-d441e-${ARM}}")
export D441E_CONFIG_DIR="${ART}/config"
CYCLE=600 CHANGE=120 WIN_LO=25 WIN_HI=60

info() { printf '[d441e] %s\n' "$*"; }
fail() {
  printf 'DEMO CHECK FAILED: %s\n' "$*" >&2
  [[ -n "${GITHUB_ACTIONS:-}" ]] && printf '::error::%s\n' "$*" >&2
  return 1
}
dc() { "${COMPOSE[@]}" "$@"; }
logs() { # capture both NWDAFs and the NRF
  local s
  for s in nrf nwdaf-mtlf nwdaf-anlf; do
    dc logs --no-color --timestamps "${s}" >"${ART}/${s}.log" 2>&1 || true
  done
}
state_of() { # SERVICE -> "<status> <exit code>"
  local id
  id="$(dc ps -a -q "$1" 2>/dev/null | head -1)"
  [[ -n "${id}" ]] && docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "${id}" 2>/dev/null
}
in_svc() { dc exec -T "$@"; }
http() { # SERVICE METHOD URL [BODY] -> status
  local body="${4:-}"
  in_svc "$1" curl -s --http2-prior-knowledge --max-time 10 -o /dev/null -w '%{http_code}' \
    -X "$2" -H 'content-type: application/json' ${body:+--data "${body}"} "$3"
}
# shellcheck disable=SC2317  # reached through the EXIT trap
teardown() { dc down -v --remove-orphans >>"${ART}/compose.log" 2>&1 || true; }
trap teardown EXIT

# --- the configs of this arm --------------------------------------------------
cp "${here}/nrf.yaml" "${here}/nwdaf-mtlf.yaml" "${here}/nwdaf-anlf.yaml" "${ART}/config/" || exit 2
python3 - "${ARM}" "${ART}/config/nwdaf-mtlf.yaml" "${ART}/config/nwdaf-anlf.yaml" <<'PY' || exit 2
import sys, yaml
arm, *paths = sys.argv[1:]
for p in paths:
    doc = yaml.safe_load(open(p))
    block = doc['demo']['d441e-model-retrain']
    if arm in ('retrain', 'no-retrain'):
        block['mode'] = arm
    elif arm == 'bogus-mode':
        block['mode'] = 'bogus'
    elif arm == 'off-absent':
        del doc['demo']
    elif arm == 'off-disabled':
        doc['demo'] = {'enabled': False}
    elif arm == 'off-key-only':
        doc['demo']['enabled'] = False
    yaml.safe_dump(doc, open(p, 'w'), sort_keys=False)
PY
chmod 644 "${ART}"/config/*.yaml
info "arm ${ARM}; artefacts ${ART}; images nwdaf=${D441E_NWDAF_IMAGE:-default} nrf=${D441E_NRF_IMAGE:-default}"

# --- private: nothing published -----------------------------------------------
model="$(dc config --format json)" || { fail "docker compose config failed"; exit 1; }
exposed="$(jq -r '.services | to_entries[]
  | select(((.value.ports // []) | length) > 0 or .value.network_mode == "host") | .key' <<<"${model}")"
[[ -z "${exposed}" ]] || { fail "the stack publishes a port or uses host networking: ${exposed}"; exit 1; }
info "no published port, no host networking"

dc down -v --remove-orphans >"${ART}/compose.log" 2>&1 || true
dc up -d nrf >>"${ART}/compose.log" 2>&1 || { fail "nrf did not start"; exit 1; }
sleep 3

# --- bogus-mode ---------------------------------------------------------------
if [[ "${ARM}" == bogus-mode ]]; then
  dc up -d --no-deps nwdaf-mtlf nwdaf-anlf >>"${ART}/compose.log" 2>&1
  rc=0
  for s in nwdaf-mtlf nwdaf-anlf; do
    for _ in $(seq 30); do
      read -r st code <<<"$(state_of "${s}")"
      [[ "${st:-}" == exited ]] && break
      sleep 1
    done
    logs
    if [[ "${st:-}" != exited || "${code:-0}" == 0 ]]; then
      fail "${s} did not fail start-up (state ${st:-?} ${code:-?})"; rc=1; continue
    fi
    grep -F 'UnknownMode { demo: "d441e-model-retrain", mode: "bogus"' "${ART}/${s}.log" \
      || { fail "${s} exited ${code} without DemoConfigError::UnknownMode"; rc=1; continue; }
    info "${s}: exited ${code}"
  done
  [[ ${rc} == 0 ]] && info "PASS bogus-mode"
  exit "${rc}"
fi

# --- off-* ----------------------------------------------------------------------
if [[ "${ARM}" == off-* ]]; then
  dc up -d --no-deps nwdaf-mtlf nwdaf-anlf >>"${ART}/compose.log" 2>&1 || { fail "the NWDAFs did not start"; exit 1; }
  sleep 30
  rc=0
  for s in nwdaf-mtlf nwdaf-anlf; do
    read -r st code <<<"$(state_of "${s}")"
    [[ "${st:-}" == running ]] || { fail "${s} is ${st:-?} (exit ${code:-?})"; rc=1; }
  done
  logs
  for s in nwdaf-mtlf nwdaf-anlf; do
    if grep -E 'DEMO MODE ACTIVE|\[demo:' "${ART}/${s}.log"; then fail "${s} logged demo lines with the demo off"; rc=1; fi
    in_svc "${s}" curl -s --max-time 5 http://127.0.0.1:9090/metrics >"${ART}/${s}.prom" 2>/dev/null
    [[ -s "${ART}/${s}.prom" ]] || { fail "${s}: no /metrics scrape"; rc=1; }
    if grep '^nextg_demo_enabled' "${ART}/${s}.prom"; then fail "${s}: nextg_demo_enabled with the demo off"; rc=1; fi
  done
  reg="$(http nwdaf-mtlf POST http://127.0.0.1:7777/nnwdaf-mlmodelmonitor/v1/registrations \
    '{"modelId":1,"consumerId":"d441e000-0468-4000-8000-00000000a001"}')"
  sub="$(http nwdaf-anlf POST http://127.0.0.1:7777/nnwdaf-mlmodelmonitor/v1/subscriptions \
    '{"modelIds":[1],"notificationUri":"http://127.0.0.1:1/x","accuThreshold":70}')"
  echo "mtlf registrations=${reg} anlf subscriptions=${sub}" >"${ART}/routes.txt"
  [[ "${reg}" == 404 ]] || { fail "MTLF MLModelMonitor registrations answered ${reg}, expected 404"; rc=1; }
  [[ "${sub}" == 404 ]] || { fail "AnLF MLModelMonitor subscriptions answered ${sub}, expected 404"; rc=1; }
  if grep -F 'subscribed to MTLF' "${ART}/nwdaf-anlf.log"; then fail "the AnLF client started with the demo off"; rc=1; fi
  grep -q 'MLModelProvision: model v1 published sha256=' "${ART}/nwdaf-mtlf.log" \
    || { fail "the MTLF published no model with the demo off"; rc=1; }
  info "MLModelMonitor routes: MTLF ${reg}, AnLF ${sub}; no demo line, no nextg_demo_enabled"
  [[ ${rc} == 0 ]] && info "PASS ${ARM}"
  exit "${rc}"
fi

# --- retrain / no-retrain: start inside the window ---------------------------------
now="$(date +%s)"; phase=$(( now % CYCLE ))
if (( phase < WIN_LO || phase > WIN_HI )); then
  wait_s=$(( (WIN_LO - phase + CYCLE) % CYCLE ))
  info "cycle phase ${phase}s; waiting ${wait_s}s for the start window [${WIN_LO}, ${WIN_HI}]s"
  sleep "${wait_s}"
fi
start="$(date +%s)"
dc up -d --no-deps nwdaf-mtlf nwdaf-anlf >>"${ART}/compose.log" 2>&1 || { fail "the NWDAFs did not start"; exit 1; }
change=$(( start - start % CYCLE + CHANGE ))
info "started at phase $(( start % CYCLE ))s; the scripted change is at unix ${change} (in $(( change - start ))s)"
deadline=$(( change + ${D441E_AFTER_CHANGE:-360} ))

passed=false
while (( $(date +%s) < deadline )); do
  sleep 10
  for s in nwdaf-mtlf nwdaf-anlf; do
    read -r st code <<<"$(state_of "${s}")"
    [[ "${st:-}" == running ]] || { logs; fail "${s} is ${st:-?} (exit ${code:-?})"; exit 1; }
  done
  logs
  if python3 "${here}/chain.py" --mode "${ARM}" --mtlf "${ART}/nwdaf-mtlf.log" \
      --anlf "${ART}/nwdaf-anlf.log" >/dev/null 2>&1; then
    passed=true; break
  fi
done
if [[ "${passed}" == true && "${ARM}" == no-retrain ]]; then
  info "the no-retrain chain holds; observing $(( ${D441E_NO_RETRAIN_HOLD:-90} ))s more"
  sleep "${D441E_NO_RETRAIN_HOLD:-90}"
  logs
fi
# The verdict, with the reason on failure.
python3 "${here}/chain.py" --mode "${ARM}" --mtlf "${ART}/nwdaf-mtlf.log" \
  --anlf "${ART}/nwdaf-anlf.log" --facts "${ART}/facts.txt" | tee "${ART}/chain.txt" || exit 1
fact() { sed -n "s/^$1=//p" "${ART}/facts.txt"; }

rc=0
if [[ "${ARM}" == retrain ]]; then
  # Criterion 2: after the refit the v1 URL still serves the v1 bytes.
  for v in v1 v2; do
    url="$(fact "${v}_url")"; want="$(fact "${v}_sha256")"
    got="$(in_svc nwdaf-anlf sh -c "curl -s --http2-prior-knowledge --max-time 10 '${url}' | sha256sum" | cut -d' ' -f1)"
    echo "${v} ${url} sha256=${got}" >>"${ART}/artefacts.txt"
    [[ "${got}" == "${want}" ]] || { fail "GET ${v} URL after v2: sha256 ${got}, expected ${want}"; rc=1; }
  done
  info "after v2: the v1 URL serves sha256=$(fact v1_sha256), the v2 URL sha256=$(fact v2_sha256)"
fi
for s in nwdaf-mtlf nwdaf-anlf; do
  grep -q "DEMO MODE ACTIVE: .*${KEY}=${ARM}" "${ART}/${s}.log" \
    || { fail "${s}: no DEMO MODE ACTIVE banner for ${KEY}=${ARM}"; rc=1; }
  in_svc "${s}" curl -s --max-time 5 http://127.0.0.1:9090/metrics >"${ART}/${s}.prom" 2>/dev/null
  grep -qF "nextg_demo_enabled{demo=\"${KEY}\",mode=\"${ARM}\"} 1" "${ART}/${s}.prom" \
    || { fail "${s}: no nextg_demo_enabled{demo=${KEY},mode=${ARM}} 1"; rc=1; }
done
grep -E '^nwdaf_model_refit' "${ART}/nwdaf-mtlf.prom" >"${ART}/refit-metrics.txt" || true
{ echo "arm=${ARM} start_phase=$(( start % CYCLE ))"; cat "${ART}/facts.txt"; } >"${ART}/results.txt"
[[ ${rc} == 0 ]] && info "PASS ${ARM}: $(tr '\n' ' ' <"${ART}/facts.txt")"
exit "${rc}"
