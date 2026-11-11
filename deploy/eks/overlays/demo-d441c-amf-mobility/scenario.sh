#!/usr/bin/env bash
# Seeded acceptance run of demo d441c-amf-mobility (nextgsim#466), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_KEY, DEMO_MODE and OUT set.
#
# The run is the same in both modes; only the assertions differ:
#   1. wait for nwdafd's mode line (and, in mode on, its AMF subscription);
#   2. restart the UE, so its registration (cell A, gnb, NCI 0x010) comes AFTER
#      the subscription, then wait for its N2 handover to gnb-east (cell B,
#      NCI 0x020), which the UE's walk triggers about 35 s after start;
#   3. ask nwdafd for UE_MOBILITY for the UE's SUPI, and the NRF for nwdafd's
#      profile; send one notify on a forged callback token.
#
#   on        ordered chain, nwdafd and amfd lines by kubelet timestamp:
#             amfd "Event subscription created: id=<id>", nwdafd "subscribed to
#             AMF LOCATION_REPORT id=<id>", nwdafd "ue-mobility ingest
#             supi=<supi> cell=99970-000000010" with an amfd "Event notification
#             delivered: sub=<id>" for it, then "... cell=99970-000000020" with
#             its delivery; the GET is 200 with ueMobs[0].locInfos
#             holding both cells, a schema-valid UeMobility; the profile lists
#             UE_MOBILITY in eventIds; the forged notify is 404.
#   baseline  no "subscribed to AMF" line; the GET is 204; the profile does not
#             list UE_MOBILITY.
#
# Everything goes through kubectl exec inside the namespace: no port-forward,
# nothing published. Captures under $OUT/scenario/.
set -uo pipefail
: "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
K=(kubectl -n "${NAMESPACE}")
S="${OUT}/scenario"
mkdir -p "${S}"
SUPI="imsi-999700000000001"
CELL_A="99970-000000010"
CELL_B="99970-000000020"
FAILS=0
say()  { printf '[scenario] %s\n' "$*"; }
bad()  { printf '[scenario] FAIL: %s\n' "$*"; FAILS=$((FAILS+1)); }
nwdaf_log() { "${K[@]}" logs deploy/nwdaf --timestamps 2>/dev/null; }
amf_log()   { "${K[@]}" logs deploy/amf --timestamps 2>/dev/null; }
# wait_for <seconds> <command...>: poll until the command succeeds.
wait_for() {
  local t="$1"; shift
  local end=$(( $(date +%s) + t ))
  until "$@" >/dev/null 2>&1; do
    [[ $(date +%s) -ge ${end} ]] && return 1
    sleep 3
  done
}
in_nwdaf() { "${K[@]}" exec deploy/nwdaf -c nwdaf -- "$@"; }
sbi_get() {
  # $1 path+query; prints "<status>\n<body>"
  in_nwdaf sh -c "curl -s --http2-prior-knowledge --max-time 10 -o /tmp/body -w '%{http_code}\n' 'http://127.0.0.1:7777$1'; cat /tmp/body 2>/dev/null"
}
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

# --- 1. the mode line ----------------------------------------------------------
if [[ "${DEMO_MODE}" == on ]]; then
  wait_for 180 sh -c "kubectl -n ${NAMESPACE} logs deploy/nwdaf | grep -q 'subscribed to AMF LOCATION_REPORT id='" \
    || bad "no 'subscribed to AMF LOCATION_REPORT' line within 180 s"
else
  wait_for 60 sh -c "kubectl -n ${NAMESPACE} logs deploy/nwdaf | grep -q 'ue-mobility: baseline'" \
    || bad "no 'ue-mobility: baseline' line"
fi

# --- 2. the seeded UE run: register at A, hand over to B -------------------------
HO_BEFORE="$(amf_log | grep -c 'HandoverNotify from association' || true)"
say "restarting the UE (handover notifies before: ${HO_BEFORE})"
"${K[@]}" rollout restart deployment/ue >/dev/null
"${K[@]}" rollout status deployment/ue --timeout=300s >/dev/null || bad "UE rollout"
wait_for 240 sh -c "[ \$(kubectl -n ${NAMESPACE} logs deploy/amf | grep -c 'HandoverNotify from association') -gt ${HO_BEFORE} ]" \
  || bad "no N2 handover (HandoverNotify at amfd) within 240 s"
if [[ "${DEMO_MODE}" == on ]]; then
  wait_for 60 sh -c "kubectl -n ${NAMESPACE} logs deploy/nwdaf | grep -q 'ue-mobility ingest supi=${SUPI} cell=${CELL_B}'" \
    || bad "no ingest of cell ${CELL_B} within 60 s of the handover"
fi
sleep 5

# --- 3. the queries ------------------------------------------------------------------
TGT="$(urlenc "{\"supis\":[\"${SUPI}\"]}")"
sbi_get "/nnwdaf-analyticsinfo/v1/analytics?event-id=UE_MOBILITY&tgt-ue=${TGT}" >"${S}/ue-mobility.http"
STATUS="$(head -1 "${S}/ue-mobility.http")"
tail -n +2 "${S}/ue-mobility.http" >"${S}/ue-mobility.json"
say "UE_MOBILITY GET: ${STATUS}"
in_nwdaf sh -c "curl -s --http2-prior-knowledge --max-time 10 'http://nrf.${NAMESPACE}.svc.cluster.local:7777/nnrf-disc/v1/nf-instances?target-nf-type=NWDAF&requester-nf-type=AMF'" \
  >"${S}/nrf-nwdaf-profile.json" 2>/dev/null
FORGED="$(in_nwdaf sh -c "curl -s --http2-prior-knowledge --max-time 10 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' --data '{\"reportList\":[]}' http://127.0.0.1:7777/nnwdaf-callback/v1/amf-location-notify/00000000000000000000000000000000")"
echo "${FORGED}" >"${S}/forged-notify.status"
nwdaf_log | grep -E 'subscribed to AMF LOCATION_REPORT|ue-mobility' >"${S}/nwdaf-chain.txt"
amf_log | grep -E 'HandoverNotify from association|Event subscription created|Event notification delivered' >"${S}/amf-chain.txt"
ADVERTISED="$(python3 - "${S}/nrf-nwdaf-profile.json" <<'PY'
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except Exception:
    print("unreadable"); sys.exit()
ids = [e for i in r.get("nfInstances", []) for e in i.get("nwdafInfo", {}).get("eventIds", [])]
print("yes" if "UE_MOBILITY" in ids else "no")
PY
)"
say "NRF profile lists UE_MOBILITY: ${ADVERTISED}; forged notify: ${FORGED}"

# --- 4. assertions -------------------------------------------------------------------
if [[ "${DEMO_MODE}" == on ]]; then
  [[ "${STATUS}" == 200 ]] || bad "UE_MOBILITY GET is ${STATUS}, expected 200"
  python3 - "${S}/ue-mobility.json" "${CELL_A#*-}" "${CELL_B#*-}" <<'PY' || FAILS=$((FAILS+1))
import json, sys
body = json.load(open(sys.argv[1])); a, b = sys.argv[2], sys.argv[3]
m = body["ueMobs"][0]
assert isinstance(m["duration"], int) and m["duration"] >= 0, m
assert m["locInfos"], m
assert ("ts" in m) != ("recurringTime" in m), m
assert all("loc" in l for l in m["locInfos"]), m
cells = [l["loc"]["nrLocation"]["ncgi"]["nrCellId"] for l in m["locInfos"]]
assert a in cells and b in cells, cells
print("[scenario] ueMobs[0].locInfos cells:", cells)
PY
  # The ordered chain across nwdafd and amfd, by kubelet timestamp.
  python3 - "${S}/nwdaf-chain.txt" "${S}/amf-chain.txt" "${SUPI}" "${CELL_A}" "${CELL_B}" <<'PY' || FAILS=$((FAILS+1))
import re, sys
from datetime import datetime
def load(path, who):
    out = []
    for l in open(path).read().splitlines():
        ts, _, msg = l.partition(" ")
        # kubelet: 2026-11-11T10:00:00.123456789Z; keep microseconds.
        m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$", ts)
        if not m:
            continue
        frac = (m.group(2) or "0")[:6].ljust(6, "0")
        out.append((datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f"), who, msg))
    return out
nwdaf = load(sys.argv[1], "nwdaf"); amf = load(sys.argv[2], "amf")
supi, a, b = sys.argv[3:6]
def fail(msg):
    raise SystemExit(f"[scenario] FAIL: {msg}")
subs = [(t, m) for t, _, m in nwdaf if "subscribed to AMF LOCATION_REPORT id=" in m]
if not subs:
    fail("no nwdafd subscription line")
t_sub, m_sub = subs[-1]
sub_id = re.search(r"id=(\S+)", m_sub).group(1)
created = [t for t, _, m in amf if f"Event subscription created: id={sub_id}" in m]
if not created or created[0] > t_sub:
    fail(f"amfd did not create subscription {sub_id} before nwdafd logged it")
def ingest(cell, after):
    for t, _, m in nwdaf:
        if t >= after and f"ue-mobility ingest supi={supi} cell={cell}" in m:
            return t
    fail(f"no ingest of {cell} after {after.isoformat()}")
t_a = ingest(a, t_sub)
t_b = ingest(b, t_a)
deliveries = sorted(t for t, _, m in amf if f"Event notification delivered: sub={sub_id}," in m)
# amfd logs the delivery once nwdafd has answered, so each lands at or just after its ingest.
for name, t in (("A", t_a), ("B", t_b)):
    if not any(t <= d for d in deliveries):
        fail(f"no amfd delivery to {sub_id} at or after the cell {name} ingest")
if not any(t_sub <= d <= t_b for d in deliveries):
    fail("no amfd delivery between the subscription and the cell B ingest")
print(f"[scenario] ordered chain ok: created {created[0].isoformat()} <= subscribed "
      f"{t_sub.isoformat()} < ingest A {t_a.isoformat()} < ingest B {t_b.isoformat()}; "
      f"{len(deliveries)} amfd deliveries to {sub_id}")
PY
  [[ "${ADVERTISED}" == yes ]] || bad "the NRF profile does not list UE_MOBILITY"
  [[ "${FORGED}" == 404 ]] || bad "forged-token notify answered ${FORGED}, expected 404"
else
  if grep -q 'subscribed to AMF LOCATION_REPORT' "${S}/nwdaf-chain.txt"; then
    bad "baseline subscribed to the AMF"
  fi
  [[ "${STATUS}" == 204 ]] || bad "UE_MOBILITY GET is ${STATUS}, expected 204"
  [[ "${ADVERTISED}" == no ]] || bad "baseline NRF profile lists UE_MOBILITY (${ADVERTISED})"
fi
if [[ ${FAILS} -eq 0 ]]; then
  say "PASS (${DEMO_MODE})"
else
  say "FAIL: ${FAILS} assertion(s)"
  exit 1
fi
