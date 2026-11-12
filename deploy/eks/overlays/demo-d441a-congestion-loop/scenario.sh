#!/usr/bin/env bash
# Seeded acceptance run of demo d441a-congestion-loop (nextgsim#465), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_KEY, DEMO_MODE and OUT set.
#
# The run is identical in every mode (statistics | prediction | no-loop); only
# the assertions differ:
#   1. trust the gNB exporter's CCA key at the NRF (the gNB generated it and
#      published its public JWK; it goes into the NRF's trusted-key ConfigMap);
#   2. seed UE-B's subscriber (imsi-...002) and start UE-B; UE-V is the base UE
#      (imsi-...001, protected);
#   3. UE-V pings the UPF gateway 10 times a second for the whole run; UE-B
#      ramps its downlink to 2C (C = 5 Mbps) with large echo requests, whose
#      replies are downlink, in 1 Mbps steps of 4 s, holds 10 Mbps for 12 s,
#      then stops; 40 s are left for the restore;
#   4. an unauthenticated POST to the ingest route.
#
#   statistics / prediction
#     ordered chain by kubelet timestamp: nwdafd "ran-ingest cell=99970-000000010",
#     nwdafd "udc GET USER_DATA_CONGESTION kind=<statistics|prediction> ...
#     congLevel=... → 200", pcfd "action=throttle(supi=imsi-999700000000002)",
#     smfd "Applying PCF-updated policy ... AMBR UL/DL=1000000/1000000 bps",
#     upfd "Installed 1 QERs for SEID=", UE-B "network set Session-AMBR",
#     then pcfd "action=restore(supi=imsi-999700000000002)"; exactly one throttle
#     and one restore, none for UE-V; nwdafd's AMF numberOfUes equals the gNB's
#     connected_ues; the tokenless POST is 401 and adds no throttle. UE-V's ping
#     p95 is written to p95.txt and compared with the newest no-loop arm's
#     (<= 0.25x) when one exists; prediction also reports the lead time of its
#     throttle over the first measured occupancy >= 80 %.
#   no-loop
#     nwdafd answers 204 (no ran-ingest line), pcfd logs hold(no-ran-data), no
#     "Applying PCF-updated policy", and UE-V's p95 >= 100 ms.
#
# Everything goes through kubectl exec inside the namespace: no port-forward,
# nothing published. Captures under $OUT/scenario/.
set -uo pipefail
: "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
K=(kubectl -n "${NAMESPACE}")
S="${OUT}/scenario"
mkdir -p "${S}"
UE_V="imsi-999700000000001"
UE_B="imsi-999700000000002"
CELL="99970-000000010"
TARGET="10.45.0.1"
EXPORTER_ID="6b1d7e3c-0000-4000-8000-00000000465a"
JWK_PATH="/tmp/d441a-cca/${EXPORTER_ID}.jwk"
FAILS=0
say()  { printf '[scenario] %s\n' "$*"; }
bad()  { printf '[scenario] FAIL: %s\n' "$*"; FAILS=$((FAILS+1)); }
logs() { "${K[@]}" logs "$1" --timestamps 2>/dev/null; }
wait_for() {
  local t="$1"; shift
  local end=$(( $(date +%s) + t ))
  until "$@" >/dev/null 2>&1; do
    [[ $(date +%s) -ge ${end} ]] && return 1
    sleep 3
  done
}

# --- 1. the exporter's CCA key -------------------------------------------------
wait_for 180 "${K[@]}" exec deploy/gnb -- test -s "${JWK_PATH}" \
  || bad "the gNB published no CCA JWK at ${JWK_PATH} within 180 s"
"${K[@]}" exec deploy/gnb -- cat "${JWK_PATH}" >"${S}/exporter.jwk" 2>/dev/null
"${K[@]}" create configmap d441a-cca-trusted --from-file="${EXPORTER_ID}.jwk=${S}/exporter.jwk" \
  --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null || bad "trusted-key ConfigMap"
say "exporter JWK published to the NRF trust store (kubelet sync can take ~60 s)"

# --- 2. UE-B ---------------------------------------------------------------------
MONGO_POD="$("${K[@]}" get pod -l app.kubernetes.io/name=mongodb -o jsonpath='{.items[0].metadata.name}')"
"${K[@]}" exec "${MONGO_POD}" -- mongosh --quiet nextgcore --eval '
  const s = db.subscribers.findOne({imsi: "999700000000001"}, {_id: 0});
  s.imsi = "999700000000002"; s.msisdn = ["821000000002"];
  db.subscribers.updateOne({imsi: s.imsi}, {$set: s}, {upsert: true});
  print("seeded " + s.imsi);' >"${S}/seed-ue-b.txt" 2>&1 || bad "UE-B subscriber seed"
"${K[@]}" scale deployment/ue-b --replicas=1 >/dev/null
"${K[@]}" rollout status deployment/ue-b --timeout=300s >/dev/null || bad "UE-B rollout"
tun_ip() { "${K[@]}" exec "deploy/$1" -c ue -- sh -c "ip -4 -o addr show uesimtun0 | awk '{print \$4}' | cut -d/ -f1"; }
wait_for 180 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/ue-b -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
  || bad "UE-B has no PDU session (uesimtun0) within 180 s"
wait_for 120 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/ue -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
  || bad "UE-V has no PDU session (uesimtun0)"
say "UE-V $(tun_ip ue) UE-B $(tun_ip ue-b)"
# The exporter's token needs the trusted key; wait for its first accepted export
# (or, in no-loop, nothing to wait for).
if [[ "${DEMO_MODE}" != no-loop ]]; then
  wait_for 180 sh -c "kubectl -n ${NAMESPACE} logs deploy/nwdaf | grep -q 'ran-ingest cell=${CELL}'" \
    || bad "no accepted cell report at nwdafd within 180 s"
fi
sleep 10

# --- 3. the load -----------------------------------------------------------------
T0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"${K[@]}" exec deploy/ue -c ue -- ping -I uesimtun0 -i 0.1 -c 900 -W 2 "${TARGET}" \
  >"${S}/ue-v-ping.txt" 2>&1 &
PING_PID=$!
sleep 10
for mbps in 1 2 3 4 5 6 7 8 9 10; do
  # 1400-byte echo requests; their replies are the downlink load.
  interval="$(python3 -c "print(f'{1400*8/($mbps*1e6):.5f}')")"
  "${K[@]}" exec deploy/ue-b -c ue -- ping -I uesimtun0 -q -s 1400 -i "${interval}" -w 4 "${TARGET}" \
    >>"${S}/ue-b-ramp.txt" 2>&1
done
"${K[@]}" exec deploy/ue-b -c ue -- ping -I uesimtun0 -q -s 1400 -i 0.00112 -w 12 "${TARGET}" \
  >>"${S}/ue-b-ramp.txt" 2>&1
T_STOP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "UE-B stopped at ${T_STOP}"
wait "${PING_PID}"

# --- 4. the tokenless POST --------------------------------------------------------
THROTTLES_BEFORE="$(logs deploy/pcf | grep -c 'action=throttle(' || true)"
"${K[@]}" exec deploy/nwdaf -c nwdaf -- sh -c "curl -s --http2-prior-knowledge --max-time 10 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' --data '{}' http://127.0.0.1:7777/nnwdaf-randata/v1/cell-reports" \
  >"${S}/tokenless-post.status" 2>/dev/null
sleep 3
THROTTLES_AFTER="$(logs deploy/pcf | grep -c 'action=throttle(' || true)"

# --- captures ---------------------------------------------------------------------
logs deploy/nwdaf | grep -E '\[demo:d441a-congestion-loop\]' >"${S}/nwdaf-chain.txt"
logs deploy/pcf   | grep -E '\[demo:d441a-congestion-loop\]' >"${S}/pcf-chain.txt"
logs deploy/gnb   | grep -E '\[demo:d441a-congestion-loop\]' >"${S}/gnb-chain.txt"
logs deploy/smf   | grep -E 'Applying PCF-updated policy' >"${S}/smf-chain.txt"
UPF_POD="$("${K[@]}" get pod -l app.kubernetes.io/name=upf -o jsonpath='{.items[0].metadata.name}')"
logs "${UPF_POD}" | grep -E 'Installed [0-9]+ QERs for SEID' >"${S}/upf-chain.txt"
logs deploy/ue-b  | grep -E 'network set Session-AMBR' >"${S}/ue-b-chain.txt"
python3 - "${S}/ue-v-ping.txt" >"${S}/p95.txt" <<'PY'
import re, sys
rtts = sorted(float(m) for m in re.findall(r"time=([\d.]+) ms", open(sys.argv[1]).read()))
if not rtts:
    print("nan"); sys.exit()
print(f"{rtts[min(len(rtts)-1, int(0.95*len(rtts)))]:.1f}")
PY
P95="$(cat "${S}/p95.txt")"
say "UE-V ping p95 = ${P95} ms; tokenless POST = $(cat "${S}/tokenless-post.status")"

# --- assertions ---------------------------------------------------------------------
[[ "$(cat "${S}/tokenless-post.status")" == 401 ]] || bad "tokenless POST is not 401"
[[ "${THROTTLES_AFTER}" == "${THROTTLES_BEFORE}" ]] || bad "the tokenless POST was followed by a throttle"
if [[ "${DEMO_MODE}" == no-loop ]]; then
  grep -q 'ran-ingest' "${S}/nwdaf-chain.txt" && bad "no-loop: nwdafd ingested a cell report"
  grep -q 'export: off (mode=no-loop)' "${S}/gnb-chain.txt" || bad "no-loop: no 'export: off' gNB line"
  grep -q 'hold(no-ran-data)' "${S}/pcf-chain.txt" || bad "no-loop: no pcfd hold(no-ran-data)"
  [[ -s "${S}/smf-chain.txt" ]] && bad "no-loop: smfd applied a PCF-updated policy"
  python3 -c "import sys; sys.exit(0 if float('${P95}') >= 100 else 1)" \
    || bad "no-loop: UE-V p95 ${P95} ms < 100 ms (the bottleneck did not build a queue)"
else
  KIND="statistics"; [[ "${DEMO_MODE}" == prediction ]] && KIND="prediction"
  python3 - "${S}" "${CELL}" "${UE_V}" "${UE_B}" "${KIND}" "${T_STOP}" <<'PY' || FAILS=$((FAILS+1))
import re, sys
from datetime import datetime
d, cell, ue_v, ue_b, kind, t_stop = sys.argv[1:7]
def load(name):
    out = []
    for l in open(f"{d}/{name}").read().splitlines():
        ts, _, msg = l.partition(" ")
        m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$", ts)
        if m:
            frac = (m.group(2) or "0")[:6].ljust(6, "0")
            out.append((datetime.strptime(f"{m.group(1)}.{frac}", "%Y-%m-%dT%H:%M:%S.%f"), msg))
    return out
def fail(msg):
    raise SystemExit(f"[scenario] FAIL: {msg}")
nw, pcf, smf, upf, ueb = (load(f) for f in
    ("nwdaf-chain.txt", "pcf-chain.txt", "smf-chain.txt", "upf-chain.txt", "ue-b-chain.txt"))
def first(rows, pat, after=None, what=None):
    for t, m in rows:
        if (after is None or t >= after) and re.search(pat, m):
            return t, m
    fail(f"no {what or pat} after {after}")
t1, _ = first(nw, rf"ran-ingest cell={cell}", what="ran-ingest")
t2, _ = first(nw, rf"udc GET USER_DATA_CONGESTION kind={kind} cell=\S+ congLevel=\d+.* → 200", t1, "UDC 200")
throttles = [(t, m) for t, m in pcf if "action=throttle(" in m]
restores = [(t, m) for t, m in pcf if "action=restore(" in m]
if any(ue_v in m for _, m in throttles + restores):
    fail("UE-V was throttled or restored")
if len(throttles) != 1 or ue_b not in throttles[0][1]:
    fail(f"expected exactly one throttle of {ue_b}, got {[m for _, m in throttles]}")
if len(restores) != 1 or ue_b not in restores[0][1]:
    fail(f"expected exactly one restore of {ue_b}, got {[m for _, m in restores]}")
t3 = throttles[0][0]
if t3 < t2:
    fail("the throttle precedes the UDC answer")
t4, _ = first(smf, r"AMBR UL/DL=1000000/1000000 bps", t3, "smfd capped policy")
t5, _ = first(upf, r"Installed 1 QERs for SEID=", t4, "upfd QER")
t6, _ = first(ueb, r"network set Session-AMBR", t3, "UE-B N1 Session-AMBR")
t7 = restores[0][0]
if t7 < t5:
    fail("the restore precedes the QER install")
first(smf, r"Applying PCF-updated policy", t7, "smfd restore policy")
print(f"[scenario] chain: ingest {t1} → udc {t2} → throttle {t3} → smf {t4} → upf {t5} → ue-b {t6} → restore {t7}")
# AMF cross-check: the last ingest names amf_ues_in_area equal to connected_ues.
last = [m for _, m in nw if "ran-ingest" in m][-1]
cu = re.search(r"connected_ues=(\d+)", last); au = re.search(r"amf_ues_in_area=(\d+)", last)
if not (cu and au and cu.group(1) == au.group(1)):
    fail(f"AMF numberOfUes does not match the gNB's connected UEs: {last}")
print(f"[scenario] connected_ues={cu.group(1)} amf_ues_in_area={au.group(1)}")
if kind == "prediction":
    hot = [t for t, m in nw if "ran-ingest" in m
           and float(re.search(r"occupancy=([\d.]+)%", m).group(1)) >= 80.0]
    lead = (hot[0] - t3).total_seconds() if hot else float("nan")
    print(f"[scenario] prediction lead time over measured >= 80%: {lead:.1f} s (reported, not asserted)")
    open(f"{d}/lead-time.txt", "w").write(f"{lead:.1f}\n")
PY
  BASE="$(ls -1d /tmp/eks-val/demos/d441a-congestion-loop/no-loop/*/scenario/p95.txt 2>/dev/null | tail -1)"
  if [[ -n "${BASE}" ]]; then
    NOLOOP="$(cat "${BASE}")"
    python3 -c "import sys; sys.exit(0 if float('${P95}') <= 0.25*float('${NOLOOP}') else 1)" \
      || bad "UE-V p95 ${P95} ms > 0.25 x no-loop ${NOLOOP} ms (${BASE})"
    say "UE-V p95 ${P95} ms vs no-loop ${NOLOOP} ms"
  else
    say "no no-loop arm captured yet: p95 ${P95} ms recorded, ratio not checked (run the no-loop arm first)"
  fi
fi

say "T0=${T0} FAILS=${FAILS}"
[[ ${FAILS} -eq 0 ]]
