#!/usr/bin/env bash
# Seeded acceptance run of demo d443a-edge-budget (nextgsim#471), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_KEY, DEMO_MODE, DEMO_VARIANT and OUT set.
# Every assertion is in analyze.py (self-test: test-scenario.sh); this script
# drives the cluster and captures. Everything goes through kubectl exec/logs
# inside the namespace: no port-forward, nothing published. Captures in
# $OUT/scenario/<act>/.
#
# The arm is DEMO_VARIANT if set, else the mode's default:
#   main          measured-budget (default). Act 1 (10 jobs), Act 2 (netem +16 ms
#                 on eas-local's veth), Act 3 (netem +20 ms on the gNB's GTP-U
#                 egress), the load act (SIGUSR1: eas-local --load 5, KPI PATCH).
#   static        static (default). The same acts: eas-local is kept throughout,
#                 and the UE logs deadline-miss once its path or compute is slow.
#   no-kpi-patch  measured-budget, revert arm: eas-local runs --no-kpi-patch, so
#                 the load act's KPI never reaches the EES: the load check fails.
#   gates         measured-budget: `mode: bogus` fails nr-she-eas, eesd, smfd and
#                 nr-ue at startup (UnknownMode), and `nr-cli ... demo
#                 d443a-edge-budget set mode=bogus` is refused and audited.
#   off           off (default): no demo: block anywhere. eesd answers in eass
#                 order, smfd still provisions N6 delay measurement (#1502, config
#                 only) and adds no n6Delays; no EAS sidecar can start (they are
#                 demo-only).
#
# Shell traps avoided (they broke earlier harnesses): no `cmd | grep -q` under
# pipefail (a SIGPIPE'd producer turns a match into a miss: capture, then grep);
# no expansion of a possibly empty array on bash 4.2 (${a[@]+"${a[@]}"}); every
# nc/curl has a timeout.
set -uo pipefail

D443A_EAS_IDS=(6b1d7e3c-0000-4000-8000-0000000471a1 6b1d7e3c-0000-4000-8000-0000000471a2
  6b1d7e3c-0000-4000-8000-0000000471a3)
D443A_EAS_NAMES=(eas-local eas-regional eas-cloud)
D443A_EEC_ID=6b1d7e3c-0000-4000-8000-0000000471ec
D443A_KEY=d443a-edge-budget

d443a_main() {
  : "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
  local K=(kubectl -n "${NAMESPACE}")
  local S="${OUT}/scenario" HERE ARM FAILS=0 keys i
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  mkdir -p "${S}"
  case "${DEMO_MODE}" in
    measured-budget) ARM="${DEMO_VARIANT:-main}" ;;
    static) ARM="${DEMO_VARIANT:-static}" ;;
    off) ARM="${DEMO_VARIANT:-off}" ;;
    *) echo "[scenario] FAIL: mode ${DEMO_MODE}"; return 1 ;;
  esac
  case "${ARM}:${DEMO_MODE}" in
    main:measured-budget|no-kpi-patch:measured-budget|gates:measured-budget) ;;
    static:static|off:off) ;;
    *) echo "[scenario] FAIL: arm ${ARM} does not run in mode ${DEMO_MODE}"; return 1 ;;
  esac
  say() { printf '[scenario] %s\n' "$*"; }
  bad() { printf '[scenario] FAIL: %s\n' "$*"; FAILS=$((FAILS+1)); }
  wait_for() {
    local t="$1"; shift
    local end=$(( $(date +%s) + t ))
    until "$@" >/dev/null 2>&1; do
      [[ $(date +%s) -ge ${end} ]] && return 1
      sleep 2
    done
  }
  # Captured, then matched: never `kubectl logs | grep -q` under pipefail.
  logs_of() { "${K[@]}" logs "deploy/$1" -c "$2" --timestamps 2>/dev/null; }
  count_in() { local t; t="$(logs_of "$1" "$2")"; grep -cE "$3" <<<"${t}" || true; }
  has_in() { [[ "$(count_in "$1" "$2" "$3")" -ge "${4:-1}" ]]; }
  scrape() {   # deploy container -> /metrics text
    "${K[@]}" exec "deploy/$1" -c "$2" -- sh -c 'curl -s --max-time 5 http://127.0.0.1:9090/metrics' 2>/dev/null
  }
  n6_avg() {   # endpoint -> smfd's latest one-way N6 average (ms), or empty
    local m; m="$(scrape smf smf)"
    sed -nE "s/^smf_n6_delay_ms\{[^}]*endpoint=\"$1\"[^}]*stat=\"avg\"\} ([0-9]+).*/\1/p" <<<"${m}" | tail -1
  }
  last_rt() {  # eesd's latest QOS_MON rtDelays (ms), or empty
    local t; t="$(logs_of ees ees)"
    sed -nE 's/.*\[demo:d443a-edge-budget\] QOS_MON rt=([0-9]+) ms.*/\1/p' <<<"${t}" | tail -1
  }
  snapshot() {  # act: logs of every component the checks read, and /metrics
    local a="${S}/$1"
    mkdir -p "${a}"
    logs_of ees ees >"${a}/ees.log"
    logs_of ees nrf-standin >"${a}/nrf-standin.log"
    logs_of smf smf >"${a}/smf.log"
    logs_of upf she-eas >"${a}/eas.log"
    logs_of ue ue >"${a}/ue.log"
    scrape smf smf >"${a}/smf.prom"
    scrape ees ees >"${a}/ees.prom"
    date -u +%FT%TZ >"${a}/at.txt"
  }
  ue_cli() {   # one nr-cli command at the base UE
    "${K[@]}" exec deploy/ue -c ue -- sh -c \
      'n=$(nr-cli --dump | grep -m1 -E "^ue[0-9]+"); nr-cli "$n" -e "$1"' sh "$1" 2>&1
  }
  jobs_act() {  # count: run jobs, wait until the UE reports them all done
    local n="$1" before
    before="$(count_in ue ue '\[demo:d443a-edge-budget\] JOB job=')"
    ue_cli "she-offload job count=${n} interval-ms=1000" >>"${S}/cli.txt"
    wait_for $(( 30 + 3 * n )) sh -c \
      "[ \$(kubectl -n ${NAMESPACE} logs deploy/ue -c ue 2>/dev/null | grep -c '\[demo:d443a-edge-budget\] JOB job=') -ge $(( before + n )) ]" \
      || bad "the UE did not finish ${n} job(s)"
  }
  netem_eas() {  # add|del: eas-local 16 ms further away (its emulated distance 4 -> 20 ms)
    local d=4
    [[ "$1" == add ]] && d=20
    "${K[@]}" exec deploy/upf -c she-eas -- ip netns exec eas-local tc qdisc change dev eth0 root netem delay "${d}ms"
  }
  netem_gnb() {  # add|del +20 ms on the gNB's GTP-U (UDP 2152) egress only
    if [[ "$1" == add ]]; then
      "${K[@]}" exec deploy/gnb -c netem -- sh -c 'tc qdisc add dev eth0 root handle 1: prio &&
        tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 20ms &&
        tc filter add dev eth0 parent 1:0 protocol ip prio 1 u32 match ip dport 2152 0xffff flowid 1:3'
    else
      "${K[@]}" exec deploy/gnb -c netem -- tc qdisc del dev eth0 root
    fi
  }
  say "arm=${ARM} mode=${DEMO_MODE}"
  printf 'arm=%s\nmode=%s\ndeadline_ms=15\n' "${ARM}" "${DEMO_MODE}" >"${S}/meta.txt"

  # --- 1. CCA keys, trusted at the NRF -------------------------------------------
  # Generated here, outside $OUT; only public JWKs go to the cluster's trust store
  # and each private key straight into the container that uses it.
  keys="$(mktemp -d -t d443a-keys-XXXXXX)"
  # shellcheck disable=SC2064  # expand now: the directory is this run's
  trap "rm -rf '${keys}'" EXIT
  python3 "${HERE}/cca.py" keygen "${keys}" "${D443A_EAS_IDS[@]}" "${D443A_EEC_ID}" >/dev/null \
    || bad "CCA key generation"
  local -a jwks=()
  for f in "${keys}"/*.jwk; do jwks+=(--from-file="$(basename "${f}")=${f}"); done
  "${K[@]}" create configmap d443a-cca-trusted ${jwks[@]+"${jwks[@]}"} --dry-run=client -o yaml \
    | "${K[@]}" apply -f - >/dev/null || bad "trusted-key ConfigMap"
  wait_for 180 "${K[@]}" exec deploy/nrf -c nrf -- test -s "/etc/nextgcore/cca-trusted/${D443A_EEC_ID}.jwk" \
    || bad "the NRF does not see the JWKs within 180 s"

  # --- 2. eesd, with the NRF's JWKS -----------------------------------------------
  local jw
  jw="$("${K[@]}" exec deploy/nrf -c nrf -- curl -s --http2-prior-knowledge --max-time 5 \
    http://127.0.0.1:7777/nnrf-oauth2/v1/jwks 2>/dev/null)"
  python3 -c 'import json,sys; k=json.loads(sys.argv[1])["keys"]; assert k' "${jw}" 2>/dev/null \
    || bad "no JWKS from the NRF"
  printf '%s' "${jw}" >"${S}/nrf-jwks.json"
  "${K[@]}" create configmap d443a-ees-jwks --from-file=jwks.json="${S}/nrf-jwks.json" \
    --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null || bad "eesd JWKS ConfigMap"
  "${K[@]}" scale deploy/ees --replicas=1 >/dev/null || bad "scale ees"
  "${K[@]}" rollout status deploy/ees --timeout=180s >/dev/null || bad "ees rollout"
  if [[ "${ARM}" == off ]]; then
    d443a_off
    return $(( FAILS > 0 ))
  fi
  wait_for 120 has_in ees ees 'Nsmf_EventExposure_Subscribe QOS_MON .* 201' \
    || bad "eesd's QOS_MON subscription at smfd was not created within 120 s"
  wait_for 60 has_in ees nrf-standin 'PUT -> 20[01]' || bad "the stand-in EES profile was not registered"

  # --- 3. the EAS sidecars ----------------------------------------------------------
  wait_for 240 "${K[@]}" exec deploy/upf -c she-eas -- test -e /tmp/d443a/ready \
    || bad "the she-eas sidecar never got ready"
  for i in 0 1 2; do
    "${K[@]}" exec -i deploy/upf -c she-eas -- sh -c "umask 077; cat >/tmp/d443a/cca/${D443A_EAS_NAMES[i]}.key" \
      <"${keys}/${D443A_EAS_IDS[i]}.key" || bad "${D443A_EAS_NAMES[i]} key handover"
  done
  local local_args="--load 5"
  [[ "${ARM}" == no-kpi-patch ]] && local_args="--load 5 --no-kpi-patch"
  printf 'eas-local: %s\neas-regional:\neas-cloud:\n' "${local_args}" \
    | "${K[@]}" exec -i deploy/upf -c she-eas -- sh -c 'cat >/tmp/d443a/start.tmp && mv /tmp/d443a/start.tmp /tmp/d443a/start' \
    || bad "EAS start"
  say "EASes started (eas-local: ${local_args})"
  wait_for 120 has_in upf she-eas '\[demo:d443a-edge-budget\] EAS-REG eas=[a-z-]+ registrationId=' 3 \
    || bad "the three EASes did not register at eesd within 120 s"

  # --- 4. the UE: PDU session, EEC key --------------------------------------------
  "${K[@]}" rollout status deploy/ue --timeout=300s >/dev/null || bad "ue rollout"
  wait_for 240 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/ue -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
    || bad "the UE has no PDU session (uesimtun0) within 240 s"
  "${K[@]}" exec deploy/ue -c ue -- sh -c "ip -4 -o addr show uesimtun0 | awk '{print \$4}' | cut -d/ -f1" \
    >"${S}/ue-ip.txt" 2>/dev/null
  "${K[@]}" exec -i deploy/ue -c ue -- sh -c 'mkdir -p /tmp/d443a-cca && umask 077 && cat >/tmp/d443a-cca/eec.key' \
    <"${keys}/${D443A_EEC_ID}.key" || bad "EEC key handover"
  if [[ "${ARM}" == gates ]]; then
    d443a_gates
    return $(( FAILS > 0 ))
  fi

  # --- 4b. netem preflight: fail loudly without NET_ADMIN or sch_netem --------------
  local pre
  pre="$("${K[@]}" exec deploy/upf -c she-eas -- sh -c \
    'ip netns exec eas-cloud tc qdisc add dev lo root netem delay 0ms && ip netns exec eas-cloud tc qdisc del dev lo root && echo netem-ok' 2>&1)"
  if [[ "${pre}" != *netem-ok* ]]; then
    bad "netem preflight: no NET_ADMIN or no sch_netem on the node (${pre//$'\n'/ }); Acts 2 and 3 cannot run"
    echo "netem=unavailable" >>"${S}/meta.txt"
  else
    echo "netem=ok" >>"${S}/meta.txt"
  fi
  pre="$("${K[@]}" exec deploy/gnb -c netem -- sh -c 'tc qdisc show dev eth0 && echo tc-ok' 2>&1)"
  [[ "${pre}" == *tc-ok* ]] || bad "the gnb netem sidecar cannot run tc: ${pre//$'\n'/ }"

  # --- 5. measurements in place ------------------------------------------------------
  # smfd provisions N6 delay measurement at association (smf_n6_delay_ms per EAS),
  # and the QOS_MON SRR on the UE's session once eesd subscribed: eesd logs a
  # QOS_MON rt= line per report. If the session predates the subscription and no
  # report arrives, the UE pod is power-cycled once (recorded in meta.txt).
  wait_for 120 bash -c "$(declare -f n6_avg scrape); K=(kubectl -n ${NAMESPACE}); [ -n \"\$(n6_avg 10.60.0.11)\" ] && [ -n \"\$(n6_avg 10.60.0.12)\" ] && [ -n \"\$(n6_avg 10.60.0.13)\" ]" \
    || bad "smfd has no N6 delay result for every EAS within 120 s"
  if ! wait_for 60 has_in ees ees '\[demo:d443a-edge-budget\] QOS_MON rt='; then
    echo "ue_power_cycled=true" >>"${S}/meta.txt"
    "${K[@]}" delete pod -l app.kubernetes.io/name=ue --wait=false >/dev/null
    sleep 5
    "${K[@]}" rollout status deploy/ue --timeout=300s >/dev/null || bad "ue rollout after the power cycle"
    wait_for 240 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/ue -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
      || bad "no PDU session after the power cycle"
    "${K[@]}" exec -i deploy/ue -c ue -- sh -c 'mkdir -p /tmp/d443a-cca && umask 077 && cat >/tmp/d443a-cca/eec.key' \
      <"${keys}/${D443A_EEC_ID}.key" || bad "EEC key handover after the power cycle"
    "${K[@]}" exec deploy/ue -c ue -- sh -c "ip -4 -o addr show uesimtun0 | awk '{print \$4}' | cut -d/ -f1" \
      >"${S}/ue-ip.txt" 2>/dev/null
    wait_for 120 has_in ees ees '\[demo:d443a-edge-budget\] QOS_MON rt=' || bad "eesd gets no QOS_MON report"
  fi
  local rt0; rt0="$(last_rt)"
  echo "rt_baseline=${rt0:-none}" >>"${S}/meta.txt"
  snapshot warm

  # --- 6. Act 1: the baseline selection ------------------------------------------------
  jobs_act 10
  snapshot act1

  if [[ "${ARM}" != no-kpi-patch ]]; then
    # --- 7. Act 2: eas-local moves away (+16 ms one way on its N6 path) -------------
    netem_eas add || bad "netem on eas-local"
    wait_for 60 bash -c "$(declare -f n6_avg scrape); K=(kubectl -n ${NAMESPACE}); v=\$(n6_avg 10.60.0.11); [ -n \"\$v\" ] && [ \"\$v\" -ge 8 ]" \
      || bad "smf_n6_delay_ms for eas-local did not reach 8 ms within 60 s"
    sleep 4   # one more QOS_MON period, so eesd's sample carries it
    jobs_act 3
    snapshot act2
    netem_eas del || bad "netem off eas-local"
    wait_for 60 bash -c "$(declare -f n6_avg scrape); K=(kubectl -n ${NAMESPACE}); v=\$(n6_avg 10.60.0.11); [ -n \"\$v\" ] && [ \"\$v\" -lt 8 ]" \
      || bad "eas-local's N6 delay did not come back under 8 ms"

    # --- 8. Act 3: the UE's own path is slow (+20 ms on the gNB's N3 egress) --------
    netem_gnb add || bad "netem on the gNB"
    wait_for 60 bash -c "$(declare -f last_rt logs_of); K=(kubectl -n ${NAMESPACE}); v=\$(last_rt); [ -n \"\$v\" ] && [ \"\$v\" -ge $(( ${rt0:-0} + 15 )) ]" \
      || bad "QOS_MON rtDelays did not rise by 15 ms within 60 s"
    jobs_act 2
    snapshot act3
    netem_gnb del || bad "netem off the gNB"
    wait_for 60 bash -c "$(declare -f last_rt logs_of); K=(kubectl -n ${NAMESPACE}); v=\$(last_rt); [ -n \"\$v\" ] && [ \"\$v\" -lt $(( ${rt0:-0} + 10 )) ]" \
      || bad "rtDelays did not come back"
  fi

  # --- 9. the load act: eas-local loses compute (avlComp 50 -> 5) --------------------
  "${K[@]}" exec deploy/upf -c she-eas -- sh -c 'kill -USR1 "$(cat /tmp/d443a/eas-local.pid)"' || bad "SIGUSR1"
  wait_for 30 has_in upf she-eas '\[eas-local\] .*LOAD eas=eas-local' || bad "eas-local did not apply the load"
  sleep 3
  jobs_act 3
  snapshot load

  # --- 10. the shutdown: every EAS deregisters --------------------------------------
  echo "failures=${FAILS}" >>"${S}/meta.txt"
  say "done, ${FAILS} driver failure(s); verdict from analyze.py"
  python3 "${HERE}/analyze.py" "${ARM}" "${S}" | tee "${S}/analyze.txt"
  local rc=${PIPESTATUS[0]}
  (( FAILS == 0 && rc == 0 ))
}

d443a_off() {
  # The demo-off arm on the overlay's topology: no demo: block anywhere.
  local K=(kubectl -n "${NAMESPACE}") S="${OUT}/scenario"
  wait_for 120 has_in smf smf 'accepted N6 Delay Measurement Control Information x[0-9]+' \
    || bad "smfd did not provision N6 delay measurement (config-only, #1502)"
  # The UE has no demo, so she-offload is the unknown command it was.
  "${K[@]}" rollout status deploy/ue --timeout=300s >/dev/null || bad "ue rollout"
  ue_cli "she-offload status" >"${S}/off-cli.txt" 2>&1
  # An EAS sidecar cannot start without the demo (nr-she-eas is demo-only).
  "${K[@]}" exec deploy/upf -c she-eas -- sh -c \
    'printf "eas_id: x\naddress: 10.60.0.11\nmax_resp_time_ms: 1\navl_comp: 1\nees: {api_root: \"http://127.0.0.1:1\"}\n" >/tmp/d443a/off.yaml; nr-she-eas -c /tmp/d443a/off.yaml; echo "rc=$?"' \
    >"${S}/off-eas.txt" 2>&1
  snapshot off
  python3 "${HERE}/analyze.py" off "${S}" | tee "${S}/analyze.txt"
  local rc=${PIPESTATUS[0]}
  (( rc == 0 )) || FAILS=$((FAILS+1))
}

d443a_gates() {
  # mode: bogus at startup, every binary of the demo; and the runtime switch.
  local K=(kubectl -n "${NAMESPACE}") S="${OUT}/scenario" g="${OUT}/scenario/gates.txt"
  : >"${g}"
  # The full output goes to gates/<name>.txt; the gate line keeps the lines a
  # check reads (the demo error, rc=, the show line), whatever precedes them.
  gate() {
    mkdir -p "${S}/gates-out"
    printf '%s\n' "$3" >"${S}/gates-out/$1-$2.txt"
    printf '%s %s: %s\n' "$1" "$2" \
      "$(grep -E 'unknown mode|rc=|demo=|mode=|Error' <<<"$3" | tr '\n' ' ' | head -c 1200)" >>"${g}"
  }
  local r
  r="$("${K[@]}" exec deploy/upf -c she-eas -- sh -c \
    'sed "s/mode: measured-budget/mode: bogus/" /tmp/d443a/eas-local.yaml >/tmp/d443a/bogus.yaml && nr-she-eas -c /tmp/d443a/bogus.yaml; echo "rc=$?"' 2>&1)"
  gate nr-she-eas bogus "${r}"
  r="$("${K[@]}" exec deploy/ees -c ees -- sh -c \
    'sed "s/mode: measured-budget/mode: bogus/" /etc/nextgcore/ees.yaml >/tmp/bogus.yaml && timeout 20 nextgcore-eesd -c /tmp/bogus.yaml --sbi-addr 127.0.0.1 --sbi-port 17999; echo "rc=$?"' 2>&1)"
  gate eesd bogus "${r}"
  r="$("${K[@]}" exec deploy/smf -c smf -- sh -c \
    'f=$(ls /etc/nextgcore-resolved/smf.yaml /etc/nextgcore/smf.yaml 2>/dev/null | head -1); sed "s/mode: measured-budget/mode: bogus/" "$f" >/tmp/bogus.yaml && SMF_METRICS_PORT=19999 timeout 20 nextgcore-smfd -c /tmp/bogus.yaml; echo "rc=$?"' 2>&1)"
  gate smfd bogus "${r}"
  r="$("${K[@]}" exec deploy/ue -c ue -- sh -c \
    'sed "s/mode: measured-budget/mode: bogus/" /etc/nextgsim/ue.yaml >/tmp/bogus.yaml && timeout 20 nr-ue -c /tmp/bogus.yaml; echo "rc=$?"' 2>&1)"
  gate nr-ue bogus "${r}"
  r="$(ue_cli "demo d443a-edge-budget set mode=bogus"; echo "rc=$?"; ue_cli "demo d443a-edge-budget show")"
  gate nr-cli set-bogus "${r}"
  r="$(ue_cli "demo d443a-edge-budget set mode=static"; ue_cli "demo d443a-edge-budget show"; ue_cli "demo d443a-edge-budget set mode=measured-budget")"
  gate nr-cli set-static "${r}"
  # Captured BEFORE the analysis: the audit line is in the UE's log.
  snapshot gates
  python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/analyze.py" gates "${S}" | tee "${S}/analyze.txt"
  local rc=${PIPESTATUS[0]}
  (( rc == 0 )) || FAILS=$((FAILS+1))
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  d443a_main
fi
