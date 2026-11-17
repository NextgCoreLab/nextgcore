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
#                 on eas-local's veth), Act 3 (netem +20 ms on the gNB's egress),
#                 the load act (SIGUSR1: eas-local --load 5, KPI PATCH).
#   static        static (default). The same acts: eas-local is kept throughout,
#                 and the UE logs deadline-miss once its path or compute is slow.
#   oauth2        measured-budget, main's acts with SBI OAuth2 required: amfd and
#                 smfd restarted with NEXTGCORE_SBI_OAUTH2_REQUIRE=1 and a CCA
#                 key, eesd an AF at the NRF (--nrf-uri, #1581), so its Subscribe
#                 carries an NRF token; a bare Subscribe is refused (401).
#   restart-flip  measured-budget: Acts 1 and 2, then, with Act 2's netem still
#                 on, eesd restarted in mode static: the selection flips back to
#                 eas-local (the anchor's toggle criterion).
#   gates         measured-budget: `mode: bogus` fails nr-she-eas, eesd, smfd and
#                 nr-ue at startup (UnknownMode), and `nr-cli ... demo
#                 d443a-edge-budget set mode=bogus` is refused and audited.
#   off           off (default): no demo: block anywhere. eesd answers in eass
#                 order, smfd still provisions N6 delay measurement (#1502, config
#                 only) and adds no n6Delays; no EAS sidecar can start (they are
#                 demo-only).
# Revert arms (measured-budget; each FAILS the act it names, analyze.py's
# REVERT_TARGET, and holds only if its cause is shown):
#   no-kpi-patch          eas-local runs --no-kpi-patch: the load act fails.
#   no-qos-mon            eesd without ees.edge_budget.smf_uri, so no QOS_MON
#                         subscription: Acts 2 and 3 fail.
#   wrong-callback-token  eesd without smf_uri, and a QOS_MON subscription at smfd
#                         whose notifUri carries a path token eesd never minted:
#                         smfd's notifies are refused, so Acts 2 and 3 fail.
#   no-upf-qos            upfd without UPF_N6_DELAY_MEASUREMENT and
#                         UPF_QOS_FLOW_MONITORING (QoS monitoring unconfigured on
#                         the UPF; upf and smf restarted): Acts 2 and 3 fail.
#   bind-eth0             the UE's EEC bound to eth0, not the PDU session: the
#                         EES still selects eas-local, but the job never reaches
#                         dn, so Act 1 fails.
#
# Every arm first records, from the she-eas and gnb netem sidecars' start lines,
# which of sch_netem, sch_prio and cls_u32 each node had loaded before the pod's
# first tc, and the node names (meta.txt).
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

d443a_main() {
  : "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
  local K=(kubectl -n "${NAMESPACE}" --request-timeout=120s)
  local S="${OUT}/scenario" HERE ARM FAILS=0 keys nf
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
    oauth2:measured-budget|restart-flip:measured-budget) ;;
    no-qos-mon:measured-budget|wrong-callback-token:measured-budget) ;;
    no-upf-qos:measured-budget|bind-eth0:measured-budget) ;;
    static:static|off:off) ;;
    *) echo "[scenario] FAIL: arm ${ARM} does not run in mode ${DEMO_MODE}"; return 1 ;;
  esac
  # Which acts the arm runs, and whether eesd gets QOS_MON reports at all.
  local REPORTS=true ACT2=true ACT3=true LOAD=true
  case "${ARM}" in
    no-qos-mon|wrong-callback-token|no-upf-qos) REPORTS=false; LOAD=false ;;
    no-kpi-patch) ACT2=false; ACT3=false ;;
    bind-eth0) ACT2=false; ACT3=false; LOAD=false ;;
    restart-flip) ACT3=false; LOAD=false ;;
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
      "[ \$(kubectl -n ${NAMESPACE} --request-timeout=60s logs deploy/ue -c ue 2>/dev/null | grep -c '\[demo:d443a-edge-budget\] JOB job=') -ge $(( before + n )) ]" \
      || bad "the UE did not finish ${n} job(s)"
  }
  netem_eas() {  # add|del: eas-local 16 ms further away (its emulated distance 4 -> 20 ms)
    local d=4
    [[ "$1" == add ]] && d=20
    "${K[@]}" exec deploy/upf -c she-eas -- ip netns exec eas-local tc qdisc change dev eth0 root netem delay "${d}ms"
  }
  netem_gnb() {  # add|del +20 ms on the gNB's egress: netem only (no prio, no u32)
    if [[ "$1" == add ]]; then
      "${K[@]}" exec deploy/gnb -c netem -- tc qdisc add dev eth0 root netem delay 20ms
    else
      "${K[@]}" exec deploy/gnb -c netem -- tc qdisc del dev eth0 root
    fi
  }
  ees_config_edit() {  # python expression over `y` (ees.yaml's text) -> ees-config
    "${K[@]}" get configmap ees-config -o json >"${S}/ees-config.before.json" || return 1
    python3 -c 'import json,re,sys
d=json.load(open(sys.argv[1])); y=d["data"]["ees.yaml"]
d["data"]["ees.yaml"]=eval(sys.argv[2])
for k in ("resourceVersion","uid","creationTimestamp","managedFields"): d["metadata"].pop(k,None)
print(json.dumps(d))' "${S}/ees-config.before.json" "$1" | "${K[@]}" apply -f - >/dev/null || return 1
    "${K[@]}" get configmap ees-config -o jsonpath='{.data.ees\.yaml}' >"${S}/ees-config.${2}.yaml"
  }
  node_modules() {  # deploy container tag -> the sidecar's module record line
    "${K[@]}" logs "deploy/$1" -c "$2" 2>/dev/null | grep -m1 -E 'modules before the first tc: ' \
      >"${S}/modules-$3.txt" || true
    printf 'node_%s=%s\nmodules_%s=%s\n' "$3" \
      "$(sed -nE 's/.* node=([^ ]+) modules before.*/\1/p' "${S}/modules-$3.txt")" "$3" \
      "$(sed -nE 's/.*modules before the first tc: (sch_netem=[a-z]+ sch_prio=[a-z]+ cls_u32=[a-z]+).*/\1/p' \
        "${S}/modules-$3.txt" | tr ' ' ',')" >>"${S}/meta.txt"
  }
  say "arm=${ARM} mode=${DEMO_MODE}"
  printf 'arm=%s\nmode=%s\ndeadline_ms=15\n' "${ARM}" "${DEMO_MODE}" >"${S}/meta.txt"

  # --- 1. the EEC's CCA key ------------------------------------------------------
  # Generated here, outside $OUT; its public JWK goes to the NRF's trust store
  # (step 3, with the EASes' own) and the private key straight into the UE. Each
  # EAS creates its own key in its pod (eas.yaml): only its JWK leaves it.
  keys="$(mktemp -d -t d443a-keys-XXXXXX)"
  # shellcheck disable=SC2064  # expand now: the directory is this run's
  trap "rm -rf '${keys}'" EXIT
  python3 "${HERE}/cca.py" keygen "${keys}" "${D443A_EEC_ID}" >/dev/null || bad "CCA key generation"

  # --- 1b. per-arm records: the node modules, before anything else ---------------
  # Which of sch_netem, sch_prio and cls_u32 each node had loaded BEFORE the
  # pod's first tc: each sidecar logs /proc/modules (and its node) at start,
  # before any tc. A NET_ADMIN tc can make the kernel autoload a module, which
  # outlives the namespace; the operator accepts sch_netem's on devtest1
  # (2026-11-16), recorded per run. Read before any arm restarts a pod.
  wait_for 240 "${K[@]}" exec deploy/upf -c she-eas -- test -e /tmp/d443a/ready \
    || bad "the she-eas sidecar never got ready"
  wait_for 120 has_in gnb netem 'modules before the first tc: ' || bad "the gnb netem sidecar logged no module record"
  node_modules upf she-eas upf
  node_modules gnb netem gnb
  # Kept for the runs before the gnb record existed: the upf node's sch_netem.
  echo "sch_netem_before_first_tc=$(sed -nE 's/.*sch_netem=([a-z]+).*/\1/p' "${S}/modules-upf.txt")" >>"${S}/meta.txt"

  # --- 1c. the arm's fault or setting, applied to the deployed overlay -----------
  case "${ARM}" in
    no-upf-qos)
      # QoS monitoring unconfigured on the UPF: upfd restarted without both, so it
      # advertises neither UN6DM nor QFQM; smfd restarted to associate afresh; the
      # UE re-attached (step 4).
      "${K[@]}" set env deploy/upf -c upf UPF_N6_DELAY_MEASUREMENT- UPF_QOS_FLOW_MONITORING- >/dev/null \
        || bad "upf env"
      "${K[@]}" rollout status deploy/upf --timeout=300s >/dev/null || bad "upf rollout"
      # Until the old pod is gone, `exec deploy/upf` may pick it.
      wait_for 180 sh -c "[ \"\$(kubectl -n ${NAMESPACE} --request-timeout=60s get pods -l app.kubernetes.io/name=upf --no-headers 2>/dev/null | wc -l)\" -eq 1 ]" \
        || bad "the old upf pod did not go within 180 s"
      wait_for 240 "${K[@]}" exec deploy/upf -c she-eas -- test -e /tmp/d443a/ready \
        || bad "the new she-eas sidecar never got ready"
      "${K[@]}" rollout restart deploy/smf >/dev/null && "${K[@]}" rollout status deploy/smf --timeout=300s >/dev/null \
        || bad "smf restart"
      "${K[@]}" delete pod -l app.kubernetes.io/name=ue --wait=false >/dev/null || bad "ue power cycle"
      ;;
    bind-eth0)
      # The EEC bound to the pod network, not the PDU session (the UE restarts).
      "${K[@]}" set env deploy/ue -c d443a-eec-config EEC_DEVICE=eth0 >/dev/null || bad "ue EEC_DEVICE"
      ;;
    no-qos-mon|wrong-callback-token)
      ees_config_edit 're.sub(r"(?m)^[ \t]*smf_uri:.*\n", "", y)' no-smf-uri || bad "ees-config without smf_uri"
      ;;
    oauth2)
      # amfd and smfd enforce SBI OAuth2 and attach NRF tokens (their CCA keys are
      # made in the pod, only the public JWKs leave it: step 3); eesd becomes an
      # AF at the NRF (#1581) with its own CCA key.
      local nf
      for nf in amf smf; do
        "${K[@]}" set env "deploy/${nf}" -c "${nf}" NEXTGCORE_SBI_OAUTH2_REQUIRE=1 \
          NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE=/tmp/d443a-cca/cca.key \
          NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR=/tmp/d443a-cca-pub >/dev/null || bad "${nf} OAuth2 env"
      done
      # NEXTGCORE_SBI_PROFILE=dev as on every base NF (k8s/manifests): eesd's NRF
      # client is then cleartext h2c like theirs, not mTLS with certificates this
      # cluster does not provision. eesd's own server and its per-operation OAuth2
      # gate do not read the profile.
      "${K[@]}" set env deploy/ees -c ees NEXTGCORE_SBI_CCA_SIGNING_KEY_FILE=/tmp/d443a-cca/cca.key \
        NEXTGCORE_SBI_CCA_PUBLIC_JWK_DIR=/tmp/d443a-cca-pub NEXTGCORE_SBI_PROFILE=dev >/dev/null || bad "ees CCA env"
      "${K[@]}" patch deploy/ees --type=json -p "[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--nrf-uri\"},{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"http://nrf.${NAMESPACE}.svc.cluster.local:7777\"}]" \
        >/dev/null || bad "ees --nrf-uri"
      for nf in amf smf; do
        "${K[@]}" rollout status "deploy/${nf}" --timeout=300s >/dev/null || bad "${nf} rollout"
      done
      ;;
  esac
  "${K[@]}" get deploy/upf deploy/gnb deploy/ees deploy/ue -o json >"${S}/pod-specs.json" 2>/dev/null || bad "pod specs"

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
  wait_for 60 has_in ees nrf-standin 'PUT -> 20[01]' || bad "the stand-in EES profile was not registered"
  if [[ "${ARM}" == oauth2 ]]; then
    for nf in amf smf ees; do
      wait_for 120 "${K[@]}" exec "deploy/${nf}" -c "${nf}" -- sh -c 'ls /tmp/d443a-cca-pub/*.jwk' \
        || bad "${nf} published no CCA public JWK"
      local j
      j="$("${K[@]}" exec "deploy/${nf}" -c "${nf}" -- sh -c 'ls /tmp/d443a-cca-pub/*.jwk | head -1' 2>/dev/null)"
      "${K[@]}" exec "deploy/${nf}" -c "${nf}" -- cat "${j}" >"${keys}/$(basename "${j}")" 2>/dev/null \
        || bad "${nf} JWK copy"
      echo "${nf} $(basename "${j}" .jwk)" >>"${S}/oauth2-ids.txt"
    done
  fi
  if [[ "${ARM}" == wrong-callback-token ]]; then
    # A QOS_MON subscription at smfd, eesd's own body, whose notifUri carries a
    # path token eesd never minted (fresh random, 128 bits).
    local ees_ip tok body
    ees_ip="$("${K[@]}" get pod -l app.kubernetes.io/name=ees -o jsonpath='{.items[0].status.podIP}')"
    tok="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
    body="{\"notifId\":\"d443a-wrong-token\",\"notifUri\":\"http://${ees_ip}:7777/d443a-edge-budget/qos-mon/${tok}\",\"eventSubs\":[{\"event\":\"QOS_MON\"}],\"anyUeInd\":true,\"notifMethod\":\"PERIODIC\",\"repPeriod\":2,\"supportedFeatures\":\"10\"}"
    "${K[@]}" exec deploy/ees -c nrf-standin -- curl -s --http2-prior-knowledge --max-time 5 -D - -o /dev/null \
      -X POST -H 'Content-Type: application/json' -d "${body}" \
      "http://smf.${NAMESPACE}.svc.cluster.local:7777/nsmf-event-exposure/v1/subscriptions" 2>&1 \
      | tr -d '\r' | grep -iE '^(HTTP/|location:)' >"${S}/wrong-sub.txt"
    grep -qE '^HTTP/[0-9.]+ 201' "${S}/wrong-sub.txt" || bad "smfd did not accept the wrong-token subscription: $(tr '\n' ' ' <"${S}/wrong-sub.txt")"
  fi

  # --- 3. the EAS sidecars ----------------------------------------------------------
  local local_args="--load 5"
  [[ "${ARM}" == no-kpi-patch ]] && local_args="--load 5 --no-kpi-patch"
  printf 'eas-local: %s\neas-regional:\neas-cloud:\n' "${local_args}" \
    | "${K[@]}" exec -i deploy/upf -c she-eas -- sh -c 'cat >/tmp/d443a/start.tmp && mv /tmp/d443a/start.tmp /tmp/d443a/start' \
    || bad "EAS start"
  say "EASes started (eas-local: ${local_args})"
  # Each EAS's own public JWK, from its own directory, then all trusted at the NRF
  # (the EASes retry their token requests until it trusts them).
  local id i=0 e
  for id in "${D443A_EAS_IDS[@]}"; do
    e="${D443A_EAS_NAMES[$i]}"; i=$((i+1))
    wait_for 60 "${K[@]}" exec deploy/upf -c she-eas -- test -s "/tmp/d443a-jwk-${e}/${id}.jwk" \
      || bad "no public JWK from EAS ${e}"
    "${K[@]}" exec deploy/upf -c she-eas -- cat "/tmp/d443a-jwk-${e}/${id}.jwk" >"${keys}/${id}.jwk" 2>/dev/null
  done
  # The EASes' isolation: each key directory and JWK, owner and mode, and the next
  # EAS's uid failing to read this one's private key.
  "${K[@]}" exec deploy/upf -c she-eas -- sh -c '
    set -- eas-local 65531 eas-regional 65532 eas-cloud 65533
    names="$1 $3 $5"; uids="$2 $4 $6"
    i=0
    for e in $names; do
      i=$((i+1)); u=$(echo $uids | cut -d" " -f$i); o=$(echo $uids | cut -d" " -f$(( i % 3 + 1 )))
      k=$(stat -c "%a:%u" /tmp/d443a-key-$e 2>&1); j=$(stat -c "%a:%u" /tmp/d443a-jwk-$e/*.jwk 2>&1)
      if err=$(setpriv --reuid=$o --regid=$o --clear-groups --no-new-privs cat /tmp/d443a-key-$e/cca.key 2>&1 >/dev/null); then
        x=readable
      else
        case "$err" in *"ermission denied"*) x=denied ;; *) x="error:$(echo "$err" | tr " " _)" ;; esac
      fi
      echo "$e uid=$u keydir=$k jwk=$j cross_uid=$o cross=$x"
    done' >"${S}/eas-keys.txt" 2>&1 || bad "EAS key isolation capture"
  local -a jwks=()
  for f in "${keys}"/*.jwk; do jwks+=(--from-file="$(basename "${f}")=${f}"); done
  "${K[@]}" create configmap d443a-cca-trusted ${jwks[@]+"${jwks[@]}"} --dry-run=client -o yaml \
    | "${K[@]}" apply -f - >/dev/null || bad "trusted-key ConfigMap"
  wait_for 180 "${K[@]}" exec deploy/nrf -c nrf -- test -s "/etc/nextgcore/cca-trusted/${D443A_EAS_IDS[0]}.jwk" \
    || bad "the NRF does not see the JWKs within 180 s"
  if [[ "${ARM}" == oauth2 ]]; then
    local nfid
    while read -r nf nfid; do
      wait_for 180 "${K[@]}" exec deploy/nrf -c nrf -- test -s "/etc/nextgcore/cca-trusted/${nfid}.jwk" \
        || bad "the NRF does not see ${nf}'s JWK within 180 s"
    done <"${S}/oauth2-ids.txt"
    # A fresh N2 and PDU session through the OAuth2 amfd and smfd.
    "${K[@]}" delete pod -l app.kubernetes.io/name=gnb --wait=true --timeout=120s >/dev/null || bad "gnb restart"
    "${K[@]}" rollout status deploy/gnb --timeout=300s >/dev/null || bad "gnb rollout"
    "${K[@]}" delete pod -l app.kubernetes.io/name=ue --wait=false >/dev/null || bad "ue power cycle"
  fi
  wait_for 240 has_in upf she-eas '\[demo:d443a-edge-budget\] EAS-REG eas=[a-z-]+ registrationId=' 3 \
    || bad "the three EASes did not register at eesd within 240 s"
  case "${ARM}" in
    no-qos-mon|wrong-callback-token)
      wait_for 60 has_in ees ees 'no ees.edge_budget.smf_uri: no QOS_MON subscription' \
        || bad "eesd did not log that it has no smf_uri" ;;
    *)
      wait_for 180 has_in ees ees 'Nsmf_EventExposure_Subscribe QOS_MON .* 201' \
        || bad "eesd's QOS_MON subscription at smfd was not created within 180 s" ;;
  esac

  # --- 4. the UE: PDU session, EEC key --------------------------------------------
  "${K[@]}" rollout status deploy/ue --timeout=300s >/dev/null || bad "ue rollout"
  wait_for 240 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} --request-timeout=60s exec deploy/ue -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
    || bad "the UE has no PDU session (uesimtun0) within 240 s"
  "${K[@]}" exec deploy/ue -c ue -- sh -c "ip -4 -o addr show uesimtun0 | awk '{print \$4}' | cut -d/ -f1" \
    >"${S}/ue-ip.txt" 2>/dev/null
  "${K[@]}" exec -i deploy/ue -c ue -- sh -c 'mkdir -p /tmp/d443a-cca && umask 077 && cat >/tmp/d443a-cca/eec.key' \
    <"${keys}/${D443A_EEC_ID}.key" || bad "EEC key handover"
  "${K[@]}" exec deploy/ue -c ue -- sh -c "grep -E '^[[:space:]]*device:' /etc/nextgsim/ue.yaml" \
    >"${S}/ue-eec.txt" 2>&1 || bad "the UE's eec device"
  if [[ "${ARM}" == oauth2 ]]; then
    # The enforcement is real: a bare Subscribe at smfd is refused.
    {
      for nf in amf smf; do
        echo "${nf}: $(logs_of "${nf}" "${nf}" | grep -m1 'OAuth2 enforcement enabled')"
      done
      echo "bare-subscribe: $("${K[@]}" exec deploy/ees -c nrf-standin -- curl -s --http2-prior-knowledge \
        --max-time 5 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
        -d '{"notifId":"bare","notifUri":"http://127.0.0.1:1/x","eventSubs":[{"event":"QOS_MON"}],"anyUeInd":true,"notifMethod":"PERIODIC","repPeriod":2}' \
        "http://smf.${NAMESPACE}.svc.cluster.local:7777/nsmf-event-exposure/v1/subscriptions" 2>&1)"
    } >"${S}/oauth2.txt"
  fi
  if [[ "${ARM}" == gates ]]; then
    d443a_gates
    return $(( FAILS > 0 ))
  fi

  # --- 4b. netem preflight: fail loudly without NET_ADMIN or sch_netem --------------
  local pre
  [[ -s "${S}/modules-upf.txt" && -s "${S}/modules-gnb.txt" ]] || bad "a sidecar did not record its node's modules before its first tc"
  pre="$("${K[@]}" exec deploy/upf -c she-eas -- sh -c \
    'ip netns exec eas-cloud tc qdisc add dev lo root netem delay 0ms && ip netns exec eas-cloud tc qdisc del dev lo root && echo netem-ok' 2>&1)"
  if [[ "${pre}" != *netem-ok* ]]; then
    bad "netem preflight: no NET_ADMIN or no sch_netem on the node (${pre//$'\n'/ }); Acts 2 and 3 cannot run"
    echo "netem=unavailable" >>"${S}/meta.txt"
  else
    echo "netem=ok" >>"${S}/meta.txt"
  fi
  pre="$("${K[@]}" exec deploy/gnb -c netem -- sh -c \
    'tc qdisc add dev lo root netem delay 0ms && tc qdisc del dev lo root && echo netem-ok' 2>&1)"
  [[ "${pre}" == *netem-ok* ]] || bad "gnb netem preflight: no NET_ADMIN or no sch_netem on its node: ${pre//$'\n'/ }"

  # --- 5. measurements in place ------------------------------------------------------
  # smfd provisions N6 delay measurement at association (smf_n6_delay_ms per EAS),
  # and the QOS_MON SRR on the UE's session once eesd subscribed: eesd logs a
  # QOS_MON rt= line per report. If the session predates the subscription and no
  # report arrives, the UE pod is power-cycled once (recorded in meta.txt).
  if [[ "${ARM}" == no-upf-qos ]]; then
    wait_for 120 has_in smf smf 'does not advertise UN6DM' || bad "smfd did not log the UPF without UN6DM"
  else
    wait_for 120 bash -c "$(declare -f n6_avg scrape); K=(kubectl -n ${NAMESPACE} --request-timeout=60s); [ -n \"\$(n6_avg 10.60.0.11)\" ] && [ -n \"\$(n6_avg 10.60.0.12)\" ] && [ -n \"\$(n6_avg 10.60.0.13)\" ]" \
      || bad "smfd has no N6 delay result for every EAS within 120 s"
  fi
  if [[ "${REPORTS}" == false ]]; then
    # No QOS_MON report can reach eesd here: give smfd's periodic reporting time
    # to show it (wrong-callback-token: smfd's refused notifies).
    if [[ "${ARM}" == wrong-callback-token ]]; then
      wait_for 60 has_in smf smf 'Nsmf_EventExposure_Notify QOS_MON .*status=401' \
        || bad "smfd logged no refused (401) notify to the wrong token"
    fi
    sleep 10
  elif ! wait_for 60 has_in ees ees '\[demo:d443a-edge-budget\] QOS_MON rt='; then
    echo "ue_power_cycled=true" >>"${S}/meta.txt"
    "${K[@]}" delete pod -l app.kubernetes.io/name=ue --wait=false >/dev/null
    sleep 5
    "${K[@]}" rollout status deploy/ue --timeout=300s >/dev/null || bad "ue rollout after the power cycle"
    wait_for 240 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} --request-timeout=60s exec deploy/ue -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
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

  local n6_rx
  if [[ "${ARM}" == no-upf-qos ]]; then n6_rx=false; else n6_rx=true; fi
  if [[ "${ACT2}" == true ]]; then
    # --- 7. Act 2: eas-local moves away (+16 ms one way on its N6 path) -------------
    netem_eas add || bad "netem on eas-local"
    if [[ "${n6_rx}" == true ]]; then
      wait_for 60 bash -c "$(declare -f n6_avg scrape); K=(kubectl -n ${NAMESPACE} --request-timeout=60s); v=\$(n6_avg 10.60.0.11); [ -n \"\$v\" ] && [ \"\$v\" -ge 8 ]" \
        || bad "smf_n6_delay_ms for eas-local did not reach 8 ms within 60 s"
    else
      sleep 8   # nothing measures N6 here: the act runs on what eesd has
    fi
    sleep 4   # one more QOS_MON period, so eesd's sample carries it
    jobs_act 3
    snapshot act2
    if [[ "${ARM}" == restart-flip ]]; then
      # --- 7b. eesd restarted from measured-budget to static, the netem still on ----
      echo "restarted=ees@flip" >>"${S}/meta.txt"
      ees_config_edit 're.sub(r"(?m)^([ \t]*mode:[ \t]*)measured-budget[ \t]*$", r"\g<1>static", y)' static \
        || bad "ees-config mode static"
      grep -q 'mode: static' "${S}/ees-config.static.yaml" || bad "ees-config has no mode: static"
      "${K[@]}" rollout restart deploy/ees >/dev/null && "${K[@]}" rollout status deploy/ees --timeout=180s >/dev/null \
        || bad "ees restart"
      wait_for 60 has_in ees ees 'edge-budget: on \(mode=static' || bad "eesd did not come back in mode static"
      # Every EAS finds its registration gone and registers again (eas.rs).
      wait_for 90 has_in upf she-eas '\[demo:d443a-edge-budget\] EAS-REG eas=[a-z-]+ registrationId=' 6 \
        || bad "the EASes did not register again at the restarted eesd within 90 s"
      jobs_act 3
      snapshot flip
    fi
    netem_eas del || bad "netem off eas-local"
    if [[ "${n6_rx}" == true ]]; then
      wait_for 60 bash -c "$(declare -f n6_avg scrape); K=(kubectl -n ${NAMESPACE} --request-timeout=60s); v=\$(n6_avg 10.60.0.11); [ -n \"\$v\" ] && [ \"\$v\" -lt 8 ]" \
        || bad "eas-local's N6 delay did not come back under 8 ms"
    fi
  fi
  if [[ "${ACT3}" == true ]]; then
    # --- 8. Act 3: the UE's own path is slow (+20 ms on the gNB's egress) -----------
    netem_gnb add || bad "netem on the gNB"
    if [[ "${REPORTS}" == true ]]; then
      wait_for 60 bash -c "$(declare -f last_rt logs_of); K=(kubectl -n ${NAMESPACE} --request-timeout=60s); v=\$(last_rt); [ -n \"\$v\" ] && [ \"\$v\" -ge $(( ${rt0:-0} + 15 )) ]" \
        || bad "QOS_MON rtDelays did not rise by 15 ms within 60 s"
    else
      sleep 8
    fi
    jobs_act 2
    snapshot act3
    netem_gnb del || bad "netem off the gNB"
    if [[ "${REPORTS}" == true ]]; then
      wait_for 60 bash -c "$(declare -f last_rt logs_of); K=(kubectl -n ${NAMESPACE} --request-timeout=60s); v=\$(last_rt); [ -n \"\$v\" ] && [ \"\$v\" -lt $(( ${rt0:-0} + 10 )) ]" \
        || bad "rtDelays did not come back"
    fi
  fi

  if [[ "${LOAD}" == true ]]; then
    # --- 9. the load act: eas-local loses compute (avlComp 50 -> 5) ------------------
    # As eas-local's own uid: the sidecar has no CAP_KILL.
    "${K[@]}" exec deploy/upf -c she-eas -- sh -c \
      'p="$(cat /tmp/d443a/eas-local.pid)"; setpriv --reuid=65531 --regid=65531 --clear-groups --no-new-privs sh -c "kill -USR1 $p"' \
      || bad "SIGUSR1"
    wait_for 30 has_in upf she-eas '\[eas-local\] .*LOAD eas=eas-local' || bad "eas-local did not apply the load"
    sleep 3
    jobs_act 3
    snapshot load
  fi

  # --- 10. the shutdown: every EAS deregisters --------------------------------------
  echo "failures=${FAILS}" >>"${S}/meta.txt"
  say "done, ${FAILS} driver failure(s); verdict from analyze.py"
  python3 "${HERE}/analyze.py" "${ARM}" "${S}" | tee "${S}/analyze.txt"
  local rc=${PIPESTATUS[0]}
  (( FAILS == 0 && rc == 0 ))
}

# One gate result: the full output goes to <S>/gates-out/<name>-<case>.txt, and
# the gate line in <g> keeps only the lines a check reads (the demo error, rc=,
# the show line), whatever precedes them: eesd's and smfd's OpenTelemetry
# preamble pushed the error past a fixed cut once (run 20261116T010236Z).
# test-scenario.sh feeds that run's real eesd output through it.
d443a_gate() {   # S g name case output
  mkdir -p "$1/gates-out"
  printf '%s\n' "$5" >"$1/gates-out/$3-$4.txt"
  printf '%s %s: %s\n' "$3" "$4" \
    "$(grep -E 'unknown mode|rc=|demo=|mode=|Error' <<<"$5" | tr '\n' ' ' | head -c 1200)" >>"$2"
}

d443a_off() {
  # The demo-off arm on the overlay's topology: no demo: block anywhere.
  local K=(kubectl -n "${NAMESPACE}" --request-timeout=120s) S="${OUT}/scenario"
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
  local K=(kubectl -n "${NAMESPACE}" --request-timeout=120s) S="${OUT}/scenario" g="${OUT}/scenario/gates.txt"
  : >"${g}"
  gate() { d443a_gate "${S}" "${g}" "$@"; }
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
