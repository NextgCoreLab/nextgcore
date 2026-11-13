#!/usr/bin/env bash
# Seeded acceptance run of demo d445a-fl-t8 (nextgsim#480), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_KEY, DEMO_MODE and OUT set. Every
# assertion is in checks.py (self-test: test-scenario.sh); this script drives the
# cluster and captures. Everything goes through kubectl exec/logs inside the
# namespace: no port-forward, nothing published. Captures in $OUT/scenario/.
#
# D445A_ARM picks the arm (default: main in t8-exclusion, poisoned in poisoned-ue):
#   main          t8-exclusion. UEs 1-3 join; before round 4 the AF holds, ue3
#                 deregisters (nr-ue-deregister normal), the NEF's T8 LoC
#                 excludes it; before round 7 ue3 is power-cycled (pod deleted)
#                 and rejoins. Checks: sources, chain, scorecard, readmission,
#                 canary, no_fin, ul_delta (checks.py says what each asserts).
#   poisoned      poisoned-ue. UEs 1-5, UE 005 poisons; four rules from the seed.
#   probe         t8-exclusion. nef_t8_probe: 10 cycles of ue3 (UE ID by address,
#                 T8 subscription by externalId, one LoC with a reason on
#                 deregistration, none within 20 s of the power cycle that follows).
#   gates         t8-exclusion. UE ID retrieval auth (401/403, no identity), the
#                 nefd kill switch and bogus mode, the AF's and the UE's bogus mode
#                 at startup, the UE's runtime `demo set mode=bogus`, and that a UE
#                 cannot reach the T8 port (while it does reach the FL port).
# Revert arms (each holds only when the check it targets FAILS and its
# preconditions hold; checks.py names both):
#   no-t8         the AF with --no-t8 (revert-hooks build): chain fails, straggler.
#   freeze-global the AF with --freeze-global: scorecard fails.
#   leak-raw      ue2 runs nr-ue-revert-hooks with fl.leak_raw: canary fails.
#   nat-on        the DN NATed again (a MASQUERADE ahead of upfd's exclusion):
#                 sources fail (identity_unresolved).
#   nefd-down     nefd scaled to 0 after the joins: chain fails, straggler.
#   udm-fallback  udmd step 3a disabled by deployment only: a NetworkPolicy keeps
#                 udm off amf, so the AMF is unreachable to udmd, which takes its
#                 tested fallback (drop_leg) and reports LoC itself: chain fails
#                 (no forwarded leg). Needs a CNI that enforces NetworkPolicy; the
#                 precondition (udmd's "EE subscription <id>: <error>" x3, no
#                 forwarded line) says whether it did.
#   eth0          ue2's FL client on eth0, to <upf pod IP>:7480 (an arm-only DNAT
#                 to the AF): bytes reach the AF without a PDU session; sources
#                 (identity_unresolved) and ul_delta fail.
set -uo pipefail

D445A_AF_ID="6b1d7e3c-0000-4000-8000-00000000480a"
D445A_DEADLINE_MS=30000

# Kubelet stamp of now, in the cluster's clock: the UPF pod's `date`.    (none)
d445a_now_epoch() { kubectl -n "${NAMESPACE}" exec deploy/upf -c fl-af -- date +%s.%N 2>/dev/null; }

d445a_main() {
  : "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
  local K=(kubectl -n "${NAMESPACE}")
  local S="${OUT}/scenario" HERE ARM FAILS=0 members n keys
  HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  mkdir -p "${S}"
  case "${DEMO_MODE}" in
    t8-exclusion) ARM="${D445A_ARM:-main}"; members=3 ;;
    poisoned-ue)  ARM="${D445A_ARM:-poisoned}"; members=5 ;;
    *) echo "[scenario] FAIL: mode ${DEMO_MODE}"; return 1 ;;
  esac
  case "${ARM}:${DEMO_MODE}" in
    poisoned:poisoned-ue|main:t8-exclusion|probe:t8-exclusion|gates:t8-exclusion) ;;
    no-t8:t8-exclusion|freeze-global:t8-exclusion|leak-raw:t8-exclusion|nat-on:t8-exclusion) ;;
    nefd-down:t8-exclusion|udm-fallback:t8-exclusion|eth0:t8-exclusion) ;;
    *) echo "[scenario] FAIL: arm ${ARM} does not run in mode ${DEMO_MODE}"; return 1 ;;
  esac
  say()  { printf '[scenario] %s\n' "$*"; }
  bad()  { printf '[scenario] FAIL: %s\n' "$*"; FAILS=$((FAILS+1)); }
  wait_for() {
    local t="$1"; shift
    local end=$(( $(date +%s) + t ))
    until "$@" >/dev/null 2>&1; do
      [[ $(date +%s) -ge ${end} ]] && return 1
      sleep 2
    done
  }
  aflog() { "${K[@]}" logs deploy/upf -c fl-af --timestamps 2>/dev/null; }
  # Not grep -q: it exits on the first match, kubectl takes SIGPIPE on a long
  # log, and pipefail turns the match into a failure.
  af_has() { aflog | grep -E "$1" >/dev/null; }
  af_count() { aflog | grep -cE "$1" || true; }
  tun_ip() { "${K[@]}" exec "deploy/$1" -c ue -- sh -c "ip -4 -o addr show uesimtun0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null; }
  ue_dep() { if [[ "$1" == 1 ]]; then echo ue; else echo "ue-$1"; fi; }
  say "arm=${ARM} mode=${DEMO_MODE} members=${members}"
  local rounds=10
  [[ "${ARM}" == probe ]] && rounds=22
  printf 'arm=%s\nmode=%s\nmembers=%s\ndeadline_ms=%s\nrounds=%s\n' "${ARM}" "${DEMO_MODE}" "${members}" \
    "${D445A_DEADLINE_MS}" "${rounds}" >"${S}/meta.txt"

  # --- 1. subscribers and UEs ---------------------------------------------------
  "${K[@]}" wait --for=condition=complete job/d445a-subscribers --timeout=300s >/dev/null \
    || bad "the d445a-subscribers Job did not complete"
  "${K[@]}" logs job/d445a-subscribers -c seed >"${S}/seed.txt" 2>&1
  # ue-2's fl-config initContainer (initContainers[1], ue-members.yaml) takes an
  # env var, by explicit JSON patch path.
  fl_env() {   # NAME VALUE
    "${K[@]}" patch deploy/ue-2 --type json -p \
      "[{\"op\":\"add\",\"path\":\"/spec/template/spec/initContainers/1/env/-\",\"value\":{\"name\":\"$1\",\"value\":\"$2\"}}]" \
      >/dev/null || bad "ue-2 env $1"
  }
  [[ "$("${K[@]}" get deploy/ue-2 -o jsonpath='{.spec.template.spec.initContainers[1].name}')" == d445a-fl-config ]] \
    || bad "ue-2 initContainers[1] is not d445a-fl-config"
  if [[ "${ARM}" == leak-raw ]]; then
    # ue2 runs the revert-hooks nr-ue with fl.leak_raw (refused by a default build).
    fl_env FL_LEAK_RAW true
    "${K[@]}" patch deploy/ue-2 --type json \
      -p '[{"op":"add","path":"/spec/template/spec/containers/0/command","value":["nr-ue-revert-hooks"]}]' >/dev/null \
      || bad "ue-2 revert-hooks patch"
  fi
  local upf_ip
  upf_ip="$("${K[@]}" get pod -l app.kubernetes.io/name=upf -o jsonpath='{.items[0].status.podIP}')"
  if [[ "${ARM}" == eth0 ]]; then
    # The client on the pod network, not the PDU session: an arm-only DNAT in the
    # UPF's namespace hands <upf pod IP>:7480 to the AF. For this arm the FL
    # listener is reachable from any pod in the cluster (cluster-internal, a
    # temporary namespace, and the AF refuses every identity the NEF cannot
    # resolve); no other arm has the rule.
    fl_env FL_DEVICE eth0
    fl_env FL_SERVER "${upf_ip}:7480"
    "${K[@]}" exec deploy/upf -c upf -- iptables -t nat -A PREROUTING -d "${upf_ip}" -p tcp --dport 7480 \
      -j DNAT --to-destination 10.46.0.10:7480 || bad "eth0 DNAT"
  fi
  if [[ "${ARM}" == udm-fallback ]]; then
    # udmd step 3a disabled by deployment only: udm may not reach amf.
    "${K[@]}" apply -f - >/dev/null <<YAML || bad "udm-fallback NetworkPolicy"
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: d445a-udm-not-to-amf
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: amf
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchExpressions:
              - {key: app.kubernetes.io/name, operator: NotIn, values: [udm]}
    - from:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [$("${K[@]}" get pod -l app.kubernetes.io/name=udm -o jsonpath='{.items[0].status.podIP}')/32]
YAML
  fi
  : >"${S}/ue-ips.txt"
  # UE n up: scaled (n > 1), its PDU session there, its address recorded.
  ue_up() {
    local n="$1" dep; dep="$(ue_dep "$1")"
    (( n == 1 )) || "${K[@]}" scale "deploy/${dep}" --replicas=1 >/dev/null
    "${K[@]}" rollout status "deploy/${dep}" --timeout=300s >/dev/null || bad "${dep} rollout"
    wait_for 240 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/${dep} -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
      || bad "${dep} has no PDU session (uesimtun0) within 240 s"
    echo "ue${n} $(tun_ip "${dep}")" >>"${S}/ue-ips.txt"
    if [[ "${ARM}" == eth0 && "${n}" == 2 ]]; then
      echo "eth0_ip=$("${K[@]}" get pod -l app.kubernetes.io/name=ue-2 -o jsonpath='{.items[0].status.podIP}')" >>"${S}/meta.txt"
    fi
  }
  # ue1 (the base UE) is up before the AF; the others join one at a time after it.
  ue_up 1
  say "UEs: $(tr '\n' ' ' <"${S}/ue-ips.txt")"

  # --- 2. the AF's CCA key, trusted at the NRF ----------------------------------
  # Generated here, outside $OUT; only public JWKs go to the cluster's trust store
  # and the private key straight into the sidecar.
  keys="$(mktemp -d -t d445a-keys-XXXXXX)"
  # shellcheck disable=SC2064  # expand now: the directory is this run's
  trap "rm -rf '${keys}'" EXIT
  python3 "${HERE}/cca.py" keygen "${keys}" "${D445A_AF_ID}" \
    6b1d7e3c-0000-4000-8000-0000000480af 6b1d7e3c-0000-4000-8000-0000000480bb >/dev/null \
    || bad "CCA key generation"
  local -a jwks=()
  for f in "${keys}"/*.jwk; do jwks+=(--from-file="$(basename "${f}")=${f}"); done
  "${K[@]}" create configmap d445a-cca-trusted "${jwks[@]}" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null \
    || bad "trusted-key ConfigMap"
  wait_for 180 "${K[@]}" exec deploy/nrf -c nrf -- test -s "/etc/nextgcore/cca-trusted/${D445A_AF_ID}.jwk" \
    || bad "the NRF does not see the AF's JWK within 180 s"
  say "AF JWK in the NRF trust store"

  # --- 3. the AF ------------------------------------------------------------------
  wait_for 240 "${K[@]}" exec deploy/upf -c fl-af -- test -e /tmp/d445a/ready || bad "the fl-af sidecar never got ready"
  "${K[@]}" exec -i deploy/upf -c fl-af -- sh -c 'umask 077; cat >/tmp/d445a/cca/af.key' <"${keys}/${D445A_AF_ID}.key" \
    || bad "AF key handover"
  "${K[@]}" exec deploy/upf -c fl-af -- cat /tmp/d445a/af.yaml >"${S}/af-base.yaml" 2>/dev/null
  python3 "${HERE}/cca.py" af-config "${ARM}" "${DEMO_MODE}" <"${S}/af-base.yaml" >"${S}/af.yaml" || bad "AF config for ${ARM}"
  "${K[@]}" exec -i deploy/upf -c fl-af -- sh -c 'cat >/tmp/d445a/af.yaml' <"${S}/af.yaml" || bad "AF config handover"
  local start="nr-fl-server"
  case "${ARM}" in
    no-t8) start="nr-fl-server-revert-hooks --no-t8" ;;
    freeze-global) start="nr-fl-server-revert-hooks --freeze-global" ;;
  esac
  if [[ "${ARM}" == nat-on ]]; then
    # The revert: NAT toward fl-dn again, ahead of upfd's UPF-NAT-EXCLUDE jump.
    "${K[@]}" exec deploy/upf -c upf -- iptables -t nat -I POSTROUTING 1 -s 10.45.0.0/16 -d 10.46.0.0/24 -j MASQUERADE \
      || bad "nat-on rule"
  fi
  "${K[@]}" exec deploy/upf -c upf -- iptables -t nat -S POSTROUTING >"${S}/nat-postrouting.txt" 2>&1
  "${K[@]}" exec deploy/upf -c upf -- sh -c 'curl -s --max-time 5 http://127.0.0.1:9090/metrics' >"${S}/metrics-before.prom" 2>/dev/null
  d445a_now_epoch >"${S}/metrics-before.ts"
  echo "${start}" | "${K[@]}" exec -i deploy/upf -c fl-af -- sh -c 'cat >/tmp/d445a/start.tmp && mv /tmp/d445a/start.tmp /tmp/d445a/start' \
    || bad "AF start"
  say "AF started: ${start}"
  # Serialised joins: UE n+1 starts only once UE n has joined (or been refused)
  # and, for each member that subscribed, udmd has logged its leg (forwarded, or
  # in udm-fallback its failure). udmd forwards legs asynchronously, so joins at
  # once would interleave the legs and leave ue3's ambiguous (checks.py fails
  # closed on that).
  local legs_re='forwarded to AMF'
  [[ "${ARM}" == udm-fallback ]] && legs_re='EE subscription [^ ]+: '
  for n in $(seq 1 "${members}"); do
    (( n == 1 )) || ue_up "${n}"
    wait_for 240 af_has "(member_joined member=ue${n} |identity_unresolved member=ue${n} )" \
      || bad "ue${n} neither joined nor was refused within 240 s"
    local subscribed
    subscribed="$(af_count 'member_joined member=ue[0-9]+ .* t8=subscribed ')"
    if (( subscribed > 0 )); then
      wait_for 180 sh -c "[ \$(kubectl -n ${NAMESPACE} logs deploy/udm -c udm | grep -cE '${legs_re}') -ge ${subscribed} ]" \
        || bad "udmd logged fewer than ${subscribed} AMF legs ('${legs_re}') after ue${n}'s join"
    fi
  done
  # Every arm but nat-on and eth0 (which refuse members by design) runs with all
  # members: say so here rather than as an obscure failure later.
  case "${ARM}" in
    nat-on|eth0) ;;
    *) wait_for 120 af_has "joined ${members}/${members} members" \
         || bad "the AF did not log joined ${members}/${members} members" ;;
  esac

  case "${ARM}" in
    nat-on|eth0)
      wait_for 120 af_has 'identity_unresolved' || bad "no identity_unresolved within 120 s"
      sleep 20 ;;
    gates)
      wait_for 300 af_has "joined ${members}/${members} members" || bad "the AF never had ${members} members"
      d445a_gates "${S}" "${keys}" ;;
    probe)
      wait_for 300 af_has "joined ${members}/${members} members" || bad "the AF never had ${members} members"
      d445a_probe "${S}" ;;
    poisoned|leak-raw|freeze-global)
      wait_for 900 af_has 'all arms done' || bad "the AF did not finish within 900 s" ;;
    main|no-t8|nefd-down|udm-fallback)
      wait_for 300 af_has 'hold before round=4 until=member-excluded' || bad "no hold before round 4"
      # udmd forwards each member's LoC subscription to the AMF after the NEF's 201
      # (#1449 review 5): deregister only once all three legs are up.
      if [[ "${ARM}" == no-t8 ]]; then
        # --no-t8: the AF subscribes nothing, so udmd has no EE subscription and
        # no leg (checks.py makes that a precondition); nothing to wait for.
        :
      elif [[ "${ARM}" == udm-fallback ]]; then
        # The AMF is unreachable to udmd: each leg ends in its fallback warning.
        wait_for 180 sh -c "[ \$(kubectl -n ${NAMESPACE} logs deploy/udm -c udm | grep -cE 'EE subscription [^ ]+: ') -ge 3 ]" \
          || bad "udmd logged fewer than 3 AMF-leg failures (NetworkPolicy not enforced?)"
      else
        wait_for 120 sh -c "[ \$(kubectl -n ${NAMESPACE} logs deploy/udm -c udm | grep -c 'forwarded to AMF') -ge 3 ]" \
          || bad "fewer than 3 udmd 'forwarded to AMF' lines"
      fi
      if [[ "${ARM}" == nefd-down ]]; then
        "${K[@]}" scale deploy/nef --replicas=0 >/dev/null
        wait_for 120 sh -c "[ -z \"\$(kubectl -n ${NAMESPACE} get pods -l app.kubernetes.io/name=nef -o name)\" ]" || bad "nefd still up"
        say "nefd scaled to 0"
      fi
      # A scrape just before ue3 leaves: the counter of ue3's first session, which
      # is released before the last scrape (checks.py ul_delta).
      d445a_now_epoch >"${S}/metrics-mid.ts"
      "${K[@]}" exec deploy/upf -c upf -- sh -c 'curl -s --max-time 5 http://127.0.0.1:9090/metrics' >"${S}/metrics-mid.prom" 2>/dev/null
      say "deregistering ue3"
      "${K[@]}" exec deploy/ue-3 -c ue -- nr-ue-deregister >"${S}/ue3-deregister.txt" 2>&1 || bad "ue3 deregistration"
      # Without the exclusion (no-t8, nefd-down) the hold before 4 runs out (240 s),
      # and rounds 4-6 each wait T (30 s) for ue3: about 330 s.
      wait_for 600 af_has 'hold before round=7 until=members-full' || bad "no hold before round 7"
      say "power-cycling ue3"
      "${K[@]}" logs deploy/ue-3 -c ue --timestamps >"${S}/ue-3-first.log" 2>/dev/null
      "${K[@]}" delete pod -l app.kubernetes.io/name=ue-3 --wait=false >/dev/null
      sleep 5
      "${K[@]}" rollout status deploy/ue-3 --timeout=300s >/dev/null || bad "ue-3 rollout after the power cycle"
      wait_for 240 sh -c "[ -n \"\$(kubectl -n ${NAMESPACE} exec deploy/ue-3 -c ue -- ip -4 -o addr show uesimtun0 2>/dev/null)\" ]" \
        || bad "ue3 has no PDU session after the power cycle"
      echo "ue3 $(tun_ip ue-3)" >>"${S}/ue-ips.txt"
      if [[ "${ARM}" == nefd-down ]]; then "${K[@]}" scale deploy/nef --replicas=1 >/dev/null; fi
      wait_for 600 af_has 'all arms done' || bad "the AF did not finish within 600 s" ;;
  esac

  # --- 4. captures ------------------------------------------------------------------
  if [[ "${ARM}" == nefd-down ]]; then
    # nef was scaled back to 1 after the power cycle: its log must exist before
    # the captures read it.
    "${K[@]}" rollout status deploy/nef --timeout=180s >/dev/null || bad "nef did not come back"
  fi
  # The pcap's window is [after the first scrape, before the last]: a packet in
  # it is in both the pcap and the counter delta (checks.py counts only those).
  d445a_now_epoch >"${S}/metrics-after.ts"
  "${K[@]}" exec deploy/upf -c upf -- sh -c 'curl -s --max-time 5 http://127.0.0.1:9090/metrics' >"${S}/metrics-after.prom" 2>/dev/null
  sleep 2   # tcpdump -U has flushed; the pcap is read while it still runs
  "${K[@]}" exec deploy/upf -c fl-af -- cat /tmp/d445a/fl-dn.pcap >"${S}/fl-dn.pcap" 2>/dev/null || bad "pcap copy"
  "${K[@]}" exec deploy/upf -c fl-af -- cat /tmp/d445a/tcpdump.log >"${S}/tcpdump.log" 2>/dev/null
  aflog >"${S}/af.log"
  # nr-fl-server's privileges, from its /proc status (checks.py af_unprivileged).
  # shellcheck disable=SC2016  # expanded by the container's sh
  "${K[@]}" exec deploy/upf -c fl-af -- sh -c 'for p in /proc/[0-9]*; do case "$(tr "\0" " " <"$p/cmdline" 2>/dev/null)" in nr-fl-server*) grep -E "^(Uid|Gid|CapPrm|CapEff|CapBnd|NoNewPrivs):" "$p/status"; break;; esac; done' \
    >"${S}/af-status.txt" 2>/dev/null
  # upf: its `Session added/removed` lines tie each pcap packet to its PDU session.
  for nf in nef udm amf nrf upf; do "${K[@]}" logs "deploy/${nf}" -c "${nf}" --timestamps >"${S}/${nf}.log" 2>/dev/null; done
  for n in $(seq 1 "${members}"); do
    "${K[@]}" logs "deploy/$(ue_dep "${n}")" -c ue --timestamps >"${S}/ue-${n}.log" 2>/dev/null
  done
  "${K[@]}" exec deploy/nef -c nef -- sh -c 'curl -s --max-time 5 http://127.0.0.1:9090/metrics' >"${S}/nef-metrics.prom" 2>/dev/null
  # A capture a check needs must not be empty (an empty log reads as "no such line").
  for f in af.log nef.log udm.log amf.log upf.log; do [[ -s "${S}/${f}" ]] || bad "empty capture ${f}"; done
  grep -E '\[demo:d445a-fl-t8\] (member_|round=|scorecard|robustness|hold |straggler|all arms|identity_|frame_refused|T8 )' \
    "${S}/af.log" >"${S}/af-chain.txt"

  python3 "${HERE}/checks.py" "${ARM}" "${S}" >"${S}/checks.txt" 2>&1; local rc=$?
  cat "${S}/checks.txt"
  (( rc == 0 )) || bad "checks.py ${ARM}"
  say "$(tail -1 "${S}/checks.txt")"
  (( FAILS == 0 ))
}

# The gates arm: UE ID retrieval auth, then nefd's kill switch and bogus mode,
# the AF's bogus mode and the UE's runtime bogus mode. Results in S/gates.txt.
d445a_gates() {
  local S="$1" keys="$2" K=(kubectl -n "${NAMESPACE}") ip1 nef_ip nrf
  local G="${S}/gates.txt"; : >"${G}"
  local HERE; HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  gate() { printf '%s %s\n' "$1" "$2" >>"${G}"; echo "[scenario] gate $1 $2"; }
  ip1="$(awk '$1=="ue1"{print $2; exit}' "${S}/ue-ips.txt")"
  nrf="http://nrf.${NAMESPACE}.svc.cluster.local:7777"
  nef_ip="$("${K[@]}" get pod -l app.kubernetes.io/name=nef -o jsonpath='{.items[0].status.podIP}')"
  local body="{\"afId\":\"d445a-gates\",\"ueIpAddr\":{\"ipv4Addr\":\"${ip1}\"}}"
  # curl from the nrf pod (core image); -i for the status and WWW-Authenticate.
  retrieve() {   # TOKEN|-  -> HTTP status line, WWW-Authenticate, body
    local auth=()
    [[ "$1" == - ]] || auth=(-H "Authorization: Bearer $1")
    "${K[@]}" exec deploy/nrf -c nrf -- curl -s -i --http2-prior-knowledge --max-time 10 \
      -X POST -H 'Content-Type: application/json' "${auth[@]}" -d "${body}" \
      "http://${nef_ip}:7777/3gpp-ueid/v1/retrieve" 2>&1
  }
  status() { awk 'NR==1{print $2}' <<<"$1" | tr -d '\r'; }
  token() {      # ID TYPE TARGET SCOPE -> access_token or the error body
    local cca; cca="$(python3 "${HERE}/cca.py" cca "${keys}" "$1")"
    "${K[@]}" exec deploy/nrf -c nrf -- curl -s --http2-prior-knowledge --max-time 10 -X POST \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode grant_type=client_credentials --data-urlencode "nfInstanceId=$1" \
      --data-urlencode "nfType=$2" --data-urlencode "targetNfType=$3" --data-urlencode "scope=$4" \
      --data-urlencode "cca=${cca}" "${nrf}/nnrf-oauth2/v1/access-token" 2>&1
  }
  register() {   # ID TYPE
    "${K[@]}" exec deploy/nrf -c nrf -- curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge --max-time 10 \
      -X PUT -H 'Content-Type: application/json' \
      -d "{\"nfInstanceId\":\"$1\",\"nfType\":\"$2\",\"nfStatus\":\"REGISTERED\",\"heartBeatTimer\":600}" \
      "${nrf}/nnrf-nfm/v1/nf-instances/$1" 2>&1
  }
  access() { python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("access_token",""))' 2>/dev/null; }
  noid() { ! grep -q '"externalId"' <<<"$1"; }
  local r t
  # Positive control first, so the refusals below are not a broken route.
  local AF2=6b1d7e3c-0000-4000-8000-0000000480af NW2=6b1d7e3c-0000-4000-8000-0000000480bb
  gate INFO "register AF probe consumer: $(register "${AF2}" AF); NWDAF probe consumer: $(register "${NW2}" NWDAF)"
  t="$(token "${AF2}" AF NEF nnef-ueid | access)"
  r="$(retrieve "${t:--}")"
  if [[ "$(status "${r}")" == 200 ]] && grep -q "\"externalId\":\"ue001@fl.nextg\"" <<<"${r}"; then
    gate PASS "AF token, scope nnef-ueid: 200 $(grep -o '{"externalId[^}]*}' <<<"${r}")"
  else gate FAIL "AF token, scope nnef-ueid: $(head -c 300 <<<"${r}" | tr '\r\n' '  ')"; fi
  r="$(retrieve -)"
  if [[ "$(status "${r}")" == 401 ]] && grep -qi '^www-authenticate: Bearer' <<<"${r}" && noid "${r}"; then
    gate PASS "no token: 401, $(grep -i '^www-authenticate' <<<"${r}" | tr -d '\r'), no externalId"
  else gate FAIL "no token: $(head -c 300 <<<"${r}" | tr '\r\n' '  ')"; fi
  r="$(retrieve garbage.not.ajwt)"
  if [[ "$(status "${r}")" == 401 ]] && noid "${r}"; then gate PASS "malformed token: 401, no externalId"
  else gate FAIL "malformed token: $(head -c 300 <<<"${r}" | tr '\r\n' '  ')"; fi
  # A non-AF consumer (an nfType NWDAF probe, not deployed here, so no NF
  # discovers it): the NRF refuses it an nnef-ueid token (allowedNfTypes [AF]).
  r="$(token "${NW2}" NWDAF NEF nnef-ueid)"
  if grep -qE 'unauthorized_client|invalid_scope' <<<"${r}" && [[ -z "$(access <<<"${r}")" ]]; then
    gate PASS "NWDAF consumer asks the NRF for nnef-ueid: refused ($(grep -oE '"error":"[a-z_]+"' <<<"${r}"))"
  else gate FAIL "NWDAF consumer got an nnef-ueid answer: $(head -c 300 <<<"${r}")"; fi
  # Any token it can get, at the NEF: 401 (another audience) or 403 (no scope).
  local tgt got=""
  for tgt in "NEF nnef-eventexposure" "UDM nudm-sdm" "BSF nbsf-management" "UDR nudr-dr"; do
    # shellcheck disable=SC2086  # tgt is "<targetNfType> <scope>"
    t="$(token "${NW2}" NWDAF ${tgt} | access)"
    [[ -n "${t}" ]] && { got="${tgt}"; break; }
  done
  if [[ -n "${got}" ]]; then
    r="$(retrieve "${t}")"
    if [[ "$(status "${r}")" =~ ^40[13]$ ]] && noid "${r}"; then
      gate PASS "NWDAF consumer's token (${got}) at the UE ID route: $(status "${r}"), no externalId"
    else gate FAIL "NWDAF consumer's token (${got}): $(head -c 300 <<<"${r}" | tr '\r\n' '  ')"; fi
  else gate INFO "the NRF minted the NWDAF probe no token for NEF, UDM, BSF or UDR"; fi
  # An AF token without the scope: 403 insufficient_scope.
  t="$(token "${AF2}" AF NEF nnef-eventexposure | access)"
  if [[ -n "${t}" ]]; then
    r="$(retrieve "${t}")"
    if [[ "$(status "${r}")" == 403 ]] && grep -qi 'insufficient_scope' <<<"${r}" && noid "${r}"; then
      gate PASS "AF token, scope nnef-eventexposure only: 403 insufficient_scope, no externalId"
    else gate FAIL "AF token without nnef-ueid: $(head -c 300 <<<"${r}" | tr '\r\n' '  ')"; fi
  else gate FAIL "no nnef-eventexposure token for the AF probe consumer"; fi

  # The UE's runtime mode switch: bogus is rejected and the mode stays.
  # shellcheck disable=SC2016  # expanded by the container's sh
  r="$("${K[@]}" exec deploy/ue -c ue -- sh -c 'n=$(nr-cli --dump | grep -m1 -E "^ue[0-9]+"); nr-cli "$n" -e "demo d445a-fl-t8 set mode=bogus"; echo "rc=$?"; nr-cli "$n" -e fl-status' 2>&1)"
  if grep -qiE 'unknown mode|bogus' <<<"${r}" && grep -q 't8-exclusion' <<<"${r}"; then
    gate PASS "nr-cli demo d445a-fl-t8 set mode=bogus: rejected, mode stays ($(tr '\n' ' ' <<<"${r}" | head -c 300))"
  else gate FAIL "UE bogus mode: $(tr '\n' ' ' <<<"${r}" | head -c 300)"; fi
  # The UE's bogus mode at startup: a second, one-shot nr-ue on the same config
  # with mode bogus must fail with UnknownMode before it does anything.
  # shellcheck disable=SC2016  # expanded by the container's sh
  r="$("${K[@]}" exec deploy/ue -c ue -- sh -c 'sed "s/mode: t8-exclusion/mode: bogus/" /etc/nextgsim/ue.yaml >/tmp/bogus.yaml; grep -q "mode: bogus" /tmp/bogus.yaml || { echo rc=99; exit 0; }; timeout 20 nr-ue -c /tmp/bogus.yaml; echo "rc=$?"' 2>&1)"
  if grep -qiE 'unknown mode \\?"bogus\\?"|UnknownMode' <<<"${r}" && ! grep -qE 'rc=(0|124)$' <<<"${r}"; then
    gate PASS "nr-ue with mode bogus fails startup: $(grep -m1 -oiE 'unknown mode[^,]*|UnknownMode[^)]*' <<<"${r}"), $(grep -o 'rc=[0-9]*' <<<"${r}" | tail -1)"
  else gate FAIL "nr-ue bogus mode: $(tr '\n' ' ' <<<"${r}" | tail -c 300)"; fi
  # A UE cannot reach the AF's T8 listener (DNATed pod port or fl-dn address),
  # while the same UE does reach the FL listener: the denial is the FORWARD rule,
  # not a broken path.
  local upf_ip c1 c2 c3
  upf_ip="$("${K[@]}" get pod -l app.kubernetes.io/name=upf -o jsonpath='{.items[0].status.podIP}')"
  probe_tcp() { "${K[@]}" exec deploy/ue -c ue -- curl --interface uesimtun0 -s -o /dev/null --connect-timeout 3 --max-time 4 "$1" >/dev/null 2>&1; echo $?; }
  c1="$(probe_tcp "http://${upf_ip}:7481/")"; c2="$(probe_tcp "http://10.46.0.10:7481/")"; c3="$(probe_tcp "http://10.46.0.10:7480/")"
  if [[ "${c1}" == 28 && "${c2}" == 28 && "${c3}" != 28 && "${c3}" != 7 ]]; then
    gate PASS "ue1 via uesimtun0: ${upf_ip}:7481 and 10.46.0.10:7481 time out (curl rc 28), 10.46.0.10:7480 connects (rc ${c3})"
  else gate FAIL "T8 port from ue1: ${upf_ip}:7481 rc=${c1}, 10.46.0.10:7481 rc=${c2}, 10.46.0.10:7480 rc=${c3} (want 28, 28, connected)"; fi
  # The AF's bogus mode fails startup with UnknownMode (a one-shot second process).
  # shellcheck disable=SC2016  # expanded by the container's sh
  r="$("${K[@]}" exec deploy/upf -c fl-af -- sh -c 'sed "s/mode: t8-exclusion/mode: bogus/" /tmp/d445a/af.yaml >/tmp/d445a/bogus.yaml; grep -q "mode: bogus" /tmp/d445a/bogus.yaml || { echo rc=99; exit 0; }; chmod 0644 /tmp/d445a/bogus.yaml; ip netns exec fl-dn setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs timeout 20 nr-fl-server -c /tmp/d445a/bogus.yaml; echo "rc=$?"' 2>&1)"
  if grep -q 'unknown mode "bogus" for demo "d445a-fl-t8"' <<<"${r}" && grep -q 'rc=1' <<<"${r}"; then
    gate PASS "AF with mode bogus: $(grep -o 'unknown mode "bogus" for demo "d445a-fl-t8"' <<<"${r}" | head -1), rc=1"
  else gate FAIL "AF bogus mode: $(tr '\n' ' ' <<<"${r}" | head -c 300)"; fi

  # nefd: kill switch, then bogus, then back on (config plus restart).
  local orig; orig="$("${K[@]}" get configmap nef-config -o jsonpath='{.data.nef\.yaml}')"
  printf '%s\n' "${orig}" >"${S}/nef-on.yaml"
  nef_with() {   # FILE: the nef.yaml to run; restarts nefd
    "${K[@]}" create configmap nef-config --from-file="nef.yaml=$1" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
    "${K[@]}" rollout restart deploy/nef >/dev/null
  }
  sed 's/^  enabled: true$/  enabled: false/' "${S}/nef-on.yaml" >"${S}/nef-kill.yaml"
  grep -q '^  enabled: false' "${S}/nef-kill.yaml" || gate FAIL "could not build the kill-switch config"
  nef_with "${S}/nef-kill.yaml"
  "${K[@]}" rollout status deploy/nef --timeout=180s >/dev/null || gate FAIL "nefd with the kill switch never became ready"
  sleep 8
  "${K[@]}" logs deploy/nef -c nef --timestamps >"${S}/nef-kill.log" 2>&1
  nef_ip="$("${K[@]}" get pod -l app.kubernetes.io/name=nef --field-selector=status.phase=Running -o jsonpath='{.items[0].status.podIP}')"
  t="$(token "${AF2}" AF NEF nnef-ueid | access)"
  r="$(retrieve "${t:--}")"
  local m
  # shellcheck disable=SC2016  # expanded by the container's sh
  m="$("${K[@]}" exec deploy/nef -c nef -- sh -c 'curl -s --max-time 3 http://127.0.0.1:9090/metrics; echo "rc=$?"' 2>&1)"
  if ! grep -q 'DEMO MODE ACTIVE' "${S}/nef-kill.log" && [[ "$(status "${r}")" == 404 ]] && grep -q 'Resource not found' <<<"${r}" \
     && ! grep -q nextg_demo_enabled <<<"${m}"; then
    gate PASS "nefd kill switch (demo.enabled false, d445a-fl-t8.enabled true): no banner, UE ID route 404 'Resource not found', no /metrics ($(tail -1 <<<"${m}"))"
  else gate FAIL "nefd kill switch: banner=$(grep -c 'DEMO MODE ACTIVE' "${S}/nef-kill.log") route=$(status "${r}") metrics=$(tail -1 <<<"${m}" | head -c 80)"; fi
  sed 's/mode: t8-exclusion/mode: bogus/' "${S}/nef-on.yaml" >"${S}/nef-bogus.yaml"
  nef_with "${S}/nef-bogus.yaml"
  sleep 25
  local pod; pod="$("${K[@]}" get pod -l app.kubernetes.io/name=nef --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')"
  "${K[@]}" logs "${pod}" -c nef >"${S}/nef-bogus.log" 2>&1
  "${K[@]}" logs "${pod}" -c nef --previous >>"${S}/nef-bogus.log" 2>&1
  if grep -qE 'UnknownMode|unknown mode "bogus"' "${S}/nef-bogus.log"; then
    gate PASS "nefd with mode bogus fails startup: $(grep -m1 -oE 'UnknownMode[^"]*"[^"]*"[^"]*"[^"]*"|unknown mode "bogus"[^,]*' "${S}/nef-bogus.log")"
  else gate FAIL "nefd bogus mode: $(tail -3 "${S}/nef-bogus.log" | tr '\n' ' ')"; fi
  nef_with "${S}/nef-on.yaml"
  "${K[@]}" rollout status deploy/nef --timeout=180s >/dev/null || gate FAIL "nefd did not come back on"
  sleep 8
  "${K[@]}" logs deploy/nef -c nef >"${S}/nef-back.log" 2>&1
  if grep -q 'DEMO MODE ACTIVE.*d445a-fl-t8=t8-exclusion' "${S}/nef-back.log"; then gate PASS "nefd back on: banner again"
  else gate FAIL "nefd did not come back with the demo on"; fi
}

# nef_t8_probe: 10 cycles on ue3. Each: ue3 is a member with a T8 subscription
# (the UE ID retrieval by address and the subscription by externalId succeeded);
# deregistration gives exactly one exclusion with a lossOfConnectReason; the
# power cycle that follows (pod deleted, a fresh registration and session) gives
# no LoC within 20 s, and ue3 is readmitted. Results in S/probe.txt.
d445a_probe() {
  local S="$1" K=(kubectl -n "${NAMESPACE}") i exc0 exc1 t_pc ok why
  # Every LoC the AF reports for ue3: an exclusion, or a repeat while excluded.
  local LOC='member_selection excluded=extid-ue003@fl\.nextg member=ue3 |T8 LOSS_OF_CONNECTIVITY for ue3 again'
  local P="${S}/probe.txt"; : >"${P}"
  for i in $(seq 1 10); do
    ok=PASS; why=""
    local hold1=$((2 * i)) hold2=$((2 * i + 1))
    wait_for 240 af_has "hold before round=${hold1} until=member-excluded" || { ok=FAIL; why+=" no hold ${hold1};"; }
    # ue3's current membership carries a T8 subscription made after a UE ID lookup.
    # Not "(A|B) " - that trailing space requires a space after `gpsi=`,
  # which never happens (`gpsi=extid-ue003@fl.nextg`). Match either line as-is.
  local j; j="$(aflog | grep -E "member_joined member=ue3 gpsi=|member_selection readmitted=extid-ue003@fl\.nextg member=ue3" | tail -1)"
    grep -q 'gpsi=extid-ue003@fl.nextg\|readmitted=extid-ue003@fl.nextg' <<<"${j}" || { ok=FAIL; why+=" ue3 not resolved to extid-ue003@fl.nextg;"; }
    grep -q 't8=subscribed ' <<<"${j}" || { ok=FAIL; why+=" no T8 subscription;"; }
    wait_for 120 sh -c "[ \$(kubectl -n ${NAMESPACE} logs deploy/udm -c udm | grep -c 'forwarded to AMF') -ge $((2 + i)) ]" \
      || { ok=FAIL; why+=" udmd leg $((2 + i)) not forwarded;"; }
    exc0="$(af_count "${LOC}")"
    "${K[@]}" exec deploy/ue-3 -c ue -- nr-ue-deregister >>"${S}/probe-deregister.txt" 2>&1 || { ok=FAIL; why+=" deregister;"; }
    wait_for 60 sh -c "[ \$(kubectl -n ${NAMESPACE} logs deploy/upf -c fl-af | grep -cE '${LOC}') -gt ${exc0} ]" \
      || { ok=FAIL; why+=" no LoC within 60 s;"; }
    sleep 5
    exc1="$(af_count "${LOC}")"
    aflog | grep -E "${LOC}" | tail -1 | grep -qE 'reason=nef_event lossOfConnectReason=[A-Z_0-9]+ ' \
      || { ok=FAIL; why+=" the LoC is not an exclusion with a reason;"; }
    [[ "${exc1}" == $((exc0 + 1)) ]] || { ok=FAIL; why+=" ${exc1} LoC lines, expected $((exc0 + 1));"; }
    wait_for 120 af_has "hold before round=${hold2} until=members-full" || { ok=FAIL; why+=" no hold ${hold2};"; }
    "${K[@]}" delete pod -l app.kubernetes.io/name=ue-3 --wait=false >/dev/null
    t_pc="$(date +%s)"
    sleep 20
    local exc2; exc2="$(af_count "${LOC}")"
    [[ "${exc2}" == "${exc1}" ]] || { ok=FAIL; why+=" a LoC within 20 s of the power cycle;"; }
    local re0; re0="$(af_count 'member_selection readmitted=extid-ue003@fl\.nextg member=ue3 ')"
    wait_for 300 sh -c "[ \$(kubectl -n ${NAMESPACE} logs deploy/upf -c fl-af | grep -c 'member_selection readmitted=extid-ue003@fl.nextg member=ue3 ') -ge ${i} ]" \
      || { ok=FAIL; why+=" not readmitted (readmissions ${re0});"; }
    echo "ue3 $(tun_ip ue-3)" >>"${S}/ue-ips.txt"
    printf 'cycle %d %s power-cycle at %s;%s\n' "${i}" "${ok}" "$(date -u -d "@${t_pc}" +%H:%M:%SZ)" "${why:- all four steps}" | tee -a "${P}"
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  d445a_main
fi
