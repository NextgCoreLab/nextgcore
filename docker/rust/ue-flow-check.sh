#!/usr/bin/env bash
# 5G UE flow checks for the nightly Docker E2E (#649): the flows the 0.2.0 wave
# fixed, driven through nextgsim's REAL gNB and UE against the deployed core.
#
# Why this exists: until it did, the nightly 5G stage asserted registration, a
# PDU session and a few signalling-only steps -- never a ping, never a
# de-registration, never paging. Every defect below was found by hand while
# that stage stayed green.
#
#   paging         CM-IDLE, then DOWNLINK data from the UPF: the SMF's
#                  N1N2MessageTransfer makes the AMF page the UE (TS 23.502
#                  §4.2.3.3), the UE answers with a Service Request, and all
#                  downlink pings are answered (the UPF buffers the first).
#   idle-uplink    CM-IDLE, then uplink data: a UE-triggered Service Request
#                  (TS 24.501 §5.6.1.2) and a 20/20 ping. The packet that
#                  triggers the request must not be lost (nextgsim #267).
#   deregister     UE-initiated de-registration from the UE CLI (nextgsim #266):
#                  a Deregistration Accept, then a fresh registration, a new
#                  PDU session and a 20/20 ping.
#   network-rereg  The UDM's Nudm_UECM DeregistrationNotification with
#                  deregReason REREGISTRATION_REQUIRED, POSTed to the AMF's
#                  callback (nextgcore #580): the UE re-registers PROMPTLY -- no
#                  T3510 expiry (nextgsim #265) -- re-establishes its PDU session
#                  (nextgsim #272) and pings 20/20.
#   all            paging, idle-uplink, paging AGAIN, deregister, network-rereg.
#                  The second paging round runs after idle-uplink on purpose: a
#                  Service Request from CM-IDLE moves the UE to a new AMF UE NGAP
#                  ID, and before nextgcore #648 every later page was answered 404
#                  by the AMF, so only a page AFTER a Service Request covers it.
#
# Each scenario prints exactly one `PASS: <scenario>` or `FAIL: <scenario> -- <why>`
# line and exits non-zero on FAIL. Every assertion is POSITIVE: a line only
# reachable when that step happened, or an exact ping reply count -- never "no
# error in the log". Log assertions only look at lines logged AFTER the scenario
# started (`docker logs --since`), so an earlier scenario cannot satisfy a later one.
#
# Containers are addressed by docker-compose.yml's fixed `container_name`s, so this
# runs the same under `docker compose` (CI) and under a plain `docker run` harness.
# Overrides: UE_CONTAINER GNB_CONTAINER AMF_CONTAINER SMF_CONTAINER UPF_CONTAINER,
# AMF_SBI / UDM_SBI (host:port), UE_SUPI, PING_TARGET, PING_COUNT, NR_CLI (host path to
# nr-cli).
#
# Usage: ue-flow-check.sh <paging|idle-uplink|deregister|network-rereg|all>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UE="${UE_CONTAINER:-nextgsim-ue}"
GNB="${GNB_CONTAINER:-nextgsim-gnb}"
AMF="${AMF_CONTAINER:-nextgcore-amf}"
SMF="${SMF_CONTAINER:-nextgcore-smf}"
UPF="${UPF_CONTAINER:-nextgcore-upf}"
AMF_SBI="${AMF_SBI:-172.23.0.5:7777}"
UDM_SBI="${UDM_SBI:-172.23.0.12:7777}"
SUPI="${UE_SUPI:-imsi-999700000000001}"
TARGET="${PING_TARGET:-10.45.0.1}"
COUNT="${PING_COUNT:-20}"
NR_CLI="${NR_CLI:-$SCRIPT_DIR/binaries/nr-cli}"
# How long a re-registration may take after the trigger. The defect it guards
# (#265) took ~26 s (T3510 16 s + T3511 10 s); a fixed UE takes well under 1 s.
REREG_BUDGET="${REREG_BUDGET:-10}"

SCENARIO=""   # set by each scenario, read by fail()
SINCE=""      # RFC 3339 instant the current scenario started
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

now() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }

fail() {
    echo "FAIL: ${SCENARIO} -- $*"
    for c in "$UE" "$GNB" "$AMF"; do
        echo "----- $c since the scenario started (tail) -----"
        docker logs --since "$SINCE" "$c" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -v "Broadcast RRC" | tail -40 || true
    done
    exit 1
}

# Logs of <container> since the scenario started, ANSI colour stripped, to a FILE.
# Grepping a file rather than `docker logs | grep -q`: under pipefail grep -q's
# early exit SIGPIPEs docker logs and turns a match into a failure.
logs_since() {
    docker logs --since "$SINCE" "$1" > "$WORK/raw" 2>&1 || true
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/raw" > "$WORK/$1.log"
    echo "$WORK/$1.log"
}

# wait_for <container> <fixed-string> <timeout-s>: 0 once the string appears in the
# container's log since the scenario started.
wait_for() {
    local c="$1" s="$2" t="$3" i f
    for i in $(seq 1 "$t"); do
        f=$(logs_since "$c")
        if grep -qF -- "$s" "$f"; then
            echo "  ok (${i}s): $c: $(grep -F -- "$s" "$f" | head -1 | cut -c1-200)"
            return 0
        fi
        sleep 1
    done
    return 1
}

install_cli() {
    [ -f "$NR_CLI" ] || { SCENARIO=setup; SINCE=$(now); fail "nr-cli not found at $NR_CLI"; }
    for c in "$UE" "$GNB"; do
        docker cp "$NR_CLI" "$c:/tmp/nr-cli" >/dev/null
        docker exec --user root "$c" chmod 0755 /tmp/nr-cli
    done
}

# nr-cli inside <container>, against the first node it discovers there.
cli() {
    local c="$1" cmd="$2" node
    node=$(docker exec "$c" /tmp/nr-cli --dump 2>/dev/null | head -1 | tr -d '\r')
    [ -n "$node" ] || return 1
    docker exec "$c" /tmp/nr-cli "$node" --exec "$cmd" 2>&1
}

ue_status() { cli "$UE" status | tr -d '\r'; }

# The UE's PDU session address on its TUN, e.g. 10.45.0.2 (empty if none).
ue_ip() {
    docker exec "$UE" ip -4 -o addr show 2>/dev/null \
        | awk '$2 ~ /^uesimtun/ { split($4, a, "/"); print a[1]; exit }'
}
ue_tun() {
    docker exec "$UE" ip -4 -o addr show 2>/dev/null \
        | awk '$2 ~ /^uesimtun/ { print $2; exit }'
}

# ping_exact <container> <dst> [-I iface]: require all COUNT replies (0% loss).
ping_exact() {
    local c="$1" dst="$2"; shift 2
    local out rx
    out=$(docker exec "$c" ping -c "$COUNT" -i 0.5 -W 3 "$@" "$dst" 2>&1 || true)
    echo "$out" | tail -2 | sed 's/^/  /'
    rx=$(echo "$out" | grep -oE '[0-9]+ (packets )?received' | grep -oE '^[0-9]+' || echo 0)
    [ "$rx" = "$COUNT" ] || fail "ping $c -> $dst: ${rx:-0}/${COUNT} replies (expected 0% loss)"
    echo "  ok: ${COUNT}/${COUNT} replies $c -> $dst"
}

# Move the UE to CM-IDLE with a gNB-initiated UE Context Release (the AMF sends
# a Release Command, both sides drop the NGAP UE context, the UE goes RRC_IDLE
# and 5GMM-IDLE). A no-op when the UE is already CM-IDLE.
ensure_idle() {
    local id i
    id=$(gnb_ue_id)
    if [ -z "$id" ]; then
        ue_status | grep -q 'CM-IDLE' \
            || fail "the gNB holds no UE context but the UE does not report CM-IDLE: $(ue_status | tr '\n' ' ')"
        echo "  ok: UE already CM-IDLE"
        return 0
    fi
    cli "$GNB" "ue-release $id" | sed 's/^/  gnb: /'
    wait_for "$UE" 'RRC connection released' 30 \
        || fail "the UE never logged its RRC connection released after ue-release $id"
    for i in $(seq 1 15); do
        ue_status | grep -q 'CM-IDLE' && { echo "  ok: UE status reports CM-IDLE"; return 0; }
        sleep 1
    done
    fail "the UE CLI status never reported CM-IDLE after the release: $(ue_status | tr '\n' ' ')"
}

# The gNB's UE context id for the UE (empty when the gNB holds none, i.e. the UE
# is RRC_IDLE / CM-IDLE). Read from the gNB, so it does not depend on the UE
# publishing its own CM state.
gnb_ue_id() {
    cli "$GNB" ue-list | grep -oE 'ue_id: [0-9]+' | head -1 | grep -oE '[0-9]+' || true
}

# Bring the UE back to CM-CONNECTED with a little uplink data (a UE-triggered
# Service Request when it is idle). The ping itself is not the assertion here.
ensure_connected() {
    local i
    for i in $(seq 1 15); do
        if [ -n "$(gnb_ue_id)" ]; then
            echo "  ok: UE CM-CONNECTED (the gNB holds its context)"
            return 0
        fi
        docker exec "$UE" ping -c 1 -W 1 -I "$(ue_tun)" "$TARGET" >/dev/null 2>&1 || true
        sleep 1
    done
    fail "the UE did not return to CM-CONNECTED: the gNB holds no context for it"
}

begin() {
    SCENARIO="$1"
    echo "=== ${SCENARIO}: $2"
    sleep 1   # docker logs --since has 1 s resolution on some engines
    SINCE=$(now)
}

pass() { echo "PASS: ${SCENARIO} -- $*"; }

# ---------------------------------------------------------------------------
scenario_idle_uplink() {
    begin idle-uplink "CM-IDLE, then uplink data: UE-triggered Service Request, ${COUNT}/${COUNT} ping (nextgsim #267)"
    [ -n "$(ue_ip)" ] || fail "the UE has no PDU session address on a uesimtun interface"
    ensure_idle
    local tun; tun=$(ue_tun)
    # The FIRST packet of this ping is what triggers the Service Request. Before
    # nextgsim #267 the UE sent it to a gNB that had no context for it: 19/20.
    ping_exact "$UE" "$TARGET" -I "$tun"
    local f; f=$(logs_since "$UE")
    grep -qF 'Sending Service Request (' "$f" \
        || fail "the ping was answered but the UE never sent a Service Request -- it was not CM-IDLE"
    grep -qF 'Service Accept received' "$f" || fail "the UE never received a Service Accept"
    pass "Service Request from CM-IDLE accepted and ${COUNT}/${COUNT} uplink-triggered pings answered"
}

scenario_paging() {
    begin paging "CM-IDLE, then downlink data from the UPF: Paging, Service Request, downlink ping answered"
    local ip; ip=$(ue_ip)
    [ -n "$ip" ] || fail "the UE has no PDU session address on a uesimtun interface"
    ensure_idle
    # Downlink to an idle UE: the UPF buffers it and reports to the SMF, the SMF
    # asks the AMF (N1N2MessageTransfer), the AMF pages through the gNB and the UE
    # answers with a Service Request (TS 23.502 §4.2.3.3).
    ping_exact "$UPF" "$ip"
    wait_for "$AMF" 'Paging sent to' 5 || fail "the AMF never sent a Paging for the downlink data"
    local f; f=$(logs_since "$UE")
    grep -qF 'Sending Service Request (' "$f" || fail "the UE never answered the page with a Service Request"
    grep -qF 'Service Accept received' "$f" || fail "the UE never received a Service Accept"
    pass "the downlink data paged the UE, its Service Request was accepted and ${COUNT}/${COUNT} downlink pings were answered"
}

scenario_deregister() {
    begin deregister "UE CLI 'deregister normal', Deregistration Accept, fresh registration, PDU session, ${COUNT}/${COUNT} ping (nextgsim #266)"
    ensure_connected
    local out
    out=$(cli "$UE" 'deregister normal' || true)
    printf '  ue-cli: %s\n' "$out"
    wait_for "$AMF" 'Deregistration Accept sent' 15 \
        || fail "the AMF never sent a Deregistration Accept (CLI said: $(echo "$out" | tr '\n' ' '))"
    wait_for "$UE" 'Deregistration Accept received' 15 \
        || fail "the UE never received the Deregistration Accept"
    ue_status | grep -q 'RM-DEREGISTERED' \
        || fail "after the accept the UE status is not RM-DEREGISTERED: $(ue_status | tr '\n' ' ')"
    echo "  ok: UE status RM-DEREGISTERED"
    # A de-registered UE stays de-registered until it is switched on again (TS
    # 24.501 §5.5.2.2.2), and nr-ue has no `register` command, so power-cycle it.
    # What this exercises is the AMF side: the context the de-registration
    # deleted must not get in the way of the new initial registration.
    docker restart -t 2 "$UE" >/dev/null
    wait_for "$UE" 'Received Registration Accept' 60 \
        || fail "the restarted UE never received a Registration Accept"
    wait_for "$UE" 'is now ACTIVE' 60 || fail "the re-registered UE never activated a PDU session"
    local i; for i in $(seq 1 10); do [ -n "$(ue_tun)" ] && break; sleep 1; done
    [ -n "$(ue_tun)" ] || fail "the new PDU session has no uesimtun interface"
    ping_exact "$UE" "$TARGET" -I "$(ue_tun)"
    pass "de-registered, re-registered, new PDU session ($(ue_ip)) and ${COUNT}/${COUNT} pings"
}

scenario_network_rereg() {
    begin network-rereg "UDM DeregistrationNotification REREGISTRATION_REQUIRED: prompt re-registration, PDU session, ${COUNT}/${COUNT} ping (nextgcore #580, nextgsim #265 #272)"
    local old_ip code t0 t1
    old_ip=$(ue_ip)
    [ -n "$old_ip" ] || fail "the UE has no PDU session to lose"
    # Make sure the UE is CM-CONNECTED: the deferred-registration path (#265) is
    # the connected one, and it is the one that used to wait for T3510.
    ensure_connected
    SINCE=$(now)
    t0=$(date +%s)
    # TS 29.503 §6.2.6.3.3: what the UDM POSTs to the deregCallbackUri the AMF
    # registered in its Nudm_UECM Registration. udmd never emits this reason
    # itself (no UDR purge path), so it is sent from the SMF container, which is on
    # the core network and ships curl.
    #
    # #947: to the URI the AMF REGISTERED, read back from the UDM with Nudm_UECM_Get
    # (TS 29.503 §5.3.2.5, GET .../registrations/amf-3gpp-access). The callback URI is
    # the consumer's (§5.3.2.2.2) and, since #753, ends in a per-registration token;
    # a notification to any other URI concerns a registration the AMF no longer holds
    # and is acknowledged without effect, as it must be.
    local reg uri
    reg=$(docker exec "$SMF" curl -s --http2-prior-knowledge \
        "http://${UDM_SBI}/nudm-uecm/v1/${SUPI}/registrations/amf-3gpp-access" || true)
    uri=$(printf '%s' "$reg" | tr -d '\n' \
        | sed -n 's/.*"deregCallbackUri"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    [ -n "$uri" ] || fail "the UDM holds no AMF 3GPP-access registration with a deregCallbackUri for ${SUPI}: ${reg}"
    echo "  registered deregCallbackUri: ${uri}"
    code=$(docker exec "$SMF" curl -s -o /dev/null -w '%{http_code}' --http2-prior-knowledge \
        -X POST -H 'Content-Type: application/json' \
        -d '{"deregReason":"REREGISTRATION_REQUIRED","accessType":"3GPP_ACCESS"}' \
        "${uri}" || true)
    echo "  dereg-notify -> HTTP ${code}"
    [ "$code" = "204" ] || fail "the AMF answered the DeregistrationNotification with HTTP ${code}, not 204"
    wait_for "$UE" 'Network-initiated de-registration' 10 \
        || fail "the UE never received the network-initiated DEREGISTRATION REQUEST"
    # #580: before it, REREGISTRATION_REQUIRED was signalled as "re-registration not
    # required", and the UE de-registered and stayed there.
    wait_for "$UE" 'Received Registration Accept' "$REREG_BUDGET" \
        || fail "no Registration Accept within ${REREG_BUDGET}s of the notification"
    t1=$(date +%s)
    local f; f=$(logs_since "$UE")
    if grep -qF 'T3510 expired' "$f"; then
        fail "the re-registration waited for T3510 (nextgsim #265): $(grep -F 'T3510 expired' "$f" | head -1)"
    fi
    [ $((t1 - t0)) -le "$REREG_BUDGET" ] \
        || fail "the Registration Accept came $((t1 - t0))s after the notification (budget ${REREG_BUDGET}s)"
    echo "  ok: re-registered $((t1 - t0))s after the notification, no T3510 expiry"
    # #272: the UE must release its old session locally and bring the default one
    # back; before, it kept a dead TUN and lost every packet.
    wait_for "$UE" 'is now ACTIVE' 30 || fail "no PDU session was re-established after the re-registration"
    local i; for i in $(seq 1 10); do [ -n "$(ue_tun)" ] && break; sleep 1; done
    [ -n "$(ue_tun)" ] || fail "the re-established PDU session has no uesimtun interface"
    ping_exact "$UE" "$TARGET" -I "$(ue_tun)"
    pass "re-registered in $((t1 - t0))s without T3510, PDU session re-established (${old_ip} -> $(ue_ip)), ${COUNT}/${COUNT} pings"
}

# ---------------------------------------------------------------------------
case "${1:-}" in
    idle-uplink)   install_cli; scenario_idle_uplink ;;
    paging)        install_cli; scenario_paging ;;
    deregister)    install_cli; scenario_deregister ;;
    network-rereg) install_cli; scenario_network_rereg ;;
    all)
        install_cli
        scenario_paging
        scenario_idle_uplink
        # #648: a page after the UE's Service Request from CM-IDLE.
        scenario_paging
        scenario_deregister
        scenario_network_rereg
        ;;
    *) echo "usage: $0 <paging|idle-uplink|deregister|network-rereg|all>"; exit 2 ;;
esac
