#!/usr/bin/env bash
# EPC attach + user-plane check (#303): the assertions that make the EPC stage a
# real end-to-end test rather than a bring-up check.
#
# Run AFTER docker-compose-epc.yml is up with every EPC NF healthy and both PFCP
# associations established, and after the `enb` and `lte-ue` services have
# started. It addresses containers by their fixed `container_name`s, so it works
# the same under `docker compose` (CI) and under a plain `docker run` harness.
#
# Asserts, in attach order (TS 23.401 §5.3.2.1), each on a line only reachable
# when that step really happened -- never "no error in the log":
#   1. S1 Setup     -- mmed accepted the eNB (TS 36.413 §8.7.3).
#   2. Attach       -- the UE reached EMM-REGISTERED, and mmed activated the
#                      default EPS bearer on the SAME EBI the UE reports.
#   3. User plane   -- a ping from the UE's TUN (the default bearer's PDN
#                      address) to the PGW-U's SGi address crosses
#                      UE -> eNB -> S1-U -> SGW-U -> S5-U -> PGW-U and back
#                      with 0% loss (lte-ue-ping-check exits 0 only then).
#
# Usage: epc-attach-check.sh [ping-target] [ping-count]
set -euo pipefail

TARGET="${1:-10.45.0.1}"
COUNT="${2:-20}"
MME=nextgcore-mme
ENB=nextgsim-lte-enb
UE=nextgsim-lte-ue
PGWU="${EPC_PGWU_CONTAINER:-nextgcore-pgwu}"
TIMEOUT="${EPC_ATTACH_TIMEOUT:-90}"

# wait_for <container> <extended-regex> <what>
wait_for() {
    local c="$1" re="$2" what="$3" i
    for i in $(seq 1 "$TIMEOUT"); do
        if docker logs "$c" 2>&1 | grep -Eq "$re"; then
            echo "OK: $what (after ${i}s)"
            docker logs "$c" 2>&1 | grep -E "$re" | head -1 | sed 's/^/    /'
            return 0
        fi
        sleep 1
    done
    echo "FAIL: $what -- no line matching /$re/ in $c within ${TIMEOUT}s"
    return 1
}

dump() {
    for c in "$ENB" "$UE" "$MME"; do
        echo "----- $c (tail) -----"
        docker logs --tail 60 "$c" 2>&1 || true
    done
}
on_exit() {
    local rc=$?
    [ "$rc" -ne 0 ] && dump
    exit "$rc"
}
trap on_exit EXIT

# The idle stage (5-6) counts MME log lines; its first baseline is taken here,
# before anything could have gone idle, so an S1 release that happens while the
# attach steps run is still seen (#961 review).
IDLE_RE='the UE goes ECM-IDLE'
idle_baseline=$(docker logs "$MME" 2>&1 | grep -Ec "$IDLE_RE" || true)

# 1. S1 Setup.
wait_for "$MME" 'S1 Setup: eNB 0x[0-9a-fA-F]+ .*accepted' "S1 Setup accepted by the MME"

# 2. Attach, with the default bearer. The EBI is read from the UE and must be the
#    one mmed activated, so two unrelated bearers cannot satisfy the pair.
wait_for "$UE" 'EMM-REGISTERED' "UE reached EMM-REGISTERED"
wait_for "$UE" 'default EPS bearer [0-9]+ activated' "UE activated its default EPS bearer"
ebi=$(docker logs "$UE" 2>&1 | grep -Eo 'default EPS bearer [0-9]+ activated' | head -1 | awk '{print $4}')
# The UE logs the PDN address with Debug formatting (e.g. `Ipv4(10.45.0.2)`),
# so take the first dotted quad after the label rather than one exact spelling.
pdn=$(docker logs "$UE" 2>&1 | grep -Eo 'PDN address [^,]*' | head -1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
[ -n "$ebi" ] || { echo "FAIL: could not read the default bearer's EBI from the UE"; exit 1; }
if [ -z "$pdn" ] || [ "$pdn" = "0.0.0.0" ]; then
    echo "FAIL: UE has no PDN address (got '${pdn}')"
    exit 1
fi
echo "    UE default bearer EBI=${ebi}, PDN address ${pdn}"
wait_for "$MME" "Default EPS bearer \\(ebi=${ebi}\\) activated" "MME activated the same default bearer (ebi=${ebi})"

# 3. User plane, 0% loss.
echo "Pinging ${TARGET} x${COUNT} from the UE's default bearer..."
docker exec "$UE" lte-ue-ping-check "$TARGET" "$COUNT"
echo "OK: ${COUNT}/${COUNT} echo replies through the default bearer (0% loss)"

# 4. The PGW-U counted that traffic (#581). Its `/metrics` serves the data-plane
#    counters of the forwarding path itself, so >= COUNT packets each way proves the
#    echoes crossed upfd's TUN path AND that the counters an operator reads move.
#    (Before #581 the only view was a log line that never printed under traffic.)
metric() {
    docker exec "$PGWU" curl -fsS http://localhost:9090/metrics 2>/dev/null \
        | awk -v m="$1" '$1 == m { print $2 }'
}
ul=$(metric upf_dataplane_ul_packets_total)
dl=$(metric upf_dataplane_dl_packets_total)
echo "    PGW-U data plane: UL=${ul:-?} DL=${dl:-?} packets"
if [ -z "$ul" ] || [ -z "$dl" ] || [ "$ul" -lt "$COUNT" ] || [ "$dl" -lt "$COUNT" ]; then
    echo "FAIL: PGW-U data-plane counters below ${COUNT} after a ${COUNT}-packet ping"
    docker exec "$PGWU" curl -fsS http://localhost:9090/metrics 2>/dev/null | grep dataplane || true
    exit 1
fi
echo "OK: PGW-U counted the ping on its TUN path (UL=${ul}, DL=${dl})"

# 5-6. Idle mode (#956, TS 23.401 §5.3.5 / §5.3.4.1 / §5.3.4.3). Off until the
#    simulator can idle an LTE UE and page it (nextgsim #350, #351): set
#    EPC_IDLE_MODE=1 with an eNB configured for a user-inactivity release.
#    Each step asserts a line only that step prints, never the absence of an
#    error.
if [ "${EPC_IDLE_MODE:-0}" = "1" ]; then
    IDLE_TIMEOUT="${EPC_IDLE_TIMEOUT:-60}"
    # mme_lines <regex>: how many lines of the MME log match, so a second
    # occurrence can be told from the first.
    mme_lines() { docker logs "$MME" 2>&1 | grep -Ec "$1" || true; }
    wait_more() {
        local re="$1" before="$2" what="$3" i
        for i in $(seq 1 "$IDLE_TIMEOUT"); do
            if [ "$(mme_lines "$re")" -gt "$before" ]; then
                echo "OK: $what (after ${i}s)"
                return 0
            fi
            sleep 1
        done
        echo "FAIL: $what -- no new /$re/ in $MME within ${IDLE_TIMEOUT}s"
        return 1
    }
    SR_RE='SERVICE REQUEST accepted: Initial Context Setup Request'
    UP_RE='SERVICE REQUEST user plane up; Modify Bearer Request'
    PAGED_RE='paged on [0-9]+ eNB'

    # 5. Mobile-originated: the eNB releases the idle UE (S1 release with
    #    Release Access Bearers), then an uplink packet makes the UE send a
    #    SERVICE REQUEST; the MME's Initial Context Setup and Modify Bearer
    #    Request bring the user plane back, and the ping recovers.
    # The eNB's inactivity timer runs from the attach, so the release may
    # already have happened: count from the baseline taken before step 1. The
    # timer must outlast steps 1-4 (EPC_IDLE_MODE needs an inactivity time
    # longer than the attach checks take, e.g. 30 s), or step 3's first echo
    # is the one that wakes the UE.
    sr=$(mme_lines "$SR_RE"); up=$(mme_lines "$UP_RE")
    wait_more "$IDLE_RE" "$idle_baseline" "S1 release: the MME took the UE to ECM-IDLE"
    echo "Uplink from the idle UE..."
    docker exec "$UE" lte-ue-ping-check "$TARGET" "$COUNT" || true
    wait_more "$SR_RE" "$sr" "mobile-originated SERVICE REQUEST answered with Initial Context Setup"
    wait_more "$UP_RE" "$up" "Serving GW given the new eNB S1-U endpoints"
    docker exec "$UE" lte-ue-ping-check "$TARGET" "$COUNT"
    echo "OK: ${COUNT}/${COUNT} echo replies after the mobile-originated SERVICE REQUEST"

    # 6. Network-triggered: idle again, then downlink to the UE's PDN address
    #    from the PGW-U side. The Serving GW buffers it and sends a Downlink Data
    #    Notification, the MME pages, the UE answers with a SERVICE REQUEST, and
    #    the user plane comes back: the buffered packets and then a fresh burst
    #    reach the UE's TUN. Counted at the UE's TUN rather than as echo replies:
    #    the UE container routes by default via eth0, so a reply to a
    #    network-originated echo does not take the bearer.
    ue_rx() { docker exec "$UE" cat /sys/class/net/lteuetun5/statistics/rx_packets; }
    idle=$(mme_lines "$IDLE_RE"); sr=$(mme_lines "$SR_RE"); paged=$(mme_lines "$PAGED_RE")
    wait_more "$IDLE_RE" "$idle" "S1 release again"
    rx0=$(ue_rx)
    echo "Downlink to the idle UE (${pdn}); UE TUN rx_packets=${rx0}..."
    docker exec "$PGWU" ping -c 3 -W 1 "$pdn" >/dev/null 2>&1 || true
    wait_more "$PAGED_RE" "$paged" "Downlink Data Notification paged the UE"
    wait_more "$SR_RE" "$sr" "network-triggered SERVICE REQUEST answered with Initial Context Setup"
    sleep 2
    rx1=$(ue_rx)
    if [ "$rx1" -le "$rx0" ]; then
        echo "FAIL: no buffered downlink reached the UE after paging (rx ${rx0} -> ${rx1})"
        exit 1
    fi
    echo "OK: $((rx1 - rx0)) buffered downlink packet(s) delivered after the paging"
    docker exec "$PGWU" ping -c "$COUNT" -i 0.2 -W 1 "$pdn" >/dev/null 2>&1 || true
    rx2=$(ue_rx)
    if [ $((rx2 - rx1)) -lt "$COUNT" ]; then
        echo "FAIL: ${COUNT} downlink packets sent, $((rx2 - rx1)) reached the UE"
        exit 1
    fi
    echo "OK: ${COUNT}/${COUNT} downlink packets reach the UE after the network-triggered SERVICE REQUEST"
fi
