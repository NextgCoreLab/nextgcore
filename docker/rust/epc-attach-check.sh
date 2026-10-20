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
