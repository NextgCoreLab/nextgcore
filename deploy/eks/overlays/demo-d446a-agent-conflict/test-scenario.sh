#!/usr/bin/env bash
# Self-test of the D446A uplink-burst check (nextgcore#1630, nextgsim#568). No
# cluster, no network.
#
#   deploy/eks/overlays/demo-d446a-agent-conflict/test-scenario.sh
#
# d446a_uplink_burst passes on a gNB-A log where the burst (len=475) comes
# before lb-1's IntentSubmitted, and FAILS when the burst is missing (the revert
# arm), when it comes after the intent (lb-1 fired on something else), when an
# incidental len=49 packet is there (IPv6 not off), and when the sidecar did not
# send its pings. Sourcing scenario.sh also runs its in_order self-test.
# `cond && ok ... || not_ok ...` throughout: ok only prints and cannot fail.
# shellcheck disable=SC2015
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
# scenario.sh's top level wants these; nothing is deployed or read from a cluster.
NAMESPACE=test-d446a OUT="${work}/out"
# shellcheck source-path=SCRIPTDIR source=scenario.sh
. "${here}/scenario.sh"

n=0
ok() { n=$((n + 1)); printf 'ok %d - %s\n' "${n}" "$*"; }
not_ok() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
holds() { local name="$1"; shift; "$@" >/dev/null 2>&1 && ok "${name}" || not_ok "${name}"; }
breaks() { local name="$1"; shift; "$@" >/dev/null 2>&1 && not_ok "${name}" || ok "${name}"; }
put() { local f="${work}/$1"; shift; printf '%s\n' "$@" >"${f}"; echo "${f}"; }

# Lines as gNB-A logs them on devtest1 (ANSI colour codes included: the
# boundary after len=475 must accept the escape that follows it).
e=$'\033'
ts='2026-11-11T23:22:46.549381Z'
active="${ts}  INFO nextgsim_gnb::gtp::task: PDU session created: ue_id=0, psi=1, ul_teid=0x10000, dl_teid=0x1"
burst="${ts} ${e}[34mDEBUG${e}[0m nextgsim_gnb::rls::task: Uplink data (RLC): ue_id=0, drb_id=1, psi=1, len=475${e}[0m"
burst2="${ts} DEBUG nextgsim_gnb::rls::task: Uplink data (RLC): ue_id=0, drb_id=1, psi=1, len=475"
v6="${ts} DEBUG nextgsim_gnb::rls::task: Uplink data (RLC): ue_id=0, drb_id=1, psi=1, len=49"
big="${ts} DEBUG nextgsim_gnb::rls::task: Uplink data (RLC): ue_id=0, drb_id=1, psi=1, len=4750"
intent="${ts}  INFO nextgsim_gnb::agent::d446a: [demo:d446a-agent-conflict] audit #1: IntentSubmitted (lb-1) TriggerHandover ue=0 target_cell=16 cause=reduce-load-in-serving-cell (served UEs 1 >= 1)"

sent="$(put sent.log '[uplink-burst] uesimtun0 is up: 5 pings, 446-byte payload, to 10.45.0.1' \
  '--- 10.45.0.1 ping statistics ---' '5 packets transmitted, 5 received, 0% packet loss, time 804ms' '[uplink-burst] done')"
unsent="$(put unsent.log '[uplink-burst] FATAL: no uesimtun* with an IPv4 address in 600 s')"

holds "burst before lb-1's intent" d446a_uplink_burst "${sent}" "$(put good.log "${active}" "${burst}" "${burst2}" "${intent}")"
breaks "no burst (the revert arm)" d446a_uplink_burst "${sent}" "$(put none.log "${active}" "${intent}")"
breaks "burst only after lb-1's intent" d446a_uplink_burst "${sent}" "$(put late.log "${active}" "${intent}" "${burst2}")"
breaks "an incidental len=49 packet" d446a_uplink_burst "${sent}" "$(put v6.log "${active}" "${v6}" "${burst2}" "${intent}")"
breaks "len=4750 is not the burst" d446a_uplink_burst "${sent}" "$(put big.log "${active}" "${big}" "${intent}")"
breaks "the sidecar sent no pings" d446a_uplink_burst "${unsent}" "$(put good2.log "${active}" "${burst2}" "${intent}")"
breaks "an empty sidecar log" d446a_uplink_burst "$(put empty.log)" "$(put good3.log "${active}" "${burst2}" "${intent}")"
breaks "no lb-1 intent at all" d446a_uplink_burst "${sent}" "$(put nointent.log "${active}" "${burst2}")"

# A GNU escape reaching awk is named, not reported as a plain missing step.
msg="$(in_order "$(put gnu.log "${burst2}")" t 'len=475\b')"
[[ "${msg}" == *"matches under grep -E but not awk"* ]] && ok "in_order names a non-portable pattern" || not_ok "gnu: ${msg}"

bash -n "${here}/scenario.sh" && ok "scenario.sh parses" || not_ok "scenario.sh parse"
echo "1..${n}"
