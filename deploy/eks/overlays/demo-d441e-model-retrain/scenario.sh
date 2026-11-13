#!/usr/bin/env bash
# Seeded acceptance run of demo d441e-model-retrain (nextgsim#468), called by
# k8s/demo-check.sh with NAMESPACE, DEMO_KEY, DEMO_MODE and OUT set.
#
# The NWDAFs came up with the deploy, at an arbitrary point of the seeded
# series. The AnLF reports accuracy as soon as the MTLF subscribes, over the
# newest 20 points, so a start shortly after a regime change would request a
# retrain at once, before any calm report. So the run:
#   1. scales nwdaf-mtlf and nwdaf-anlf to 0 (strategy Recreate: the old pods
#      are gone before new ones start; their NRF profiles are pinned ids, so
#      the new pods replace them);
#   2. waits for 25-60 s into a 600 s cycle (at most 10 min) and scales both
#      to 1: the first reports are on the calm part, and the scripted change
#      (step 120 of the cycle) comes 60-95 s later;
#   3. polls both logs (kubectl logs --timestamps) until chain.py's chain holds
#      for DEMO_MODE, or D441E_AFTER_CHANGE s (default 360) after the change;
#      in no-retrain it then observes D441E_NO_RETRAIN_HOLD s (default 90) more;
#   4. asserts the chain with docker/rust/configs/demo-d441e/chain.py (its
#      header lists the steps, by kubelet timestamp), and in retrain fetches
#      the v1 and the v2 URL from inside the AnLF after v2: each serves the
#      bytes of its own sha256 (the v1 URL still v1).
# demo-check.sh then asserts each NWDAF's DEMO MODE ACTIVE banner and
# nextg_demo_enabled series from its own captures.
#
# Everything goes through kubectl inside the namespace: no port-forward,
# nothing published. Captures under $OUT/scenario/.
set -uo pipefail
: "${NAMESPACE:?}" "${DEMO_MODE:?}" "${OUT:?}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN="$(cd "${here}/../../../.." && pwd)/docker/rust/configs/demo-d441e/chain.py"
K=(kubectl -n "${NAMESPACE}")
S="${OUT}/scenario"
mkdir -p "${S}"
CYCLE=600 CHANGE=120 WIN_LO=25 WIN_HI=60
say() { printf '[scenario] %s\n' "$*"; }
die() { printf '[scenario] FAIL: %s\n' "$*"; exit 1; }
case "${DEMO_MODE}" in retrain | no-retrain) ;; *) die "unknown mode ${DEMO_MODE}" ;; esac
capture() {
  local d
  for d in nwdaf-mtlf nwdaf-anlf; do
    "${K[@]}" logs "deploy/${d}" -c nwdaf --timestamps >"${S}/${d}.log" 2>/dev/null || : >"${S}/${d}.log"
  done
}

# --- 1. stop both ----------------------------------------------------------------
"${K[@]}" scale deployment/nwdaf-mtlf deployment/nwdaf-anlf --replicas=0 >/dev/null || die "scale to 0"
"${K[@]}" wait --for=delete pod -l 'app.kubernetes.io/name in (nwdaf-mtlf,nwdaf-anlf)' --timeout=120s >/dev/null 2>&1 \
  || [[ -z "$("${K[@]}" get pods -l 'app.kubernetes.io/name in (nwdaf-mtlf,nwdaf-anlf)' -o name)" ]] \
  || die "the old NWDAF pods did not go away"

# --- 2. start inside the window ------------------------------------------------------
phase=$(( $(date +%s) % CYCLE ))
if (( phase < WIN_LO || phase > WIN_HI )); then
  wait_s=$(( (WIN_LO - phase + CYCLE) % CYCLE ))
  say "cycle phase ${phase}s; waiting ${wait_s}s for the start window [${WIN_LO}, ${WIN_HI}]s"
  sleep "${wait_s}"
fi
start="$(date +%s)"
"${K[@]}" scale deployment/nwdaf-mtlf deployment/nwdaf-anlf --replicas=1 >/dev/null || die "scale to 1"
change=$(( start - start % CYCLE + CHANGE ))
say "started at phase $(( start % CYCLE ))s; the scripted change is at unix ${change} (in $(( change - start ))s)"
"${K[@]}" rollout status deployment/nwdaf-mtlf --timeout=120s >/dev/null || die "nwdaf-mtlf rollout"
"${K[@]}" rollout status deployment/nwdaf-anlf --timeout=120s >/dev/null || die "nwdaf-anlf rollout"
echo "start=${start} start_phase=$(( start % CYCLE )) change=${change}" >"${S}/timing.txt"

# --- 3. wait for the chain ----------------------------------------------------------
deadline=$(( change + ${D441E_AFTER_CHANGE:-360} ))
held=false
while (( $(date +%s) < deadline )); do
  sleep 10
  capture
  if python3 "${CHAIN}" --mode "${DEMO_MODE}" --mtlf "${S}/nwdaf-mtlf.log" --anlf "${S}/nwdaf-anlf.log" >/dev/null 2>&1; then
    held=true; break
  fi
done
if [[ "${held}" == true && "${DEMO_MODE}" == no-retrain ]]; then
  say "the no-retrain chain holds; observing ${D441E_NO_RETRAIN_HOLD:-90}s more"
  sleep "${D441E_NO_RETRAIN_HOLD:-90}"
  capture
fi
for d in nwdaf-mtlf nwdaf-anlf; do [[ -s "${S}/${d}.log" ]] || die "empty ${d} capture"; done

# --- 4. assertions --------------------------------------------------------------------
python3 "${CHAIN}" --mode "${DEMO_MODE}" --mtlf "${S}/nwdaf-mtlf.log" --anlf "${S}/nwdaf-anlf.log" \
  --facts "${S}/facts.txt" 2>&1 | tee "${S}/chain.txt"
[[ ${PIPESTATUS[0]} == 0 ]] || die "the ${DEMO_MODE} chain does not hold (above)"
fact() { sed -n "s/^$1=//p" "${S}/facts.txt"; }
if [[ "${DEMO_MODE}" == retrain ]]; then
  for v in v1 v2; do
    url="$(fact "${v}_url")"; want="$(fact "${v}_sha256")"
    got="$("${K[@]}" exec deploy/nwdaf-anlf -c nwdaf -- sh -c \
      "curl -s --http2-prior-knowledge --max-time 10 '${url}' | sha256sum" 2>/dev/null | cut -d' ' -f1)"
    echo "${v} ${url} sha256=${got}" >>"${S}/artefacts.txt"
    [[ "${got}" == "${want}" ]] || die "GET ${v} URL after v2: sha256 ${got}, expected ${want}"
  done
  say "after v2 the v1 URL serves sha256=$(fact v1_sha256) and the v2 URL sha256=$(fact v2_sha256)"
fi
say "PASS (${DEMO_MODE}): $(tr '\n' ' ' <"${S}/facts.txt")"
