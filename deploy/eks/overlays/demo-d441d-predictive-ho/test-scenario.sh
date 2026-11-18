#!/usr/bin/env bash
# Self-test of demo d441d-predictive-ho's overlay and scenario (nextgsim#467).
# No cluster, no network. Needs PyYAML and nextgsim checked out beside nextgcore
# (CI does, for the renders).
#
#   deploy/eks/overlays/demo-d441d-predictive-ho/test-scenario.sh
#
#   1. configs-patch.yaml's gnb.yaml, gnb-east.yaml and ue.yaml are nextgsim's
#      config/demo-predictive-ho/ files except the addresses (Service names),
#      the demo block (the post-render adds it) and the parked route; the
#      start_after_secs scenario.sh restores is nextgsim's.
#   2. d441d_rewrite: the seed on both gNBs, the route unparked, a second seed
#      on an unparked config, the invalid and conflict edits (still YAML, both
#      demos under demo:), and a refusal for an unknown variant or a config
#      that drifted (two seed lines).
#   3. the onnx init container (patches/gnb-d441d-onnx.yaml) adds d440b in
#      verify and the model path in mode onnx only, and refuses a second run.
#   4. d441d_shadowing_agrees and d441d_banner pass and fail as they must.
#   5. the model files are nextgsim's tools/d440b-model ones, byte for byte.
#   6. nextgsim's scorer self-test (scripts/demo/test_d441d_score.py), the one
#      scenario.sh scores with.
# `cond && ok ... || not_ok ...` throughout: ok only prints and cannot fail.
# shellcheck disable=SC2015
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
core="$(cd "${here}/../../../.." && pwd)"
sim="${NEXTGSIM_DIR:-${core}/../nextgsim}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
NAMESPACE=test-d441d OUT="${work}/out"
# shellcheck source-path=SCRIPTDIR source=scenario.sh
. "${here}/scenario.sh"
trap 'rm -rf "${work}"' EXIT

n=0
ok() { n=$((n + 1)); printf 'ok %d - %s\n' "${n}" "$*"; }
not_ok() { printf 'not ok - %s\n' "$*" >&2; exit 1; }

# --- 1. parity with nextgsim's committed configs -----------------------------------
python3 -I - "${here}/configs-patch.yaml" "${sim}/config/demo-predictive-ho" "${ROUTE_START_SECS}" <<'PY' \
    && ok "configs-patch.yaml is nextgsim's config/demo-predictive-ho/ but for addresses, demo and the parked route" \
    || not_ok "configs-patch.yaml differs from nextgsim's configs"
import sys, yaml
patch, src, start = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = yaml.safe_load(open(patch))["data"]
ADDR = {"amf_configs", "link_ip", "ngap_ip", "gtp_ip", "upf_addr", "gnb_search_list"}
for ours, theirs in (("gnb.yaml", "gnb-west.yaml"), ("gnb-east.yaml", "gnb-east.yaml"), ("ue.yaml", "ue.yaml")):
    a = yaml.safe_load(data[ours])
    b = yaml.safe_load(open(f"{src}/{theirs}"))
    assert "demo" not in a, f"{ours} carries a demo block"
    if theirs != "ue.yaml":
        assert "demo" in b, f"nextgsim's {theirs} lost its demo block"
    b.pop("demo", None)
    if ours == "ue.yaml":
        assert a["sim_route"]["start_after_secs"] == 86400, "the deployed route is not parked"
        assert b["sim_route"]["start_after_secs"] == start, \
            f"scenario.sh restores {start}, nextgsim commits {b['sim_route']['start_after_secs']}"
        a["sim_route"]["start_after_secs"] = start
        assert a["gnb_search_list"] == ["gnb.nextg-system.svc.cluster.local",
                                        "gnb-east.nextg-system.svc.cluster.local"], a["gnb_search_list"]
    for k in ADDR:
        a.pop(k, None); b.pop(k, None)
    diff = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
    assert not diff, f"{ours} differs from nextgsim's {theirs} in {diff}"
PY

# --- 2. d441d_rewrite ---------------------------------------------------------------
# The deployed ConfigMap: configs-patch's data with the block the post-render merges.
python3 -I - "${here}/configs-patch.yaml" "${work}/cm.json" <<'PY'
import json, sys, yaml
cm = yaml.safe_load(open(sys.argv[1]))
for k in ("gnb.yaml", "gnb-east.yaml"):
    doc = yaml.safe_load(cm["data"][k])
    doc["demo"] = {"enabled": True, "d441d-predictive-ho": {"enabled": True, "mode": "lsq"}}
    cm["data"][k] = yaml.safe_dump(doc, default_flow_style=False, sort_keys=False)
cm["metadata"]["resourceVersion"] = "1"
json.dump(cm, open(sys.argv[2], "w"))
PY
field() {   # JSON KEY: the parsed config
    python3 -I -c 'import json,sys,yaml; print(json.dumps(yaml.safe_load(json.load(open(sys.argv[1]))["data"][sys.argv[2]])))' "$1" "$2"
}
q() { python3 -I -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval(sys.argv[2], {"d": d}))' "$1" "$2"; }

d441d_rewrite "${work}/cm.json" "${work}/s7.json" 7 \
    && [[ "$(q "$(field "${work}/s7.json" gnb.yaml)" 'd["shadowing"]["seed"]')" == 7 ]] \
    && [[ "$(q "$(field "${work}/s7.json" gnb-east.yaml)" 'd["shadowing"]["seed"]')" == 7 ]] \
    && [[ "$(q "$(field "${work}/s7.json" ue.yaml)" 'd["sim_route"]["start_after_secs"]')" == 40 ]] \
    && [[ "$(q "$(field "${work}/s7.json" gnb.yaml)" 'd["demo"]["d441d-predictive-ho"]["mode"]')" == lsq ]] \
    && ! grep -q resourceVersion "${work}/s7.json" \
    && ok "d441d_rewrite: the seed on both gNBs, the route unparked, the mode untouched" \
    || not_ok "d441d_rewrite seed 7"
d441d_rewrite "${work}/s7.json" "${work}/s8.json" 8 \
    && [[ "$(q "$(field "${work}/s8.json" gnb-east.yaml)" 'd["shadowing"]["seed"]')" == 8 ]] \
    && ok "d441d_rewrite: a second seed on an unparked config" || not_ok "d441d_rewrite seed 8"
d441d_rewrite "${work}/cm.json" "${work}/inv.json" 1 invalid \
    && [[ "$(q "$(field "${work}/inv.json" gnb.yaml)" 'd["demo"]["d441d-predictive-ho"]["mode"]')" == bogus ]] \
    && [[ "$(q "$(field "${work}/inv.json" gnb-east.yaml)" 'd["demo"]["d441d-predictive-ho"]["mode"]')" == lsq ]] \
    && ok "d441d_rewrite invalid: mode bogus on gnb-west only" || not_ok "d441d_rewrite invalid"
d441d_rewrite "${work}/cm.json" "${work}/con.json" 1 conflict \
    && [[ "$(q "$(field "${work}/con.json" gnb.yaml)" 'sorted(d["demo"])')" == "['d441d-predictive-ho', 'd446a-agent-conflict', 'enabled']" ]] \
    && [[ "$(q "$(field "${work}/con.json" gnb.yaml)" 'd["demo"]["d446a-agent-conflict"]["mode"]')" == load-balancing ]] \
    && [[ "$(q "$(field "${work}/con.json" gnb.yaml)" 'd["demo"]["d441d-predictive-ho"]["mode"]')" == lsq ]] \
    && ok "d441d_rewrite conflict: D446A beside D441D under demo:, still YAML" || not_ok "d441d_rewrite conflict"
if d441d_rewrite "${work}/cm.json" "${work}/x.json" 1 bogus-variant 2>/dev/null; then not_ok "an unknown variant staged"; fi
ok "d441d_rewrite: refuses an unknown variant"
python3 -I -c '
import json, sys
cm = json.load(open(sys.argv[1])); cm["data"]["gnb-east.yaml"] += "  seed: 9\n"
json.dump(cm, open(sys.argv[2], "w"))' "${work}/cm.json" "${work}/drift.json"
if d441d_rewrite "${work}/drift.json" "${work}/x.json" 1 2>"${work}/err"; then not_ok "a drifted config staged"; fi
grep -q 'matched 2 time(s), expected 1' "${work}/err" && ok "d441d_rewrite: a drifted config (two seed lines) fails" \
    || not_ok "drift: $(cat "${work}/err")"

# --- 3. the onnx init container ------------------------------------------------------
python3 -I - "${here}/patches/gnb-d441d-onnx.yaml" "${work}/onnx-init.sh" <<'PY'
import sys, yaml
p = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], "w").write(p[0]["value"]["command"][2].replace("f=/etc/nextgsim/gnb.yaml", 'f="$1"'))
PY
# shellcheck disable=SC2016  # a literal $1 in the extracted script
grep -q 'f="$1"' "${work}/onnx-init.sh" || not_ok "the init script's config path was not redirected"
cfg() {   # MODE OUT: a deployed gnb.yaml in MODE
    python3 -I - "${work}/cm.json" "$1" "$2" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))["data"]["gnb.yaml"].replace("    mode: lsq", "    mode: " + sys.argv[2])
open(sys.argv[3], "w").write(t)
PY
}
cfg onnx "${work}/onnx.yaml"
sh "${work}/onnx-init.sh" "${work}/onnx.yaml" >/dev/null \
    && python3 -I -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
assert d["demo"]["d440b-model-verify"] == {"enabled": True, "mode": "verify"}, d["demo"]
assert d["demo"]["d441d-predictive-ho"]["mode"] == "onnx"
assert d["nwdaf_model_path"] == "/opt/nextgsim/models/nwdaf-trajectory-cv.onnx"' "${work}/onnx.yaml" \
    && ok "onnx init: d440b in verify beside d441d, and the model path" || not_ok "onnx init (onnx)"
if sh "${work}/onnx-init.sh" "${work}/onnx.yaml" >/dev/null 2>&1; then not_ok "the onnx init ran twice"; fi
ok "onnx init: refuses a config that already names d440b or a model path"
cfg a3 "${work}/a3.yaml"; cp "${work}/a3.yaml" "${work}/a3.orig"
sh "${work}/onnx-init.sh" "${work}/a3.yaml" >/dev/null && cmp -s "${work}/a3.yaml" "${work}/a3.orig" \
    && ok "onnx init: any other mode leaves the config as it is" || not_ok "onnx init (a3)"

# --- 4. the per-seed checks -------------------------------------------------------------
line='2026-11-18T10:00:00.1Z  INFO nextgsim_gnb::rls::task: RLS: seeded log-normal shadowing on: sigma=4 dB seed=3 decorrelation=20 m (non-normative simulator model)'
printf '%s\n' "${line}" > "${work}/w.log"; printf '%s\n' "${line}" > "${work}/e.log"
before=${fails}
d441d_shadowing_agrees "${work}/w.log" "${work}/e.log" 3 >/dev/null && (( fails == before )) \
    && ok "shadowing: both gNBs, the same line, this seed" || not_ok "shadowing agrees"
printf '%s\n' "${line/seed=3/seed=4}" > "${work}/e4.log"
d441d_shadowing_agrees "${work}/w.log" "${work}/e4.log" 3 >/dev/null && not_ok "different seeds passed" || true
d441d_shadowing_agrees "${work}/w.log" "${work}/e.log" 5 >/dev/null && not_ok "another seed passed" || true
: > "${work}/none.log"
d441d_shadowing_agrees "${work}/none.log" "${work}/none.log" 3 >/dev/null && not_ok "no shadowing line passed" || true
(( fails == before + 3 )) && ok "shadowing: fails on differing lines, another seed, no line" || not_ok "shadowing negatives (${fails})"
fails=0
printf '%s\n' '2026-11-18T10:00:00Z  WARN nextgsim_demo: DEMO MODE ACTIVE: d440b-model-verify=verify,d441d-predictive-ho=onnx' > "${work}/b.log"
d441d_banner "${work}/b.log" onnx >/dev/null && ! d441d_banner "${work}/b.log" lsq >/dev/null \
    && ! d441d_banner "${work}/b.log" onn >/dev/null \
    && ok "banner: names the mode among the active demos, not another or a prefix" || not_ok "banner"
fails=0

# --- 5. the model is nextgsim's ------------------------------------------------------------
for f in nwdaf-trajectory-cv.onnx nwdaf-trajectory-cv.manifest.json; do
    cmp -s "${here}/model/${f}" "${sim}/tools/d440b-model/${f}" || not_ok "model/${f} differs from nextgsim's"
done
ok "model/ is nextgsim's tools/d440b-model, byte for byte"

# --- 6. the scorer scenario.sh uses ----------------------------------------------------------
[[ "${score_py}" == "${core}/../nextgsim/scripts/demo/d441d_score.py" ]] || not_ok "score_py ${score_py}"
python3 -I "${sim}/scripts/demo/test_d441d_score.py" >"${work}/score.out" 2>&1 \
    && ok "nextgsim's d441d_score.py self-test passes" || { cat "${work}/score.out" >&2; not_ok "scorer self-test"; }

bash -n "${here}/scenario.sh" && ok "scenario.sh parses" || not_ok "scenario.sh parse"
echo "1..${n}"
