#!/usr/bin/env python3
"""Verdict of one demo d440c-nwdaf-paging run (nextgsim#464) from its captures.

    analyze.py <scenario dir> <mode> <variant>

scenario.sh captures, under <scenario dir>, every log with kubelet timestamps
(`kubectl logs --timestamps`): amf.log, smf.log, nwdaf.log, gnb-a.log, gnb-b.log,
gnb-c.log and ue.log (the UE pod scenario.sh started), plus ping.txt (the UPF's
downlink ping), ue-mobility.http (scenario.sh's own UE_MOBILITY GET: the status,
then the body) and amf.prom (amfd's /metrics after the page).

The anchors come from the logs, not from this host's clock:
  t_start  the first line of ue.log (the restarted UE);
  t_rel    the UE's `Received RRC Release from cell` after its route started
           (the harness's release in the dwell).
Only lines after t_start count for the laps, and only lines after t_rel for the
page, so nothing from the deploy's first UE or the base e2e can satisfy a check.

Arms (mode, variant):
  nwdaf-mobility, none        the success chain: smfd's downlink data report
      -> amfd `predicted=(999-70, 0x000000020)` (logged only for nwdafd's 200
      naming that cell) -> `Paging sent to 2/2 ...
      scope=nwdaf-mobility targets=[gNB 0x2,gNB 0x1] attempt 1` -> gNB B
      `PAGING assistance: cells=[0x10,0x20] attempt 1/5 next-scope=changed` ->
      `page answered ... via gNB 0x2 attempt 1`; gNB C gets no PAGING.
  registration-area, none     the page-all baseline: 3/3 on attempt 1, no NWDAF
      query from amfd (no `NWDAF UE mobility` line, no hint series), no Assistance Data at any gNB.
  off, none                   no demo block: the base core pages 3/3, no NWDAF
      query, no assistance line, no demo line.
  nwdaf-mobility, nwdaf-down  nwdafd scaled to 0 before the downlink: amfd logs
      a fail-open reason and pages the whole area on time.
  nwdaf-mobility, revert      nwdafd's UE_MOBILITY knob off (no history): it
      answers 204, amfd pages the whole area, and the success chain fails.
Every arm also checks the common chain: nine handovers A->B->C->A x3 while
connected, the release, an idle reselection, the page answered on attempt 1 at
NCI 0x20 (Initial UE Message) and >= 19/20 downlink pings, and the PAGING within
PAGING_BUDGET_MS of smfd's PFCP Session Report Request.

Prints one `[analyze] ok|FAIL ...` line per check and a `RESULT {json}` line for
the docs table. Exit 0 when every check of the arm holds. Python 3.7 or newer.
"""
import json
import re
import sys
from datetime import datetime

SUPI = "imsi-999700000000001"
KEY = "d440c-nwdaf-paging"
CELL = {"A": "000000010", "B": "000000020", "C": "000000030"}
PAGING_BUDGET_MS = 2000
ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$")


def load(path):
    """[(datetime, line)] of a kubelet-timestamped log; [] when absent."""
    out = []
    try:
        text = open(path, errors="replace").read()
    except OSError:
        return out
    for raw in text.splitlines():
        ts, _, msg = raw.partition(" ")
        m = TS.match(ts)
        if not m:
            continue
        frac = (m.group(2) or "0")[:6].ljust(6, "0")
        t = datetime.strptime(m.group(1) + "." + frac, "%Y-%m-%dT%H:%M:%S.%f")
        out.append((t, ANSI.sub("", msg)))
    return out


class Run:
    def __init__(self, d, mode, variant):
        self.d, self.mode, self.variant = d, mode, variant
        self.fails = []
        self.logs = {n: load("%s/%s.log" % (d, n))
                     for n in ("amf", "smf", "nwdaf", "gnb-a", "gnb-b", "gnb-c", "ue")}
        self.result = {"mode": mode, "variant": variant or "none"}

    def ok(self, msg):
        print("[analyze] ok   " + msg)

    def bad(self, msg):
        print("[analyze] FAIL " + msg)
        self.fails.append(msg)

    def check(self, cond, msg):
        (self.ok if cond else self.bad)(msg)
        return cond

    def find(self, log, pattern, after=None, before=None):
        """The first (t, line) of `log` matching `pattern` in [after, before)."""
        rx = re.compile(pattern)
        for t, line in self.logs[log]:
            if after is not None and t < after:
                continue
            if before is not None and t >= before:
                break
            if rx.search(line):
                return t, line
        return None

    def every(self, log, pattern, after=None, before=None):
        rx = re.compile(pattern)
        return [(t, l) for t, l in self.logs[log]
                if (after is None or t >= after) and (before is None or t < before)
                and rx.search(l)]


def ms(a, b):
    return int(round((b - a).total_seconds() * 1000))


def analyze(d, mode, variant):
    r = Run(d, mode, variant)
    for name, lines in r.logs.items():
        if not r.check(bool(lines), "%s.log captured and non-empty" % name):
            return r
    ue = r.logs["ue"]
    t_start = ue[0][0]

    # --- the laps: registration at A, then nine handovers ----------------------
    motion = r.find("ue", r"Simulated motion started: sim_route from \(30, 17, 0\)")
    if not r.check(motion is not None, "UE route started (Simulated motion started: sim_route)"):
        return r
    t_motion = motion[0]
    reg = r.find("amf", r"Initial UE Message: .*nci=0x10\b", after=t_start)
    r.check(reg is not None and reg[0] < t_motion,
            "the restarted UE registered through gNB A (Initial UE Message nci=0x10) before its route")
    rel = r.find("ue", r"Received RRC Release from cell (\d+)", after=t_motion)
    if not r.check(rel is not None, "UE released to RRC_IDLE after its route started"):
        return r
    t_rel, rel_line = rel
    cell_a = re.search(r"from cell (\d+)", rel_line).group(1)
    hos = r.every("amf", r"HandoverNotify from association \d+", after=t_start, before=t_rel)
    r.result["handovers"] = len(hos)
    # Seconds from the UE's start-up, beside the route model's (nextgsim
    # tests/src/d440c_lap_route.rs print_the_seed_table).
    rel = lambda t: round((t - t_start).total_seconds(), 1)
    r.result["motion_s"] = rel(t_motion)
    r.result["last_handover_s"] = rel(hos[-1][0]) if hos else None
    r.result["release_s"] = rel(t_rel)
    r.check(len(hos) == 9, "nine N2 handovers before the release (got %d)" % len(hos))
    idle = r.find("ue", r"CM state changed to: CM-IDLE", after=t_rel)
    r.check(idle is not None, "UE CM-IDLE after the release")
    if variant != "revert":
        ingests = [re.search(r"cell=99970-(\d{9})", l).group(1)
                   for _, l in r.every("nwdaf", r"ue-mobility ingest supi=%s cell=99970-\d{9}" % SUPI,
                                       after=t_start, before=t_rel)]
        want = [CELL[c] for c in "ABCABCABCA"]
        r.result["ingested_cells"] = len(ingests)
        r.check(ingests == want,
                "nwdafd ingested the restarted UE's cells A,B,C,A,B,C,A,B,C,A in order (got %s)"
                % ",".join(c[-2:] for c in ingests))
    else:
        r.check(not r.every("nwdaf", r"ue-mobility ingest", after=t_start),
                "revert: nwdafd ingested no LOCATION_REPORT (knob off)")
        r.check(r.find("nwdaf", r"ue-mobility: on") is None,
                "revert: nwdafd never logged `ue-mobility: on`")

    # --- idle reselection, then the page ----------------------------------------
    resel = None
    for t, line in r.every("ue", r"Cell reselection: id=(\d+),", after=t_rel):
        cid = re.search(r"id=(\d+),", line).group(1)
        if cid != cell_a:
            resel = (t, cid)
            break
    if not r.check(resel is not None, "idle reselection away from gNB A's cell %s" % cell_a):
        return r
    cell_b = resel[1]
    r.result["reselected_s"] = rel(resel[0])
    report = r.find("smf", r"PFCP Session Report Request: SEID=", after=t_rel)
    sent = r.every("amf", r"^(?!.*\[demo:).*Paging sent to \d+/\d+ gNB\(s\) ", after=t_rel)
    if not r.check(bool(sent), "amfd sent a PAGING after the release"):
        return r
    t_page, page_line = sent[0]
    r.check(resel[0] < t_page, "the UE reselected before the page")
    r.check("attempt 1" in page_line and len(sent) == 1,
            "exactly one PAGING round, attempt 1 (%d round(s))" % len(sent))
    m = re.search(r"Paging sent to (\d+)/(\d+) gNB\(s\) (.*?): 5G-S-TMSI", page_line)
    r.result["pagings"] = int(m.group(1)) if m else None
    r.result["scope_phrase"] = m.group(3) if m else None
    if r.check(report is not None and report[0] <= t_page,
               "smfd's PFCP Session Report Request precedes the PAGING"):
        lat = ms(report[0], t_page)
        r.result["report_to_paging_ms"] = lat
        r.check(lat <= PAGING_BUDGET_MS,
                "PAGING %d ms after the downlink data report (budget %d ms)" % (lat, PAGING_BUDGET_MS))
    initial = r.find("amf", r"Initial UE Message: .*nci=0x20\b", after=t_page)
    answered = r.find("amf", r"Service Request from CM-IDLE: .*\(page answered, T3513 stopped\)", after=t_page)
    r.check(initial is not None, "the answer came through gNB B (Initial UE Message nci=0x20)")
    r.check(answered is not None, "amfd: Service Request from CM-IDLE (page answered, T3513 stopped)")
    r.check(r.find("ue", r"Paged by cell %s in RRC_IDLE" % cell_b, after=t_rel) is not None,
            "UE paged by its camped cell %s in RRC_IDLE" % cell_b)
    r.check(r.find("ue", r"Sending Service Request \(MobileTerminatedServices\)", after=t_page) is not None,
            "UE sent a mobile-terminated Service Request")
    r.check(r.find("ue", r"Service Accept received", after=t_page) is not None, "UE: Service Accept received")
    try:
        ping = open("%s/ping.txt" % d).read()
    except OSError:
        ping = ""
    got = re.search(r"(\d+) (?:packets )?received", ping)
    rx = int(got.group(1)) if got else 0
    r.result["downlink_pings"] = "%d/20" % rx
    r.check(rx >= 19, "downlink pings answered: %d/20 (>= 19)" % rx)

    per_gnb = {}
    for g in ("gnb-a", "gnb-b", "gnb-c"):
        per_gnb[g] = len(r.every(g, r"PAGING from AMF\[\d+\]: matched \d+ served TAI", after=t_rel))
    r.result["pagings_per_gnb"] = per_gnb
    assist = {g: [l for _, l in r.every(g, r"\[demo:%s\] PAGING assistance: " % KEY, after=t_rel)]
              for g in per_gnb}
    demo_sent = r.find("amf", r"\[demo:%s\] Paging sent to " % KEY, after=t_rel)
    demo_answer = r.find("amf", r"\[demo:%s\] page answered ue=%s via gNB 0x(\w+) attempt (\d+)" % (KEY, SUPI),
                         after=t_page)
    # nwdafd logs `Analytics Info Query: <path>` without the query string, and
    # pcfd's intent loop polls the same path, so nwdafd's log cannot tell an
    # amfd UE_MOBILITY query apart. amfd's side is the evidence: its
    # `NWDAF UE mobility:` lines and amf_paging_nwdaf_hints_total. A
    # `predicted=` line is logged only for a 200 whose body names a cell.
    nwdaf_lines = r.every("amf", r"NWDAF UE mobility: ue=%s " % SUPI, after=t_rel)
    predicted = r.find("amf", r"NWDAF UE mobility: ue=%s predicted=\((\S+), 0x(\w+)\) confidence=(\S+)" % SUPI,
                       after=t_rel)
    r.result["amf_nwdaf_lines"] = len(nwdaf_lines)
    r.result["attempt1_hit"] = bool(initial and answered and len(sent) == 1)
    if demo_sent:
        ds = re.search(r"Paging sent to \S+ ue=\S+ scope=(\S+) targets=\[([^\]]*)\]", demo_sent[1])
        if ds:
            r.result["scope"], r.result["targets"] = ds.group(1), ds.group(2)
    try:
        http = open("%s/ue-mobility.http" % d).read().split("\n", 1)
    except OSError:
        http = ["", ""]
    r.result["scenario_get"] = http[0].strip()

    hits = {}
    try:
        for line in open("%s/amf.prom" % d):
            mm = re.match(r'amf_paging_nwdaf_hints_total\{outcome="(\w+)"\} (\d+)', line)
            if mm:
                hits[mm.group(1)] = int(mm.group(2))
    except OSError:
        pass
    r.result["nwdaf_hints"] = hits

    # scenario.sh's own GET, after the reselection and before the downlink.
    # Corroboration only: a separate request with its own window, not amfd's
    # exchange (amfd's `predicted=` line and hint counter are that evidence).
    if variant == "revert":
        r.check(http[0].strip() == "204", "revert: corroboration: scenario's own UE_MOBILITY GET is 204 (got %s)" % http[0].strip())
    else:
        r.check(http[0].strip() == "200" and predicts(http[1], CELL["B"]),
                "corroboration: scenario's own UE_MOBILITY GET before the downlink: 200 predicting cell %s (got %s)"
                % (CELL["B"], http[0].strip()))

    want_answer = (r"page answered ue=%s via gNB 0x2 attempt 1" % SUPI)
    if mode == "off":
        r.check(per_gnb == {"gnb-a": 1, "gnb-b": 1, "gnb-c": 1}, "off: every gNB got one PAGING (%s)" % per_gnb)
        r.check(m is not None and m.group(1) == "3" and m.group(3) == "serving the registration area",
                "off: `Paging sent to 3/3 gNB(s) serving the registration area`")
        r.check(not nwdaf_lines and not hits, "off: amfd made no UE_MOBILITY query (no line, no hint series)")
        r.check(not any(assist.values()), "off: no gNB logged a PAGING assistance line")
        r.check(not r.every("amf", r"\[demo:|NWDAF UE mobility"), "off: amfd logged no demo or NWDAF line")
    elif mode == "registration-area":
        r.check(per_gnb == {"gnb-a": 1, "gnb-b": 1, "gnb-c": 1},
                "registration-area: every gNB got one PAGING (%s)" % per_gnb)
        r.check(demo_sent is not None and r.result.get("scope") == "registration-area"
                and "Paging sent to 3/3" in demo_sent[1]
                and sorted(r.result.get("targets", "").split(",")) == ["gNB 0x1", "gNB 0x2", "gNB 0x3"],
                "registration-area: `Paging sent to 3/3 ... scope=registration-area targets=[gNB 0x1..0x3] attempt 1`")
        r.check(not nwdaf_lines and not hits,
                "registration-area: amfd made no UE_MOBILITY query (no line, no hint series)")
        r.check(not any(assist.values()), "registration-area: no Assistance Data at any gNB")
        r.check(demo_answer is not None and re.search(want_answer, demo_answer[1]) is not None,
                "registration-area: `%s`" % want_answer)
    elif mode == "nwdaf-mobility" and variant in ("", "none"):
        chain = success_chain(r, t_rel, report, predicted, demo_sent, assist, demo_answer, want_answer)
        r.check(chain is None, "the ordered success chain" + ("" if chain is None else ": " + chain))
        r.check(per_gnb == {"gnb-a": 1, "gnb-b": 1, "gnb-c": 0},
                "nwdaf-mobility: attempt 1 paged gNB B and gNB A only (%s)" % per_gnb)
        r.check(hits.get("predicted") == 1, "amf_paging_nwdaf_hints_total{outcome=\"predicted\"} 1 (%s)" % hits)
        if predicted:
            r.result["confidence"] = predicted[1] and re.search(r"confidence=(\S+)", predicted[1]).group(1)
    elif mode == "nwdaf-mobility" and variant in ("nwdaf-down", "revert"):
        fail_open = r.find("amf", r"NWDAF UE mobility: ue=%s (no prediction \(|no answer within)" % SUPI,
                           after=t_rel)
        if variant == "nwdaf-down":
            r.check(fail_open is not None, "nwdaf-down: amfd logged a fail-open reason")
            if fail_open:
                r.result["fail_open"] = fail_open[1][fail_open[1].index("NWDAF UE mobility"):]
            try:
                down = open("%s/nwdaf-down.txt" % d).read()
            except OSError:
                down = ""
            r.check("nwdaf pods before the downlink: 0" in down,
                    "nwdaf-down: no nwdaf pod was left when the downlink started (%s)" % down.strip())
            r.check(hits.get("error", 0) + hits.get("timeout", 0) == 1 and not hits.get("predicted"),
                    "nwdaf-down: one error or timeout hint outcome, none predicted (%s)" % hits)
        else:
            r.check(fail_open is None and predicted is None,
                    "revert: amfd logged neither a prediction nor a failure (nwdafd answered without a cell)")
            r.check(hits.get("no_prediction") == 1,
                    "revert: amf_paging_nwdaf_hints_total{outcome=\"no_prediction\"} 1 (%s)" % hits)
        r.check(per_gnb == {"gnb-a": 1, "gnb-b": 1, "gnb-c": 1}, "%s: every gNB got one PAGING (%s)" % (variant, per_gnb))
        r.check(m is not None and m.group(1) == "3" and m.group(3) == "serving the registration area",
                "%s: `Paging sent to 3/3 gNB(s) serving the registration area`" % variant)
        r.check(demo_sent is not None and r.result.get("scope") == "registration-area",
                "%s: demo line scope=registration-area" % variant)
        r.check(all(any("cells=[] attempt 1/5 next-scope=same" in l for l in assist[g]) for g in assist),
                "%s: each gNB logged `PAGING assistance: cells=[] attempt 1/5 next-scope=same`" % variant)
        r.check(demo_answer is not None and re.search(want_answer, demo_answer[1]) is not None,
                "%s: `%s`" % (variant, want_answer))
        chain = success_chain(r, t_rel, report, predicted, demo_sent, assist, demo_answer, want_answer)
        r.result["success_chain"] = "fails: " + chain if chain else "holds"
        r.check(chain is not None, "%s: the success chain does NOT hold (%s)" % (variant, chain))
    else:
        r.bad("no assertions for mode=%s variant=%s" % (mode, variant))
    return r


def predicts(body, cell):
    """Whether a UE_MOBILITY AnalyticsData body's best locInfos entry is `cell`."""
    try:
        doc = json.loads(body)
        infos = [i for m in doc["ueMobs"] for i in m.get("locInfos", [])]
        best = max(infos, key=lambda i: i.get("confidence", 0))
        return best["loc"]["nrLocation"]["ncgi"]["nrCellId"] == cell
    except (ValueError, KeyError, TypeError):
        return False


def success_chain(r, t_rel, report, predicted, demo_sent, assist, demo_answer, want_answer):
    """None when the ordered success chain holds, else the first missing step."""
    if report is None:
        return "no smfd PFCP Session Report Request (no downlink data)"
    if predicted is None:
        return "no amfd `NWDAF UE mobility: ... predicted=` line"
    if not re.search(r"predicted=\(999-70, 0x0000000?20\) confidence=\d+%", predicted[1]):
        return "amfd predicted another cell: " + predicted[1]
    want = "Paging sent to 2/2 ue=%s scope=nwdaf-mobility targets=[gNB 0x2,gNB 0x1] attempt 1" % SUPI
    if demo_sent is None or want not in demo_sent[1]:
        return "no `%s` (got %s)" % (want, demo_sent[1] if demo_sent else "none")
    b = [l for l in assist["gnb-b"] if "cells=[0x10,0x20] attempt 1/5 next-scope=changed" in l]
    if not b:
        return "no gNB B `PAGING assistance: cells=[0x10,0x20] attempt 1/5 next-scope=changed`"
    tb = r.find("gnb-b", re.escape("cells=[0x10,0x20] attempt 1/5 next-scope=changed"), after=t_rel)[0]
    if demo_answer is None or not re.search(want_answer, demo_answer[1]):
        return "no `%s`" % want_answer
    # amfd logs `Paging sent` after its send loop, so the gNBs' receipt lines
    # can carry an earlier kubelet stamp: gNB B is ordered after the prediction
    # and before the answer, not against amfd's send line.
    for order in ([report[0], predicted[0], demo_sent[0], demo_answer[0]],
                  [predicted[0], tb, demo_answer[0]]):
        if order != sorted(order):
            return "out of order: report %s, predicted %s, sent %s, gNB B %s, answered %s" % tuple(
                t.time().isoformat() for t in (report[0], predicted[0], demo_sent[0], tb, demo_answer[0]))
    return None


def main(argv):
    if len(argv) != 4:
        sys.exit(__doc__)
    d, mode, variant = argv[1], argv[2], argv[3]
    r = analyze(d, mode, variant)
    print("RESULT " + json.dumps(r.result, sort_keys=True))
    if r.fails:
        print("[analyze] FAIL: %d check(s)" % len(r.fails))
        return 1
    print("[analyze] PASS (%s%s)" % (mode, "+" + variant if variant not in ("", "none") else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
