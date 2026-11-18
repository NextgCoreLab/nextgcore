#!/usr/bin/env python3
"""Verdict for one d440a-ai-paging EKS arm (nextgsim#462), from scenario.sh's
capture directory.

    analyze.py <scenario dir> <mode> <variant>

The checks, each named in the output, all in kubelet-timestamp order within one
log:
  ue        is now ACTIVE -> Simulated motion started: sim_route -> RRC connection
            released -> CM-IDLE -> Paged by cell N in RRC_IDLE -> Service Request
            (MobileTerminatedServices) -> Service Accept received
  amf       Paging sent to K/M gNB(s) <scope>: ... attempt 1 -> Service Request
            from CM-IDLE: ... (page answered, T3513 stopped). <scope> is
            "recommended by the RAN in the registration area" for a predictor
            mode, and "serving the registration area" on all six gNBs for page-all
            and off
  amf-demo  (all but off) the forced strategy at startup, then
            [demo:d440a-ai-paging] Paging sent to ... ue=<supi> scope=<recommended
            | registration-area> targets=[...] attempt 1 -> page answered ue=<supi>
            via gNB 0x.. attempt K. off: no [demo: line in amfd
  serving   (predictor modes) the serving gNB's paging recommendation, then its
            UE Context Release Complete with nodes=[0x<serving>(visited),...];
            attempt 1's demo targets are exactly those nodes, in that order
  gnbs      every gNB logs the banner and a paging grid of 5 cells (all but off);
            no gNB recommends in page-all or off; no demo line at all in off
  metrics   amf_paging_attempts_total: recommended >= 1 for a predictor mode, 0
            for page-all (whose attempt 1 is the area); absent in off
  upf       at least one downlink ping answered by the paged UE

Recorded, not asserted (result.txt): the serving gNB, the recommendation,
attempt 1's targets, the gNB that answered, whether attempt 1 reached it, and
the PAGING messages sent. Whether a mode hits is the measurement.

variant `revert` runs the same checks: amfd has no demo block, so they must
fail at the amf step. Exit 0 when every check holds.
"""
import os
import re
import sys

SUPI = "imsi-999700000000001"
KEY = "d440a-ai-paging"
GNBS = ["gnb", "gnb-2", "gnb-3", "gnb-4", "gnb-5", "gnb-6"]
GNB_ID = {g: i + 1 for i, g in enumerate(GNBS)}
PREDICTORS = ("last-served", "ct", "lsq")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def load(d, name):
    try:
        with open(os.path.join(d, name), errors="replace") as f:
            return [ANSI.sub("", l.rstrip("\n")) for l in f]
    except OSError:
        return None


class Report:
    def __init__(self):
        self.fails = []

    def check(self, name, ok, why):
        print(("ok   " if ok else "FAIL ") + f"[{name}] {why}")
        if not ok:
            self.fails.append(name)
        return ok


def in_order(lines, patterns):
    """(index of each match in order, or None from the first missing step on)."""
    found, at = [], 0
    for p in patterns:
        rx = re.compile(p)
        hit = next((i for i in range(at, len(lines)) if rx.search(lines[i])), None)
        found.append(hit)
        if hit is None:
            return found, patterns.index(p)
        at = hit + 1
    return found, None


def chain(r, name, lines, patterns):
    if not lines:
        return r.check(name, False, "empty or missing capture")
    _, missing = in_order(lines, patterns)
    if missing is None:
        return r.check(name, True, f"{len(patterns)} steps in order")
    return r.check(name, False, f"step {missing + 1}/{len(patterns)} missing: {patterns[missing]}")


def gnb_ids(text):
    return [int(x, 16) for x in re.findall(r"0x([0-9a-f]+)", text)]


def metric(prom, scope):
    for l in prom or []:
        m = re.match(r'amf_paging_attempts_total\{scope="%s"\} (\d+)' % re.escape(scope), l)
        if m:
            return int(m.group(1))
    return None


def analyze(d, mode, variant):
    r = Report()
    predictor = mode in PREDICTORS
    demo_on = mode != "off"
    ue = load(d, "ue.log")
    amf = load(d, "amf.log")
    serving = (load(d, "serving.txt") or [""])[0].strip()
    chain(r, "ue", ue, [
        r"is now ACTIVE",
        r"Simulated motion started: sim_route",
        r"RRC connection released",
        r"CM state changed to: CM-IDLE",
        r"Paged by cell [0-9]+ in RRC_IDLE",
        r"Sending Service Request \(MobileTerminatedServices\)",
        r"Service Accept received",
    ])
    if predictor:
        scope = r"Paging sent to [1-6]/[1-6] gNB\(s\) recommended by the RAN in the registration area: .*attempt 1"
    else:
        scope = r"Paging sent to 6/6 gNB\(s\) serving the registration area: .*attempt 1"
    chain(r, "amf", amf, [scope, r"Service Request from CM-IDLE: .*\(page answered, T3513 stopped\)"])

    demo_scope = "recommended" if predictor else "registration-area"
    sent_rx = (r"\[demo:%s\] Paging sent to (\d+)/(\d+) ue=%s scope=%s targets=\[([^]]*)\] attempt 1$"
               % (KEY, SUPI, demo_scope))
    answered_rx = r"\[demo:%s\] page answered ue=%s via gNB 0x([0-9a-f]+) attempt (\d+)$" % (KEY, SUPI)
    if demo_on:
        chain(r, "amf-demo", amf, [
            r"\[demo:%s\] Paging strategy: recommended-first \(mode %s supersedes" % (KEY, re.escape(mode)),
            sent_rx,
            answered_rx,
        ])
    else:
        r.check("amf-demo", amf is not None and not any("[demo:" in l for l in amf),
                "off: no [demo: line in amfd")

    first = next((re.search(sent_rx, l) for l in amf or [] if re.search(sent_rx, l)), None)
    targets = gnb_ids(first.group(3)) if first else []
    nodes = None
    if predictor:
        log = load(d, f"{serving}.log") if serving in GNB_ID else None
        sid = GNB_ID.get(serving, 0)
        ok = chain(r, "serving", log, [
            r"\[demo:%s\] paging recommendation ue=[0-9]+ predictor=%s " % (KEY, re.escape(mode)),
            r"\[demo:%s\] UE Context Release Complete sent ue_id=[0-9]+ amf_ue_ngap_id=[0-9]+ "
            r"nodes=\[0x%x\(visited\)" % (KEY, sid),
        ])
        if ok:
            m = next(re.search(r"nodes=\[([^]]*)\]", l) for l in log
                     if "UE Context Release Complete sent ue_id=" in l)
            nodes = gnb_ids(m.group(1))
            r.check("serving", targets == nodes,
                    f"attempt 1 pages the recommended nodes in order: targets {targets} nodes {nodes}")

    for g in GNBS:
        log = load(d, f"{g}.log")
        if not log:
            r.check("gnbs", False, f"{g}: empty or missing capture")
            continue
        if demo_on:
            chain(r, "gnbs", log, [
                r"DEMO MODE ACTIVE: %s=%s" % (KEY, re.escape(mode)),
                r"\[demo:%s\] paging grid: this gNB 0x[0-9a-f]+ at \([-0-9]+, [-0-9]+, [-0-9]+\), "
                r"5 neighbour cell\(s\)" % KEY,
            ])
        else:
            r.check("gnbs", not any("DEMO MODE ACTIVE" in l or "[demo:" in l for l in log),
                    f"{g}: off, no demo line")
        if not predictor:
            r.check("gnbs", not any("paging recommendation" in l for l in log),
                    f"{g}: {mode} recommends nothing")

    prom = load(d, "amf.prom")
    reco, area = metric(prom, "recommended"), metric(prom, "registration-area")
    if not prom:
        r.check("metrics", False, "no amfd /metrics scrape")
    elif not demo_on:
        r.check("metrics", reco is None and area is None, "off: no amf_paging_attempts_total")
    elif predictor:
        r.check("metrics", (reco or 0) >= 1, f"recommended attempts {reco} >= 1")
    else:
        r.check("metrics", reco == 0 and (area or 0) >= 1,
                f"page-all: recommended attempts {reco} == 0, registration-area {area} >= 1")

    ping = load(d, "ping.txt") or []
    got = next((int(m.group(1)) for m in (re.search(r" (\d+) received", l) for l in ping) if m), 0)
    r.check("upf", got >= 1, f"{got} downlink ping(s) answered")

    # The measurement.
    pagings, answered, attempt = 0, None, None
    for l in amf or []:
        m = re.search(r"Paging sent to (\d+)/\d+ gNB\(s\) .*attempt \d+", l)
        if m and answered is None:
            pagings += int(m.group(1))
        m = re.search(answered_rx, l)
        if m and answered is None:
            answered, attempt = int(m.group(1), 16), int(m.group(2))
    line = (f"live mode={mode} variant={variant} serving={serving or 'none'}"
            f" recommended={nodes if nodes is not None else 'none'} attempt1_targets={targets or 'none'}"
            f" answered={'0x%x' % answered if answered is not None else 'unknown'}"
            f" first_attempt_hit={str(attempt == 1).lower() if attempt else 'unknown'} pagings={pagings}")
    print(line)
    with open(os.path.join(d, "result.txt"), "w") as f:
        f.write(line + "\n")
    if variant == "revert":
        print("revert arm: these checks are expected to FAIL at the amf step")
    print("VERDICT: " + ("PASS" if not r.fails else "FAIL (" + ", ".join(dict.fromkeys(r.fails)) + ")"))
    return 0 if not r.fails else 1


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    return analyze(*argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
