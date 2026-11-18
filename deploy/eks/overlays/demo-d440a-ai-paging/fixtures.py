#!/usr/bin/env python3
"""Write a synthetic scenario capture for one d440a-ai-paging arm, in the real
line formats of amfd, the gNBs and the UE (test-scenario.sh feeds it to
analyze.py).

    fixtures.py <dir> <mode> [mutation]

The capture: seed 1's UE is served by gnb-6 at the release; with a predictor
mode gnb-6 recommends [0x6(visited), 0x5]; amfd pages those two on attempt 1 and
the UE answers through gNB 0x6. A mutation breaks one thing (MUTATIONS).
"""
import os
import sys

SUPI = "imsi-999700000000001"
KEY = "d440a-ai-paging"
GNBS = ["gnb", "gnb-2", "gnb-3", "gnb-4", "gnb-5", "gnb-6"]
TS = "2026-11-18T10:00:%02d.%03dZ"
MUTATIONS = (
    "no-paged", "no-base-scope", "no-demo-sent", "no-demo-answer", "no-strategy",
    "no-recommendation", "wrong-visited", "targets-differ", "no-banner", "no-grid",
    "metric-zero", "no-ping", "empty-ue", "revert", "page-all-recommends", "off-demo-line",
    "page-all-metric", "wrong-mode-banner", "revert-still-recommended",
)


def stamp(lines):
    return [TS % (i // 10, (i % 10) * 100) + " " + l for i, l in enumerate(lines)]


def write(d, name, lines):
    with open(os.path.join(d, name), "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def capture(d, mode, mut=None):
    os.makedirs(d, exist_ok=True)
    predictor = mode in ("last-served", "ct", "lsq")
    on = mode != "off"
    revert = mut is not None and mut.startswith("revert")
    demo_amf = on and not revert
    reco = predictor and (not revert or mut == "revert-still-recommended") and mut != "no-base-scope"
    p = f"[demo:{KEY}] "

    ue = [
        "INFO nr_ue: PDU Session 1 is now ACTIVE (IPv4: Some([10, 45, 0, 2]))",
        "INFO nextgsim_ue::rls: Simulated motion started: sim_route, 25 waypoints",
        "INFO nextgsim_ue::rrc: RRC connection released by the network",
        "INFO nextgsim_ue::nas: CM state changed to: CM-IDLE",
        "INFO nextgsim_ue::rrc: Paged by cell 96 in RRC_IDLE",
        "INFO nextgsim_ue::nas: Sending Service Request (MobileTerminatedServices)",
        "INFO nextgsim_ue::nas: Service Accept received",
    ]
    if mut == "no-paged":
        ue = [l for l in ue if "Paged by cell" not in l]
    write(d, "ue.log", [] if mut == "empty-ue" else stamp(ue))

    amf = []
    if demo_amf:
        amf.append(f"WARN DEMO MODE ACTIVE: {KEY}={mode}")
        if mut != "no-strategy":
            amf.append(p + f"Paging strategy: recommended-first (mode {mode} supersedes "
                       "amf.paging.strategy: registration-area)")
    targets = [6, 5] if reco or mut == "targets-differ" else [1, 2, 3, 4, 5, 6]
    if mut == "targets-differ":
        targets = [5, 6]
    if reco:
        amf.append(f"INFO Paging sent to 2/2 gNB(s) recommended by the RAN in the registration area: "
                   "5G-S-TMSI=(1, 1, 0x00000001), attempt 1")
    else:
        amf.append("INFO Paging sent to 6/6 gNB(s) serving the registration area: "
                   "5G-S-TMSI=(1, 1, 0x00000001), attempt 1")
    scope = "recommended" if reco else "registration-area"
    if demo_amf and mut != "no-demo-sent":
        amf.append(p + f"Paging sent to {len(targets)}/{len(targets)} ue={SUPI} scope={scope} "
                   f"targets=[{','.join('gNB 0x%x' % t for t in targets)}] attempt 1")
    if demo_amf and mut != "no-demo-answer":
        amf.append(p + f"page answered ue={SUPI} via gNB 0x6 attempt 1")
    amf.append("INFO Service Request from CM-IDLE: UE 1 -> 2, Service Accept in Initial Context "
               "Setup with 1 PDU session(s) (page answered, T3513 stopped)")
    write(d, "amf.log", stamp(amf))

    for i, g in enumerate(GNBS):
        log = ["INFO Received NG Setup Response"]
        if on:
            banner_mode = "ct" if mut == "wrong-mode-banner" and mode != "ct" else (
                "lsq" if mut == "wrong-mode-banner" else mode)
            if mut != "no-banner":
                log.append(f"WARN DEMO MODE ACTIVE: {KEY}={banner_mode}")
            if mut != "no-grid":
                log.append(p + f"paging grid: this gNB 0x{i + 1:x} at (0, 0, 0), 5 neighbour cell(s): [..]")
        if g == "gnb-6" and (predictor or mut == "page-all-recommends"):
            if mut != "no-recommendation":
                log.append(p + f"paging recommendation ue=1 predictor={mode} predicted=gNB 0x5 cell 0x50 "
                           "at (120, 120) samples=12")
            visited = 0x5 if mut == "wrong-visited" else 0x6
            log.append(p + f"UE Context Release Complete sent ue_id=1 amf_ue_ngap_id=1 "
                       f"nodes=[0x{visited:x}(visited),0x5] cells=[0x60(visited, 14 s),0x50]")
        if mode == "off" and mut == "off-demo-line" and g == "gnb-3":
            log.append(p + "paging grid: this gNB 0x3 at (0, 0, 0), 5 neighbour cell(s): [..]")
        write(d, f"{g}.log", stamp(log))
    write(d, "serving.txt", ["gnb-6"])
    write(d, "release-offset.txt", ["15.2"])

    prom = []
    if demo_amf:
        r = 0 if mut == "metric-zero" or not reco else 1
        if mut == "page-all-metric":
            r = 1
        prom = ["# TYPE amf_paging_attempts_total counter",
                f'amf_paging_attempts_total{{scope="recommended"}} {r}',
                'amf_paging_attempts_total{scope="registration-area"} %d' % (0 if reco else 1)]
    prom.append("nextgcore_sbi_request_total 3")
    write(d, "amf.prom", prom)
    got = 0 if mut == "no-ping" else 38
    write(d, "ping.txt", [f"40 packets transmitted, {got} received, {100 - got * 100 // 40}% packet loss"])


if __name__ == "__main__":
    capture(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
