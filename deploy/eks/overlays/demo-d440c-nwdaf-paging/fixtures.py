#!/usr/bin/env python3
"""Fixture captures for test-scenario.sh (demo d440c-nwdaf-paging, nextgsim#464).

    fixtures.py <dir> <arm> [drop-regex] [replace-from replace-to]

Writes the files scenario.sh captures (amf.log, smf.log, nwdaf.log, gnb-a.log,
gnb-b.log, gnb-c.log, ue.log, ping.txt, ue-mobility.http, amf.prom and, for
nwdaf-down, nwdaf-down.txt) for one arm: off, registration-area,
nwdaf-mobility, nwdaf-down or revert. A drop-regex removes every matching line
from every file (a negative control); a replace pair rewrites text in every
file.

What the fixtures copy from real runs, so a check that passes here can pass
on EKS:
  * the line formats: the kubelet RFC 3339 nanosecond stamp, amfd's and
    nwdafd's env_logger prefix and the nextgsim tracing prefix with its ANSI
    colours, as captured by demo-check.sh on devtest1 (d441c-amf-mobility run
    20261111T175711Z); the message texts are the format strings in the code;
  * what the run really holds besides the chain: the deploy's first UE (its
    registration, a handover and two ingests before the restart, with the
    session address the restarted UE then reuses), the UE re-selecting its own
    cell right after the release, gNB A's demo line on the same PAGING, the
    Decoded/Initial UE Message pair, and pcfd's periodic NF_LOAD queries,
    which nwdafd logs as `Analytics Info Query: /nnwdaf-analyticsinfo/v1/analytics`
    with no query string;
  * the timing of the committed route (sim-lap.yaml): motion at 60.3 s, nine
    handovers, the release at the dwell's far point, the idle reselection near
    x 52, the route end at 276 s, then the downlink.
"""
import json
import re
import sys
from datetime import datetime, timedelta

T0 = datetime(2026, 11, 13, 10, 0, 0)
SUPI = "imsi-999700000000001"
KEY = "d440c-nwdaf-paging"


def stamp(t):
    return (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"


def core(t, module, msg, level="INFO "):
    s = (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    return "%s [%sZ %s nextgcore_%s] %s" % (stamp(t), s, level, module, msg)


def sim(t, module, msg):
    s = (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return "%s \x1b[2m%sZ\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2m%s\x1b[0m\x1b[2m:\x1b[0m %s" % (
        stamp(t), s, module, msg)


def build(arm):
    # Negative controls, "<arm>+<extra>":
    #   paged-c      gNB C also gets the attempt-1 PAGING
    #   unpaged-c    gNB C logs no PAGING although amfd paged it
    #   late-b       gNB B logs the assistance after the answer
    #   late-resel   the idle reselection is stamped after the page
    #   attempt2     attempt 1 goes unanswered; attempt 2 (whole area) is answered
    #   queried      amfd asks nwdafd and logs a prediction (and a hint series)
    #   nwdaf-on     the revert arm's nwdafd still logs `ue-mobility: on`
    #   timeout      the revert arm's amfd logs a timeout instead of a 204
    arm, _, extra = arm.partition("+")
    demo = arm != "off"
    mode = {"off": None, "registration-area": "registration-area"}.get(arm, "nwdaf-mobility")
    f = {k: [] for k in ("amf", "smf", "nwdaf", "gnb-a", "gnb-b", "gnb-c", "ue")}
    amf = lambda t, m: f["amf"].append(core(t, "amfd::ngap_path", m))
    amfn = lambda t, m: f["amf"].append(core(t, "amfd::nwdaf_mobility", m))
    amfd = lambda t, m: f["amf"].append(core(t, "amfd::ngap_path", "[demo:%s] %s" % (KEY, m)))
    nwdaf = lambda t, m: f["nwdaf"].append(core(t, "nwdafd::amf_mobility", m))
    gnb = lambda g, t, m: f[g].append(sim(t, "nextgsim_gnb::ngap::task", m))
    ue = lambda t, mod, m: f["ue"].append(sim(t, mod, m))

    if mode:
        f["amf"].append(core(-300, "demo", "DEMO MODE ACTIVE: %s=%s" % (KEY, mode), "WARN "))
    for g in ("gnb-a", "gnb-b", "gnb-c"):
        if demo:
            f[g].append(sim(-290, "nextgsim_demo", "DEMO MODE ACTIVE: %s=%s" % (KEY, mode)))
        gnb(g, -289, "Received NG Setup Response from AMF 0: name=nextgcore-amf0")
    if arm == "revert":
        nwdaf(-20, "NWDAF registered with NRF successfully (id=8c2f0b7e-0000-4000-8000-00000000da01)")
        if extra == "nwdaf-on":
            nwdaf(-19, "ue-mobility: on (subscribing to AMF LOCATION_REPORT; UE_MOBILITY served)")
    else:
        nwdaf(-280, "ue-mobility: on (subscribing to AMF LOCATION_REPORT; UE_MOBILITY served)")
        nwdaf(-250, "subscribed to AMF LOCATION_REPORT id=sub-0b6e1d2a-1111-4c2e-9e3a-5f0d2c7e9a10")
    # pcfd's intent loop polls NF_LOAD every 10 s: the same log line as any query.
    for t in range(-300, 320, 10):
        f["nwdaf"].append(core(t, "nwdafd::sbi_handler", "Analytics Info Query: /nnwdaf-analyticsinfo/v1/analytics"))

    # The deploy's first UE (before the restart), its route parked: it registers
    # on A and stays there. When nwdafd ingests that registration (as here), its
    # history starts A, A (the restarted UE's registration): one A -> A beside
    # the laps' three A -> B, so the prediction is B at 75%. Without that ingest
    # every transition out of A is A -> B and it is B at 100%; analyze.py checks
    # the predicted cell, not the confidence.
    amf(-200, "Decoded Initial UE Message: ran_ue_ngap_id=1, nas_pdu_len=23, nci=0x10, tac=1, cause=3")
    amf(-200, "Initial UE Message: ran_ue_ngap_id=1, nas_pdu_len=23, tac=1, nci=0x10")
    if arm != "revert":
        nwdaf(-200, "ue-mobility ingest supi=%s cell=99970-000000010 tac=0001" % SUPI)

    # The restarted UE: t = 0 is its first line.
    # Cell ids are the UE's RLS discovery order, not the NCI: here B is 0.
    f["ue"].append(stamp(0.0) + " nextgsim UE - 5G User Equipment Simulator")
    f["ue"].append(stamp(0.0) + " ==========================================")
    ue(0.0, "nr_ue", "Loading configuration from: /etc/nextgsim/ue.yaml")
    ue(0.001, "nextgsim_ue::app::task", "CM state changed to: CM-IDLE")
    ue(1.0, "nextgsim_ue::rls::task", "Cell discovered: cell_id=0, dbm=-71")
    ue(1.0, "nextgsim_ue::rls::task", "Cell discovered: cell_id=1, dbm=-35")
    ue(1.0, "nextgsim_ue::rls::task", "Cell discovered: cell_id=2, dbm=-74")
    ue(2.0, "nextgsim_ue::rrc::task", "Cell selection complete: cell_id=1, plmn=999-70, tac=1, category=SuitableCell")
    amf(2.1, "Decoded Initial UE Message: ran_ue_ngap_id=2, nas_pdu_len=23, nci=0x10, tac=1, cause=3")
    amf(2.1, "Initial UE Message: ran_ue_ngap_id=2, nas_pdu_len=23, tac=1, nci=0x10")
    ue(2.4, "nextgsim_ue::app::task", "CM state changed to: CM-CONNECTED")
    if arm != "revert":
        nwdaf(2.5, "ue-mobility ingest supi=%s cell=99970-000000010 tac=0001" % SUPI)
    ue(3.2, "nr_ue", "PDU Session 1 is now ACTIVE (IPv4: Some([10, 45, 0, 2]))")
    ue(60.3, "nextgsim_ue::rls::task", "Simulated motion started: sim_route from (30, 17, 0) at 60.3 s after start-up")
    cells = {"A": "000000010", "B": "000000020", "C": "000000030"}
    for i, (t, c) in enumerate(zip((72.1, 89.0, 106.2, 124.0, 140.1, 155.2, 172.0, 188.1, 204.3), "BCABCABCA")):
        amf(t, "HandoverNotify from association %d (amf_ue_ngap_id=2, ran_ue_ngap_id=%d)" % ("ABC".index(c) + 1, i + 2))
        if arm != "revert":
            nwdaf(t + 0.002, "ue-mobility ingest supi=%s cell=99970-%s tac=0001" % (SUPI, cells[c]))
    # The release at the dwell's far point (60.3 + 172.8 s).
    ue(233.2, "nextgsim_ue::rrc::task", "Received RRC Release from cell 1")
    ue(233.2, "nextgsim_ue::app::task", "CM state changed to: CM-IDLE")
    ue(235.7, "nextgsim_ue::rrc::cell_selection", "Cell reselection: id=1, plmn=999-70, tac=1, category=SuitableCell")
    ue(281.0 if extra == "late-resel" else 262.4, "nextgsim_ue::rrc::cell_selection",
       "Cell reselection: id=0, plmn=999-70, tac=1, category=SuitableCell")

    # The downlink at 280 s.
    f["smf"].append(core(-310, "smfd", "NextGCore SMF v0.1.0 starting..."))
    f["smf"].append(core(280.10, "smfd", "PFCP Session Report Request: SEID=0x0000000000000002, seq=7, peer=10.0.4.17:8805"))
    f["smf"].append(core(280.11, "smfd", "PFCP Session Report Response sent: SEID=0x0000000000000002, seq=7, peer=10.0.4.17:8805"))
    third = {"registration-area": "registration-area", "off": None}.get(arm, "nwdaf")
    if arm == "nwdaf-mobility" or extra == "queried":
        amfn(280.13, "NWDAF UE mobility: ue=%s predicted=(999-70, 0x000000020) confidence=75%%" % SUPI)
    if arm == "revert" and extra == "timeout":
        amfn(280.42, "NWDAF UE mobility: ue=%s no answer within 300 ms; paging the registration area" % SUPI)
    if arm == "nwdaf-mobility":
        # send_paging maps each cell to the gNB that owns it (ngap_path.rs
        # cell_owner_associations), the predicted cell first.
        amf(280.19, "NWDAF UE mobility: predicted cell 0x000000020 is served by gNB 0x2 (association 2)")
        amf(280.19, "NWDAF UE mobility: last known cell 0x000000010 is served by gNB 0x1 (association 1)")
        targets, base = ["gnb-b", "gnb-a"], "predicted by NWDAF UE mobility in the registration area"
    elif arm == "nwdaf-down":
        amfn(280.12, "NWDAF UE mobility: ue=%s no prediction (no NWDAF (NRF discovery found none, "
                     "NWDAF_SBI_ADDR unset)); paging the registration area" % SUPI)
        targets, base = ["gnb-a", "gnb-b", "gnb-c"], "serving the registration area"
    else:
        targets, base = ["gnb-a", "gnb-b", "gnb-c"], "serving the registration area"
    amf(280.20, "Paging sent to %d/%d gNB(s) %s: 5G-S-TMSI=(1, 0, 0xc0000002), attempt 1"
        % (len(targets), len(targets), base))
    gid = {"gnb-a": "0x1", "gnb-b": "0x2", "gnb-c": "0x3"}
    if demo:
        scope = "nwdaf-mobility" if arm == "nwdaf-mobility" else "registration-area"
        amfd(280.20, "Paging sent to %d/%d ue=%s scope=%s targets=[%s] attempt 1" % (
            len(targets), len(targets), SUPI, scope, ",".join("gNB " + gid[g] for g in targets)))
    paged = targets + (["gnb-c"] if extra == "paged-c" else [])
    if extra == "unpaged-c":
        paged = [g for g in paged if g != "gnb-c"]
    for g in paged:
        # The gNB's receipt can be stamped before amfd's `Paging sent`, which
        # amfd logs after its send loop.
        gnb(g, 280.199, "PAGING from AMF[0]: matched 1 served TAI(s); triggering RRC Paging")
        if third == "nwdaf":
            cellsl = "0x10,0x20" if arm == "nwdaf-mobility" else ""
            nxt = "changed" if arm == "nwdaf-mobility" else "same"
            late = extra == "late-b" and g == "gnb-b"
            gnb(g, 280.5 if late else 280.199, "[demo:%s] PAGING assistance: cells=[%s] attempt 1/5 next-scope=%s" % (KEY, cellsl, nxt))
    t_ans = 0.0
    if extra == "attempt2":
        # T3513 (5 s) expires unanswered; attempt 2 pages the whole area.
        t_ans = 5.0
        all3 = ["gnb-a", "gnb-b", "gnb-c"]
        amf(285.20, "Paging sent to 3/3 gNB(s) serving the registration area: 5G-S-TMSI=(1, 0, 0xc0000002), attempt 2")
        if demo:
            amfd(285.20, "Paging sent to 3/3 ue=%s scope=registration-area targets=[gNB 0x1,gNB 0x2,gNB 0x3] attempt 2" % SUPI)
        for g in all3:
            gnb(g, 285.199, "PAGING from AMF[0]: matched 1 served TAI(s); triggering RRC Paging")
    ue(280.25 + t_ans, "nextgsim_ue::rrc::task", "Paged by cell 0 in RRC_IDLE: 5G-S-TMSI [01, 00, c0, 00, 00, 02]")
    ue(280.26 + t_ans, "nextgsim_ue::nas::mm::orchestrator", "Sending Service Request (MobileTerminatedServices), T3517 started")
    gnb("gnb-b", 280.30 + t_ans, "Sending Initial UE Message: ue_id=0, ran_ue_ngap_id=1, amf_id=0, stream=1, len=44")
    amf(280.31 + t_ans, "Decoded Initial UE Message: ran_ue_ngap_id=1, nas_pdu_len=21, nci=0x20, tac=1, cause=4")
    amf(280.31 + t_ans, "Initial UE Message: ran_ue_ngap_id=1, nas_pdu_len=21, tac=1, nci=0x20")
    amf(280.33 + t_ans, "Service Request from CM-IDLE: UE 2 -> 3, Service Accept in Initial Context Setup with 1 "
                "PDU session(s) (page answered, T3513 stopped)")
    if demo:
        amfd(280.33 + t_ans, "page answered ue=%s via gNB 0x2 attempt %d" % (SUPI, 2 if t_ans else 1))
    ue(280.40 + t_ans, "nextgsim_ue::nas::mm::orchestrator", "Service Accept received")
    files = {"%s.log" % k: "\n".join(v) + "\n" for k, v in f.items()}
    files["ping.txt"] = ("PING 10.45.0.2 (10.45.0.2) 56(84) bytes of data.\n"
                         "--- 10.45.0.2 ping statistics ---\n"
                         "20 packets transmitted, 20 received, 0% packet loss, time 9512ms\n"
                         "rtt min/avg/max/mdev = 0.412/31.205/598.511/129.640 ms\n")
    if arm == "revert":
        files["ue-mobility.http"] = "204\n"
    else:
        body = {"ueMobs": [{"ts": stamp(2.5)[:19] + "+00:00", "duration": 202, "locInfos": [
            {"loc": {"nrLocation": {"ncgi": {"plmnId": {"mcc": "999", "mnc": "70"}, "nrCellId": "000000020"},
                                    "tai": {"plmnId": {"mcc": "999", "mnc": "70"}, "tac": "0001"}}},
             "confidence": 75}]}]}
        files["ue-mobility.http"] = "200\n" + json.dumps(body) + "\n"
    prom = ['nextgcore_build_info{nf="amf"} 1']
    if mode:
        prom.append('nextg_demo_enabled{demo="%s",mode="%s"} 1' % (KEY, mode))
    if mode == "nwdaf-mobility" or extra == "queried":
        n = {"predicted": int(arm == "nwdaf-mobility" or extra == "queried"), "no_prediction": int(arm == "revert" and extra != "timeout"),
             "error": int(arm == "nwdaf-down"), "timeout": int(extra == "timeout"), "late": 0, "cap_full": 0}
        prom.append("# TYPE amf_paging_nwdaf_hints_total counter")
        prom += ['amf_paging_nwdaf_hints_total{outcome="%s"} %d' % kv for kv in sorted(n.items())]
    files["amf.prom"] = "\n".join(prom) + "\n"
    if arm == "nwdaf-down":
        files["nwdaf-down.txt"] = "nwdaf pods before the downlink: 0\n"
    return files


def main(argv):
    d, arm = argv[1], argv[2]
    drop = re.compile(argv[3]) if len(argv) > 3 and argv[3] else None
    rep = (argv[4], argv[5]) if len(argv) > 5 else None
    for name, text in build(arm).items():
        lines = text.splitlines(True)
        if drop:
            lines = [l for l in lines if not drop.search(l)]
        text = "".join(lines)
        if rep:
            text = text.replace(rep[0], rep[1])
        open("%s/%s" % (d, name), "w").write(text)


if __name__ == "__main__":
    main(sys.argv)
