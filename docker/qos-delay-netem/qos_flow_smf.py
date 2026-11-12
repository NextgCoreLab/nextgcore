#!/usr/bin/env python3
"""#1389 part 3 netem leg: a stand-in SMF for per QoS flow QoS monitoring (QFQM).

It sets up a PFCP association with a running nextgcore-upfd and establishes one
PFCP session (TS 29.244 Table 7.5.2.1-1):
- an uplink PDR on the explicit F-TEID 0x1001 @ <upf-n3-ip>, and a downlink PDR
  for the UE IP 10.46.0.2, both with QER 1 (QFI 9);
- a downlink FAR toward the far end (TEID 0x2002 @ <peer-ip>);
- a Create SRR (Table 7.5.2.9-1) with one QoS Monitoring per QoS flow Control
  Information (IE 242) for QFI 9: DL, UL and round-trip packet delay, Periodic,
  Measurement Period 2 s.
It then answers every Session Report Request and collects the QoS Monitoring
Reports (IE 247 in the Session Report IE 214), checking each reported delay
against the expected one.

Usage: qos_flow_smf.py <upf-pfcp-ip:port> <upf-n3-ip> <peer-ip>
                       <expect DL,UL,RTT ms | off> <tol-ms> <secs>
Exit status 0 when every check holds.
"""
import socket, struct, sys, time

host, port = sys.argv[1].rsplit(":", 1)
UPF = (host, int(port))
N3 = socket.inet_aton(sys.argv[2])
PEER = socket.inet_aton(sys.argv[3])
EXPECT = None if sys.argv[4] == "off" else [int(x) for x in sys.argv[4].split(",")]
TOL = int(sys.argv[5])
SECS = float(sys.argv[6])
UE = socket.inet_aton("10.46.0.2")
SMF_SEID = 0x5EED


def ie(t, v):
    return struct.pack("!HH", t, len(v)) + v


def ies(b):
    out, i = [], 0
    while i + 4 <= len(b):
        t, l = struct.unpack("!HH", b[i:i + 4])
        out.append((t, b[i + 4:i + 4 + l]))
        i += 4 + l
    return out


def u32(v):
    return struct.pack("!I", v)


node = ie(60, b"\x00" + socket.inet_aton("127.0.0.1"))
smf = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
smf.bind(("127.0.0.1", 0))
smf.settimeout(1)


def node_msg(mtype, seq, body):
    return struct.pack("!BBH", 0x20, mtype, len(body) + 4) + struct.pack("!I", seq << 8) + body


def sess_msg(mtype, seid, seq, body):
    return (struct.pack("!BBH", 0x21, mtype, len(body) + 12) + struct.pack("!Q", seid)
            + struct.pack("!I", seq << 8) + body)


body = node + ie(96, u32(int(time.time()) + 2208988800 & 0xffffffff))
smf.sendto(node_msg(5, 1, body), UPF)
resp, _ = smf.recvfrom(4096)
r = dict(ies(resp[8:]))
feat = r.get(43, b"")
qfqm = len(feat) > 4 and bool(feat[4] & 0x02)
print(f"Association Setup Response: cause {r[19][0]}, UP Function Features {feat.hex()} "
      f"({len(feat)} octets), QFQM {qfqm}", flush=True)

qer = ie(109, u32(1))
ul_pdi = ie(20, b"\x00") + ie(21, b"\x01" + u32(0x1001) + N3) + ie(93, b"\x02" + UE)
dl_pdi = ie(20, b"\x01") + ie(93, b"\x06" + UE)  # V4 + S/D (destination)
pdr_ul = ie(1, ie(56, b"\x00\x01") + ie(29, u32(100)) + ie(2, ul_pdi) + ie(95, b"\x00")
            + ie(108, u32(1)) + qer)
pdr_dl = ie(1, ie(56, b"\x00\x02") + ie(29, u32(100)) + ie(2, dl_pdi) + ie(108, u32(2)) + qer)
far_ul = ie(3, ie(108, u32(1)) + ie(44, b"\x02\x00") + ie(4, ie(42, b"\x01")))
far_dl = ie(3, ie(108, u32(2)) + ie(44, b"\x02\x00")
            + ie(4, ie(42, b"\x00") + ie(84, b"\x01\x00" + u32(0x2002) + PEER)))
qer_ie = ie(7, ie(109, u32(1)) + ie(25, b"\x00") + ie(124, b"\x09"))
# IE 242: QFI 9; Requested QoS Monitoring DLPD|ULPD|RPPD; Reporting Frequency
# PERIO; Measurement Period 2 s.
ctl = ie(242, ie(124, b"\x09") + ie(243, b"\x07") + ie(244, b"\x02") + ie(64, u32(2)))
srr = ie(212, ie(215, b"\x01") + ctl)
fseid = ie(57, b"\x02" + struct.pack("!Q", SMF_SEID) + socket.inet_aton("127.0.0.1"))
est = node + fseid + pdr_ul + pdr_dl + far_ul + far_dl + qer_ie + srr
smf.sendto(sess_msg(50, 0, 2, est), UPF)
resp, _ = smf.recvfrom(4096)
r = dict(ies(resp[16:]))
upf_seid = struct.unpack("!Q", r[57][1:9])[0] if 57 in r else 0
print(f"Session Establishment Response: cause {r[19][0]}, UPF SEID {upf_seid:#x}", flush=True)

got = []
end = time.time() + SECS
while time.time() < end:
    try:
        m, a = smf.recvfrom(8192)
    except socket.timeout:
        continue
    if m[1] != 56:
        continue
    seq = m[12:15]
    for t, v in ies(m[16:]):
        if t == 39:
            print(f"  Session Report Request: Report Type {v[0]:#04x}", flush=True)
        if t != 214:
            continue
        d = ies(v)
        srr_id = dict(d)[215][0]
        for mt, mv in d:
            if mt != 247:
                continue
            rep = dict(ies(mv))
            meas = rep[248]
            flags, at, vals = meas[0], 1, {}
            for bit, name in ((1, "DL"), (2, "UL"), (4, "RTT")):
                if flags & bit:
                    vals[name] = struct.unpack("!I", meas[at:at + 4])[0]
                    at += 4
            plmf = bool(flags & 0x08)
            print(f"  QoS Monitoring Report: SRR {srr_id} QFI {rep[124][0]} "
                  f"{'FAILURE (PLMF)' if plmf else vals}", flush=True)
            got.append(None if plmf else vals)
    rsp = ie(19, b"\x01")
    smf.sendto(struct.pack("!BBH", 0x21, 57, len(rsp) + 12) + struct.pack("!Q", upf_seid)
               + seq + b"\x00" + rsp, a)

ok = True
if EXPECT is None:
    ok = not qfqm and not got
    print(f"OFF arm: QFQM advertised {qfqm}, reports {len(got)}: {'PASS' if ok else 'FAIL'}")
else:
    # The first period may start before the far end answered: a measurement
    # failure there is not a delay error. Every measured report must be in range,
    # and there must be measured reports.
    measured = [g for g in got if g is not None]
    ok = qfqm and len(measured) >= 2
    for name, want in zip(("DL", "UL", "RTT"), EXPECT):
        xs = [g[name] for g in measured]
        good = bool(xs) and all(want <= x <= want + TOL for x in xs)
        ok &= good
        print(f"{name}: expected {want} ms, reported {xs}, tolerance [{want}, {want + TOL}] ms: "
              f"{'PASS' if good else 'FAIL'}")
    fails = sum(1 for g in got if g is None)
    ok &= fails <= 1
    print(f"measurement failures {fails} (at most the first period): {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
