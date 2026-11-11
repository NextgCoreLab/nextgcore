#!/usr/bin/env python3
"""#1389 netem leg: a stand-in SMF. It sets up a PFCP association with a running
nextgcore-upfd and provisions:
- GTP-U Path QoS Control Information (IE 238, TS 29.244 Table 7.4.4.1.3-1) for
  the explicit peer, IRE + PER every 2 s;
- N6 Delay Measurement Control Information (IE 355, Table 7.4.4.1.4-1) for the
  endpoint, STAMP, IRE + PER every 2 s.
It then answers every Node Report Request, collects the reported average delays
(GTP-U Path QoS Report IE 239, N6 Delay Measurement Report IE 356), and checks
them against the expected one-way delay.

Usage: qos_delay_smf.py <upf-pfcp-ip:port> <peer-ip> <expect-ms|off> <tol-ms> <secs>
Exit status 0 when every check holds.
"""
import socket, struct, sys, time

host, port = sys.argv[1].rsplit(":", 1)
UPF = (host, int(port))
PEER = sys.argv[2]
EXPECT = None if sys.argv[3] == "off" else int(sys.argv[3])
TOL = int(sys.argv[4])
SECS = float(sys.argv[5])


def ie(t, v):
    return struct.pack("!HH", t, len(v)) + v


def ies(b):
    out, i = [], 0
    while i + 4 <= len(b):
        t, l = struct.unpack("!HH", b[i:i + 4])
        out.append((t, b[i + 4:i + 4 + l]))
        i += 4 + l
    return out


peer4 = socket.inet_aton(PEER)
gpqm = ie(238, ie(103, b"\x02" + peer4) + ie(237, b"\x05") + ie(64, struct.pack("!I", 2)))
n6 = ie(355, ie(377, b"\x00\x01") + ie(358, b"\x01" + peer4) + ie(22, b"\x08internet")
        + ie(354, b"\x04") + ie(375, b"\x05") + ie(64, struct.pack("!I", 2)))
node = ie(60, b"\x00" + socket.inet_aton("127.0.0.1"))
body = node + ie(96, struct.pack("!I", int(time.time()) + 2208988800 & 0xffffffff)) + gpqm + n6
smf = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
smf.bind(("127.0.0.1", 0))
smf.settimeout(1)
smf.sendto(struct.pack("!BBH", 0x20, 5, len(body) + 4) + struct.pack("!I", 1 << 8) + body, UPF)
resp, _ = smf.recvfrom(4096)
r = dict(ies(resp[8:]))
feat = r.get(43, b"")
print(f"Association Setup Response: cause {r[19][0]}, UP Function Features {feat.hex()} "
      f"({len(feat)} octets), IE 354 {r.get(354, b'').hex() or 'absent'}", flush=True)

gpqm_ms, n6_ms = [], []
end = time.time() + SECS
while time.time() < end:
    try:
        m, a = smf.recvfrom(8192)
    except socket.timeout:
        continue
    if m[1] != 12:
        continue
    for t, v in ies(m[8:]):
        d = dict(ies(v))
        if t == 239 and 240 in d:
            avg = struct.unpack("!I", dict(ies(d[240]))[234])[0]
            gpqm_ms.append(avg)
            print(f"  GTP-U path QoS report (GPQR): trigger {d[237][0]:#04x} avg {avg} ms", flush=True)
        if t == 356:
            if 357 in d:
                avg = struct.unpack("!I", d[357][1:5])[0]
                n6_ms.append(avg)
                print(f"  N6 delay report (N6DR): type {d[375][0]:#04x} avg {avg} ms", flush=True)
            else:
                print(f"  N6 delay FAILURE cause {d[376][0]}", flush=True)
    rsp = node + ie(19, b"\x01")
    smf.sendto(struct.pack("!BBH", 0x20, 13, len(rsp) + 4) + m[4:7] + b"\x00" + rsp, a)

ok = True
if EXPECT is None:
    # Demo-off arm: nothing advertised, nothing measured.
    ok &= len(feat) == 8 and feat[4] & 0x04 == 0 and 354 not in r
    ok &= not gpqm_ms and not n6_ms
    print(f"OFF arm: features {len(feat)} octets, GPQM bit {bool(feat[4] & 4)}, IE 354 "
          f"{354 in r}, reports {len(gpqm_ms)}+{len(n6_ms)}: {'PASS' if ok else 'FAIL'}")
else:
    for name, xs in (("GTP-U path (GPQM)", gpqm_ms), ("N6 (UN6DM)", n6_ms)):
        good = bool(xs) and all(EXPECT <= x <= EXPECT + TOL for x in xs)
        ok &= good
        print(f"{name}: injected one-way {EXPECT} ms, reported {xs}, tolerance "
              f"[{EXPECT}, {EXPECT + TOL}] ms: {'PASS' if good else 'FAIL'}")
sys.exit(0 if ok else 1)
