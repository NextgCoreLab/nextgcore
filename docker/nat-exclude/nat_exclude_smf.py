#!/usr/bin/env python3
"""#1455 harness: a stand-in SMF and gNB for nextgcore-upfd.

  nat_exclude_smf.py establish <upf-pfcp-ip:port> <n3-ip> <teid> <ue-ip>
      PFCP Association Setup, then a Session Establishment with one uplink PDR
      (Access, F-TEID <n3-ip>/<teid>, UE IP <ue-ip>, outer header removal) and its
      FAR (FORW to Core). Prints "UPF SEID 0x<seid>" and stays bound to answer
      nothing more (exits once the session is up).

  nat_exclude_smf.py send <n3-ip> <teid> <ue-ip> <dn-ip> <count> [<ue-port>]
      Sends <count> G-PDUs to <n3-ip>:2152, each carrying one inner IPv4/UDP
      datagram <ue-ip>:<ue-port, default 40000> -> <dn-ip>:9999 with a 100-byte
      payload (128 inner IP bytes). A new port is a new flow (conntrack). Prints
      the inner byte total.

  nat_exclude_smf.py dn <listen-ip> <count> <secs>
      A DN server: prints "src=<ip> len=<n>" per datagram received on <ip>:9999,
      for up to <count> datagrams or <secs> seconds.
"""
import socket, struct, sys, time


def ie(t, v):
    return struct.pack("!HH", t, len(v)) + v


def ies(b):
    out, i = {}, 0
    while i + 4 <= len(b):
        t, l = struct.unpack("!HH", b[i:i + 4])
        out[t] = b[i + 4:i + 4 + l]
        i += 4 + l
    return out


def establish(upf, n3, teid, ue):
    host, port = upf.rsplit(":", 1)
    upf = (host, int(port))
    smf = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    smf.bind(("127.0.0.1", 0))
    smf.settimeout(2)
    node = ie(60, b"\x00" + socket.inet_aton("127.0.0.1"))
    rts = ie(96, struct.pack("!I", int(time.time()) + 2208988800 & 0xffffffff))
    body = node + rts
    smf.sendto(struct.pack("!BBH", 0x20, 5, len(body) + 4) + struct.pack("!I", 1 << 8) + body, upf)
    resp, _ = smf.recvfrom(4096)
    cause = ies(resp[8:]).get(19, b"\x00")[0]
    print(f"Association Setup Response cause {cause}", flush=True)
    if cause != 1:
        sys.exit(1)

    pdi = ie(20, b"\x00") + ie(21, b"\x01" + struct.pack("!I", teid) + socket.inet_aton(n3)) \
        + ie(93, b"\x02" + socket.inet_aton(ue))
    pdr = ie(1, ie(56, struct.pack("!H", 1)) + ie(29, struct.pack("!I", 100)) + ie(2, pdi)
             + ie(95, b"\x00") + ie(108, struct.pack("!I", 1)))
    far = ie(3, ie(108, struct.pack("!I", 1)) + ie(44, b"\x02\x00") + ie(4, ie(42, b"\x01")))
    fseid = ie(57, b"\x02" + struct.pack("!Q", 0x1455) + socket.inet_aton("127.0.0.1"))
    body = node + fseid + pdr + far
    hdr = struct.pack("!BBH", 0x21, 50, len(body) + 12) + struct.pack("!Q", 0) + struct.pack("!I", 2 << 8)
    smf.sendto(hdr + body, upf)
    resp, _ = smf.recvfrom(4096)
    r = ies(resp[16:])
    cause = r.get(19, b"\x00")[0]
    up_fseid = r.get(57, b"")
    print(f"Session Establishment Response cause {cause}", flush=True)
    if cause != 1 or len(up_fseid) < 9:
        sys.exit(1)
    print(f"UPF SEID 0x{struct.unpack('!Q', up_fseid[1:9])[0]:x}", flush=True)


def checksum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def send(n3, teid, ue, dn, count, sport):
    payload = b"N" * 100
    udp = struct.pack("!HHHH", sport, 9999, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0,
                     socket.inet_aton(ue), socket.inet_aton(dn))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    inner = ip + udp
    gpdu = struct.pack("!BBHI", 0x30, 0xff, len(inner), teid) + inner
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(count):
        s.sendto(gpdu, (n3, 2152))
        time.sleep(0.02)
    print(f"sent {count} G-PDUs, {count * total} inner bytes", flush=True)


def dn(listen, count, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((listen, 9999))
    s.settimeout(0.5)
    end, got = time.time() + secs, 0
    while got < count and time.time() < end:
        try:
            data, (src, _) = s.recvfrom(4096)
        except socket.timeout:
            continue
        got += 1
        print(f"src={src} len={len(data)}", flush=True)


cmd = sys.argv[1]
if cmd == "establish":
    establish(sys.argv[2], sys.argv[3], int(sys.argv[4], 0), sys.argv[5])
elif cmd == "send":
    send(sys.argv[2], int(sys.argv[3], 0), sys.argv[4], sys.argv[5], int(sys.argv[6]),
         int(sys.argv[7]) if len(sys.argv) > 7 else 40000)
elif cmd == "dn":
    dn(sys.argv[2], int(sys.argv[3]), float(sys.argv[4]))
else:
    sys.exit(f"unknown command {cmd}")
