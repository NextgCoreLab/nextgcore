#!/usr/bin/env python3
"""#1389 netem leg: the far end of the measured paths, run inside the network
namespace whose link carries the injected netem delay.

- STAMP Session-Reflector, stateless, unauthenticated (IETF RFC 8762 §4.3.1),
  on UDP <addr>:862, with T2/T3 stamped, so upfd subtracts the turnaround.
- GTP-U Echo responder (TS 29.281 §7.2.2) on UDP <addr>:2152: answers an Echo
  Request with an Echo Response carrying the same sequence number and a
  Recovery IE.
- #1389 part 3: a stand-in NG-RAN for per QoS flow QoS monitoring, on the same
  GTP-U socket. A downlink G-PDU on TEID 0x2002 whose PDU Session Container has
  QMP set (TS 38.415 §5.5.2.1) is answered at once with a dummy uplink G-PDU (no
  T-PDU, TS 29.281 §5.2.2.7) on TEID 0x1001 carrying QMP, T1 repeated, T2 (DL
  received), T3 (UL sent) and the stated RAN DL/UL Delay Results (§5.5.2.2),
  the way nextgsim's gNB does with `qos_monitoring.ran_*_delay_ms` set. The RAN
  delays are configured values, not measurements.
Usage: qos_delay_responder.py <addr> [<ran-dl-ms> <ran-ul-ms>]
"""
import selectors, socket, struct, sys, time

ADDR = sys.argv[1]
RAN_DL = int(sys.argv[2]) if len(sys.argv) > 3 else 0
RAN_UL = int(sys.argv[3]) if len(sys.argv) > 3 else 0
DL_TEID, UL_TEID = 0x2002, 0x1001
NTP_OFFSET = 2208988800


def ntp64():
    t = time.time() + NTP_OFFSET
    return (int(t) << 32) | int((t - int(t)) * (1 << 32))


def qmp_answer(sock, pkt, peer):
    t2 = ntp64()
    teid = struct.unpack("!I", pkt[4:8])[0]
    n = pkt[12] * 4
    c = pkt[13:12 + n - 1]
    if teid != DL_TEID or len(c) < 2 or c[0] >> 4 != 0 or not c[0] & 0x08:
        return
    qfi = c[1] & 0x3F
    at = 3 if c[1] & 0x80 else 2  # skip the PPI octet when PPP is set
    t1 = c[at:at + 8]
    tpdu = len(pkt) - 12 - n
    ind = 0x04 | 0x02  # DL and UL Delay Ind.
    content = bytes([0x10 | 0x08 | ind, qfi]) + t1 + struct.pack("!Q", t2)
    t3 = ntp64()
    content += struct.pack("!QII", t3, RAN_DL, RAN_UL)
    while (len(content) + 2) % 4:
        content += b"\x00"
    ext = bytes([(len(content) + 2) // 4]) + content + b"\x00"
    hdr = struct.pack("!BBHI", 0x34, 0xFF, 4 + len(ext), UL_TEID) + b"\x00\x00\x00\x85"
    sock.sendto(hdr + ext, peer)
    print(f"QMP qfi={qfi} tpdu={tpdu} answered", flush=True)


stamp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
stamp.bind((ADDR, 862))
gtpu = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
gtpu.bind((ADDR, 2152))
sel = selectors.DefaultSelector()
sel.register(stamp, selectors.EVENT_READ, "stamp")
sel.register(gtpu, selectors.EVENT_READ, "gtpu")
print(f"responder on {ADDR}: STAMP 862, GTP-U 2152", flush=True)
rseq = 0
while True:
    for key, _ in sel.select():
        sock = key.fileobj
        pkt, peer = sock.recvfrom(2048)
        if key.data == "stamp":
            t2 = ntp64()
            if len(pkt) < 44:
                continue
            r = bytearray(44)
            r[0:4] = struct.pack("!I", rseq)
            rseq += 1
            r[12:14] = b"\x00\x01"
            r[16:24] = struct.pack("!Q", t2)
            r[24:36] = pkt[0:12]
            r[36:38] = pkt[12:14]
            r[40] = 255
            r[4:12] = struct.pack("!Q", ntp64())
            sock.sendto(bytes(r), peer)
        else:
            if len(pkt) >= 16 and pkt[1] == 0xFF and pkt[0] & 0x04 and pkt[11] == 0x85:
                qmp_answer(sock, pkt, peer)
                continue
            # GTPv1-U, E/S/PN flags; Echo Request = type 1 with S set.
            if len(pkt) < 12 or pkt[1] != 1:
                continue
            seq = pkt[8:10]
            body = b"\x0e\x00"  # Recovery IE (type 14), restart counter 0
            hdr = struct.pack("!BBHI", 0x32, 2, 4 + len(body), 0) + seq + b"\x00\x00"
            sock.sendto(hdr + body, peer)
