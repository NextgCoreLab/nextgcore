#!/usr/bin/env python3
"""#1389 netem leg: the far end of the measured paths, run inside the network
namespace whose link carries the injected netem delay.

- STAMP Session-Reflector, stateless, unauthenticated (IETF RFC 8762 §4.3.1),
  on UDP <addr>:862, with T2/T3 stamped, so upfd subtracts the turnaround.
- GTP-U Echo responder (TS 29.281 §7.2.2) on UDP <addr>:2152: answers an Echo
  Request with an Echo Response carrying the same sequence number and a
  Recovery IE.
Usage: qos_delay_responder.py <addr>
"""
import selectors, socket, struct, sys, time

ADDR = sys.argv[1]
NTP_OFFSET = 2208988800


def ntp64():
    t = time.time() + NTP_OFFSET
    return (int(t) << 32) | int((t - int(t)) * (1 << 32))


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
            # GTPv1-U, E/S/PN flags; Echo Request = type 1 with S set.
            if len(pkt) < 12 or pkt[1] != 1:
                continue
            seq = pkt[8:10]
            body = b"\x0e\x00"  # Recovery IE (type 14), restart counter 0
            hdr = struct.pack("!BBHI", 0x32, 2, 4 + len(body), 0) + seq + b"\x00\x00"
            sock.sendto(hdr + body, peer)
