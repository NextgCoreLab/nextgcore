#!/usr/bin/env python3
"""Assertions of demo d445a-fl-t8 (nextgsim#480) over a scenario capture dir.

    checks.py <arm> DIR      print one PASS/FAIL line per check, exit 0 iff the
                             arm's verdict holds (a revert arm holds when the
                             check it targets FAILS for the expected reason)
    checks.py --self-test    every check passes on a complete fixture and fails
                             on the same fixture with a line removed, out of
                             order, or a value wrong; no cluster, no network

DIR holds what scenario.sh captured (every log with kubelet --timestamps):
    af.log  nef.log  udm.log  amf.log     the AF (upf pod, fl-af), nefd, udmd, amfd
    ue-ips.txt                            "ueN <tun IPv4>" per member at join; a
                                          second line for ue3 after its power cycle
    metrics-before.prom, metrics-after.prom, metrics-before.ts
                                          upfd /metrics around the run, and the
                                          first scrape's epoch (the UPF pod's clock)
    fl-dn.pcap                            tcpdump on fl-up (UPF side of fl-dn)
    meta.txt                              key=value: deadline_ms, members
    gates.txt, probe.txt                  the gates and probe arms' own results

Arms: main poisoned probe gates, and the revert arms no-t8 freeze-global leak-raw
nat-on nefd-down udm-fallback eth0.
Only the standard library is used.
"""
import ipaddress
import os
import re
import struct
import sys
import tempfile

KEY = 'd445a-fl-t8'
REALM = 'fl.nextg'
UE_NET = ipaddress.ip_network('10.45.0.0/16')
AF_IP = '10.46.0.10'
AF_PORT = 7480
STAMP = re.compile(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z$')


def gpsi(member):
    return f'extid-ue{member:03d}@{REALM}'


def ns(stamp):
    """A kubelet RFC 3339 (nano, trailing zeros trimmed) stamp in epoch ns."""
    import calendar
    import time
    m = STAMP.match(stamp)
    if not m:
        return None
    secs = calendar.timegm(time.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S'))
    frac = (m.group(2) or '0')[:9].ljust(9, '0')
    return secs * 10**9 + int(frac)


def load(d, name):
    """[(ns, message)] of a kubelet-stamped log; [] when absent."""
    path = os.path.join(d, name)
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, errors='replace').read().splitlines():
        ts, _, msg = line.partition(' ')
        t = ns(ts)
        if t is not None:
            out.append((t, msg))
    return out


def meta(d):
    out = {}
    p = os.path.join(d, 'meta.txt')
    if os.path.exists(p):
        for line in open(p).read().splitlines():
            k, _, v = line.partition('=')
            out[k.strip()] = v.strip()
    return out


def ue_ips(d):
    """{label: [ip, ...]} in capture order."""
    out = {}
    p = os.path.join(d, 'ue-ips.txt')
    if os.path.exists(p):
        for line in open(p).read().splitlines():
            parts = line.split()
            if len(parts) == 2:
                out.setdefault(parts[0], []).append(parts[1])
    return out


def first(rows, pat, after=None):
    rx = re.compile(pat)
    for t, m in rows:
        if (after is None or t > after) and rx.search(m):
            return t, m, rx.search(m)
    return None


def every(rows, pat):
    rx = re.compile(pat)
    return [(t, m, rx.search(m)) for t, m in rows if rx.search(m)]


class Result:
    def __init__(self):
        self.rows = []

    def add(self, name, ok, evidence):
        self.rows.append((name, bool(ok), evidence))
        return ok

    def ok(self, name):
        return all(o for n, o, _ in self.rows if n == name) and any(n == name for n, _, _ in self.rows)

    def failed(self, name):
        return any(n == name and not o for n, o, _ in self.rows)

    def print(self):
        for name, ok, ev in self.rows:
            print(f"{'PASS' if ok else 'FAIL'} {name}: {ev}")


# --- the checks -------------------------------------------------------------

JOIN_RX = re.compile(
    r'\[demo:d445a-fl-t8\] (?:member_joined member=(?P<l1>ue\d+) gpsi=(?P<g1>\S+)'
    r'|member_selection readmitted=(?P<g2>\S+) member=(?P<l2>ue\d+)) peer=(?P<ip>[\d.]+):(?P<port>\d+) '
    r't8=(?P<t8>off|subscribed (?P<loc>\S+))')


def joins(af):
    out = []
    for t, m in af:
        x = JOIN_RX.search(m)
        if x:
            out.append(dict(t=t, label=x.group('l1') or x.group('l2'),
                            gpsi=x.group('g1') or x.group('g2'), ip=x.group('ip'),
                            port=int(x.group('port')), loc=x.group('loc'),
                            readmit=x.group('g2') is not None, line=m))
    return out


def check_sources(r, d, members):
    """Every member joined, from its own PDU session's address in 10.45.0.0/16,
    and the NEF resolved that address to the member's own External Identifier."""
    af = load(d, 'af.log')
    js = joins(af)
    ips = ue_ips(d)
    seen = set()
    bad = []
    for j in js:
        n = int(j['label'][2:])
        if ipaddress.ip_address(j['ip']) not in UE_NET:
            bad.append(f"{j['label']} from {j['ip']}, not in {UE_NET}")
        if j['gpsi'] != gpsi(n):
            bad.append(f"{j['label']} resolved to {j['gpsi']}, expected {gpsi(n)}")
        if j['ip'] not in ips.get(j['label'], []):
            bad.append(f"{j['label']} joined from {j['ip']}, its uesimtun0 is {ips.get(j['label'])}")
        seen.add(j['label'])
    unresolved = every(af, r'identity_unresolved member=(ue\d+) peer=([\d.]+)')
    for _, _, x in unresolved:
        bad.append(f'identity_unresolved {x.group(1)} peer={x.group(2)}')
    missing = [f'ue{n}' for n in range(1, members + 1) if f'ue{n}' not in seen]
    if missing:
        bad.append(f'never joined: {missing}')
    ev = '; '.join(f"{j['label']} {j['ip']} -> {j['gpsi']}" for j in js if not j['readmit'])
    return r.add('sources', not bad, '; '.join(bad) if bad else f'{len(js)} joins, {ev}')


def sub_id(loc):
    return loc.rstrip('/').rsplit('/', 1)[-1] if loc else None


def ue3_departure(d):
    """(t_hold, t_accept) of ue3's deregistration: the AF's hold before round 4
    and the first amfd Deregistration Accept after it."""
    af, amf = load(d, 'af.log'), load(d, 'amf.log')
    hold = first(af, r'hold before round=4 until=member-excluded')
    if not hold:
        return None, None
    acc = first(amf, r'Deregistration Accept sent to UE', hold[0])
    return hold[0], (acc[0] if acc else None)


def ue3_legs(udm, before):
    """ue3's udmd AMF leg, exact or nothing: (forwarded LoC legs before `before`,
    ue3's leg or None, why).

    udmd logs no line holding both an EE id and its SUPI, and forwards each leg
    asynchronously after its 201 (spawn_reconcile), so the tie is by count, and
    fails closed. It is exact only when, at ue3's own `EE Subscribe`, every earlier
    EE Subscribe already has its own forwarded line (as many distinct EE ids as
    subscribes), and no later EE Subscribe comes before the next new EE id, which is
    then ue3's. scenario.sh serialises the joins so that this holds on a correct run."""
    subs = every(udm, r'EE Subscribe: ueIdentity=(imsi-\d+)')
    fwd = [x for x in every(udm, r'EE subscription (\S+) \(.*LOSS_OF_CONNECTIVITY.*\) forwarded to AMF (\S+): (\S+)')
           if x[0] < before]
    mine = [x for x in subs if x[2].group(1) == UE3_SUPI and x[0] < before]
    if not mine:
        return fwd, None, f'no udmd EE Subscribe for {UE3_SUPI}'
    t3 = mine[0][0]
    earlier = [x for x in subs if x[0] < t3]
    seen = {x[2].group(1) for x in fwd if x[0] < t3}
    if len(seen) != len(earlier):
        return fwd, None, (f"ue3's leg is ambiguous: {len(earlier)} EE Subscribe(s) before ue3's, "
                           f"{len(seen)} forwarded by then")
    new = [x for x in fwd if x[0] > t3 and x[2].group(1) not in seen]
    if not new:
        return fwd, None, "no udmd leg forwarded after ue3's EE Subscribe"
    later = [x for x in subs if t3 < x[0] < new[0][0]]
    if later:
        return fwd, None, (f"ue3's leg is ambiguous: another EE Subscribe ({later[0][2].group(1)}) "
                           "before the next forwarded leg")
    return fwd, new[0], 'exact'


UE3_SUPI = 'imsi-999700000000003'


def check_chain(r, d, deadline_ms):
    """The causal chain of ue3's departure. Hard order, only where one line
    causes the next: amfd `Deregistration Accept sent to UE` < AF exclusion of ue3
    by the NEF < round 4 at participants=2 with dur_ms < 0.3 T. Linked by
    content: udmd forwarded every member's LoC leg (x3) before the Accept; amfd
    delivered LoC (2xx) on ue3's leg, and nefd delivered T8 (2xx) on ue3's
    subscription with the reason the AF logged, both inside (Accept, round 4).
    amfd and nefd log on the 204 they get back, and nefd answers amfd before it
    forwards, so neither delivery line is ordered against the exclusion; their
    offsets are reported, not gated. Each line is also stamped by its own node."""
    af, nef, udm, amf = (load(d, f) for f in ('af.log', 'nef.log', 'udm.log', 'amf.log'))
    fail = lambda why: r.add('chain', False, why)
    js = [j for j in joins(af) if j['label'] == 'ue3' and not j['readmit']]
    if not js or not js[0]['loc']:
        return fail('ue3 never joined with a T8 subscription')
    s3 = sub_id(js[0]['loc'])
    t_hold, t_acc = ue3_departure(d)
    if t_hold is None:
        return fail('no AF hold before round 4')
    if t_acc is None:
        return fail('no amfd "Deregistration Accept sent to UE" after the hold')
    fwd, leg, why = ue3_legs(udm, t_acc)
    legs = {x[2].group(1) for x in fwd}
    if len(legs) < 3:
        return fail(f'{len(legs)} distinct udmd LoC leg(s) forwarded to AMF before the Deregistration Accept, need 3')
    if leg is None:
        return fail(why)
    exc = first(af, rf'member_selection excluded={re.escape(gpsi(3))} member=ue3 reason=nef_event '
                    r'lossOfConnectReason=(\S+) subscription=(\S+)', t_acc)
    if not exc:
        return fail('no AF exclusion of ue3 by the NEF after the Deregistration Accept')
    if sub_id(exc[2].group(2)) != s3:
        return fail(f'the exclusion names subscription {exc[2].group(2)}, ue3 has {s3}')
    reason = exc[2].group(1)
    if reason in ('-', ''):
        return fail('the exclusion carries no lossOfConnectReason')
    rnd = first(af, r'round=4 arm=\d+ rule=\S+ participants=(\d+) ', exc[0])
    if not rnd or rnd[2].group(1) != '2':
        return fail(f'round 4 after the exclusion: {rnd[1] if rnd else "none"} (need participants=2)')
    done = first(af, r'round=4 done .* dur_ms=(\d+) ', rnd[0])
    if not done:
        return fail('round 4 never finished')
    dur = int(done[2].group(1))
    if dur >= 0.3 * deadline_ms:
        return fail(f'round 4 dur_ms={dur} >= 0.3 T ({0.3 * deadline_ms:.0f})')
    leg3 = sub_id(leg[2].group(3))
    dls = [x for x in every(amf, r'Event notification delivered: sub=([^,\s]+), status=(\d+)')
           if t_acc < x[0] < rnd[0] and x[2].group(2).startswith('2')]
    mine = [x for x in dls if x[2].group(1) == leg3]
    if not mine:
        return fail(f"no amfd 2xx delivery on ue3's leg {leg3} between the Accept and round 4")
    others = [x for x in dls if x[2].group(1) != leg3]
    if others:
        return fail(f"amfd also delivered on {[x[2].group(1) for x in others]}, not ue3's leg")
    dl = mine[0]
    nd = None
    for t, m, x in every(nef, r'\[demo:d445a-fl-t8\] T8 delivery sub=(\S+) monitoringType=LOSS_OF_CONNECTIVITY '
                              r'lossOfConnectReason=(\S+) status=(\d+)'):
        if t_acc < t < rnd[0] and x.group(1) == s3:
            nd = (t, m, x)
            break
    if not nd:
        return fail(f'no nefd T8 delivery on sub={s3} between the Accept and round 4')
    if nd[2].group(2) != reason or not nd[2].group(3).startswith('2'):
        return fail(f'nefd delivered lossOfConnectReason={nd[2].group(2)} status={nd[2].group(3)}, '
                    f'AF saw {reason}')
    ms = lambda t: f'{(t - t_acc) / 1e6:+.1f} ms'
    return r.add('chain', True,
                 f'udmd forwarded x{len(fwd)} (ue3\'s leg {leg[2].group(1)} -> {leg3}, tie exact); from the Accept: '
                 f'amfd delivered {ms(dl[0])}, nefd T8 sub={s3} {ms(nd[0])}, AF excluded {gpsi(3)} '
                 f'(lossOfConnectReason={reason}) {ms(exc[0])}, round 4 participants=2 {ms(rnd[0])}, '
                 f'dur_ms={dur} (< {0.3 * deadline_ms:.0f})')


def check_straggler(r, d, deadline_ms):
    """Without the T8 exclusion (a revert arm): round 4 waits for ue3 until T."""
    af = load(d, 'af.log')
    st = first(af, r'straggler_timeout round=4 member=ue3 after (\d+) ms')
    done = first(af, r'round=4 done .* dur_ms=(\d+) ')
    ok = bool(st and done and int(done[2].group(1)) >= deadline_ms)
    return r.add('straggler', ok,
                 (st[1].split('] ', 1)[-1] if st else 'no straggler_timeout for ue3 in round 4') +
                 (f'; round 4 dur_ms={done[2].group(1)} (T={deadline_ms})' if done else ''))


SCORE = re.compile(r'scorecard rule=(\S+) seed=480 rounds=(\d+) .* last/r1=([\d.e+-]+|NaN|inf) '
                   r'last/local=([\d.e+-]+|NaN|inf) last/pooled=([\d.e+-]+|NaN|inf) '
                   r'oracle_bit_identical=(true|false)')


def scorecards(af):
    return {x.group(1): x for _, _, x in every(af, SCORE.pattern)}


def check_scorecard(r, d):
    sc = scorecards(load(d, 'af.log')).get('fedavg')
    if not sc:
        return r.add('scorecard', False, 'no fedavg scorecard')
    r1, loc, pool = (float(sc.group(i)) for i in (3, 4, 5))
    bit = sc.group(6) == 'true'
    rounds = int(sc.group(2))
    want = int(meta(d).get('rounds', '10'))
    ok = rounds == want and r1 <= 0.5 and loc <= 0.8 and pool <= 1.2 and bit
    return r.add('scorecard', ok, f'rounds={rounds} (={want}) last/r1={r1} (<=0.5) last/local={loc} (<=0.8) '
                                  f'last/pooled={pool} (<=1.2) oracle_bit_identical={sc.group(6)}')


def check_readmission(r, d):
    af = load(d, 'af.log')
    re_ = first(af, rf'member_selection readmitted={re.escape(gpsi(3))} member=ue3 ')
    rounds = {int(x.group(1)): int(x.group(2)) for _, _, x in
              every(af, r'round=(\d+) arm=1 rule=\S+ participants=(\d+) ')}
    late = {k: rounds.get(k) for k in (7, 8, 9, 10)}
    ok = bool(re_) and all(v == 3 for v in late.values())
    return r.add('readmission', ok, ('readmitted ' + gpsi(3) if re_ else 'no readmission of ue3') +
                 f'; rounds 7-10 participants={[late[k] for k in (7, 8, 9, 10)]}')


def check_canary(r, d):
    af = load(d, 'af.log')
    done = first(af, r'all arms done: canary_rows=(\d+) refused_frames=(\d+) ')
    if not done:
        return r.add('canary', False, 'no "all arms done" line')
    ok = done[2].group(1) == '0' and done[2].group(2) == '0'
    return r.add('canary', ok, f'canary_rows={done[2].group(1)} refused_frames={done[2].group(2)}')


def check_poisoned(r, d):
    af = load(d, 'af.log')
    rob = {x.group(1): float(x.group(2)) for _, _, x in
           every(af, r'robustness rule=(\S+) poisoned_last_mse=\S+ clean_last_mse=\S+ ratio=([\d.e+-]+|inf|NaN) ')}
    need = {'median': lambda v: v <= 1.1, 'trimmed-mean': lambda v: v <= 1.1, 'fedavg': lambda v: v >= 10}
    bad = [f'{k} ratio={rob.get(k)}' for k, f in need.items() if k not in rob or not f(rob[k])]
    r.add('poisoned', not bad, '; '.join(bad) if bad else
          f"median {rob['median']} (<=1.1), trimmed-mean {rob['trimmed-mean']} (<=1.1), fedavg {rob['fedavg']} (>=10)")
    kr = every(af, r'member_selection round=(\d+) rule=krum excluded=(\S+) member=(ue\d+) reason=krum_worst')
    rounds = int(meta(d).get('rounds', '10'))
    worst5 = [x for x in kr if x[2].group(2) == gpsi(5)]
    return r.add('krum', len(kr) == rounds and len(worst5) == rounds,
                 f'{len(worst5)}/{rounds} krum rounds excluded={gpsi(5)} ({len(kr)} krum lines)')


def read_pcap(path):
    """[(epoch_ns, src, sport, dst, dport, flags, ip_len)] of TCP over IPv4."""
    out = []
    if not os.path.exists(path):
        return None
    data = open(path, 'rb').read()
    if len(data) < 24:
        return out
    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        e = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '>'
    else:
        raise ValueError('not a pcap file')
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    link = struct.unpack(e + 'I', data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(e + 'IIII', data[off:off + 16])
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        t = sec * 10**9 + (frac if nano else frac * 1000)
        if link == 1:
            if len(pkt) < 14 or pkt[12:14] != b'\x08\x00':
                continue
            ip = pkt[14:]
        elif link in (101, 228):
            ip = pkt
        elif link == 113:
            ip = pkt[16:]
        else:
            continue
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0xf) * 4
        tot = struct.unpack('>H', ip[2:4])[0]
        tcp = ip[ihl:]
        if len(tcp) < 14:
            continue
        sport, dport = struct.unpack('>HH', tcp[:4])
        out.append((t, '.'.join(map(str, ip[12:16])), sport, '.'.join(map(str, ip[16:20])), dport,
                    tcp[13], tot))
    return out


FIN, RST = 0x01, 0x04


def check_no_fin(r, d):
    """ue3's first FL connection is never closed from the UE side: after the
    deregistration and the power cycle no user plane is left to carry a FIN or
    RST. The pcap must show that connection carrying data first."""
    pk = read_pcap(os.path.join(d, 'fl-dn.pcap'))
    if pk is None:
        return r.add('no_fin', False, 'no fl-dn.pcap')
    js = [j for j in joins(load(d, 'af.log')) if j['label'] == 'ue3' and not j['readmit']]
    if not js:
        return r.add('no_fin', False, 'ue3 never joined')
    ip, port = js[0]['ip'], js[0]['port']
    conn = [p for p in pk if p[1] == ip and p[2] == port and p[3] == AF_IP and p[4] == AF_PORT]
    if not conn:
        return r.add('no_fin', False, f'no packet of ue3 {ip}:{port} in the pcap (capture empty?)')
    data = [p for p in conn if p[6] > 52]
    closes = [p for p in conn if p[5] & (FIN | RST)]
    ok = bool(data) and not closes
    return r.add('no_fin', ok, f'ue3 {ip}:{port} -> {AF_IP}:{AF_PORT}: {len(conn)} segments '
                               f'({len(data)} with data), {len(closes)} FIN/RST from the UE; '
                               f'{len(pk)} segments in the pcap')


METRIC = re.compile(r'^upf_session_ul_bytes_total\{([^}]*)\} (\d+)')


def ul_series(path):
    out = {}
    if not os.path.exists(path):
        return None
    for line in open(path).read().splitlines():
        m = METRIC.match(line)
        if m:
            labels = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            out[(labels.get('seid'), labels.get('ue_ipv4'))] = int(m.group(2))
    return out


def check_ul_delta(r, d):
    """Per session: the UPF's UL byte delta over the run is at least the bytes the
    fl-dn pcap saw from that UE address to the AF in the same window."""
    before = ul_series(os.path.join(d, 'metrics-before.prom'))
    after = ul_series(os.path.join(d, 'metrics-after.prom'))
    pk = read_pcap(os.path.join(d, 'fl-dn.pcap'))
    tsf = os.path.join(d, 'metrics-before.ts')
    if before is None or after is None or pk is None or not os.path.exists(tsf):
        return r.add('ul_delta', False, 'missing metrics or pcap capture')
    t0 = int(round(float(open(tsf).read().strip()) * 1e9))
    if not after:
        return r.add('ul_delta', False, 'no upf_session_ul_bytes_total series (UPF_SESSION_METRICS off?)')
    sent = {}
    for t, src, _, dst, dport, _, tot in pk:
        if t >= t0 and dst == AF_IP and dport == AF_PORT:
            sent[src] = sent.get(src, 0) + tot
    bad, ev = [], []
    members = {ip for ips in ue_ips(d).values() for ip in ips}
    covered = set()
    for (seid, ip), v in sorted(after.items(), key=lambda kv: kv[0][1] or ''):
        delta = v - before.get((seid, ip), 0)
        b = sent.get(ip, 0)
        if ip in members:
            covered.add(ip)
        ev.append(f'{ip} seid={seid} UL+{delta} >= AF {b}')
        if delta < b:
            bad.append(f'{ip} seid={seid}: UL delta {delta} < {b} bytes to the AF')
    unseen = [ip for ip in sent if ip not in {k[1] for k in after}]
    for ip in unseen:
        if ip in members and ipaddress.ip_address(ip) in UE_NET:
            # A session released during the run has no series at the end (ue3's first).
            ev.append(f'{ip} released before the last scrape ({sent[ip]} bytes to the AF)')
        else:
            bad.append(f'{sent[ip]} bytes reached the AF from {ip}, which has no PDU session')
    for ip in members:
        if ip not in sent:
            bad.append(f'member address {ip} sent nothing to the AF in the pcap')
    if not covered:
        bad.append('no member session in the UPF metrics')
    return r.add('ul_delta', not bad, '; '.join(bad) if bad else '; '.join(ev))


def check_af_unprivileged(r, d):
    """nr-fl-server, the one listener UEs reach, ran as nobody with no
    capabilities, an empty bounding set and no_new_privs (its /proc status, which
    scenario.sh captures)."""
    p = os.path.join(d, 'af-status.txt')
    st = {}
    if os.path.exists(p):
        for line in open(p).read().splitlines():
            k, _, v = line.partition(':')
            st[k.strip()] = v.split()
    want = {'Uid': ['65534'] * 4, 'Gid': ['65534'] * 4, 'CapEff': ['0000000000000000'],
            'CapPrm': ['0000000000000000'], 'CapBnd': ['0000000000000000'], 'NoNewPrivs': ['1']}
    bad = [f'{k}={" ".join(st.get(k, ["?"]))}' for k, v in want.items() if st.get(k) != v]
    return r.add('af_unprivileged', not bad, '; '.join(bad) if bad else
                 'uid/gid 65534, CapEff/CapPrm/CapBnd 0, NoNewPrivs 1')


def check_gates(r, d):
    p = os.path.join(d, 'gates.txt')
    rows = open(p).read().splitlines() if os.path.exists(p) else []
    if not rows:
        return r.add('gates', False, 'no gates.txt')
    for row in rows:
        verdict, _, rest = row.partition(' ')
        if verdict == 'INFO':
            print(f'INFO gates: {rest}')
            continue
        r.add('gates', verdict == 'PASS', rest)
    return r.ok('gates')


def check_probe(r, d):
    p = os.path.join(d, 'probe.txt')
    rows = [x for x in (open(p).read().splitlines() if os.path.exists(p) else []) if x.startswith('cycle ')]
    passed = [x for x in rows if ' PASS ' in x]
    for x in rows:
        r.add('probe-cycle', ' PASS ' in x, x)
    return r.add('probe', len(rows) == 10 and len(passed) == 10, f'{len(passed)}/10 cycles pass')


# --- arms -------------------------------------------------------------------

def run(arm, d):
    r = Result()
    m = meta(d)
    T = int(m.get('deadline_ms', '30000'))
    members = int(m.get('members', '3'))
    verdict = False
    if arm == 'main':
        check_sources(r, d, members)
        check_chain(r, d, T)
        check_scorecard(r, d)
        check_readmission(r, d)
        check_canary(r, d)
        check_no_fin(r, d)
        check_ul_delta(r, d)
        check_af_unprivileged(r, d)
        verdict = all(ok for _, ok, _ in r.rows)
    elif arm == 'poisoned':
        check_sources(r, d, members)
        check_poisoned(r, d)
        check_canary(r, d)
        check_ul_delta(r, d)
        verdict = all(ok for _, ok, _ in r.rows)
    elif arm == 'probe':
        verdict = check_probe(r, d)
    elif arm == 'gates':
        verdict = check_gates(r, d)
    elif arm in ('no-t8', 'nefd-down', 'udm-fallback'):
        check_chain(r, d, T)
        af, udm = load(d, 'af.log'), load(d, 'udm.log')
        _, t_acc = ue3_departure(d)
        fwd = every(udm, r'forwarded to AMF')
        pre = [('the Deregistration Accept', t_acc is not None)]
        if arm == 'no-t8':
            j = [x for x in joins(af) if x['label'] == 'ue3' and not x['readmit']]
            pre.append(('ue3 joined with t8=off', bool(j) and j[0]['loc'] is None))
            pre.append(('the AF subscribed nothing: no udmd EE Subscribe, no forwarded leg',
                        not every(udm, r'EE Subscribe: ') and not fwd))
        amf = load(d, 'amf.log')
        if arm == 'nefd-down':
            pre.append(('udmd forwarded x3', len(fwd) >= 3))
            pre.append(('no AF exclusion of ue3', not first(af, r'member_selection excluded=')))
            _, leg, why = ue3_legs(udm, t_acc if t_acc is not None else 0)
            leg3 = sub_id(leg[2].group(3)) if leg else None
            after = [x for x in amf if t_acc is not None and x[0] > t_acc]
            failed = bool(leg3) and any(f'Event notification delivery failed (sub={leg3})' in m for _, m in after)
            ok2xx = bool(leg3) and any(re.search(rf'Event notification delivered: sub={re.escape(leg3)}, status=2', m)
                                       for _, m in after)
            pre.append((f"amfd fired LoC at the down nefd: delivery failed on ue3's leg {leg3 or '(' + why + ')'}",
                        failed and not ok2xx))
        if arm == 'udm-fallback':
            warns = every(udm, r'EE subscription \S+: ')
            pre.append(('udmd could not reach the AMF (EE subscription <id>: <error>)', len(warns) >= 3))
            pre.append(('udmd forwarded no leg', not fwd))
            dl = [m for t, m in amf if t_acc is not None and t > t_acc
                  and re.search(r'Event notification delivered: sub=\S+, status=2', m)]
            pre.append(('no amfd 2xx LoC delivery after the Accept (no AMF leg carried it)', not dl))
            exc = first(af, rf'member_selection excluded={re.escape(gpsi(3))} member=ue3 reason=nef_event '
                            r'lossOfConnectReason=(\S+)')
            print('INFO udm-fallback: ' + (f'ue3 still excluded through udmd\'s UECM fallback, '
                                           f'lossOfConnectReason={exc[2].group(1)}' if exc else
                                           'no exclusion of ue3 reached the AF'))
        if arm != 'udm-fallback':
            check_straggler(r, d, T)
        for name, ok in pre:
            r.add('precondition', ok, name)
        verdict = r.failed('chain') and r.ok('precondition') and (arm == 'udm-fallback' or r.ok('straggler'))
    elif arm == 'freeze-global':
        check_scorecard(r, d)
        sc = scorecards(load(d, 'af.log')).get('fedavg')
        frozen = bool(sc) and 0.95 <= float(sc.group(3)) <= 1.05
        r.add('precondition', frozen, 'a fedavg scorecard with 0.95 <= last/r1 <= 1.05 (the global never moved)')
        verdict = r.failed('scorecard') and frozen
    elif arm == 'leak-raw':
        check_canary(r, d)
        done = first(load(d, 'af.log'), r'all arms done: canary_rows=(\d+) ')
        refused = first(load(d, 'af.log'), r'frame_refused member=ue2')
        ok = bool(done) and int(done[2].group(1)) > 0 and bool(refused)
        r.add('precondition', ok, 'canary_rows > 0 and frame_refused member=ue2')
        verdict = r.failed('canary') and ok
    elif arm == 'nat-on':
        check_sources(r, d, members)
        ok = bool(first(load(d, 'af.log'), r'identity_unresolved .*peer=10\.46\.0\.1:'))
        r.add('precondition', ok, 'identity_unresolved from the NATed 10.46.0.1')
        verdict = r.failed('sources') and ok
    elif arm == 'eth0':
        eth = m.get('eth0_ip', '')
        check_sources(r, d, members)
        check_ul_delta(r, d)
        pk = read_pcap(os.path.join(d, 'fl-dn.pcap')) or []
        seen = any(p[1] == eth and p[3] == AF_IP for p in pk)
        unres = bool(eth) and bool(first(load(d, 'af.log'), rf'identity_unresolved member=ue2 peer={re.escape(eth)}:'))
        r.add('precondition', bool(eth) and seen, f'ue2 on eth0 ({eth or "no eth0_ip"}) reached the AF in the pcap')
        r.add('precondition', unres, f'identity_unresolved member=ue2 peer={eth}')
        named = any(n == 'ul_delta' and not o and f'bytes reached the AF from {eth}, which has no PDU session' in ev
                    for n, o, ev in r.rows) if eth else False
        members_series = any(k[1] in {ip for ips in ue_ips(d).values() for ip in ips}
                             for k in (ul_series(os.path.join(d, 'metrics-after.prom')) or {}))
        r.add('precondition', named, f'ul_delta fails on the bytes from {eth} (no PDU session)')
        r.add('precondition', members_series, 'the UPF metrics hold member session series')
        verdict = r.failed('ul_delta') and r.failed('sources') and r.ok('precondition')
    else:
        sys.exit(f'unknown arm {arm}')
    r.print()
    print(f"ARM {arm}: {'HOLDS' if verdict else 'DOES NOT HOLD'}"
          + (' (a revert arm: its target check fails and every precondition holds)'
             if arm not in ('main', 'poisoned', 'probe', 'gates') else ''))
    return verdict


# --- self-test --------------------------------------------------------------

def _fixture(d, af=None, nef=None, udm=None, amf=None, extra=None):
    def st(s):
        return f'2026-11-13T06:{s // 60:02d}:{s % 60:02d}.{s % 7}00Z'
    P = '[demo:d445a-fl-t8] '
    loc = lambda n: f'http://nef:7777/3gpp-monitoring-event/v1/d445a-fl-af/subscriptions/nsub{n}'
    A = [(1, f'{P}member_joined member=ue{n} gpsi={gpsi(n)} peer=10.45.0.{n + 1}:4{n}000 t8=subscribed {loc(n)}')
         for n in (1, 2, 3)]
    A += [(10, f'{P}round=1 arm=1 rule=fedavg participants=3 selected=ue1,ue2,ue3 excluded=-'),
          (20, f'{P}hold before round=4 until=member-excluded (timeout 240 s)'),
          (31, f'{P}member_selection excluded={gpsi(3)} member=ue3 reason=nef_event lossOfConnectReason=DEREGISTERED subscription={loc(3)}'),
          (32, f'{P}round=4 arm=1 rule=fedavg participants=2 selected=ue1,ue2 excluded={gpsi(3)}(ue3)'),
          (33, f'{P}round=4 done arm=1 rule=fedavg updates=2 from=ue1,ue2 dur_ms=12 mse=0.5'),
          (40, f'{P}member_selection readmitted={gpsi(3)} member=ue3 peer=10.45.0.9:45000 t8=subscribed {loc(9)}')]
    A += [(41 + k, f'{P}round={k} arm=1 rule=fedavg participants=3 selected=ue1,ue2,ue3 excluded=-') for k in (7, 8, 9, 10)]
    A += [(60, f'{P}scorecard rule=fedavg seed=480 rounds=10 r1_mse=1 last_mse=0.2 local_only_mse=0.4 pooled_mse=0.19 '
               'last/r1=0.184 last/local=0.465 last/pooled=1.069 oracle_bit_identical=true'),
          (61, f'{P}all arms done: canary_rows=0 refused_frames=0 exclusions=1 readmissions=1')]
    U = []
    for n in (1, 2, 3):
        U.append((2 * n, f'EE Subscribe: ueIdentity=imsi-99970000000000{n}'))
        U.append((2 * n + 1, f'EE subscription usub{n} (["LOSS_OF_CONNECTIVITY"]) forwarded to AMF amf-1: '
                             f'http://amf:7777/namf-evts/v1/subscriptions/asub{n}'))
    M = [(29, 'Deregistration Accept sent to UE 3'),
         (30, 'Event notification delivered: sub=asub3, status=204')]
    N = [(31, f'{P}T8 delivery sub=nsub3 monitoringType=LOSS_OF_CONNECTIVITY lossOfConnectReason=DEREGISTERED status=204 to http://x/[redacted]')]
    for name, rows in (('af.log', af if af is not None else A), ('udm.log', udm if udm is not None else U),
                       ('amf.log', amf if amf is not None else M), ('nef.log', nef if nef is not None else N)):
        with open(os.path.join(d, name), 'w') as f:
            for s, line in rows:
                f.write(f'{st(s)} 2026-11-13T06:00:00Z INFO x: {line}\n')
    with open(os.path.join(d, 'ue-ips.txt'), 'w') as f:
        f.write('ue1 10.45.0.2\nue2 10.45.0.3\nue3 10.45.0.4\nue3 10.45.0.9\n')
    with open(os.path.join(d, 'meta.txt'), 'w') as f:
        f.write('deadline_ms=30000\nmembers=3\nrounds=10\n')
    with open(os.path.join(d, 'af-status.txt'), 'w') as f:
        f.write('Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\nCapPrm:\t0000000000000000\n'
                'CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\n')
    # pcap: ue3's first connection carries data and never closes; every member
    # sends to the AF after the first scrape (t = 06:00:05).
    t0 = ns('2026-11-13T06:00:05Z') / 1e9
    with open(os.path.join(d, 'metrics-before.ts'), 'w') as f:
        f.write(f'{t0:.6f}\n')
    pkts = []
    for n, ip, port in ((1, '10.45.0.2', 41000), (2, '10.45.0.3', 42000), (3, '10.45.0.4', 43000),
                        (3, '10.45.0.9', 45000)):
        pkts.append((t0 + 1 + n, ip, port, 0x18, 1040))
        pkts.append((t0 + 2 + n, ip, port, 0x10, 52))
    for e in (extra or []):
        pkts.append(e)
    _pcap(os.path.join(d, 'fl-dn.pcap'), pkts)
    with open(os.path.join(d, 'metrics-before.prom'), 'w') as f:
        f.write('upf_session_ul_bytes_total{seid="0x1",ue_ipv4="10.45.0.2"} 100\n'
                'upf_session_ul_bytes_total{seid="0x2",ue_ipv4="10.45.0.3"} 100\n'
                'upf_session_ul_bytes_total{seid="0x3",ue_ipv4="10.45.0.4"} 100\n')
    with open(os.path.join(d, 'metrics-after.prom'), 'w') as f:
        f.write('# HELP x\nupf_session_ul_bytes_total{seid="0x1",ue_ipv4="10.45.0.2"} 5000\n'
                'upf_session_ul_bytes_total{seid="0x2",ue_ipv4="10.45.0.3"} 5000\n'
                'upf_session_ul_bytes_total{seid="0x4",ue_ipv4="10.45.0.9"} 2000\n')


def _pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for t, ip, port, flags, tot in pkts:
            iph = struct.pack('>BBHHHBBH4s4s', 0x45, 0, tot, 0, 0, 64, 6, 0,
                              bytes(map(int, ip.split('.'))), bytes(map(int, AF_IP.split('.'))))
            tcp = struct.pack('>HHIIBBHHH', port, AF_PORT, 0, 0, 0x50, flags, 0, 0, 0)
            frame = b'\0' * 12 + b'\x08\x00' + iph + tcp
            f.write(struct.pack('<IIII', int(t), int((t - int(t)) * 1e6), len(frame), len(frame)))
            f.write(frame)


MAIN_FAILS = {'no udmd forwarded lines': 'chain', 'only two forwarded lines': 'chain', 'no Deregistration Accept': 'chain', 'the amfd delivery is not 2xx': 'chain', 'the amfd delivery names an unknown subscription': 'chain', 'no nefd T8 delivery': 'chain', 'nefd delivered another subscription': 'chain', 'nefd delivered no reason': 'chain', 'no AF exclusion': 'chain', 'the exclusion carries no reason': 'chain', 'round 4 at participants=3': 'chain', 'round 4 too slow': 'chain', 'ue3 resolved to another GPSI': 'sources', 'a source outside 10.45.0.0/16': 'sources', 'a member never joined': 'sources', 'scorecard over 0.5x round 1': 'scorecard', 'oracle not bit-identical': 'scorecard', 'no readmission': 'readmission', 'round 9 at participants=2': 'readmission', 'a canary row': 'canary', 'a FIN from ue3': 'no_fin', 'an RST from ue3': 'no_fin', 'UL delta below the AF bytes': 'ul_delta', 'no per-session series': 'ul_delta', "the amfd delivery on another member's leg": 'chain', 'a second amfd delivery on another leg': 'chain', 'no udmd EE Subscribe for ue3': 'chain', 'the exclusion before the Deregistration Accept': 'chain', 'round 4 before the exclusion': 'chain', 'the scorecard ran 5 rounds': 'scorecard', 'bytes to the AF from an address with no session': 'ul_delta', 'the AF kept its bounding set': 'af_unprivileged', 'the AF ran as root': 'af_unprivileged', 'no AF status captured': 'af_unprivileged', 'three forwarded lines but two legs (a re-forward)': 'chain'}


def self_test():
    n = [0]

    def expect(name, arm, mutate, want, fails=None):
        with tempfile.TemporaryDirectory() as d:
            mutate(d)
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                got = run(arm, d)
            if got != want:
                print(buf.getvalue())
                sys.exit(f'not ok - {name}: arm {arm} verdict {got}, expected {want}')
            if fails:
                bad = sorted({x.split(':')[0][5:] for x in buf.getvalue().splitlines() if x.startswith('FAIL ')})
                if bad != [fails]:
                    print(buf.getvalue())
                    sys.exit(f'not ok - {name}: failed {bad}, expected only {fails}')
            n[0] += 1
            print(f'ok {n[0]} - {name}')
            return buf.getvalue()

    def base(**kw):
        return lambda d: _fixture(d, **kw)

    out = expect('the complete fixture holds', 'main', base(), True)
    assert 'FAIL' not in out, out
    # Each mutation breaks the check it names.

    def without(name, pat):
        def m(d):
            _fixture(d)
            p = os.path.join(d, name)
            lines = [x for x in open(p).read().splitlines() if not re.search(pat, x)]
            open(p, 'w').write('\n'.join(lines) + '\n')
        return m

    def edit(name, old, new):
        def m(d):
            _fixture(d)
            p = os.path.join(d, name)
            s = open(p).read()
            assert old in s, (name, old)
            open(p, 'w').write(s.replace(old, new))
        return m

    for label, mut in [
        ('no udmd forwarded lines', without('udm.log', 'forwarded to AMF')),
        ('only two forwarded lines', without('udm.log', 'usub2')),
        ('no Deregistration Accept', without('amf.log', 'Deregistration Accept')),
        ('the amfd delivery is not 2xx', edit('amf.log', 'status=204', 'status=500')),
        ('the amfd delivery names an unknown subscription', edit('amf.log', 'sub=asub3', 'sub=other')),
        ('no nefd T8 delivery', without('nef.log', 'T8 delivery')),
        ('nefd delivered another subscription', edit('nef.log', 'sub=nsub3', 'sub=nsub1')),
        ('nefd delivered no reason', edit('nef.log', 'lossOfConnectReason=DEREGISTERED', 'lossOfConnectReason=-')),
        ('no AF exclusion', without('af.log', 'member_selection excluded=')),
        ('the exclusion carries no reason', edit('af.log', 'reason=nef_event lossOfConnectReason=DEREGISTERED', 'reason=nef_event lossOfConnectReason=-')),
        ('round 4 at participants=3', edit('af.log', 'round=4 arm=1 rule=fedavg participants=2', 'round=4 arm=1 rule=fedavg participants=3')),
        ('round 4 too slow', edit('af.log', 'dur_ms=12 ', 'dur_ms=9000 ')),
        ('ue3 resolved to another GPSI', edit('af.log', f'member=ue3 gpsi={gpsi(3)}', f'member=ue3 gpsi={gpsi(4)}')),
        ('a source outside 10.45.0.0/16', edit('af.log', 'peer=10.45.0.2:', 'peer=10.46.0.1:')),
        ('a member never joined', without('af.log', 'member_joined member=ue2')),
        ('scorecard over 0.5x round 1', edit('af.log', 'last/r1=0.184', 'last/r1=0.9')),
        ('oracle not bit-identical', edit('af.log', 'oracle_bit_identical=true', 'oracle_bit_identical=false')),
        ('no readmission', without('af.log', 'readmitted=')),
        ('round 9 at participants=2', edit('af.log', 'round=9 arm=1 rule=fedavg participants=3', 'round=9 arm=1 rule=fedavg participants=2')),
        ('a canary row', edit('af.log', 'canary_rows=0', 'canary_rows=1')),
        ('a FIN from ue3', lambda d: _fixture(d, extra=[(ns('2026-11-13T06:00:30Z') / 1e9, '10.45.0.4', 43000, 0x11, 52)])),
        ('an RST from ue3', lambda d: _fixture(d, extra=[(ns('2026-11-13T06:00:40Z') / 1e9, '10.45.0.4', 43000, 0x04, 40)])),
        ('UL delta below the AF bytes', edit('metrics-after.prom', 'ue_ipv4="10.45.0.2"} 5000', 'ue_ipv4="10.45.0.2"} 1000')),
        ('no per-session series', lambda d: (_fixture(d), open(os.path.join(d, 'metrics-after.prom'), 'w').write('x 1\n'))),
        ("the amfd delivery on another member's leg", edit('amf.log', 'sub=asub3', 'sub=asub1')),
        ('a second amfd delivery on another leg', lambda d: (_fixture(d), open(os.path.join(d, 'amf.log'), 'a').write(
            '2026-11-13T06:00:31.000Z x Event notification delivered: sub=asub2, status=204\n'))),
        ("no udmd EE Subscribe for ue3", without('udm.log', 'ueIdentity=imsi-999700000000003')),
        ('the exclusion before the Deregistration Accept', edit('amf.log', '06:00:29.100Z', '06:00:31.900Z')),
        ('round 4 before the exclusion', edit('af.log', '06:00:32.400Z', '06:00:31.100Z')),
        ('the scorecard ran 5 rounds', edit('af.log', 'rounds=10 r1_mse', 'rounds=5 r1_mse')),
        ('three forwarded lines but two legs (a re-forward)', edit('udm.log', 'EE subscription usub2 ', 'EE subscription usub1 ')),
        ('the AF kept its bounding set', edit('af-status.txt', 'CapBnd:\t0000000000000000', 'CapBnd:\t00000000002030c1')),
        ('the AF ran as root', edit('af-status.txt', 'Uid:\t65534', 'Uid:\t0')),
        ('no AF status captured', lambda d: (_fixture(d), os.remove(os.path.join(d, 'af-status.txt')))),
        ('bytes to the AF from an address with no session', lambda d: _fixture(d, extra=[
            (ns('2026-11-13T06:00:20Z') / 1e9, '10.10.5.5', 46000, 0x18, 300)])),
    ]:
        expect(label, 'main', mut, False, fails=MAIN_FAILS[label])
    # The deliveries are not ordered against the exclusion: amfd's line 0.6 s after
    # it, and nefd's before it, still hold.
    def late(d):
        _fixture(d)
        for name, old_, new_ in (('amf.log', '06:00:30.200Z', '06:00:31.900Z'),
                                 ('nef.log', '06:00:31.300Z', '06:00:29.900Z')):
            pth = os.path.join(d, name)
            text = open(pth).read()
            assert old_ in text, (name, old_)
            open(pth, 'w').write(text.replace(old_, new_))
    out = expect('the delivery lines may fall either side of the exclusion', 'main', late, True)

    # udmd's legs land asynchronously: Sub(ue1) fwd1 Sub(ue2) Sub(ue3) fwd2 fwd3.
    # ue3's leg cannot be told apart, so the chain FAILS closed, whichever leg
    # amfd delivered on (the reviewer's false fail and false pass).
    def interleaved(d, sub='asub3'):
        _fixture(d)
        U = ['EE Subscribe: ueIdentity=imsi-999700000000001', 'fwd 1', 'EE Subscribe: ueIdentity=imsi-999700000000002',
             'EE Subscribe: ueIdentity=imsi-999700000000003', 'fwd 2', 'fwd 3']
        rows = []
        for k, u in enumerate(U):
            if u.startswith('fwd'):
                n = u[-1]
                u = (f'EE subscription usub{n} (["LOSS_OF_CONNECTIVITY"]) forwarded to AMF amf-1: '
                     f'http://amf:7777/namf-evts/v1/subscriptions/asub{n}')
            rows.append(f'2026-11-13T06:00:0{k + 2}.000Z x {u}')
        open(os.path.join(d, 'udm.log'), 'w').write('\n'.join(rows) + '\n')
        a = os.path.join(d, 'amf.log')
        text = open(a).read()
        open(a, 'w').write(text.replace('sub=asub3', f'sub={sub}'))
    for sub in ('asub3', 'asub2'):
        o = expect(f'interleaved legs, amfd on {sub}: ambiguous, fails', 'main',
                   lambda d, sub=sub: interleaved(d, sub), False, fails='chain')
        assert "ue3's leg is ambiguous" in o, o
    # Serialised (every earlier subscribe forwarded before ue3's): exact.
    def serial_late(d):
        _fixture(d)   # the default fixture is serialised: Sub1 fwd1 Sub2 fwd2 Sub3 fwd3
    expect('serialised legs: exact', 'main', serial_late, True)
    def later_sub(d):
        _fixture(d)
        u = os.path.join(d, 'udm.log')
        lines = open(u).read().splitlines()
        lines.insert(5, '2026-11-13T06:00:06.900Z x EE Subscribe: ueIdentity=imsi-999700000000004')
        open(u, 'w').write('\n'.join(lines) + '\n')
    o = expect("a later subscribe before ue3's leg: ambiguous", 'main', later_sub, False, fails='chain')
    assert "ue3's leg is ambiguous" in o, o
    # The pcap reader must see the fixture's segments; an empty capture fails.
    expect('an empty pcap fails no_fin', 'main', lambda d: (_fixture(d), _pcap(os.path.join(d, 'fl-dn.pcap'), [])), False)

    # Revert arms hold only when their target check fails AND every precondition
    # holds; each wrong-reason case below must not hold.
    def strag(d, accept=True, t8='off', fwd=3, excl=False, failed=True):
        """t8='off' is the no-t8 shape (no T8 subscription, so udmd has nothing);
        t8='on' keeps the members' legs (nefd-down)."""
        _fixture(d)
        p_ = os.path.join(d, 'af.log')
        a_ = open(p_).read()
        if not excl:
            a_ = '\n'.join(x for x in a_.splitlines() if 'member_selection excluded=' not in x) + '\n'
        if t8 == 'off':
            a_ = re.sub(r'(member_joined member=ue3 gpsi=\S+ peer=\S+ )t8=subscribed \S+', r'\1t8=off', a_)
        a_ = a_.replace('dur_ms=12 ', 'dur_ms=30004 ')
        a_ += '2026-11-13T06:00:33.000Z x [demo:d445a-fl-t8] straggler_timeout round=4 member=ue3 after 30000 ms\n'
        open(p_, 'w').write(a_)
        if not accept:
            open(os.path.join(d, 'amf.log'), 'w').write('')
        else:
            open(os.path.join(d, 'amf.log'), 'w').write(
                '2026-11-13T06:00:29.100Z x Deregistration Accept sent to UE 3\n'
                + ('2026-11-13T06:00:29.500Z x Event notification delivery failed (sub=asub3): connection refused\n'
                   if failed else ''))
        u_ = os.path.join(d, 'udm.log')
        if t8 == 'off':
            keep = []
        else:
            keep = [x for x in open(u_).read().splitlines()
                    if 'forwarded' not in x or any(f'usub{n} ' in x for n in range(1, fwd + 1))]
        open(u_, 'w').write('\n'.join(keep) + '\n')
    expect('no-t8 does not hold on a good run', 'no-t8', base(), False)
    expect('no-t8 holds: t8=off, ue3 straggles to T', 'no-t8', strag, True)
    expect('no-t8 does not hold without the Deregistration Accept', 'no-t8', lambda d: strag(d, accept=False), False)
    expect('no-t8 does not hold with a T8 subscription', 'no-t8', lambda d: strag(d, t8='on'), False)

    def subscribed_anyway(d):
        strag(d)
        open(os.path.join(d, 'udm.log'), 'w').write(
            '2026-11-13T06:00:04.000Z x EE Subscribe: ueIdentity=imsi-999700000000003\n')
    expect('no-t8 does not hold when udmd shows a subscribe', 'no-t8', subscribed_anyway, False)
    expect('nefd-down holds: legs up, Accept, no delivery, straggler', 'nefd-down', lambda d: strag(d, t8='on'), True)
    expect('nefd-down does not hold without the Accept', 'nefd-down', lambda d: strag(d, t8='on', accept=False), False)
    expect('nefd-down does not hold with two legs', 'nefd-down', lambda d: strag(d, t8='on', fwd=2), False)
    expect('nefd-down does not hold when ue3 was excluded', 'nefd-down', lambda d: strag(d, t8='on', excl=True), False)
    expect('nefd-down does not hold when amfd never tried to deliver', 'nefd-down',
           lambda d: strag(d, t8='on', failed=False), False)

    def fallback(d, enforced=True):
        _fixture(d)
        rows = [f'2026-11-13T06:00:0{n}.000Z x EE subscription usub{n}: connect timed out' for n in (1, 2, 3)]
        if not enforced:
            rows += [x for x in open(os.path.join(d, 'udm.log')).read().splitlines() if 'forwarded' in x]
        open(os.path.join(d, 'udm.log'), 'w').write('\n'.join(rows) + '\n')
        open(os.path.join(d, 'amf.log'), 'w').write('2026-11-13T06:00:29.100Z x Deregistration Accept sent to UE 3\n')
    expect('udm-fallback holds: no leg reached the AMF, chain fails', 'udm-fallback', fallback, True)
    expect('udm-fallback does not hold when the legs were forwarded', 'udm-fallback',
           lambda d: fallback(d, enforced=False), False)
    expect('udm-fallback does not hold on a good run', 'udm-fallback', base(), False)
    expect('udm-fallback does not hold with an amfd 2xx delivery after the Accept', 'udm-fallback',
           lambda d: (fallback(d), open(os.path.join(d, 'amf.log'), 'a').write(
               '2026-11-13T06:00:30.000Z x Event notification delivered: sub=asub3, status=204\n')), False)

    expect('freeze-global does not hold on a good scorecard', 'freeze-global', base(), False)
    expect('freeze-global holds on a frozen scorecard', 'freeze-global',
           edit('af.log', 'last/r1=0.184', 'last/r1=1.000'), True)
    expect('freeze-global does not hold without a scorecard', 'freeze-global', without('af.log', 'scorecard'), False)
    for v in ('0.600', '3.000', 'inf'):
        expect(f'freeze-global does not hold at last/r1={v} (moved or diverged)', 'freeze-global',
               edit('af.log', 'last/r1=0.184', f'last/r1={v}'), False)
    expect('leak-raw does not hold on a clean run', 'leak-raw', base(), False)

    def leak(d, rows='1'):
        _fixture(d)
        p_ = os.path.join(d, 'af.log')
        a_ = open(p_).read().replace('canary_rows=0 refused_frames=0', f'canary_rows={rows} refused_frames=1')
        a_ += '2026-11-13T06:00:20.000Z x [demo:d445a-fl-t8] frame_refused member=ue2: canary; connection closed\n'
        open(p_, 'w').write(a_)
    expect('leak-raw holds on a refused, counted canary', 'leak-raw', leak, True)
    expect('leak-raw does not hold with canary_rows=0', 'leak-raw', lambda d: leak(d, rows='0'), False)
    expect('nat-on does not hold on resolved sources', 'nat-on', base(), False)

    def nat(d):
        _fixture(d)
        p_ = os.path.join(d, 'af.log')
        a_ = '\n'.join(x for x in open(p_).read().splitlines() if 'member_joined' not in x) + '\n'
        a_ += '2026-11-13T06:00:01.000Z x [demo:d445a-fl-t8] identity_unresolved member=ue1 peer=10.46.0.1:41000: UE ID: 404; refused\n'
        open(p_, 'w').write(a_)
    expect('nat-on holds when the NATed source is unresolved', 'nat-on', nat, True)

    def eth0(d, pcap=True, unres=True):
        _fixture(d, extra=[(ns('2026-11-13T06:00:20Z') / 1e9, '10.10.5.5', 46000, 0x18, 300)] if pcap else None)
        open(os.path.join(d, 'meta.txt'), 'a').write('eth0_ip=10.10.5.5\n')
        p_ = os.path.join(d, 'af.log')
        a_ = '\n'.join(x for x in open(p_).read().splitlines() if 'member_joined member=ue2' not in x) + '\n'
        if unres:
            a_ += '2026-11-13T06:00:02.000Z x [demo:d445a-fl-t8] identity_unresolved member=ue2 peer=10.10.5.5:46000: UE ID: 404; refused\n'
        open(p_, 'w').write(a_)
    expect('eth0 holds: unresolved, and bytes with no session', 'eth0', eth0, True)
    expect('eth0 does not hold without its packets in the pcap', 'eth0', lambda d: eth0(d, pcap=False), False)
    expect('eth0 does not hold without identity_unresolved', 'eth0', lambda d: eth0(d, unres=False), False)
    expect('eth0 does not hold on a good run', 'eth0', base(), False)
    expect('eth0 does not hold when ul_delta fails only for empty metrics', 'eth0',
           lambda d: (eth0(d), open(os.path.join(d, 'metrics-after.prom'), 'w').write('')), False)

    # poisoned
    def pois(d, fed='1860000.000', med='0.937', kr=10):
        _fixture(d)
        P = '[demo:d445a-fl-t8] '
        rows = [f'2026-11-13T06:00:0{n}.000Z x {P}member_joined member=ue{n} gpsi={gpsi(n)} peer=10.45.0.{n + 1}:4{n}000 t8=subscribed http://n/s{n}' for n in range(1, 6)]
        rows += [f'2026-11-13T06:01:00.000Z x {P}robustness rule={r} poisoned_last_mse=1 clean_last_mse=1 ratio={v} (attacker ue5 x-10)'
                 for r, v in (('fedavg', fed), ('median', med), ('trimmed-mean', '1.042'), ('krum', '1.0'))]
        rows += [f'2026-11-13T06:01:1{k}.000Z x {P}member_selection round={k + 1} rule=krum excluded={gpsi(5)} member=ue5 reason=krum_worst selected=x (ue1)'
                 for k in range(kr)]
        rows += [f'2026-11-13T06:02:00.000Z x {P}all arms done: canary_rows=0 refused_frames=0 exclusions=0 readmissions=0']
        open(os.path.join(d, 'af.log'), 'w').write('\n'.join(rows) + '\n')
        open(os.path.join(d, 'ue-ips.txt'), 'w').write(''.join(f'ue{n} 10.45.0.{n + 1}\n' for n in range(1, 6)))
        open(os.path.join(d, 'meta.txt'), 'w').write('deadline_ms=30000\nmembers=5\nrounds=10\n')
        t0 = ns('2026-11-13T06:00:05Z') / 1e9
        _pcap(os.path.join(d, 'fl-dn.pcap'), [(t0 + n, f'10.45.0.{n + 1}', 40000 + n, 0x18, 500) for n in range(1, 6)])
        open(os.path.join(d, 'metrics-after.prom'), 'w').write(
            ''.join(f'upf_session_ul_bytes_total{{seid="0x{n}",ue_ipv4="10.45.0.{n + 1}"}} 9000\n' for n in range(1, 6)))
    expect('the poisoned fixture holds', 'poisoned', pois, True)
    expect('fedavg did not diverge', 'poisoned', lambda d: pois(d, fed='3.0'), False)
    expect('median over 1.1x', 'poisoned', lambda d: pois(d, med='1.2'), False)
    expect('krum missed a round', 'poisoned', lambda d: pois(d, kr=9), False)

    # gates and probe read their own result files.
    expect('gates without results', 'gates', base(), False)
    expect('gates with one FAIL', 'gates', lambda d: (_fixture(d), open(os.path.join(d, 'gates.txt'), 'w').write('PASS a\nFAIL b\n')), False)
    expect('gates all PASS', 'gates', lambda d: (_fixture(d), open(os.path.join(d, 'gates.txt'), 'w').write('INFO x\nPASS a\nPASS b\n')), True)
    expect('gates with INFO only', 'gates', lambda d: (_fixture(d), open(os.path.join(d, 'gates.txt'), 'w').write('INFO x\n')), False)
    probe = lambda k: lambda d: (_fixture(d), open(os.path.join(d, 'probe.txt'), 'w').write(
        ''.join(f"cycle {i} {'PASS' if i <= k else 'FAIL'} x\n" for i in range(1, 11))))
    expect('probe 10/10', 'probe', probe(10), True)
    expect('probe 9/10', 'probe', probe(9), False)
    print(f'1..{n[0]}')


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        self_test()
    elif len(sys.argv) == 3:
        sys.exit(0 if run(sys.argv[1], sys.argv[2]) else 1)
    else:
        sys.exit(__doc__)
