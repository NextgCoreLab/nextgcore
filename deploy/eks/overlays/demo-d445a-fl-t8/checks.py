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

Arms: main poisoned probe gates no-t8 freeze-global leak-raw nat-on nefd-down.
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


def check_chain(r, d, deadline_ms):
    """udmd forwarded (once per member, before) < amfd Deregistration Accept <
    amfd LoC delivered on a forwarded subscription < AF exclusion of ue3 by the
    NEF < round 4 at participants=2 with dur_ms < 0.3 T; nefd's T8 delivery on
    ue3's subscription with a reason lies between the amfd delivery and round 4.
    (nefd logs its line on the AF's 204, which the AF sends after queueing the
    report, so nefd's line and the AF's exclusion carry no causal order.)"""
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
    fwd = [x for x in every(udm, r'EE subscription (\S+) \(.*LOSS_OF_CONNECTIVITY.*\) forwarded to AMF (\S+): (\S+)')
           if x[0] < t_acc]
    if len(fwd) < 3:
        return fail(f'{len(fwd)} udmd "forwarded to AMF" LoC line(s) before the Deregistration Accept, need 3')
    amf_subs = {sub_id(x[2].group(3)) for x in fwd}
    dl = None
    for t, m, x in every(amf, r'Event notification delivered: sub=([^,\s]+), status=(\d+)'):
        if t > t_acc and x.group(1) in amf_subs and x.group(2).startswith('2'):
            dl = (t, m, x)
            break
    if not dl:
        return fail(f'no amfd 2xx delivery on a forwarded subscription {sorted(amf_subs)} after the Accept')
    exc = first(af, rf'member_selection excluded={re.escape(gpsi(3))} member=ue3 reason=nef_event '
                    r'lossOfConnectReason=(\S+) subscription=(\S+)')
    if not exc:
        return fail('no AF exclusion of ue3 by the NEF')
    if exc[0] <= dl[0]:
        return fail('the AF exclusion is not after the amfd delivery')
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
    nd = None
    for t, m, x in every(nef, r'\[demo:d445a-fl-t8\] T8 delivery sub=(\S+) monitoringType=LOSS_OF_CONNECTIVITY '
                              r'lossOfConnectReason=(\S+) status=(\d+)'):
        if dl[0] < t < rnd[0] and x.group(1) == s3:
            nd = (t, m, x)
            break
    if not nd:
        return fail(f'no nefd T8 delivery on sub={s3} between the amfd delivery and round 4')
    if nd[2].group(2) != reason or not nd[2].group(3).startswith('2'):
        return fail(f'nefd delivered lossOfConnectReason={nd[2].group(2)} status={nd[2].group(3)}, '
                    f'AF saw {reason}')
    return r.add('chain', True,
                 f'udmd forwarded x{len(fwd)} < amfd Accept < amfd delivered sub={dl[2].group(1)} '
                 f'< AF excluded {gpsi(3)} (lossOfConnectReason={reason}, nefd sub={s3}, nefd at '
                 f'{(nd[0] - dl[0]) / 1e6:+.1f} ms, AF at {(exc[0] - dl[0]) / 1e6:+.1f} ms) '
                 f'< round 4 participants=2 dur_ms={dur} (< {0.3 * deadline_ms:.0f})')


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
    ok = r1 <= 0.5 and loc <= 0.8 and pool <= 1.2 and bit
    return r.add('scorecard', ok, f'last/r1={r1} (<=0.5) last/local={loc} (<=0.8) '
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
        # A session released during the run has no series at the end (ue3's first).
        ev.append(f'{ip} released before the last scrape ({sent[ip]} bytes to the AF)')
    for ip in members:
        if ip not in sent:
            bad.append(f'member address {ip} sent nothing to the AF in the pcap')
    if not covered:
        bad.append('no member session in the UPF metrics')
    return r.add('ul_delta', not bad, '; '.join(bad) if bad else '; '.join(ev))


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
    elif arm in ('no-t8', 'nefd-down'):
        check_chain(r, d, T)
        check_straggler(r, d, T)
        verdict = r.failed('chain') and r.ok('straggler')
    elif arm == 'freeze-global':
        check_scorecard(r, d)
        verdict = r.failed('scorecard')
    elif arm == 'leak-raw':
        check_canary(r, d)
        verdict = r.failed('canary') and bool(first(load(d, 'af.log'), r'frame_refused member=ue2'))
        r.add('leak-raw-refused', verdict, 'frame_refused member=ue2 and canary_rows > 0')
    elif arm == 'nat-on':
        check_sources(r, d, members)
        verdict = r.failed('sources') and bool(first(load(d, 'af.log'), r'identity_unresolved .*peer=10\.46\.0\.1:'))
        r.add('nat-on-unresolved', verdict, 'identity_unresolved from the NATed 10.46.0.1')
    else:
        sys.exit(f'unknown arm {arm}')
    r.print()
    print(f"ARM {arm}: {'HOLDS' if verdict else 'DOES NOT HOLD'}"
          + (' (a revert arm: the targeted check must fail)' if arm not in ('main', 'poisoned', 'probe', 'gates') else ''))
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
    U = [(2, f'EE subscription usub{n} (["LOSS_OF_CONNECTIVITY"]) forwarded to AMF amf-1: http://amf:7777/namf-evts/v1/subscriptions/asub{n}')
         for n in (1, 2, 3)]
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


MAIN_FAILS = {'no udmd forwarded lines': 'chain', 'only two forwarded lines': 'chain', 'no Deregistration Accept': 'chain', 'the amfd delivery is not 2xx': 'chain', 'the amfd delivery names an unknown subscription': 'chain', 'no nefd T8 delivery': 'chain', 'nefd delivered another subscription': 'chain', 'nefd delivered no reason': 'chain', 'no AF exclusion': 'chain', 'the exclusion carries no reason': 'chain', 'round 4 at participants=3': 'chain', 'round 4 too slow': 'chain', 'ue3 resolved to another GPSI': 'sources', 'a source outside 10.45.0.0/16': 'sources', 'a member never joined': 'sources', 'scorecard over 0.5x round 1': 'scorecard', 'oracle not bit-identical': 'scorecard', 'no readmission': 'readmission', 'round 9 at participants=2': 'readmission', 'a canary row': 'canary', 'a FIN from ue3': 'no_fin', 'an RST from ue3': 'no_fin', 'UL delta below the AF bytes': 'ul_delta', 'no per-session series': 'ul_delta'}


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
    ]:
        expect(label, 'main', mut, False, fails=MAIN_FAILS[label])
    # The pcap reader must see the fixture's segments; an empty capture fails.
    expect('an empty pcap fails no_fin', 'main', lambda d: (_fixture(d), _pcap(os.path.join(d, 'fl-dn.pcap'), [])), False)

    # Revert arms hold only when their target check fails.
    expect('no-t8 does not hold on a good run', 'no-t8', base(), False)

    def strag(d):
        _fixture(d)
        p = os.path.join(d, 'af.log')
        s = open(p).read()
        s = '\n'.join(x for x in s.splitlines() if 'member_selection excluded=' not in x) + '\n'
        s = s.replace('dur_ms=12 ', 'dur_ms=30004 ')
        s += '2026-11-13T06:00:33.000Z x [demo:d445a-fl-t8] straggler_timeout round=4 member=ue3 after 30000 ms\n'
        open(p, 'w').write(s)
    expect('no-t8 holds: no exclusion, ue3 straggles to T', 'no-t8', strag, True)
    expect('freeze-global does not hold on a good scorecard', 'freeze-global', base(), False)
    expect('freeze-global holds on a frozen scorecard', 'freeze-global',
           edit('af.log', 'last/r1=0.184', 'last/r1=1.000'), True)
    expect('leak-raw does not hold on a clean run', 'leak-raw', base(), False)

    def leak(d):
        _fixture(d)
        p = os.path.join(d, 'af.log')
        s = open(p).read().replace('canary_rows=0 refused_frames=0', 'canary_rows=1 refused_frames=1')
        s += '2026-11-13T06:00:20.000Z x [demo:d445a-fl-t8] frame_refused member=ue2: canary; connection closed\n'
        open(p, 'w').write(s)
    expect('leak-raw holds on a refused, counted canary', 'leak-raw', leak, True)
    expect('nat-on does not hold on resolved sources', 'nat-on', base(), False)

    def nat(d):
        _fixture(d)
        p = os.path.join(d, 'af.log')
        s = '\n'.join(x for x in open(p).read().splitlines() if 'member_joined' not in x) + '\n'
        s += '2026-11-13T06:00:01.000Z x [demo:d445a-fl-t8] identity_unresolved member=ue1 peer=10.46.0.1:41000: UE ID: 404; refused\n'
        open(p, 'w').write(s)
    expect('nat-on holds when the NATed source is unresolved', 'nat-on', nat, True)

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
