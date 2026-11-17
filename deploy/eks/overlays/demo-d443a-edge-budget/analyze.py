#!/usr/bin/env python3
"""Assertions of demo d443a-edge-budget (nextgsim#471) over a scenario capture.

    analyze.py <arm> DIR     one PASS/FAIL line per check, exit 0 iff the arm's
                             verdict holds (a revert arm holds when every check it
                             targets FAILS and every other check, its cause
                             included, passes: REVERT_TARGET)
    analyze.py --self-test   every check passes on a complete fixture and FAILS on
                             that check's negative control; with the check forced
                             to PASS, the arm's verdict on the negative control
                             wrongly passes (so each check is what catches it);
                             no cluster, no network

DIR holds what scenario.sh captured, one directory per act (warm, act1, act2,
act3, load, flip; off; gates), each with the full log of every component at the
end of that act (kubelet --timestamps), /metrics scrapes and at.txt:
    ees.log nrf-standin.log smf.log eas.log ue.log smf.prom ees.prom
and meta.txt (arm, mode, rt_baseline, the node module records), ue-ip.txt,
ue-eec.txt, eas-keys.txt, pod-specs.json, gates.txt, off-*.txt, wrong-sub.txt,
oauth2.txt.

Acts are compared by line count: an act's lines are those of its capture past
the previous act's count, per component. Logs only grow (a pod restart would
show as a shorter log and fails `acts_ordered`), so no check reads a clock across
pods: order is used only where it is causal (job n's EES-SEL, JOB and EAS-EXEC
lines are matched by job number and per-component sequence, never by time; the
Association Update before the QoS monitoring Session Modification is one smfd
log). The one restart an arm makes on purpose (restart-flip: eesd, so the ees
pod's two logs, before `flip`) is named in meta.txt (restarted=ees@flip): that
act's lines of those two logs are its whole capture.

Log formats are the sources' (nextgcore eesd edge_budget.rs, smfd n6_delay.rs /
demo_d443a.rs; nextgsim she d443a/{eas,eec,job}.rs). Only the standard library.
"""
import os
import re
import sys
import tempfile

KEY = 'd443a-edge-budget'
P = rf'\[demo:{KEY}\] '
EAS = ('eas-local', 'eas-regional', 'eas-cloud')
EAS_IP = {'eas-local': '10.60.0.11', 'eas-regional': '10.60.0.12', 'eas-cloud': '10.60.0.13'}
DEADLINE_MS = 15
MEASURED = 'upf-n3+upf-n6'
BOGUS = re.compile(r'unknown mode "bogus" for demo "d443a-edge-budget"')

SEL = re.compile(P + r'EES-SEL ac=\S* src=(\S+) selected=\[([^\]]*)\] budget=\[[^\]]*\] '
                 r'deadline=(\d+)(?: n3_rt=(\d+))? result=(\d+)')
JOB_OK = re.compile(P + r'JOB job=(\d+) eas=(\S+) rtt=(\d+) predicted=(\S+) src=(\S+) '
                    r'deadline=(\d+) mode=(\S+) result=(ok|deadline-miss)$')
JOB_MISS = re.compile(P + r'JOB job=(\d+) eas=(\S+) rtt=\? deadline=(\d+) mode=(\S+) '
                      r'result=deadline-miss')
JOB_DEV = re.compile(P + r'JOB job=(\d+) on-device fallback reason=(\S+) mode=(\S+)$')
EXEC = re.compile(r'\[(eas-[a-z]+)\] .*' + P + r'EAS-EXEC job=(\d+) src=(\S+) eas=(\S+) ')
REG = re.compile(r'\[(eas-[a-z]+)\] .*' + P + r'EAS-REG eas=(\S+) registrationId=(\S+) endPt=(\S+) ')
PATCH = re.compile(r'\[(eas-[a-z]+)\] .*' + P + r'EAS-KPI-PATCH eas=(\S+) svcKpi\.avlComp=(\d+) \((\d+)\)')
LOAD_LOCAL_ONLY = re.compile(r'\[eas-local\] .*' + P + r'LOAD eas=eas-local avlComp 50 -> 5 locally; '
                             r'--no-kpi-patch: the EES is NOT told')
QOSMON = re.compile(P + r'QOS_MON rt=(\d+) ms n6=\[([^\]]*)\]')
SUBSCRIBED = re.compile(P + r'Nsmf_EventExposure_Subscribe QOS_MON .* 201 ')
N6_ACCEPTED = re.compile(r'accepted N6 Delay Measurement Control Information x\d+ \(Association Update')
N6_METRIC = re.compile(r'^smf_n6_delay_ms\{[^}]*endpoint="([0-9.]+)"[^}]*stat="avg"\} (\d+)', re.M)
MERGE_PATCHED = re.compile(r'EAS registration merge-patched')
SRR_CREATE = re.compile(r'QoS monitoring of QFI \d+ requested from the UPF: SRR \d+')
NO_SMF_URI = re.compile(P + r'no ees\.edge_budget\.smf_uri: no QOS_MON subscription')
NO_UN6DM = re.compile(r'UPF \S+ does not advertise UN6DM: N6 delay measurement not requested')
NO_QFQM = re.compile(r'QOS_MON subscription \S+ but \S+ did not advertise QFQM')
NOTIFY = re.compile(r'Nsmf_EventExposure_Notify QOS_MON .* subscription (\S+): status=(\d+)')
AF_REG = re.compile(r'EES registered at the NRF as AF nfInstanceId ')
STATIC_BANNER = re.compile(P + r'edge-budget: on \(mode=static')
FALLBACK = 'static-fallback'
EES_POD = ('ees.log', 'nrf-standin.log')
STANDIN = re.compile(r'\[d443a nrf-standin\] stand-in EES profile \S+ \(nfType EES, '
                     r'eees-easregistration, eees-eecregistration\) PUT -> 20[01]')

COMPONENTS = ('ees.log', 'nrf-standin.log', 'smf.log', 'eas.log', 'ue.log')


# ---- capture access ---------------------------------------------------------

def read(d, *parts):
    p = os.path.join(d, *parts)
    return open(p, errors='replace').read() if os.path.exists(p) else ''


def lines(d, act, comp):
    return read(d, act, comp).splitlines()


def meta(d):
    out = {}
    for line in read(d, 'meta.txt').splitlines():
        k, _, v = line.partition('=')
        out[k.strip()] = v.strip()
    return out


def delta(d, acts, act, comp):
    """The lines of `comp` that `act` added over the act before it in `acts`."""
    i = acts.index(act)
    cur = lines(d, act, comp)
    if restarted(d, act, comp):
        return cur
    prev = len(lines(d, acts[i - 1], comp)) if i > 0 else 0
    return cur[prev:]


def grep(rx, ls):
    return [m for m in (rx.search(x) for x in ls) if m]


def first(sel):
    return sel.group(2).split(',')[0] if sel.group(2) else ''


def ue_ip(d):
    return read(d, 'ue-ip.txt').strip()


def n6_avg(d, act, ip):
    vals = [int(v) for e, v in N6_METRIC.findall(read(d, act, 'smf.prom')) if e == ip]
    return vals[-1] if vals else None


# ---- checks: each returns (ok, why) -------------------------------------------

ACTS_MAIN = ('warm', 'act1', 'act2', 'act3', 'load')
ACTS_OF = {
    'no-kpi-patch': ('warm', 'act1', 'load'),
    'no-qos-mon': ('warm', 'act1', 'act2', 'act3'),
    'wrong-callback-token': ('warm', 'act1', 'act2', 'act3'),
    'no-upf-qos': ('warm', 'act1', 'act2', 'act3'),
    'bind-eth0': ('warm', 'act1'),
    'restart-flip': ('warm', 'act1', 'act2', 'flip'),
}


def acts_of(d):
    return ACTS_OF.get(meta(d).get('arm'), ACTS_MAIN)


def restarted(d, act, comp):
    """Whether `comp`'s capture at `act` is a new container's (named in meta.txt)."""
    return comp in EES_POD and meta(d).get('restarted') == f'ees@{act}'


def c_acts_ordered(d):
    acts = acts_of(d)
    for a in acts:
        if not os.path.isdir(os.path.join(d, a)):
            return False, f'no capture for {a}'
    for comp in COMPONENTS:
        n = [len(lines(d, a, comp)) for a in acts]
        if any(n[i] < n[i - 1] and not restarted(d, acts[i], comp) for i in range(1, len(n))):
            return False, f'{comp} shrank between acts {n} (a restart)'
    return True, 'every act captured, every log only grew (but for a restart the arm names)'


def c_registrations(d):
    regs = grep(REG, lines(d, 'warm', 'eas.log'))
    got = {(m.group(1), m.group(2), m.group(4)) for m in regs}
    want = {(e, e, EAS_IP[e]) for e in EAS}
    if not want <= got:
        return False, f'EAS-REG for {sorted(want - got)} missing'
    return True, 'eas-local/regional/cloud registered at their dn addresses'


def c_standin(d):
    if not grep(STANDIN, lines(d, 'warm', 'nrf-standin.log')):
        return False, 'no accepted stand-in EES profile PUT'
    return True, 'stand-in EES profile at the NRF'


def c_n6_provisioned(d):
    if not grep(N6_ACCEPTED, lines(d, acts_of(d)[-1], 'smf.log')):
        return False, 'smfd logged no accepted N6 Delay Measurement Control Information'
    return True, 'upfd accepted the N6 delay measurement control (Association Update)'


def c_n6_measured(d):
    missing = [ip for ip in EAS_IP.values() if n6_avg(d, 'warm', ip) is None]
    if missing:
        return False, f'no smf_n6_delay_ms avg for {missing} at warm'
    return True, 'smf_n6_delay_ms avg for every EAS'


def c_qos_mon(d):
    if not grep(SUBSCRIBED, lines(d, 'warm', 'ees.log')):
        return False, 'no 201 QOS_MON subscription at smfd'
    reps = grep(QOSMON, lines(d, 'warm', 'ees.log'))
    # The report used must carry smfd's n6Delays for the EASes: the token-less
    # notify was admitted (#1525) and the member arrived.
    good = [m for m in reps if all(f'{ip}=' in m.group(2) for ip in EAS_IP.values())]
    if not good:
        return False, f'{len(reps)} QOS_MON report(s), none with n6 for all three EASes'
    return True, f'{len(good)} QOS_MON report(s) with rtDelays and n6Delays'


def act_jobs(d, act):
    """(selections, ok-jobs, miss-jobs, device-jobs, exec-lines) of an act."""
    acts = acts_of(d)
    sel = grep(SEL, delta(d, acts, act, 'ees.log'))
    ue = delta(d, acts, act, 'ue.log')
    return (sel, grep(JOB_OK, ue), grep(JOB_MISS, ue), grep(JOB_DEV, ue),
            grep(EXEC, delta(d, acts, act, 'eas.log')))


def selection_act(d, act, src, eas, result_ok, n_min):
    """Every job of `act` selected `eas` first with budget source `src`; the UE
    ran each job on the EES's first choice, and that EAS executed it from the
    UE's address; each job is `ok` or a `deadline-miss` as `result_ok` says."""
    sel, ok, miss, dev, ex = act_jobs(d, act)
    jobs = ok + miss
    if len(jobs) < n_min or dev:
        return False, f'{len(jobs)} job(s) on an EAS, {len(dev)} on-device (want >= {n_min} on an EAS)'
    if len(sel) != len(jobs) + len(dev):
        return False, f'{len(sel)} EES-SEL line(s) for {len(jobs) + len(dev)} job(s)'
    bad = [m.group(0) for m in sel if m.group(1) != src or first(m) != eas or m.group(5) != '201']
    if bad:
        return False, f'a selection is not {src} [{eas},...] 201: {bad[0][-120:]}'
    # Causal per component: job n is the n-th selection of the act.
    for s, j in zip(sel, sorted(jobs, key=lambda m: int(m.group(1)))):
        if j.group(2) != first(s):
            return False, f'job {j.group(1)} ran on {j.group(2)}, the EES chose {first(s)}'
    ip = ue_ip(d)
    executed = {(m.group(2), m.group(1)) for m in ex if m.group(3) == ip}
    for j in ok:
        if (j.group(1), j.group(2)) not in executed:
            return False, f'job {j.group(1)} has no EAS-EXEC at {j.group(2)} from {ip}'
    want = 'ok' if result_ok else 'deadline-miss'
    wrong = [j.group(1) for j in ok if j.group(8) != want] + ([] if not result_ok else [j.group(1) for j in miss])
    if wrong:
        return False, f'job(s) {wrong} are not {want}'
    return True, f'{len(jobs)} job(s): {src} [{eas},...], run there, {want}'


def c_act1(d):
    return selection_act(d, 'act1', MEASURED, 'eas-local', True, 8)


def c_accuracy(d):
    _, ok, _, _, _ = act_jobs(d, 'act1')
    pairs = [(int(m.group(3)), int(m.group(4))) for m in ok if m.group(4).isdigit()]
    if len(pairs) < 10:
        return False, f'{len(pairs)} predicted job(s) in act1 (want 10)'
    good = sum(1 for rtt, pred in pairs if abs(rtt - pred) <= max(3, pred / 4))
    if good < 8:
        return False, f'{good} of {len(pairs)} within max(3 ms, 25 %): {pairs}'
    return True, f'{good} of {len(pairs)} within max(3 ms, 25 %)'


def no_eas_local_change(d, act):
    acts = acts_of(d)
    eas = delta(d, acts, act, 'eas.log')
    if [m for m in grep(REG, eas) if m.group(1) == 'eas-local'] or \
       [m for m in grep(PATCH, eas) if m.group(1) == 'eas-local']:
        return 'eas-local re-registered or patched'
    if grep(MERGE_PATCHED, delta(d, acts, act, 'ees.log')):
        return 'eesd merge-patched a registration'
    return None


def c_act2(d):
    v = n6_avg(d, 'act2', EAS_IP['eas-local'])
    if v is None or v < 8:
        return False, f'smf_n6_delay_ms{{endpoint="10.60.0.11",stat="avg"}} = {v} (want >= 8)'
    why = no_eas_local_change(d, 'act2')
    if why:
        return False, f'{why}: the registration must stay byte-identical'
    ok, why = selection_act(d, 'act2', MEASURED, 'eas-regional', True, 3)
    return ok, (f'N6 local {v} ms; ' + why) if ok else why


def c_act3(d):
    sel, ok, miss, dev, _ = act_jobs(d, 'act3')
    rt0 = meta(d).get('rt_baseline', '')
    rts = [int(m.group(1)) for m in grep(QOSMON, delta(d, acts_of(d), 'act3', 'ees.log'))]
    if not rt0.isdigit() or not rts or max(rts) < max(9, int(rt0) + 15):
        return False, f'rtDelays {rts} vs baseline {rt0}: no per-flow delay >= max(9, baseline + 15)'
    if len(dev) < 2 or ok or miss:
        return False, f'{len(dev)} on-device job(s), {len(ok) + len(miss)} on an EAS (want >= 2, 0)'
    if [m for m in dev if m.group(2) != 'ees-404']:
        return False, 'an on-device job is not reason=ees-404'
    if len(sel) != len(dev) or [m for m in sel if m.group(5) != '404' or m.group(1) != MEASURED]:
        return False, 'not every EES-SEL of act3 is src=upf-n3+upf-n6 result=404'
    return True, f'rt up to {max(rts)} ms; {len(dev)} job(s) on-device reason=ees-404'


def patched(d, act, avl):
    return [m for m in grep(PATCH, delta(d, acts_of(d), act, 'eas.log'))
            if m.group(1) == 'eas-local' and m.group(3) == str(avl) and m.group(4) in ('200', '204')]


def c_load(d):
    if not patched(d, 'load', 5):
        return False, 'eas-local did not merge-patch svcKpi.avlComp=5 (200/204)'
    return selection_act(d, 'load', MEASURED, 'eas-regional', True, 3)


# static: the advertisement, whatever is measured.
def c_act1_static(d):
    return selection_act(d, 'act1', 'static', 'eas-local', True, 8)


def c_act2_static(d):
    return selection_act(d, 'act2', 'static', 'eas-local', False, 3)


def c_act3_static(d):
    return selection_act(d, 'act3', 'static', 'eas-local', False, 2)


def c_load_static(d):
    if not patched(d, 'load', 5):
        return False, 'eas-local did not merge-patch svcKpi.avlComp=5'
    return selection_act(d, 'load', 'static', 'eas-local', False, 3)


# no-kpi-patch: preconditions of the revert arm.
def c_revert_pre(d):
    eas = delta(d, acts_of(d), 'load', 'eas.log')
    if not grep(LOAD_LOCAL_ONLY, eas):
        return False, 'eas-local did not apply the load locally with --no-kpi-patch'
    if [m for m in grep(PATCH, eas) if m.group(1) == 'eas-local']:
        return False, 'eas-local patched its KPI despite --no-kpi-patch'
    ok, why = selection_act(d, 'load', MEASURED, 'eas-local', False, 3)
    return ok, ('the EES kept eas-local on the stale KPI and the UE missed: ' + why) if ok else why


# Every arm: the capability sets the operator approved (2026-11-16), from the
# deployed pod spec, and the per-run sch_netem record.
SHE_EAS_CAPS = {'NET_ADMIN', 'SYS_ADMIN', 'SETUID', 'SETGID'}
GNB_NETEM_CAPS = {'NET_ADMIN'}


def container_sc(d, deploy, name):
    import json
    try:
        doc = json.loads(read(d, 'pod-specs.json') or '{}')
    except ValueError:
        return None
    items = doc.get('items', [doc]) if isinstance(doc, dict) else []
    for it in items:
        if it.get('metadata', {}).get('name') != deploy:
            continue
        for c in it.get('spec', {}).get('template', {}).get('spec', {}).get('containers', []):
            if c.get('name') == name:
                return c.get('securityContext') or {}
    return None


def caps_ok(sc, want):
    if sc is None:
        return 'not in the pod spec'
    caps = sc.get('capabilities') or {}
    if set(caps.get('add') or []) != want:
        return f'adds {sorted(caps.get("add") or [])}, want exactly {sorted(want)}'
    if caps.get('drop') != ['ALL']:
        return f'drops {caps.get("drop")}, want [ALL]'
    if sc.get('privileged') is not False or sc.get('allowPrivilegeEscalation') is not False:
        return 'privileged or allows privilege escalation'
    return None


def c_caps(d):
    for deploy, name, want in (('upf', 'she-eas', SHE_EAS_CAPS), ('gnb', 'netem', GNB_NETEM_CAPS)):
        why = caps_ok(container_sc(d, deploy, name), want)
        if why:
            return False, f'{deploy}/{name}: {why}'
    return True, 'she-eas: exactly NET_ADMIN SYS_ADMIN SETUID SETGID; gnb netem: exactly NET_ADMIN'


MODULES = ('sch_netem', 'sch_prio', 'cls_u32')


def c_netem_recorded(d):
    """Both sidecars recorded, before their pod's first tc, which of sch_netem,
    sch_prio and cls_u32 their node had loaded, and the node."""
    m = meta(d)
    out = []
    for side in ('upf', 'gnb'):
        node = m.get(f'node_{side}', '')
        if not node or node == 'unknown':
            return False, f'the {side} sidecar recorded no node ({node!r})'
        rec = dict(kv.partition('=')[::2] for kv in m.get(f'modules_{side}', '').split(',') if kv)
        if set(rec) != set(MODULES) or any(v not in ('loaded', 'absent') for v in rec.values()):
            return False, f'{side} node {node}: modules not recorded before the first tc ({rec})'
        out.append(f'{side} node {node}: ' + ' '.join(f'{k}={rec[k]}' for k in MODULES))
    same = ' (one node: the gnb record may follow the upf sidecar\'s tc)' if m['node_upf'] == m['node_gnb'] else ''
    return True, '; '.join(out) + same


def c_assoc_order(d):
    """smfd's Association Update with the N6 Delay Measurement Control comes
    before the Session Modification that creates the QoS monitoring SRR (one
    smfd log, so its order is causal)."""
    smf = lines(d, acts_of(d)[-1], 'smf.log')
    n6 = [i for i, x in enumerate(smf) if N6_ACCEPTED.search(x)]
    srr = [i for i, x in enumerate(smf) if SRR_CREATE.search(x)]
    if not srr:
        return False, 'smfd logged no QoS monitoring Session Modification (SRR)'
    # (No accepted Association Update at all is c_n6_provisioned's failure.)
    if n6 and n6[0] > srr[0]:
        return False, 'the N6 Association Update comes after the QoS monitoring Session Modification'
    at = f'line {n6[0] + 1}' if n6 else 'none'
    return True, f'Association Update (N6, {at}) before the SRR Session Modification (line {srr[0] + 1})'


EAS_UID = {'eas-local': 65531, 'eas-regional': 65532, 'eas-cloud': 65533}
EAS_KEYS = re.compile(r'^(eas-[a-z]+) uid=(\d+) keydir=(\d+):(\d+) jwk=(\d+):(\d+) cross_uid=(\d+) cross=(\S+)$')


def c_eas_isolation(d):
    """Each EAS runs as its own uid, its key directory is 0700 and its JWK its
    own (not group- or world-writable), and another EAS's uid cannot read its
    private key."""
    rows = {m.group(1): m for m in (EAS_KEYS.match(x) for x in read(d, 'eas-keys.txt').splitlines()) if m}
    if set(rows) != set(EAS):
        return False, f'key records for {sorted(rows)}, want {list(EAS)}'
    for e, m in rows.items():
        uid = int(m.group(2))
        if uid != EAS_UID[e]:
            return False, f'{e} runs as uid {uid}, want {EAS_UID[e]}'
        if m.group(3) != '700' or int(m.group(4)) != uid:
            return False, f'{e}: key directory {m.group(3)}:{m.group(4)}, want 700:{uid}'
        if int(m.group(6)) != uid or int(m.group(5), 8) & 0o022:
            return False, f'{e}: JWK {m.group(5)}:{m.group(6)}, want owned by {uid} and not group/other-writable'
        if int(m.group(7)) == uid or m.group(8) != 'denied':
            return False, f'{e}: uid {m.group(7)} reading its private key: {m.group(8)}'
    return True, 'each EAS its own uid (65531-65533), key directory 0700, JWK its own; cross-EAS key read denied'


def fallback_act1(d):
    """Act 1 with no QOS_MON report at eesd: the advertisement (static-fallback)
    keeps eas-local, and the jobs are on time."""
    return selection_act(d, 'act1', FALLBACK, 'eas-local', True, 8)


def no_reports(d):
    ees = lines(d, acts_of(d)[-1], 'ees.log')
    if grep(QOSMON, ees):
        return 'eesd got a QOS_MON report'
    return None


def c_nosub_pre(d):
    """no-qos-mon: eesd has no smf_uri, holds no subscription, gets no report, and
    ranks Act 1 on the advertisement."""
    acts = acts_of(d)
    if not grep(NO_SMF_URI, lines(d, 'warm', 'ees.log')):
        return False, 'eesd did not log that it has no smf_uri'
    if grep(SUBSCRIBED, lines(d, acts[-1], 'ees.log')):
        return False, 'eesd holds a QOS_MON subscription'
    why = no_reports(d)
    if why:
        return False, why
    ok, why = fallback_act1(d)
    return ok, ('no smf_uri, no subscription, no report; Act 1 ' + why) if ok else why


def c_wrongtoken_pre(d):
    """wrong-callback-token: smfd accepted a subscription whose notifUri carries a
    path token eesd never minted, refused (401) every notify on it at eesd, and
    eesd, holding no subscription of its own, got no report."""
    acts = acts_of(d)
    sub = read(d, 'wrong-sub.txt')
    st = re.search(r'^HTTP/\S+ (\d+)', sub, re.M)
    loc = re.search(r'^location: \S*/subscriptions/(\S+)\s*$', sub, re.M | re.I)
    if not st or st.group(1) != '201' or not loc:
        return False, f'smfd did not create the wrong-token subscription: {sub[:200]!r}'
    sid = loc.group(1)
    notes = [m for m in grep(NOTIFY, lines(d, acts[-1], 'smf.log')) if m.group(1) == sid]
    if not notes:
        return False, f'smfd sent no notify on subscription {sid}'
    if [m for m in notes if m.group(2) != '401']:
        return False, f'a notify on {sid} was not refused (401): {sorted({m.group(2) for m in notes})}'
    if not grep(NO_SMF_URI, lines(d, 'warm', 'ees.log')):
        return False, 'eesd did not log that it has no smf_uri'
    if grep(SUBSCRIBED, lines(d, acts[-1], 'ees.log')):
        return False, 'eesd holds a QOS_MON subscription of its own'
    why = no_reports(d)
    if why:
        return False, why
    ok, why = fallback_act1(d)
    return ok, (f'{len(notes)} notify(s) on the wrong token, all 401; Act 1 ' + why) if ok else why


def container_env(d, deploy, name):
    import json
    try:
        doc = json.loads(read(d, 'pod-specs.json') or '{}')
    except ValueError:
        return None
    for it in doc.get('items', []) if isinstance(doc, dict) else []:
        if it.get('metadata', {}).get('name') != deploy:
            continue
        for c in it.get('spec', {}).get('template', {}).get('spec', {}).get('containers', []):
            if c.get('name') == name:
                return {e.get('name'): e.get('value') for e in c.get('env') or []}
    return None


def c_noupf_pre(d):
    """no-upf-qos: upfd runs without N6 delay measurement and QoS flow
    monitoring, so smfd provisions neither, while eesd's subscription stands and
    no report reaches it; Act 1 ranks on the advertisement."""
    acts = acts_of(d)
    env = container_env(d, 'upf', 'upf')
    if env is None:
        return False, 'no upf container in the pod spec'
    on = [k for k in ('UPF_N6_DELAY_MEASUREMENT', 'UPF_QOS_FLOW_MONITORING') if k in env]
    if on:
        return False, f'upfd still has {on}'
    smf = lines(d, acts[-1], 'smf.log')
    if not grep(NO_UN6DM, smf):
        return False, 'smfd did not log the UPF without UN6DM'
    if not grep(NO_QFQM, smf):
        return False, 'smfd did not log the UPF without QFQM for the subscription'
    if grep(N6_ACCEPTED, smf):
        return False, 'smfd provisioned N6 delay measurement'
    if [ip for ip in EAS_IP.values() if n6_avg(d, 'warm', ip) is not None]:
        return False, 'smfd has an N6 delay result'
    if not grep(SUBSCRIBED, lines(d, 'warm', 'ees.log')):
        return False, 'eesd has no QOS_MON subscription (the arm is not no-qos-mon)'
    why = no_reports(d)
    if why:
        return False, why
    ok, why = fallback_act1(d)
    return ok, ('no UN6DM, no QFQM, subscribed, no report; Act 1 ' + why) if ok else why


def c_bind_pre(d):
    """bind-eth0: the EEC is bound to eth0; eesd still selects eas-local on the
    measured budget, but no job reaches it (no EAS-EXEC), so each one misses."""
    if not re.search(r'^\s*device:\s*eth0\s*$', read(d, 'ue-eec.txt'), re.M):
        return False, f'the EEC is not bound to eth0: {read(d, "ue-eec.txt")[:100]!r}'
    sel, ok, miss, dev, ex = act_jobs(d, 'act1')
    if len(sel) < 8 or [m for m in sel if m.group(1) != MEASURED or first(m) != 'eas-local' or m.group(5) != '201']:
        return False, f'{len(sel)} selection(s), not all {MEASURED} [eas-local,...] 201'
    if ok or dev or len(miss) < 8 or [m for m in miss if m.group(2) != 'eas-local']:
        return False, f'{len(ok)} job(s) answered, {len(dev)} on-device, {len(miss)} unanswered (want >= 8 unanswered on eas-local)'
    if ex:
        return False, f'{len(ex)} job(s) reached an EAS'
    return True, f'EEC on eth0: {len(sel)} selection(s) of eas-local, {len(miss)} job(s) never reached dn'


def c_flip(d):
    """restart-flip: with Act 2's netem still on eas-local, eesd restarted in mode
    static ranks on the advertisement again: eas-local, which misses."""
    if not grep(STATIC_BANNER, lines(d, 'flip', 'ees.log')):
        return False, 'the restarted eesd is not in mode static'
    v = n6_avg(d, 'flip', EAS_IP['eas-local'])
    if v is None or v < 8:
        return False, f'eas-local N6 {v} ms at the flip: Act 2\'s netem is not on (want >= 8)'
    regs = {m.group(1) for m in grep(REG, delta(d, acts_of(d), 'flip', 'eas.log'))}
    if regs != set(EAS):
        return False, f'EASes registered again at the restarted eesd: {sorted(regs)}'
    ok, why = selection_act(d, 'flip', 'static', 'eas-local', False, 3)
    return ok, (f'restarted in static, N6 local {v} ms: ' + why) if ok else why


def c_oauth2(d):
    """oauth2: amfd and smfd enforce OAuth2, a bare Subscribe is refused, and
    eesd's Subscribe (as an AF with an NRF token) is accepted after it
    registered at the NRF."""
    txt = read(d, 'oauth2.txt')
    for nf in ('amf', 'smf'):
        if not re.search(rf'^{nf}: .*OAuth2 enforcement enabled', txt, re.M):
            return False, f'{nf}d did not enable OAuth2 enforcement'
    bare = re.search(r'^bare-subscribe: (\S*)', txt, re.M)
    if not bare or bare.group(1) != '401':
        return False, f'a bare Subscribe at smfd got {bare.group(1) if bare else "nothing"}, want 401'
    ees = lines(d, acts_of(d)[-1], 'ees.log')
    reg = [i for i, x in enumerate(ees) if AF_REG.search(x)]
    sub = [i for i, x in enumerate(ees) if SUBSCRIBED.search(x)]
    if not reg:
        return False, 'eesd did not register at the NRF as an AF'
    # (No subscription at all is c_qos_mon's failure.)
    if sub and sub[0] < reg[0]:
        return False, 'eesd subscribed before it registered at the NRF (no token on that Subscribe)'
    return True, 'amfd and smfd require OAuth2; bare Subscribe 401; eesd (AF, NRF token) subscribed 201'


# gates
GATES = {
    'nr-she-eas bogus': (BOGUS, r'rc=1\b'),
    'eesd bogus': (BOGUS, r'rc=(?!0\b|124\b)\d+'),
    'smfd bogus': (BOGUS, r'rc=(?!0\b|124\b)\d+'),
    'nr-ue bogus': (BOGUS, r'rc=(?!0\b|124\b)\d+'),
}


def gate_line(d, name):
    for line in read(d, 'gates.txt').splitlines():
        if line.startswith(name + ':'):
            return line
    return ''


def c_gates_startup(d):
    for name, (rx, rc) in GATES.items():
        line = gate_line(d, name)
        if not rx.search(line) or not re.search(rc, line):
            return False, f'{name}: {line[:200] or "not run"}'
    return True, 'nr-she-eas, eesd, smfd and nr-ue refuse mode: bogus at startup (UnknownMode)'


def c_gates_runtime(d):
    line = gate_line(d, 'nr-cli set-bogus')
    if not BOGUS.search(line) or 'mode=measured-budget' not in line.split('rc=')[-1]:
        return False, f'set mode=bogus: {line[:300] or "not run"}'
    line = gate_line(d, 'nr-cli set-static')
    if 'mode=static' not in line:
        return False, f'set mode=static: {line[:300] or "not run"}'
    audit = [x for x in lines(d, 'gates', 'ue.log') if re.search(P + r'audit:.*bogus', x)]
    if not audit:
        return False, 'the refused set is not audited'
    return True, 'nr-cli: bogus refused (audited, mode kept), static accepted'


# off
def c_off(d):
    smf = lines(d, 'off', 'smf.log')
    if not grep(N6_ACCEPTED, smf):
        return False, 'smfd did not provision N6 delay measurement with the demo off (#1502)'
    for comp in ('ees.log', 'smf.log', 'ue.log', 'eas.log'):
        hit = [x for x in lines(d, 'off', comp) if '[demo:' in x or 'DEMO MODE ACTIVE' in x]
        if hit:
            return False, f'{comp}: a demo line with the demo off: {hit[0][-120:]}'
    if '+n6Delays' in read(d, 'off', 'smf.log'):
        return False, 'smfd added n6Delays with the demo off'
    cli = read(d, 'off-cli.txt')
    if 'Unknown command: she-offload' not in cli or 'JOB' in cli or '[demo:' in cli:
        return False, f'she-offload is not the unknown command it was: {cli[:200]}'
    eas = read(d, 'off-eas.txt')
    if 'runs only with demo d443a-edge-budget enabled' not in eas or 'rc=1' not in eas:
        return False, f'nr-she-eas started without the demo: {eas[:200]}'
    return True, 'demo off: N6 provisioned, no demo line, no n6Delays, no she-offload, no EAS'


BASE = [c_caps, c_netem_recorded, c_acts_ordered, c_registrations, c_standin, c_eas_isolation]
MEASURES = [c_n6_provisioned, c_n6_measured, c_assoc_order, c_qos_mon]
ARMS = {
    'main': BASE + MEASURES + [c_act1, c_accuracy, c_act2, c_act3, c_load],
    'static': BASE + MEASURES[:3] + [c_act1_static, c_act2_static, c_act3_static, c_load_static],
    'oauth2': BASE + MEASURES + [c_oauth2, c_act1, c_accuracy, c_act2, c_act3, c_load],
    'restart-flip': BASE + MEASURES + [c_act1, c_act2, c_flip],
    'no-kpi-patch': BASE + MEASURES + [c_act1, c_revert_pre, c_load],
    'no-qos-mon': BASE + [c_n6_provisioned, c_n6_measured, c_nosub_pre, c_act2, c_act3],
    'wrong-callback-token': BASE + [c_n6_provisioned, c_n6_measured, c_wrongtoken_pre, c_act2, c_act3],
    'no-upf-qos': BASE + [c_noupf_pre, c_act2, c_act3],
    'bind-eth0': BASE + MEASURES + [c_bind_pre, c_act1],
    'gates': [c_caps, c_netem_recorded, c_eas_isolation, c_gates_startup, c_gates_runtime],
    'off': [c_caps, c_netem_recorded, c_off],
}
# A revert arm holds when every check it targets FAILS and every other check
# (its cause, *_pre, included) passes.
REVERT_TARGET = {
    'no-kpi-patch': {'c_load'},
    'no-qos-mon': {'c_act2', 'c_act3'},
    'wrong-callback-token': {'c_act2', 'c_act3'},
    'no-upf-qos': {'c_act2', 'c_act3'},
    'bind-eth0': {'c_act1'},
}
# Checks reported but not part of the verdict: the plan states them as targets on
# real paths, not guarantees. c_accuracy: the anchor proves the loop, not the
# estimation. On EKS the prediction came out ABOVE the measured rtt (Act 1
# predicted 11, measured 9-10; run 20261116T003320Z): rtDelays includes the
# gNB's stated 1 + 1 ms RAN delay, which the simulated radio never incurs.
ADVISORY = {'c_accuracy'}


def verdict(arm, d, forced=None):
    results = []
    for c in ARMS[arm]:
        ok, why = (True, 'forced') if c.__name__ == forced else c(d)
        results.append((c.__name__, ok, why))
    target = REVERT_TARGET.get(arm, set())
    holds = True
    for name, ok, _ in results:
        if name in ADVISORY:
            continue
        if name in target:
            holds &= not ok
        else:
            holds &= ok
    return holds, results


def main(arm, d):
    holds, results = verdict(arm, d)
    for name, ok, why in results:
        tag = 'PASS' if ok else 'FAIL'
        if name in ADVISORY:
            tag += ' (advisory)'
        if name in REVERT_TARGET.get(arm, set()):
            tag += ' (revert target: must FAIL)'
        print(f'{tag} {name[2:]}: {why}')
    print(f'VERDICT {arm}: {"HOLDS" if holds else "DOES NOT HOLD"}')
    return 0 if holds else 1


# ---- self-test ------------------------------------------------------------------
# Fixture lines in the sources' formats (see the module docstring), with the
# plan's and #1523's values: rt 6, N6 local 2 / regional 3 / cloud 20 at warm and
# Act 1 (budgets 12/14/...), local N6 18 in Act 2 (regional 14), rt 26 in Act 3
# (404), avlComp 5 in the load act (local 30 > 15: regional).

UE_IP = '10.45.0.2'
TS = '2026-11-15T10:00:00.000000000Z'


def sel_line(src, selected, result='201', rt=6):
    sel = ','.join(selected)
    budget = ','.join(f'{e}=12' for e in selected)
    return (f'{TS} INFO [demo:{KEY}] EES-SEL ac=ac-d443a src={src} selected=[{sel}] '
            f'budget=[{budget}] deadline=15 n3_rt={rt} result={result}')


def job_line(n, eas, rtt, pred, src, result, mode):
    return (f'{TS} INFO [demo:{KEY}] JOB job={n} eas={eas} rtt={rtt} predicted={pred} '
            f'src={src} deadline=15 mode={mode} result={result}')


def exec_line(n, eas):
    return (f'{TS} [{eas}] {TS} INFO [demo:{KEY}] EAS-EXEC job={n} src={UE_IP} eas={eas} '
            f'reqComp=100 avlComp=50 compute=2ms')


def qosmon_line(rt, local=2):
    return (f'{TS} INFO [demo:{KEY}] QOS_MON rt={rt} ms n6=[10.60.0.11={local}ms,'
            f'10.60.0.12=3ms,10.60.0.13=20ms]')


def metric(local):
    return ''.join(f'smf_n6_delay_ms{{upf="1",endpoint="{ip}",stat="avg"}} {v}\n'
                   for ip, v in (('10.60.0.11', local), ('10.60.0.12', 3), ('10.60.0.13', 20)))


SMF_N6_LINE = ('2026-11-16T00:24:51.996274977Z [2026-11-16T00:24:51.996Z INFO  nextgcore_smfd::n6_delay] '
               'UPF 10.10.1.73:8805 accepted N6 Delay Measurement Control Information x1 '
               '(Association Update, TS 29.244 §5.33.8.2)')
# The real smfd lines (EKS run 20261116T140046Z).
SMF_SRR_LINE = ('2026-11-16T14:03:55.365894591Z [2026-11-16T14:03:55.365Z INFO  nextgcore_smfd::qos_mon] ref=1: '
                'QoS monitoring of QFI 9 requested from the UPF: SRR 1, Periodic every 2 s (QOS_MON subscription '
                '52d26401-7f09-48df-8f70-d2ab25858749)')
SUB_LINE = (f'{TS} INFO [demo:{KEY}] Nsmf_EventExposure_Subscribe QOS_MON (anyUeInd, '
            f'PERIODIC 2 s, QoSMonitoring) at http://smf:7777: 201 /nsmf-event-exposure/v1/subscriptions/1')
NO_SMF_URI_LINE = (f'{TS} INFO [demo:{KEY}] no ees.edge_budget.smf_uri: no QOS_MON subscription, so '
                   f'measured-budget ranks on the advertisement (src=static-fallback)')
AF_REG_LINE = (f'{TS} INFO EES registered at the NRF as AF nfInstanceId 6b1d7e3c-0000-4000-8000-0000000004ee '
               f'(TS 23.558 §6.2), for 5GC access tokens')
WRONG_SUB = 'w1'


def notify_line(sub, status):
    return (f'{TS} [2026-11-17T10:00:00.000Z INFO  nextgcore_smfd::event_exposure] Nsmf_EventExposure_Notify '
            f'QOS_MON (SUPI imsi-999700000000001, PSI 1) → subscription {sub}: status={status}')


EAS_KEYS_OK = ''.join(f'{e} uid={u} keydir=700:{u} jwk=644:{u} cross_uid={EAS_UID[EAS[(i + 1) % 3]]} cross=denied\n'
                      for i, (e, u) in enumerate(EAS_UID.items()))
OAUTH2_OK = ('amf: 2026-11-17T10:00:00Z [INFO  nextgcore_amfd] OAuth2 enforcement enabled (JWKS: http://nrf:7777/x)\n'
             'smf: 2026-11-17T10:00:00Z [INFO  nextgcore_smfd] OAuth2 enforcement enabled (JWKS: http://nrf:7777/x)\n'
             'bare-subscribe: 401\n')
FALLBACK_ARMS = ('no-qos-mon', 'wrong-callback-token', 'no-upf-qos')


def fixture(arm):
    """{act: {component: [lines]}, '_meta': ..., '_files': {...}} of a run that
    meets every check of `arm` (every arm but gates and off), its revert
    targets aside."""
    mode = 'static' if arm == 'static' else 'measured-budget'
    src = {'static': 'static'}.get(arm, FALLBACK if arm in FALLBACK_ARMS else MEASURED)
    reports = arm not in FALLBACK_ARMS
    regs = [f'{TS} [{e}] {TS} INFO [demo:{KEY}] EAS-REG eas={e} registrationId=r-{e} '
            f'endPt={EAS_IP[e]} maxRespTime=10 ms avlComp=50' for e in EAS]
    ees0 = {'no-qos-mon': [NO_SMF_URI_LINE], 'wrong-callback-token': [NO_SMF_URI_LINE],
            'no-upf-qos': [SUB_LINE], 'oauth2': [AF_REG_LINE, SUB_LINE, qosmon_line(6)]}.get(
        arm, [SUB_LINE, qosmon_line(6)])
    smf0 = {'no-upf-qos': ['2026-11-17T10:00:00Z [INFO  nextgcore_smfd::n6_delay] UPF 10.10.1.73:8805 does not '
                           'advertise UN6DM: N6 delay measurement not requested',
                           '2026-11-17T10:00:01Z [WARN  nextgcore_smfd::qos_mon] ref=1: QOS_MON subscription s1 '
                           'but 10.10.1.73:8805 did not advertise QFQM (TS 29.244 §5.24.4.1): no QoS monitoring '
                           'requested'],
            'wrong-callback-token': [SMF_N6_LINE] + [notify_line(WRONG_SUB, 401) for _ in range(3)],
            'no-qos-mon': [SMF_N6_LINE]}.get(arm, [SMF_N6_LINE, SMF_SRR_LINE])
    base = {
        'ees.log': ees0,
        'nrf-standin.log': [f'{TS} 2026-11-15T10:00:00Z [d443a nrf-standin] stand-in EES profile '
                            f'6b1d7e3c-0000-4000-8000-00000000471e (nfType EES, eees-easregistration, '
                            f'eees-eecregistration) PUT -> 201'],
        'smf.log': smf0,
        'eas.log': list(regs),
        'ue.log': [],
    }
    acts = {}
    cur = {k: list(v) for k, v in base.items()}
    nom6 = arm == 'no-upf-qos'
    prom = {'warm': '' if nom6 else metric(2)}
    acts['warm'] = {k: list(v) for k, v in cur.items()}
    n = 0

    def run(act, k, eas, rtt, pred, result, sel_src=None, sel_eas=None):
        nonlocal n
        for _ in range(k):
            n += 1
            cur['ees.log'].append(sel_line(sel_src or src, [sel_eas or eas, 'eas-cloud']))
            cur['ue.log'].append(job_line(n, eas, rtt, pred, sel_src or src, result, mode))
            cur['eas.log'].append(exec_line(n, eas))
        acts[act] = {k2: list(v) for k2, v in cur.items()}

    def qos(rt, local=2):
        if reports:
            cur['ees.log'].append(qosmon_line(rt, local))

    local_pred = 10 if src != MEASURED else 12
    qos(6)
    if arm == 'bind-eth0':
        # The EES selects eas-local on the measured budget; no job reaches dn.
        for _ in range(10):
            n += 1
            cur['ees.log'].append(sel_line(MEASURED, ['eas-local', 'eas-cloud']))
            cur['ue.log'].append(f'{TS} INFO [demo:{KEY}] JOB job={n} eas=eas-local rtt=? deadline=15 '
                                 f'mode={mode} result=deadline-miss (connect: timed out)')
        acts['act1'] = {k: list(v) for k, v in cur.items()}
    else:
        run('act1', 10, 'eas-local', 11, local_pred, 'ok')
    prom['act1'] = prom['warm']
    if arm not in ('no-kpi-patch', 'bind-eth0'):
        qos(6, 18)
        if src != MEASURED:
            run('act2', 3, 'eas-local', 38, 10, 'deadline-miss')
        else:
            run('act2', 3, 'eas-regional', 13, 14, 'ok')
        prom['act2'] = '' if nom6 else metric(18)
        if arm == 'restart-flip':
            # eesd restarted in mode static: a new ees pod, so a new log; every
            # EAS registers again; the jobs, on eas-local, miss (netem still on).
            cur['ees.log'] = [f'{TS} WARN DEMO MODE ACTIVE: {KEY}=static',
                              f'{TS} INFO [demo:{KEY}] edge-budget: on (mode=static, deadline=15 ms local policy)']
            cur['nrf-standin.log'] = list(base['nrf-standin.log'])
            cur['eas.log'] += [r.replace('registrationId=r-', 'registrationId=r2-') for r in regs]
            run('flip', 3, 'eas-local', 38, 10, 'deadline-miss', sel_src='static')
            prom['flip'] = metric(18)
        else:
            qos(26)
            if src != MEASURED:
                run('act3', 2, 'eas-local', 30, 10, 'deadline-miss')
            else:
                for _ in range(2):
                    n += 1
                    cur['ees.log'].append(sel_line(MEASURED, [], '404', 26))
                    cur['ue.log'].append(f'{TS} INFO [demo:{KEY}] JOB job={n} on-device fallback '
                                         f'reason=ees-404 mode={mode}')
                acts['act3'] = {k: list(v) for k, v in cur.items()}
            prom['act3'] = '' if nom6 else metric(2)
    if arm == 'no-kpi-patch':
        cur['eas.log'].append(f'{TS} [eas-local] {TS} WARN [demo:{KEY}] LOAD eas=eas-local avlComp 50 -> 5 '
                              f'locally; --no-kpi-patch: the EES is NOT told (revert arm)')
        run('load', 3, 'eas-local', 23, 12, 'deadline-miss')
    elif arm in ('main', 'static', 'oauth2'):
        cur['eas.log'].append(f'{TS} [eas-local] {TS} INFO [demo:{KEY}] EAS-KPI-PATCH eas=eas-local '
                              f'svcKpi.avlComp=5 (200)')
        if arm == 'static':
            run('load', 3, 'eas-local', 23, 10, 'deadline-miss')
        else:
            run('load', 3, 'eas-regional', 13, 14, 'ok')
    prom['load'] = metric(2)
    for a in acts:
        acts[a]['smf.prom'] = [prom.get(a, metric(2))]
    acts['_meta'] = f'arm={arm}\nmode={mode}\nrt_baseline=6\n' + ('restarted=ees@flip\n' if arm == 'restart-flip' else '')
    files = {'eas-keys.txt': EAS_KEYS_OK,
             'ue-eec.txt': '      device: eth0\n' if arm == 'bind-eth0' else '      device: uesimtun0\n'}
    if arm == 'wrong-callback-token':
        files['wrong-sub.txt'] = f'HTTP/2 201\nlocation: http://smf:7777/nsmf-event-exposure/v1/subscriptions/{WRONG_SUB}\n'
    if arm == 'oauth2':
        files['oauth2.txt'] = OAUTH2_OK
    if arm == 'no-upf-qos':
        files['pod-specs.json'] = pod_specs(upf_env=('UPF_NAT_EXCLUDE',))
    acts['_files'] = files
    return acts


def gates_fixture():
    """The real gates capture of run 20261116T011728Z (ANSI stripped): its
    gates.txt, kept beside this file, and the UE's audit lines."""
    here = os.path.dirname(os.path.abspath(__file__))
    g = open(os.path.join(here, 'fixture-gates-20261116T011728Z.txt')).read()
    ue = ['2026-11-16T01:24:06.858634695Z 2026-11-16T01:24:06.858596Z  WARN nextgsim_demo: '
          '[demo:d443a-edge-budget] audit: rejected set mode="bogus" from nr-cli: demo config: '
          'unknown mode "bogus" for demo "d443a-edge-budget" (known modes ["measured-budget", '
          '"static"]); mode unchanged (measured-budget)',
          '2026-11-16T01:24:09.080948021Z 2026-11-16T01:24:09.080896Z  WARN nextgsim_demo: '
          '[demo:d443a-edge-budget] audit: mode measured-budget -> static from nr-cli; applies '
          'to the next decision']
    return {'gates': {'ue.log': ue}, '_files': {'gates.txt': g, 'eas-keys.txt': EAS_KEYS_OK}, '_meta': 'arm=gates\n'}


def off_fixture():
    """The off arm, from run 20261116T011013Z's real lines."""
    return {'off': {
        'smf.log': ['2026-11-16T01:11:02.789343434Z [2026-11-16T01:11:02.789Z INFO  nextgcore_smfd::n6_delay] '
                    'UPF 10.10.5.190:8805 accepted N6 Delay Measurement Control Information x1 '
                    '(Association Update, TS 29.244 §5.33.8.2)'],
        'ees.log': [f'{TS} INFO EEC Register'], 'ue.log': [f'{TS} INFO UE up'],
        'eas.log': [f'{TS} [d443a-sidecar] dn ready']},
        '_files': {'off-cli.txt': 'ERROR: Unknown command: she-offload\ncommand terminated with exit code 1\n',
                   'off-eas.txt': '2026-11-16T01:14:06.486914Z ERROR nr_she_eas: nr-she-eas: /tmp/d443a/off.yaml: '
                                  'nr-she-eas runs only with demo d443a-edge-budget enabled (demo.enabled and '
                                  'demo.d443a-edge-budget.enabled)\nrc=1\n'},
        '_meta': 'arm=off\nmode=off\n'}


UPF_ENV = ('UPF_NAT_EXCLUDE', 'UPF_N6_DELAY_MEASUREMENT', 'UPF_QOS_FLOW_MONITORING')


def pod_specs(she=SHE_EAS_CAPS, gnb=GNB_NETEM_CAPS, drop=('ALL',), privileged=False, upf_env=UPF_ENV,
              she_name='she-eas'):
    import json

    def dep(name, cname, add, env=()):
        return {'metadata': {'name': name}, 'spec': {'template': {'spec': {'containers': [
            {'name': name, 'env': [{'name': e, 'value': 'true'} for e in env]},
            {'name': cname, 'securityContext': {
                'privileged': privileged, 'allowPrivilegeEscalation': False, 'runAsUser': 0,
                'capabilities': {'drop': list(drop), 'add': sorted(add)}}}]}}}}
    return json.dumps({'kind': 'List', 'items': [dep('upf', she_name, she, upf_env), dep('gnb', 'netem', gnb)]})


MODULES_OK = {'node_upf': 'ip-10-10-0-1', 'modules_upf': 'sch_netem=loaded,sch_prio=absent,cls_u32=absent',
              'node_gnb': 'ip-10-10-0-2', 'modules_gnb': 'sch_netem=absent,sch_prio=absent,cls_u32=absent'}


def with_modules(fx, **kw):
    """A copy of `fx` whose module record differs from MODULES_OK by `kw` (a
    value None drops that key)."""
    import copy
    out = copy.deepcopy(fx)
    out['_modules'] = {k: v for k, v in dict(MODULES_OK, **kw).items() if v is not None}
    return out


def write(fx, root):
    for act, comps in fx.items():
        if act == '_meta':
            open(os.path.join(root, 'meta.txt'), 'w').write(comps)
            continue
        if act in ('_no_netem_record', '_modules'):
            continue
        if act == '_files':
            for name, text in comps.items():
                open(os.path.join(root, name), 'w').write(text)
            continue
        os.makedirs(os.path.join(root, act), exist_ok=True)
        for comp, ls in comps.items():
            text = ''.join(ls) if comp.endswith('.prom') else '\n'.join(ls) + ('\n' if ls else '')
            open(os.path.join(root, act, comp), 'w').write(text)
    open(os.path.join(root, 'ue-ip.txt'), 'w').write(UE_IP + '\n')
    if not os.path.exists(os.path.join(root, 'pod-specs.json')):
        open(os.path.join(root, 'pod-specs.json'), 'w').write(pod_specs())
    mp = os.path.join(root, 'meta.txt')
    if '_no_netem_record' not in fx:
        open(mp, 'a').write(''.join(f'{k}={v}\n' for k, v in fx.get('_modules', MODULES_OK).items()))


def edit(fx, act, comp, fn):
    """A copy of `fx` with `fn` applied to the lines `act` added to `comp`; the
    later acts' captures carry the same edited lines (logs only grow)."""
    import copy
    out = copy.deepcopy(fx)
    keys = [k for k in out if not k.startswith('_')]
    if act not in keys:
        return out
    i = keys.index(act)
    prev = len(out[keys[i - 1]].get(comp, [])) if i > 0 else 0
    cur = len(out[act][comp])
    new = fn(out[act][comp][prev:cur])
    restart = re.search(r'^restarted=ees@(\S+)$', out.get('_meta', ''), re.M)
    for a in keys[i:]:
        if a != act and restart and a == restart.group(1) and comp in EES_POD:
            break   # a new container's log: the edit does not carry over
        ls = out[a][comp]
        out[a][comp] = ls[:prev] + new + ls[cur:]
    return out


def edit_only(fx, act, comp, fn):
    """A copy of `fx` with `fn` applied to `act`'s capture of `comp` alone."""
    import copy
    out = copy.deepcopy(fx)
    if act in out:
        out[act][comp] = fn(out[act][comp])
    return out


def drop(rx):
    return lambda ls: [x for x in ls if not re.search(rx, x)]


def sub(rx, rep):
    return lambda ls: [re.sub(rx, rep, x) for x in ls]


def with_files(fx, **files):
    import copy
    out = copy.deepcopy(fx)
    out['_files'] = dict(out.get('_files', {}), **files)
    return out


def drop_act(fx, act):
    import copy
    out = copy.deepcopy(fx)
    out.pop(act, None)
    return out


def append(line):
    return lambda ls: ls + [line]


def nth(rx, rep, n=0):
    """Substitute in the n-th line matching rx only."""
    def f(ls):
        out, k = [], 0
        for x in ls:
            if re.search(rx, x):
                if k == n:
                    x = re.sub(rx, rep, x)
                k += 1
            out.append(x)
        return out
    return f


def drop_nth(rx, n=0):
    def f(ls):
        out, k = [], 0
        for x in ls:
            if re.search(rx, x):
                k += 1
                if k - 1 == n:
                    continue
            out.append(x)
        return out
    return f


def common_negatives(fx, upf_env=UPF_ENV):
    ps = lambda **kw: pod_specs(upf_env=upf_env, **kw)  # noqa: E731
    return {
        'c_caps': [
            with_files(fx, **{'pod-specs.json': ps(she=SHE_EAS_CAPS | {'CHOWN'})}),
            with_files(fx, **{'pod-specs.json': ps(she=SHE_EAS_CAPS | {'KILL'})}),
            with_files(fx, **{'pod-specs.json': ps(she=SHE_EAS_CAPS - {'SYS_ADMIN'})}),
            with_files(fx, **{'pod-specs.json': ps(gnb={'NET_ADMIN', 'SYS_ADMIN'})}),
            with_files(fx, **{'pod-specs.json': ps(drop=())}),
            with_files(fx, **{'pod-specs.json': ps(privileged=True)}),
            # No she-eas container in the upf pod spec.
            with_files(fx, **{'pod-specs.json': ps(she_name='eas')}),
        ],
        'c_netem_recorded': [
            dict(fx, _no_netem_record=True),
            with_modules(fx, node_gnb=None, modules_gnb=None),
            with_modules(fx, node_upf=None, modules_upf=None),
            with_modules(fx, modules_gnb='sch_netem=absent,sch_prio=absent'),
            with_modules(fx, modules_upf='sch_netem=maybe,sch_prio=absent,cls_u32=absent'),
            with_modules(fx, node_gnb='unknown'),
        ],
        'c_eas_isolation': [
            with_files(fx, **{'eas-keys.txt': ''.join(EAS_KEYS_OK.splitlines(True)[:2])}),
            with_files(fx, **{'eas-keys.txt': EAS_KEYS_OK.replace('eas-regional uid=65532 keydir=700:65532 jwk=644:65532',
                                                                  'eas-regional uid=65531 keydir=700:65531 jwk=644:65531')}),
            with_files(fx, **{'eas-keys.txt': EAS_KEYS_OK.replace('keydir=700:65531', 'keydir=755:65531')}),
            with_files(fx, **{'eas-keys.txt': EAS_KEYS_OK.replace('keydir=700:65531', 'keydir=700:65532')}),
            with_files(fx, **{'eas-keys.txt': EAS_KEYS_OK.replace('jwk=644:65532', 'jwk=644:65533')}),
            with_files(fx, **{'eas-keys.txt': EAS_KEYS_OK.replace('jwk=644:65533', 'jwk=666:65533')}),
            with_files(fx, **{'eas-keys.txt': EAS_KEYS_OK.replace('cross_uid=65532 cross=denied',
                                                                  'cross_uid=65532 cross=readable')}),
            with_files(fx, **{'eas-keys.txt': EAS_KEYS_OK.replace('cross_uid=65532', 'cross_uid=65531')}),
        ],
    }


def negatives(arm):
    n = negatives_of(arm)
    base = {'gates': gates_fixture(), 'off': off_fixture()}.get(arm) or fixture(arm)
    names = {c.__name__ for c in ARMS[arm]}
    env = ('UPF_NAT_EXCLUDE',) if arm == 'no-upf-qos' else UPF_ENV
    n.update({k: v for k, v in common_negatives(base, env).items() if k in names})
    return n


def negatives_of(arm):
    """{check name: [negative-control fixtures]} for `arm`: one control per
    condition the check asserts, each breaking that condition alone (the
    forced-true sweep in self_test proves no other check catches it)."""
    if arm == 'gates':
        g = gates_fixture()
        txt = g['_files']['gates.txt']

        def gate_sub(old, new):
            assert old in txt, old
            return with_files(g, **{'gates.txt': txt.replace(old, new)})
        return {
            'c_gates_startup': [
                # Each binary on its own: its refusal gone, or its rc not 1.
                gate_sub('nr-she-eas: /tmp/d443a/bogus.yaml: demo config: unknown mode "bogus"',
                         'nr-she-eas: /tmp/d443a/bogus.yaml: started'),
                gate_sub('eesd bogus: Error: demo config: unknown mode "bogus"', 'eesd bogus: started'),
                gate_sub('smfd bogus: Error: demo config: unknown mode "bogus"', 'smfd bogus: started'),
                gate_sub('UE failed: Invalid demo block in /tmp/bogus.yaml: demo config: unknown mode "bogus"',
                         'UE started'),
                # Killed by the timeout, not refused.
                with_files(g, **{'gates.txt': re.sub(r'(eesd bogus: .*?) rc=1', r'\1 rc=124', txt, count=1)}),
            ],
            'c_gates_runtime': [
                # The refused set changed the mode anyway.
                gate_sub('rc=1 demo=d443a-edge-budget active=true mode=measured-budget',
                         'rc=1 demo=d443a-edge-budget active=true mode=bogus'),
                # set mode=static was not accepted.
                with_files(g, **{'gates.txt': re.sub(r'nr-cli set-static: .*\n',
                                                     'nr-cli set-static: ERROR: refused\n', txt)}),
                # The refused set is not audited.
                edit_only(g, 'gates', 'ue.log', drop(r'audit: rejected')),
            ],
        }
    if arm == 'off':
        o = off_fixture()
        demo_line = f'{TS} INFO [demo:{KEY}] EES-SEL x'
        return {'c_off': [
            edit_only(o, 'off', 'smf.log', drop(r'accepted N6')),
            edit_only(o, 'off', 'ees.log', append(demo_line)),
            edit_only(o, 'off', 'ue.log', append(f'{TS} WARN DEMO MODE ACTIVE: {KEY}=static')),
            edit_only(o, 'off', 'smf.log', append(f'{TS} INFO QOS_MON ref=1 +n6Delays upf=u [x]')),
            with_files(o, **{'off-cli.txt': 'Error from server (NotFound): pods "ue" not found\n'}),
            with_files(o, **{'off-eas.txt': 'rc=1\n'}),
            with_files(o, **{'off-eas.txt': o['_files']['off-eas.txt'].replace('rc=1', 'rc=0')}),
        ]}
    fx = fixture(arm)
    sel_rx = r'EES-SEL ac='
    upf_ip = '10.45.255.254'
    n = {
        'c_acts_ordered': [
            # A restart: the warm capture of nrf-standin.log is longer than the next.
            edit_only(fx, 'warm', 'nrf-standin.log', lambda ls: ls + ls),
            # (An act not captured at all also fails every check of that act, so
            # it has no single-check control; the shrink above is this check's.)
        ],
        'c_registrations': [
            edit(fx, 'warm', 'eas.log', drop(r'EAS-REG eas=eas-cloud')),
            edit(fx, 'warm', 'eas.log', sub(r'endPt=10\.60\.0\.11', 'endPt=10.60.0.99')),
        ],
        'c_standin': [edit(fx, 'warm', 'nrf-standin.log', sub(r'PUT -> 201', 'PUT -> 401'))],
        'c_n6_provisioned': [edit(fx, 'warm', 'smf.log', drop(r'accepted N6'))],
        'c_n6_measured': [edit_only(fx, 'warm', 'smf.prom',
                                    lambda ls: [ls[0].replace('10.60.0.13', '10.60.0.99')])],
        'c_qos_mon': [
            edit(fx, 'warm', 'ees.log', drop(r'Nsmf_EventExposure_Subscribe')),
            edit(fx, 'warm', 'ees.log', sub(r',10\.60\.0\.13=20ms', '')),
        ],
        # selection_act through c_act1 (and its static twin): one control per condition.
        'c_act1': [
            # Fewer jobs than asked for (job + selection + execution lines all gone).
            edit(edit(edit(fx, 'act1', 'ue.log', drop(r'JOB job=(?:[3-9]|10) ')),
                      'act1', 'ees.log', lambda ls: [x for x in ls if 'EES-SEL' not in x]
                      + [x for x in ls if 'EES-SEL' in x][:2]),
                 'act1', 'eas.log', drop(r'EAS-EXEC job=(?:[3-9]|10) ')),
            # One job on-device (with its own selection line).
            edit(edit(fx, 'act1', 'ue.log', append(f'{TS} INFO [demo:{KEY}] JOB job=99 on-device '
                                                   f'fallback reason=ees-404 mode=measured-budget')),
                 'act1', 'ees.log', append(sel_line(MEASURED, ['eas-local', 'eas-cloud']))),
            # A selection line too few.
            edit(fx, 'act1', 'ees.log', drop_nth(sel_rx, 3)),
            # One selection from another budget source.
            edit(fx, 'act1', 'ees.log', nth(r'src=upf-n3\+upf-n6', 'src=static-fallback', 4)),
            # One selection not 201 (still naming eas-local).
            edit(fx, 'act1', 'ees.log', nth(r'result=201', 'result=207', 4)),
            # One job run elsewhere than the EES's first choice (and executed there).
            edit(edit(fx, 'act1', 'ue.log', sub(r'JOB job=5 eas=eas-local', 'JOB job=5 eas=eas-regional')),
                 'act1', 'eas.log', sub(r'\[eas-local\] (.*)EAS-EXEC job=5 src=(\S+) eas=eas-local',
                                        r'[eas-regional] \1EAS-EXEC job=5 src=\2 eas=eas-regional')),
            # One execution not from the UE's address (NATed).
            edit(fx, 'act1', 'eas.log', sub(r'EAS-EXEC job=6 src=\S+', f'EAS-EXEC job=6 src={upf_ip}')),
            # One job late.
            edit(fx, 'act1', 'ue.log', sub(r'(JOB job=7 .*)result=ok', r'\1result=deadline-miss')),
            # One selection (and its job, run there) not on the expected EAS.
            edit(edit(edit(fx, 'act1', 'ees.log', nth(r'selected=\[eas-local', 'selected=[eas-regional', 7)),
                      'act1', 'ue.log', sub(r'JOB job=8 eas=eas-local', 'JOB job=8 eas=eas-regional')),
                 'act1', 'eas.log', sub(r'\[eas-local\] (.*)EAS-EXEC job=8 src=(\S+) eas=eas-local',
                                        r'[eas-regional] \1EAS-EXEC job=8 src=\2 eas=eas-regional')),
        ],
        'c_accuracy': [edit(fx, 'act1', 'ue.log', sub(r'rtt=11 ', 'rtt=40 '))],
        'c_act2': [
            # The live N6 control: eas-local's N6 average under 8 ms.
            edit_only(fx, 'act2', 'smf.prom', lambda ls: [ls[0].replace('"10.60.0.11",stat="avg"} 18',
                                                                        '"10.60.0.11",stat="avg"} 7')]),
            # Byte-identical, part 1: eas-local re-registered.
            edit(fx, 'act2', 'eas.log', append(
                f'{TS} [eas-local] {TS} INFO [demo:{KEY}] EAS-REG eas=eas-local registrationId=r2 '
                f'endPt=10.60.0.11 maxRespTime=10 ms avlComp=50')),
            # Part 2: eas-local merge-patched its KPI.
            edit(fx, 'act2', 'eas.log', append(
                f'{TS} [eas-local] {TS} INFO [demo:{KEY}] EAS-KPI-PATCH eas=eas-local svcKpi.avlComp=50 (200)')),
            # Part 3: eesd merge-patched a registration.
            edit(fx, 'act2', 'ees.log', append(
                f'{TS} INFO EAS registration merge-patched: registrationId=r-eas-local')),
            # The selection did not move.
            edit(edit(fx, 'act2', 'ees.log', sub(r'selected=\[eas-regional', 'selected=[eas-local')),
                 'act2', 'ue.log', sub(r'eas=eas-regional', 'eas=eas-local')),
        ] if arm in ('main', 'oauth2', 'restart-flip') else [],
        'c_act3': [
            # rtDelays did not rise (rt 6 throughout).
            edit(fx, 'act3', 'ees.log', sub(r'QOS_MON rt=26', 'QOS_MON rt=6')),
            # An on-device job for another reason.
            edit(fx, 'act3', 'ue.log', nth(r'reason=ees-404', 'reason=ees-401', 1)),
            # A job ran on an EAS.
            edit(edit(fx, 'act3', 'ue.log', append(job_line(98, 'eas-local', 11, 12, MEASURED, 'ok',
                                                            'measured-budget'))),
                 'act3', 'ees.log', append(sel_line(MEASURED, [], '404', 26))),
            # A selection was 201, not 404.
            edit(fx, 'act3', 'ees.log', nth(r'result=404', 'result=201', 1)),
            # A selection from another budget source.
            edit(fx, 'act3', 'ees.log', nth(r'src=upf-n3\+upf-n6', 'src=static-fallback', 0)),
        ] if arm in ('main', 'oauth2') else [],
        'c_load': [
            edit(fx, 'load', 'eas.log', drop(r'EAS-KPI-PATCH')),
            edit(fx, 'load', 'eas.log', sub(r'svcKpi\.avlComp=5 \(200\)', 'svcKpi.avlComp=5 (500)')),
            edit(edit(fx, 'load', 'ees.log', sub(r'selected=\[eas-regional', 'selected=[eas-local')),
                 'load', 'ue.log', sub(r'eas=eas-regional', 'eas=eas-local')),
        ] if arm in ('main', 'oauth2') else [],
        'c_act1_static': [edit(fx, 'act1', 'ees.log', sub(r'src=static', 'src=static-fallback'))],
        'c_act2_static': [edit(fx, 'act2', 'ue.log', sub(r'rtt=38 (.*)result=deadline-miss', r'rtt=12 \1result=ok'))],
        'c_act3_static': [edit(fx, 'act3', 'ees.log', sub(r'selected=\[eas-local', 'selected=[eas-regional'))],
        'c_load_static': [
            edit(fx, 'load', 'eas.log', drop(r'EAS-KPI-PATCH')),
            edit(fx, 'load', 'ue.log', sub(r'(JOB job=1[6-8] .*)result=deadline-miss', r'\1result=ok')),
        ],
        'c_revert_pre': [
            edit(fx, 'load', 'eas.log', drop(r'--no-kpi-patch')),
            edit(fx, 'load', 'eas.log', append(
                f'{TS} [eas-local] {TS} INFO [demo:{KEY}] EAS-KPI-PATCH eas=eas-local svcKpi.avlComp=5 (200)')),
            edit(fx, 'load', 'ue.log', sub(r'(JOB job=1[1-3] .*)result=deadline-miss', r'\1result=ok')),
        ],
    }
    swap01 = lambda ls: [ls[1], ls[0]] + ls[2:] if len(ls) > 1 else ls  # noqa: E731
    act1_fallback_negs = [
        edit(fx, 'act1', 'ees.log', sub(r'src=static-fallback', 'src=upf-n3+upf-n6')),
        edit(fx, 'act1', 'ue.log', sub(r'(JOB job=7 .*)result=ok', r'\1result=deadline-miss')),
    ]
    n.update({
        'c_assoc_order': [
            edit(fx, 'warm', 'smf.log', drop(r'requested from the UPF: SRR')),
            edit(fx, 'warm', 'smf.log', swap01),
        ],
        'c_nosub_pre': [
            edit(fx, 'warm', 'ees.log', drop(r'no ees\.edge_budget\.smf_uri')),
            edit(fx, 'warm', 'ees.log', append(SUB_LINE)),
            edit(fx, 'warm', 'ees.log', append(qosmon_line(6))),
        ] + act1_fallback_negs if arm == 'no-qos-mon' else [],
        'c_wrongtoken_pre': [
            with_files(fx, **{'wrong-sub.txt': 'HTTP/2 400\n'}),
            with_files(fx, **{'wrong-sub.txt': 'HTTP/2 201\n'}),
            edit(fx, 'warm', 'smf.log', nth(r'status=401', 'status=204', 1)),
            edit(fx, 'warm', 'smf.log', sub(r'subscription w1:', 'subscription w2:')),
            edit(fx, 'warm', 'ees.log', drop(r'no ees\.edge_budget\.smf_uri')),
            edit(fx, 'warm', 'ees.log', append(SUB_LINE)),
            edit(fx, 'warm', 'ees.log', append(qosmon_line(6))),
        ] + act1_fallback_negs if arm == 'wrong-callback-token' else [],
        'c_noupf_pre': [
            with_files(fx, **{'pod-specs.json': pod_specs()}),
            with_files(fx, **{'pod-specs.json': pod_specs(upf_env=('UPF_NAT_EXCLUDE', 'UPF_QOS_FLOW_MONITORING'))}),
            edit(fx, 'warm', 'smf.log', drop(r'does not advertise UN6DM')),
            edit(fx, 'warm', 'smf.log', drop(r'did not advertise QFQM')),
            edit(fx, 'warm', 'smf.log', append(SMF_N6_LINE)),
            edit_only(fx, 'warm', 'smf.prom', lambda ls: [metric(2)]),
            edit(fx, 'warm', 'ees.log', drop(r'Nsmf_EventExposure_Subscribe')),
            edit(fx, 'warm', 'ees.log', append(qosmon_line(6))),
        ] + act1_fallback_negs if arm == 'no-upf-qos' else [],
        'c_bind_pre': [
            with_files(fx, **{'ue-eec.txt': '      device: uesimtun0\n'}),
            edit(fx, 'act1', 'ees.log', nth(r'src=upf-n3\+upf-n6', 'src=static-fallback', 2)),
            edit(fx, 'act1', 'ees.log', nth(r'selected=\[eas-local', 'selected=[eas-regional', 3)),
            edit(fx, 'act1', 'ue.log', append(job_line(99, 'eas-local', 11, 12, MEASURED, 'ok', 'measured-budget'))),
            edit(fx, 'act1', 'ue.log', drop(r'JOB job=[1-3] ')),
            edit(fx, 'act1', 'ue.log', append(f'{TS} INFO [demo:{KEY}] JOB job=98 on-device fallback '
                                              f'reason=ees-404 mode=measured-budget')),
            edit(fx, 'act1', 'eas.log', append(exec_line(1, 'eas-local'))),
        ] if arm == 'bind-eth0' else [],
        'c_flip': [
            edit_only(fx, 'flip', 'ees.log', sub(r'edge-budget: on \(mode=static', 'edge-budget: on (mode=measured-budget')),
            edit_only(fx, 'flip', 'smf.prom', lambda ls: [metric(3)]),
            edit_only(fx, 'flip', 'eas.log', drop(r'registrationId=r2-eas-local')),
            edit_only(fx, 'flip', 'ees.log', nth(r'src=static selected', 'src=upf-n3+upf-n6 selected', 1)),
            edit_only(fx, 'flip', 'ue.log', sub(r'(JOB job=15 .*)result=deadline-miss', r'\1result=ok')),
        ] if arm == 'restart-flip' else [],
        'c_oauth2': [
            with_files(fx, **{'oauth2.txt': OAUTH2_OK.replace('amf: 2026', 'amf: \n#')}),
            with_files(fx, **{'oauth2.txt': OAUTH2_OK.replace('OAuth2 enforcement enabled (JWKS: http://nrf:7777/x)\nbare',
                                                              'started\nbare')}),
            with_files(fx, **{'oauth2.txt': OAUTH2_OK.replace('bare-subscribe: 401', 'bare-subscribe: 201')}),
            edit(fx, 'warm', 'ees.log', drop(r'EES registered at the NRF as AF')),
            edit(fx, 'warm', 'ees.log', swap01),
        ] if arm == 'oauth2' else [],
    })
    names = {c.__name__ for c in ARMS[arm]}
    out = {k: v for k, v in n.items() if k in names and v}
    # The revert targets' controls are the other way round (self_test).
    for t in REVERT_TARGET.get(arm, set()):
        out.pop(t, None)
    return out


def self_test():
    fails = []
    for arm in ARMS:
        fx = {'gates': gates_fixture(), 'off': off_fixture()}.get(arm) or fixture(arm)
        with tempfile.TemporaryDirectory() as d:
            write(fx, d)
            holds, results = verdict(arm, d)
            targets = REVERT_TARGET.get(arm, set())
            bad = [(n, w) for n, ok, w in results if not ok and n not in targets]
            if not holds or bad:
                fails.append(f'{arm}: the complete fixture does not hold: {bad}')
            passing = [n for n, ok, _ in results if n in targets and ok]
            if passing or len([n for n, _, _ in results if n in targets]) != len(targets):
                fails.append(f'{arm}: revert target(s) {passing or sorted(targets)} pass on, or are missing from, '
                             f'the complete fixture')
        negs = negatives(arm)
        for c in ARMS[arm]:
            name = c.__name__
            if name in REVERT_TARGET.get(arm, set()):
                with tempfile.TemporaryDirectory() as d:
                    write(fixture('main'), d)
                    if not c(d)[0]:
                        fails.append(f'{arm}: the revert target {name} fails on main\'s fixture')
                continue
            if name not in negs:
                fails.append(f'{arm}: {name} has no negative control')
                continue
            for i, neg in enumerate(negs[name]):
                with tempfile.TemporaryDirectory() as d:
                    write(neg, d)
                    ok, _ = c(d)
                    if ok:
                        fails.append(f'{arm}: {name} does not react to its negative control #{i}')
                    if name in ADVISORY:
                        continue
                    holds, _ = verdict(arm, d)
                    if holds:
                        fails.append(f'{arm}: the verdict holds on {name}\'s negative control #{i}')
                    # Forced-true sweep: with the check forced to PASS, the verdict
                    # now holds, so this check (alone) is what catches the control.
                    forced, _ = verdict(arm, d, forced=name)
                    if not forced:
                        fails.append(f'{arm}: {name} forced true still fails the verdict on control #{i}: '
                                     f'it also breaks another check')
    for f in fails:
        print('not ok -', f)
    print('ok' if not fails else f'{len(fails)} failure(s)')
    return 0 if not fails else 1


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        sys.exit(self_test())
    if len(sys.argv) != 3 or sys.argv[1] not in ARMS:
        sys.exit(f'usage: analyze.py {{{"|".join(ARMS)}}} DIR | --self-test')
    sys.exit(main(sys.argv[1], sys.argv[2]))
