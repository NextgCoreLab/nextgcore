#!/usr/bin/env python3
"""Assertions of demo d443a-edge-budget (nextgsim#471) over a scenario capture.

    analyze.py <arm> DIR     one PASS/FAIL line per check, exit 0 iff the arm's
                             verdict holds (the revert arm no-kpi-patch holds when
                             the check it targets FAILS and its preconditions hold)
    analyze.py --self-test   every check passes on a complete fixture and FAILS on
                             that check's negative control; with the check forced
                             to PASS, the arm's verdict on the negative control
                             wrongly passes (so each check is what catches it);
                             no cluster, no network

DIR holds what scenario.sh captured, one directory per act (warm, act1, act2,
act3, load; off; gates), each with the full log of every component at the end of
that act (kubelet --timestamps), /metrics scrapes and at.txt:
    ees.log nrf-standin.log smf.log eas.log ue.log smf.prom ees.prom
and meta.txt (arm, mode, rt_baseline), ue-ip.txt, gates.txt, off-*.txt.

Acts are compared by line count: an act's lines are those of its capture past
the previous act's count, per component. Logs only grow (a pod restart would
show as a shorter log and fails `acts_ordered`), so no check reads a clock across
pods: order is used only where it is causal (job n's EES-SEL, JOB and EAS-EXEC
lines are matched by job number and per-component sequence, never by time).

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
ACTS_REVERT = ('warm', 'act1', 'load')


def acts_of(d):
    arm = meta(d).get('arm')
    return ACTS_REVERT if arm == 'no-kpi-patch' else ACTS_MAIN


def c_acts_ordered(d):
    acts = acts_of(d)
    for a in acts:
        if not os.path.isdir(os.path.join(d, a)):
            return False, f'no capture for {a}'
    for comp in COMPONENTS:
        n = [len(lines(d, a, comp)) for a in acts]
        if any(b < a for a, b in zip(n, n[1:])):
            return False, f'{comp} shrank between acts {n} (a restart)'
    return True, 'every act captured, every log only grew'


def c_registrations(d):
    regs = grep(REG, lines(d, acts_of(d)[-1], 'eas.log'))
    got = {(m.group(1), m.group(2), m.group(4)) for m in regs}
    want = {(e, e, EAS_IP[e]) for e in EAS}
    if not want <= got:
        return False, f'EAS-REG for {sorted(want - got)} missing'
    return True, 'eas-local/regional/cloud registered at their dn addresses'


def c_standin(d):
    if not grep(STANDIN, lines(d, acts_of(d)[-1], 'nrf-standin.log')):
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


ARMS = {
    'main': [c_acts_ordered, c_registrations, c_standin, c_n6_provisioned, c_n6_measured,
             c_qos_mon, c_act1, c_accuracy, c_act2, c_act3, c_load],
    'static': [c_acts_ordered, c_registrations, c_standin, c_n6_provisioned, c_n6_measured,
               c_act1_static, c_act2_static, c_act3_static, c_load_static],
    'no-kpi-patch': [c_acts_ordered, c_registrations, c_n6_measured, c_qos_mon, c_act1,
                     c_revert_pre, c_load],
    'gates': [c_gates_startup, c_gates_runtime],
    'off': [c_off],
}
# A revert arm holds when its target FAILS and every other check passes.
REVERT_TARGET = {'no-kpi-patch': 'c_load'}
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
    target = REVERT_TARGET.get(arm)
    holds = True
    for name, ok, _ in results:
        if name in ADVISORY:
            continue
        if name == target:
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
        if name == REVERT_TARGET.get(arm):
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


def fixture(arm):
    """{act: {component: [lines]}, '_meta': ..., '_files': {...}} of a run that
    meets every check of `arm` (main, static, no-kpi-patch)."""
    mode = 'static' if arm == 'static' else 'measured-budget'
    src = 'static' if arm == 'static' else MEASURED
    regs = [f'{TS} [{e}] {TS} INFO [demo:{KEY}] EAS-REG eas={e} registrationId=r-{e} '
            f'endPt={EAS_IP[e]} maxRespTime=10 ms avlComp=50' for e in EAS]
    base = {
        'ees.log': [f'{TS} INFO [demo:{KEY}] Nsmf_EventExposure_Subscribe QOS_MON (anyUeInd, '
                    f'PERIODIC 2 s, QoSMonitoring) at http://smf:7777: 201 /nsmf-event-exposure/v1/subscriptions/1',
                    qosmon_line(6)],
        'nrf-standin.log': [f'{TS} 2026-11-15T10:00:00Z [d443a nrf-standin] stand-in EES profile '
                            f'6b1d7e3c-0000-4000-8000-00000000471e (nfType EES, eees-easregistration, '
                            f'eees-eecregistration) PUT -> 201'],
        # The real smfd line (EKS run 20261116T002400Z): one instance, three endpoints.
        'smf.log': ['2026-11-16T00:24:51.996274977Z [2026-11-16T00:24:51.996Z INFO  nextgcore_smfd::n6_delay] '
                    'UPF 10.10.1.73:8805 accepted N6 Delay Measurement Control Information x1 '
                    '(Association Update, TS 29.244 §5.33.8.2)'],
        'eas.log': list(regs),
        'ue.log': [],
    }
    acts = {}
    cur = {k: list(v) for k, v in base.items()}
    prom = {'warm': metric(2)}
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

    local_pred = 10 if arm == 'static' else 12
    cur['ees.log'].append(qosmon_line(6))
    run('act1', 10, 'eas-local', 11, local_pred, 'ok')
    prom['act1'] = metric(2)
    if arm != 'no-kpi-patch':
        cur['ees.log'].append(qosmon_line(6, 18))
        if arm == 'static':
            run('act2', 3, 'eas-local', 38, 10, 'deadline-miss')
        else:
            run('act2', 3, 'eas-regional', 13, 14, 'ok')
        prom['act2'] = metric(18)
        cur['ees.log'].append(qosmon_line(26))
        if arm == 'static':
            run('act3', 2, 'eas-local', 30, 10, 'deadline-miss')
        else:
            for _ in range(2):
                n += 1
                cur['ees.log'].append(sel_line(MEASURED, [], '404', 26))
                cur['ue.log'].append(f'{TS} INFO [demo:{KEY}] JOB job={n} on-device fallback '
                                     f'reason=ees-404 mode={mode}')
            acts['act3'] = {k: list(v) for k, v in cur.items()}
        prom['act3'] = metric(2)
    if arm == 'no-kpi-patch':
        cur['eas.log'].append(f'{TS} [eas-local] {TS} WARN [demo:{KEY}] LOAD eas=eas-local avlComp 50 -> 5 '
                              f'locally; --no-kpi-patch: the EES is NOT told (revert arm)')
        run('load', 3, 'eas-local', 23, 12, 'deadline-miss')
    else:
        cur['eas.log'].append(f'{TS} [eas-local] {TS} INFO [demo:{KEY}] EAS-KPI-PATCH eas=eas-local '
                              f'svcKpi.avlComp=5 (200)')
        if arm == 'static':
            run('load', 3, 'eas-local', 23, 10, 'deadline-miss')
        else:
            run('load', 3, 'eas-regional', 13, 14, 'ok')
    prom['load'] = metric(2)
    for a in acts:
        acts[a]['smf.prom'] = [prom.get(a, metric(2))]
    acts['_meta'] = f'arm={arm}\nmode={mode}\nrt_baseline=6\n'
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
    return {'gates': {'ue.log': ue}, '_files': {'gates.txt': g}, '_meta': 'arm=gates\n'}


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


def write(fx, root):
    for act, comps in fx.items():
        if act == '_meta':
            open(os.path.join(root, 'meta.txt'), 'w').write(comps)
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
    for a in keys[i:]:
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


def negatives(arm):
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
        ] if arm == 'main' else [],
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
        ] if arm == 'main' else [],
        'c_load': [
            edit(fx, 'load', 'eas.log', drop(r'EAS-KPI-PATCH')),
            edit(fx, 'load', 'eas.log', sub(r'svcKpi\.avlComp=5 \(200\)', 'svcKpi.avlComp=5 (500)')),
            edit(edit(fx, 'load', 'ees.log', sub(r'selected=\[eas-regional', 'selected=[eas-local')),
                 'load', 'ue.log', sub(r'eas=eas-regional', 'eas=eas-local')),
        ] if arm == 'main' else [],
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
    names = {c.__name__ for c in ARMS[arm]}
    out = {k: v for k, v in n.items() if k in names and v}
    # The revert target's controls are the other way round (self_test).
    out.pop(REVERT_TARGET.get(arm), None)
    return out


def self_test():
    fails = []
    for arm in ARMS:
        fx = {'gates': gates_fixture(), 'off': off_fixture()}.get(arm) or fixture(arm)
        with tempfile.TemporaryDirectory() as d:
            write(fx, d)
            holds, results = verdict(arm, d)
            bad = [(n, w) for n, ok, w in results if not ok and n != REVERT_TARGET.get(arm)]
            if not holds or bad:
                fails.append(f'{arm}: the complete fixture does not hold: {bad}')
            if arm in REVERT_TARGET:
                tgt = [ok for n, ok, _ in results if n == REVERT_TARGET[arm]]
                if tgt != [False]:
                    fails.append(f'{arm}: the revert target passes on the complete fixture')
        negs = negatives(arm)
        for c in ARMS[arm]:
            name = c.__name__
            if name == REVERT_TARGET.get(arm):
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
