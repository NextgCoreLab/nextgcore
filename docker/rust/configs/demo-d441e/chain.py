#!/usr/bin/env python3
"""The ordered-chain check of demo d441e-model-retrain (nextgsim#468).

One checker for both runners: configs/demo-d441e/check.sh (compose) and
deploy/eks/overlays/demo-d441e-model-retrain/scenario.sh (EKS). It reads the
two nwdafd logs WITH a runtime timestamp per line, either

    nwdaf-mtlf-1  | 2026-11-13T10:00:00.123456789Z <line>   (docker compose logs --timestamps)
    2026-11-13T10:00:00.123456789Z <line>                   (kubectl logs --timestamps)

and asserts, by those timestamps:

  both modes (S1-S7)
    S1 AnLF  subscribed to MTLF <id> threshold=0.70
    S2 MTLF  MLModelProvision: model v1 provisioned sha256=<S1>
    S3 AnLF  model v1 verified sha256=<S1> from <url ending in /<S1>> (after S1;
             S2 is logged on the Notify's 204, which can come after the verify)
    S4 AnLF  MLModelMonitor registered at MTLF ... modelId=<M1>
    S5 MTLF  MLModelMonitor subscribed at AnLF ... modelId=<M1> threshold=0.70
    S6 AnLF  accuracy >= 0.70 reported for modelId=<M1> (a calm report)
    S7 MTLF  seeded series: regime alternating ... (scripted regime change)
  mode retrain (S8-S13)
    S8  MTLF accuracy <r> < 0.70: retrain requested (modelId=<M1>)
    S9  MTLF retrain: AR(5) least-squares refit of v1 ... held-out MAE ...
    S10 MTLF retrain: model v2 published sha256=<S2> modelId=<M2> (replaces v1)
    S11 MTLF MLModelProvision: model v2 provisioned sha256=<S2>
    S12 AnLF model v2 verified sha256=<S2> (after S10, for the same reason)
    S13 AnLF accuracy >= 0.70 reported for modelId=<M2>, and every v2 report is
    plus exactly one "retrain requested" and no "model refused".
  mode no-retrain (S8)
    S8  MTLF accuracy <r> < 0.70: mode no-retrain, no retrain (modelId=<M1>)
    plus no "retrain requested", no "retrain:" line, no model v2, and at least
    NO_RETRAIN_REPORTS AnLF reports for <M1> after S8, every one < 0.70.

On success it prints the chain and writes KEY=VALUE facts (--facts FILE) for
the runner: v1/v2 sha and url, model ids, accuracies, the held-out MAEs. On
failure it prints `DEMO CHECK FAILED: step N missing: ...` (or the violated
rule) and exits 1.

    chain.py --mode retrain|no-retrain --mtlf LOG --anlf LOG [--facts FILE]
    chain.py --self-test
"""
import argparse
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta

THRESHOLD = 0.70
# A step on one NWDAF that follows a step on the other is compared with this
# much slack: the two lines carry two hosts' clocks (on EKS the pods can sit on
# different nodes). Each such step is also tied to its predecessor by content
# (the sha256, the modelId), which is what makes the order causal.
SKEW = timedelta(seconds=2)
NO_RETRAIN_REPORTS = 2
SHA = r'([0-9a-f]{64})'
TS = re.compile(r'^(?:\S+\s+\|\s+)?(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z\s(.*)$')


class Fail(Exception):
    pass


def load(path, who):
    """(time, who, line) per timestamped line of PATH."""
    out = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for raw in f:
            m = TS.match(raw.rstrip('\n'))
            if not m:
                continue
            frac = (m.group(2) or '0')[:6].ljust(6, '0')
            t = datetime.strptime(f'{m.group(1)}.{frac}', '%Y-%m-%dT%H:%M:%S.%f')
            out.append((t, who, m.group(3)))
    if not out:
        raise Fail(f'the {who} log {path} has no timestamped line (wrong container or empty capture?)')
    return out


def first(lines, pattern, after=None, step=''):
    rx = re.compile(pattern)
    for t, _, msg in lines:
        if after is not None and t < after:
            continue
        m = rx.search(msg)
        if m:
            return t, m
    where = f' after {after.isoformat()}' if after else ''
    raise Fail(f'step {step} missing: /{pattern}/{where}')


def check(mode, mtlf, anlf):
    facts = {}
    chain = []

    def note(step, t, who, what):
        chain.append(f'  {step:>3} {t.isoformat()} {who:<4} {what}')

    t1, m = first(anlf, r'subscribed to MTLF (\S+) threshold=0\.70\b', step='S1 (AnLF subscribed to the MTLF)')
    note('S1', t1, 'AnLF', m.group(0))
    t2, m = first(mtlf, r'MLModelProvision: model v1 provisioned sha256=' + SHA, t1 - SKEW, 'S2 (MTLF notified v1)')
    sha1 = m.group(1)
    note('S2', t2, 'MTLF', m.group(0))
    # The MTLF logs `provisioned` when the Notify's 204 comes back, and the AnLF
    # may verify before or after that (seen both ways on the real stack), so S3
    # follows the subscription and is tied to S2 by the sha256, not by time.
    t3, m = first(anlf, r'model v1 verified sha256=' + SHA + r' from (\S+)', t1, 'S3 (AnLF verified v1)')
    if m.group(1) != sha1:
        raise Fail(f'step S3: the AnLF verified sha256={m.group(1)}, the MTLF notified {sha1}')
    url1 = m.group(2)
    if not url1.endswith('/' + sha1):
        raise Fail(f'step S3: the v1 URL {url1} does not end in its sha256')
    note('S3', t3, 'AnLF', m.group(0))
    t4, m = first(anlf, r'MLModelMonitor registered at MTLF \S+ modelId=(\d+) registrationId=', t3,
                  'S4 (AnLF registered v1 for monitoring)')
    m1 = m.group(1)
    note('S4', t4, 'AnLF', m.group(0))
    t5, m = first(mtlf, rf'MLModelMonitor subscribed at AnLF \S+ sub=\S+ modelId={m1} threshold=0\.70\b', t4 - SKEW,
                  'S5 (MTLF subscribed at the AnLF)')
    note('S5', t5, 'MTLF', m.group(0))
    rep = re.compile(r'accuracy (\d\.\d\d) \(n=\d+\) reported for modelId=(\d+) ')
    reports = [(t, float(r.group(1)), r.group(2)) for t, _, msg in anlf for r in [rep.search(msg)] if r]
    # S7 first: S6 must be a report of the calm part, before the change.
    t7, m7 = first(mtlf, r'seeded series: regime alternating from step (\d+) \(scripted regime change\)',
                   t5 - SKEW, 'S7 (the scripted regime change)')
    calm = [(t, a) for t, a, mid in reports if mid == m1 and t5 - SKEW <= t <= t7 and a >= THRESHOLD]
    if not calm:
        raise Fail(f'step S6 missing: no AnLF accuracy report >= {THRESHOLD:.2f} for modelId={m1} '
                   f'before the regime change')
    t6, a6 = calm[0]
    note('S6', t6, 'AnLF', f'accuracy {a6:.2f} reported for modelId={m1}')
    m = m7
    note('S7', t7, 'MTLF', m.group(0))
    facts.update(v1_sha256=sha1, v1_url=url1, v1_model_id=m1, v1_calm_accuracy=f'{a6:.2f}',
                 change_at=t7.isoformat())
    refused = [msg for _, _, msg in anlf if 'model refused' in msg]
    requested = [msg for _, _, msg in mtlf if 'retrain requested' in msg]

    if mode == 'retrain':
        t8, m = first(mtlf, rf'accuracy (\d\.\d\d) < 0\.70: retrain requested \(modelId={m1}\)', t7,
                      'S8 (MTLF retrain requested after the change)')
        note('S8', t8, 'MTLF', m.group(0))
        facts['retrain_accuracy'] = m.group(1)
        t9, m = first(mtlf, r'retrain: AR\(5\) least-squares refit of v1 .*held-out MAE (\S+) refit, (\S+) '
                      r'current model \(no-retrain\), (\S+) persistence', t8, 'S9 (MTLF refit)')
        note('S9', t9, 'MTLF', m.group(0))
        facts.update(mae_refit=m.group(1), mae_current=m.group(2), mae_persistence=m.group(3))
        t10, m = first(mtlf, r'retrain: model v2 published sha256=' + SHA + r' modelId=(\d+) \(replaces v1\)', t9,
                       'S10 (MTLF published v2)')
        sha2, m2 = m.group(1), m.group(2)
        note('S10', t10, 'MTLF', m.group(0))
        t11, m = first(mtlf, rf'MLModelProvision: model v2 provisioned sha256={sha2}', t10,
                       'S11 (MTLF notified v2)')
        note('S11', t11, 'MTLF', m.group(0))
        # As S3: after the publish, tied to S10/S11 by the sha256 (CI saw the
        # AnLF's verify 39 ms before the MTLF's `provisioned`).
        t12, m = first(anlf, rf'model v2 verified sha256={sha2} from (\S+)', t10 - SKEW, 'S12 (AnLF verified v2)')
        url2 = m.group(1)
        note('S12', t12, 'AnLF', m.group(0))
        v2 = [(t, a) for t, a, mid in reports if mid == m2 and t >= t12]
        if not v2:
            raise Fail(f'step S13 missing: no AnLF accuracy report for v2 (modelId={m2})')
        low = [a for _, a in v2 if a < THRESHOLD]
        if low:
            raise Fail(f'step S13: v2 (modelId={m2}) reported below {THRESHOLD:.2f}: {low}')
        note('S13', v2[0][0], 'AnLF', f'accuracy {v2[0][1]:.2f} reported for modelId={m2} '
             f'({len(v2)} v2 report(s), min {min(a for _, a in v2):.2f})')
        if len(requested) != 1:
            raise Fail(f'exactly one "retrain requested" expected, got {len(requested)}')
        if refused:
            raise Fail(f'the AnLF refused a model: {refused[0]}')
        facts.update(v2_sha256=sha2, v2_url=url2, v2_model_id=m2,
                     v2_accuracy_min=f'{min(a for _, a in v2):.2f}', v2_reports=str(len(v2)))
    elif mode == 'no-retrain':
        t8, m = first(mtlf, rf'accuracy (\d\.\d\d) < 0\.70: mode no-retrain, no retrain \(modelId={m1}\)', t7,
                      'S8 (MTLF accuracy drop, no retrain)')
        note('S8', t8, 'MTLF', m.group(0))
        facts['drop_accuracy'] = m.group(1)
        if requested:
            raise Fail(f'mode no-retrain logged "retrain requested": {requested[0]}')
        # `retrain: ` as the refit's own prefix, not `model-retrain: on (...)`.
        for who, lines, pat in (('MTLF', mtlf, r'(?<![\w-])retrain: |model v2 '), ('AnLF', anlf, r'model v2 ')):
            hit = [msg for _, _, msg in lines if re.search(pat, msg)]
            if hit:
                raise Fail(f'mode no-retrain: the {who} logged {hit[0]!r}')
        after = [a for t, a, mid in reports if mid == m1 and t > t8]
        if len(after) < NO_RETRAIN_REPORTS:
            raise Fail(f'mode no-retrain: {len(after)} AnLF report(s) after the drop, '
                       f'{NO_RETRAIN_REPORTS} needed')
        high = [a for a in after if a >= THRESHOLD]
        if high:
            raise Fail(f'mode no-retrain: the AnLF reported {high} >= {THRESHOLD:.2f} after the drop')
        note('-', t8, 'AnLF', f'{len(after)} report(s) after the drop, max {max(after):.2f}')
        facts.update(after_drop_max=f'{max(after):.2f}', after_drop_reports=str(len(after)))
        if refused:
            raise Fail(f'the AnLF refused a model: {refused[0]}')
    else:
        raise Fail(f'unknown mode {mode!r}')
    return chain, facts


def run(mode, mtlf_path, anlf_path, facts_path=None):
    try:
        chain, facts = check(mode, load(mtlf_path, 'MTLF'), load(anlf_path, 'AnLF'))
    except Fail as e:
        print(f'DEMO CHECK FAILED: [{mode}] {e}', file=sys.stderr)
        return 1
    print(f'[chain] {mode}: ordered chain holds')
    print('\n'.join(chain))
    if facts_path:
        with open(facts_path, 'w') as f:
            f.writelines(f'{k}={v}\n' for k, v in facts.items())
    return 0


# --- self-test: a good log per mode passes, and every step taken out fails ----

S1_ = 'a' * 64
S2_ = 'b' * 64
URL = 'http://nwdaf-mtlf:7777/nnwdaf-mlmodelprovision/v1/models/NF_LOAD/'
P = '[demo:d441e-model-retrain] '


def header(mode):
    """The start-up lines each NWDAF logs before the chain (never cut)."""
    series = (P + 'seeded series nf=d441e000-0468-4000-8000-000000000468 seed=468 step=1s: calm '
              '(0.5 + 0.1 sin) for steps [0, 120) of every 600-step cycle, then alternating')
    v1 = f'MLModelProvision: model v1 published sha256={S1_} (231 bytes)'
    return ([(25, f'WARN  nextgcore_demo] DEMO MODE ACTIVE: d441e-model-retrain={mode}'),
             (25, P + f'model-retrain: on (mode={mode}, role=mtlf; no AnLF client)'), (25, series), (25, v1)],
            [(26, f'WARN  nextgcore_demo] DEMO MODE ACTIVE: d441e-model-retrain={mode}'),
             (26, P + f'model-retrain: on (mode={mode}, role=anlf; AnLF client to an MTLF discovered '
              'at the NRF, threshold=0.70)'), (26, series), (26, v1)])


def fixture(mode):
    """(mtlf, anlf) lines: (second, text) in the order the real stack logs them."""
    m, a = [], []
    a.append((40, P + 'subscribed to MTLF d441e000-0468-4000-8000-00000000f001 threshold=0.70'))
    m.append((40, f'MLModelProvision: model v1 provisioned sha256={S1_} sub=s1'))
    a.append((41, P + f'model v1 verified sha256={S1_} from {URL}{S1_}'))
    a.append((41, P + 'MLModelMonitor registered at MTLF nwdaf-mtlf:7777 modelId=111 registrationId=r1'))
    m.append((41, P + 'MLModelMonitor subscribed at AnLF d441e-anlf sub=m1 modelId=111 threshold=0.70'))
    a.append((41, P + 'accuracy 0.98 (n=20) reported for modelId=111 sub=m1'))
    a.append((71, P + 'accuracy 0.98 (n=20) reported for modelId=111 sub=m1'))
    m.append((120, P + 'seeded series: regime alternating from step 120 (scripted regime change)'))
    a.append((120, P + 'seeded series: regime alternating from step 120 (scripted regime change)'))
    for s, acc in ((131, '0.75'), (161, '0.64'), (191, '0.64')):
        a.append((s, P + f'accuracy {acc} (n=20) reported for modelId=111 sub=m1'))
    if mode == 'retrain':
        m.append((191, P + 'accuracy 0.68 < 0.70: retrain requested (modelId=111)'))
        m.append((195, P + 'retrain: AR(5) least-squares refit of v1 (modelId=111) on 48 points of nf=x '
                  '(32 training rows, 11 held out): held-out MAE 0.020 refit, 0.380 current model '
                  '(no-retrain), 0.590 persistence'))
        m.append((195, P + f'retrain: model v2 published sha256={S2_} modelId=222 (replaces v1)'))
        m.append((196, f'MLModelProvision: model v2 provisioned sha256={S2_} sub=s1'))
        a.append((196, P + f'model v2 verified sha256={S2_} from {URL}{S2_}'))
        a.append((197, P + 'MLModelMonitor registered at MTLF nwdaf-mtlf:7777 modelId=222 registrationId=r2'))
        a.append((197, P + 'accuracy 0.99 (n=20) reported for modelId=222 sub=m2'))
    else:
        m.append((191, P + 'accuracy 0.68 < 0.70: mode no-retrain, no retrain (modelId=111)'))
        for s in (221, 251):
            a.append((s, P + 'accuracy 0.64 (n=20) reported for modelId=111 sub=m1'))
    return m, a


# Fixture lines the check does not need, by (side, index) in fixture(mode):
# a[3]/a[4] the two calm reports (each stands in for the other; both cut is
# its own control), a[5] the AnLF's regime line, a[6]-a[8] the reports around
# the change, and in retrain a[10] the v2 registration.
OPTIONAL = {
    'retrain': {('a', 3), ('a', 4), ('a', 5), ('a', 6), ('a', 7), ('a', 8), ('a', 10)},
    'no-retrain': {('a', 3), ('a', 4), ('a', 5), ('a', 6), ('a', 7), ('a', 8)},
}


def write(lines, path, compose_prefix):
    with open(path, 'w') as f:
        for s, text in lines:
            ts = f'2026-11-13T10:{s // 60:02d}:{s % 60:02d}.{s:09d}Z'
            f.write((f'svc-1  | {ts} {text}' if compose_prefix else f'{ts} {text}') + '\n')


def self_test():
    failures = []
    with tempfile.TemporaryDirectory() as d:
        mp, ap = os.path.join(d, 'mtlf.log'), os.path.join(d, 'anlf.log')

        def outcome(mode, m, a, prefix=False):
            hm, ha = header(mode)
            write(hm + m, mp, prefix)
            write(ha + a, ap, prefix)
            try:
                check(mode, load(mp, 'MTLF'), load(ap, 'AnLF'))
                return None
            except Fail as e:
                return str(e)

        for mode in ('retrain', 'no-retrain'):
            m, a = fixture(mode)
            for prefix in (False, True):
                why = outcome(mode, m, a, prefix)
                if why is not None:
                    failures.append(f'{mode}: the good log failed ({"compose" if prefix else "kubectl"}): {why}')
            # Negative controls: each line taken out alone must fail the check,
            # except the ones it does not need: the AnLF's own regime line, the
            # v2 registration and the reports another report stands in for.
            for side in ('m', 'a'):
                lines = m if side == 'm' else a
                for i, (_, text) in enumerate(lines):
                    if (side, i) in OPTIONAL[mode]:
                        continue
                    cut = lines[:i] + lines[i + 1:]
                    why = outcome(mode, cut if side == 'm' else m, a if side == 'm' else cut)
                    if why is None:
                        failures.append(f'{mode}: passed without {side}[{i}] {text!r}')
        def expect(label, mode, m, a, step):
            """A negative control: the check must fail, and name `step`."""
            why = outcome(mode, sorted(m, key=lambda x: x[0]), sorted(a, key=lambda x: x[0]))
            if why is None or step not in why:
                failures.append(f'{mode}: {label}: expected a failure naming {step!r}, got {why!r}')

        def edit(lines, needle, f):
            return [f(s, t) if needle in t else (s, t) for s, t in lines]

        for mode in ('retrain', 'no-retrain'):
            m, a = fixture(mode)
            # S1: the subscription must carry the 0.70 threshold.
            expect('subscribed with threshold 0.50', mode, m,
                   edit(a, 'subscribed to MTLF', lambda s, t: (s, t.replace('0.70', '0.50'))), 'S1')
            # S2 must follow the subscription.
            expect('v1 provisioned 30 s before the subscription', mode,
                   edit(m, 'v1 provisioned', lambda s, t: (10, t)), a, 'S2')
            # S6: no calm report at all, or only reports below 0.70 before the change.
            expect('no calm report', mode, m, [x for x in a if '0.98' not in x[1]], 'S6')
            expect('the only pre-change reports < 0.70', mode, m,
                   edit(a, 'accuracy 0.98', lambda s, t: (s, t.replace('0.98', '0.65'))), 'S6')
            # S3 ordering: v1 verified before the subscription fails; before the
            # MTLF's `provisioned` line (the 204 race) passes.
            expect('v1 verified before the subscription', mode, m,
                   edit(a, 'v1 verified', lambda s, t: (30, t)), 'S3')
            why = outcome(mode, edit(m, 'v1 provisioned', lambda s, t: (42, t)), a)
            if why is not None:
                failures.append(f'{mode}: v1 verified before the 204-time provisioned line failed: {why}')
            # S3 content: the URL must end in the sha256 it was verified as.
            expect('v1 URL not ending in its sha256', mode, m,
                   edit(a, 'v1 verified', lambda s, t: (s, t.replace(f'{URL}{S1_}', f'{URL}{S2_}'))), 'S3')
            expect('v1 verified under a sha256 never notified', mode, m,
                   edit(a, 'v1 verified', lambda s, t: (s, t.replace(f'sha256={S1_}', f'sha256={S2_}'))), 'S3')
            # S5: the MTLF's Subscribe must name the registered modelId.
            expect('S5 for another modelId', mode,
                   edit(m, 'subscribed at AnLF', lambda s, t: (s, t.replace('modelId=111', 'modelId=333'))), a, 'S5')
            # S8 must follow the scripted change. The report between is cut so
            # nothing else can trip first.
            moved = edit(m, 'retrain requested' if mode == 'retrain' else 'no retrain', lambda s, t: (110, t))
            expect('the drop before the regime change', mode, moved,
                   [x for x in a if '0.75' not in x[1]], 'S8')
        # retrain-specific rules.
        m, a = fixture('retrain')
        expect('a v2 report below 0.70', 'retrain', m,
               a + [(198, P + 'accuracy 0.62 (n=20) reported for modelId=222 sub=m2')], 'S13')
        expect('only a v1 report after v2 verified', 'retrain', m,
               [x for x in a if 'reported for modelId=222' not in x[1]]
               + [(197, P + 'accuracy 0.99 (n=20) reported for modelId=111 sub=m1')], 'S13')
        expect('v2 verified before v2 was published', 'retrain', m,
               edit(a, 'v2 verified', lambda s, t: (190, t)), 'S12')
        why = outcome('retrain', edit(m, 'v2 provisioned', lambda s, t: (197, t)), a)
        if why is not None:
            failures.append(f'retrain: v2 verified before the 204-time provisioned line failed: {why}')
        expect('v2 provisioned under another sha256', 'retrain',
               edit(m, 'v2 provisioned', lambda s, t: (s, t.replace(S2_, 'c' * 64))), a, 'S11')
        expect('two retrain requests', 'retrain',
               m + [(250, P + 'accuracy 0.60 < 0.70: retrain requested (modelId=222)')], a, 'exactly one')
        refused = P + f'model refused (sha256 mismatch) from {URL}{S2_}: x; keeping v1'
        expect('a refused model', 'retrain', m, a + [(199, refused)], 'refused a model')
        # The flipped-byte revert's log: v2 refused, kept v1 -> fails at S12.
        expect('the flipped-byte revert log', 'retrain', m,
               [(s, t) for s, t in a if 'v2 verified' not in t and 'modelId=222' not in t] + [(196, refused)], 'S12')
        # The feed-patched-out revert's log: no rolling lines -> fails at S8.
        expect('the no-feed revert log', 'retrain',
               [(s, t) for s, t in m if not re.search(r'retrain requested|retrain: |v2', t)],
               [(s, t) for s, t in a if '222' not in t and 'v2' not in t], 'S8')
        # no-retrain-specific rules.
        m, a = fixture('no-retrain')
        expect('a report >= 0.70 after the drop', 'no-retrain', m,
               a + [(281, P + 'accuracy 0.71 (n=20) reported for modelId=111 sub=m1')], '>= 0.70 after the drop')
        expect('one report after the drop', 'no-retrain', m, a[:-1], 'report(s) after the drop')
        expect('a v2', 'no-retrain',
               m + [(200, P + f'retrain: model v2 published sha256={S2_} modelId=2 (replaces v1)')], a,
               'the MTLF logged')
        expect('a retrain request', 'no-retrain',
               m + [(200, P + 'accuracy 0.60 < 0.70: retrain requested (modelId=111)')], a, 'retrain requested')
        # An empty capture is a failure, never "no such line".
        open(mp, 'w').close()
        write(fixture('retrain')[1], ap, False)
        try:
            load(mp, 'MTLF')
            failures.append('an empty log loaded')
        except Fail:
            pass
    if failures:
        print('chain.py self-test FAILED:\n  ' + '\n  '.join(failures), file=sys.stderr)
        return 1
    print('chain.py self-test: good logs pass in both modes and both log formats; every needed '
          'line taken out fails, and each negative control fails at the step it targets')
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--mode', choices=['retrain', 'no-retrain'])
    ap.add_argument('--mtlf')
    ap.add_argument('--anlf')
    ap.add_argument('--facts')
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not (a.mode and a.mtlf and a.anlf):
        ap.error('--mode, --mtlf and --anlf are required')
    return run(a.mode, a.mtlf, a.anlf, a.facts)


if __name__ == '__main__':
    sys.exit(main())
