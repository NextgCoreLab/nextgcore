#!/usr/bin/env python3
"""udmd's durable state file gets a volume only when it is enabled (#1885).

#1855 (#1836) made udmd persist its SDM subscriptions, its am-data
subscriptions at the UDR and the am-data changes waiting for an AMF in a state
file (NEXTGCORE_UDM_STATE_FILE). The compose stack mounted a volume for it; the
k8s manifests and the Helm chart did not. This checks rendered manifests
(`helm template`, `kubectl kustomize`), offline:

  --off FILE   the udm Deployment has no NEXTGCORE_UDM_STATE_FILE, no udm-state
               volume or mount, and the render no udm-state claim. The shipped
               defaults are memory-only.
  --on MODE:FILE  (MODE pvc or emptydir) the udm Deployment sets
               NEXTGCORE_UDM_STATE_FILE to a file directly in the udm-state
               mount; the volume is a claim (pvc) or an emptyDir; the pod keeps
               an fsGroup so the non-root container can write it, and no
               container of the pod runs privileged or as root. For pvc: one
               replica, strategy Recreate, and a ReadWriteOnce(Pod) claim of
               that name in the render: one writer per file.

Every option may repeat. --self-test runs the checks against synthetic
manifests that must pass and fail; a check that silently stopped matching
would otherwise pass every render.
"""

import copy
import posixpath
import sys

import yaml

ENV = 'NEXTGCORE_UDM_STATE_FILE'
VOLUME = 'udm-state'
ONE_WRITER_MODES = ('ReadWriteOnce', 'ReadWriteOncePod')


def _docs(path):
    with open(path) as f:
        return [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]


def _udm_deployments(docs):
    return [d for d in docs if d.get('kind') == 'Deployment'
            and (d.get('metadata', {}).get('name') == 'udm'
                 or d.get('metadata', {}).get('name', '').endswith('-udm'))]


def _container(pod):
    return next((c for c in pod.get('containers', []) if c.get('name') == 'udm'), None)


def _claims(docs):
    return {d['metadata']['name']: d for d in docs
            if d.get('kind') == 'PersistentVolumeClaim'}


def check_off(docs):
    errs = []
    deps = _udm_deployments(docs)
    if not deps:
        return ['no udm Deployment in the render']
    for d in deps:
        pod = d['spec']['template']['spec']
        c = _container(pod) or {}
        if any(e.get('name') == ENV for e in c.get('env') or []):
            errs.append(f'{d["metadata"]["name"]}: {ENV} is set with durable state off')
        if any(v.get('name') == VOLUME for v in pod.get('volumes') or []):
            errs.append(f'{d["metadata"]["name"]}: a {VOLUME} volume with durable state off')
        if any(m.get('name') == VOLUME for m in c.get('volumeMounts') or []):
            errs.append(f'{d["metadata"]["name"]}: a {VOLUME} mount with durable state off')
    for name in _claims(docs):
        if name == VOLUME or name.endswith('-' + VOLUME):
            errs.append(f'PersistentVolumeClaim {name} rendered with durable state off')
    return errs


def check_on(docs, mode):
    deps = _udm_deployments(docs)
    if len(deps) != 1:
        return [f'expected one udm Deployment, found {len(deps)}']
    d = deps[0]
    name = d['metadata']['name']
    pod = d['spec']['template']['spec']
    c = _container(pod)
    if c is None:
        return [f'{name}: no udm container']
    errs = []
    env = next((e for e in c.get('env') or [] if e.get('name') == ENV), None)
    mount = next((m for m in c.get('volumeMounts') or [] if m.get('name') == VOLUME), None)
    vol = next((v for v in pod.get('volumes') or [] if v.get('name') == VOLUME), None)
    if env is None or not env.get('value'):
        errs.append(f'{name}: {ENV} is not set')
    if mount is None:
        errs.append(f'{name}: no {VOLUME} mount on the udm container')
    elif mount.get('readOnly'):
        errs.append(f'{name}: the {VOLUME} mount is read-only')
    elif mount.get('subPath'):
        errs.append(f'{name}: the {VOLUME} mount uses a subPath')
    if env and env.get('value') and mount and \
            posixpath.dirname(env['value']) != posixpath.normpath(mount['mountPath']):
        errs.append(f'{name}: {ENV}={env["value"]} is not in the mount {mount["mountPath"]}')
    if vol is None:
        errs.append(f'{name}: no {VOLUME} volume')
    elif mode == 'emptydir' and 'emptyDir' not in vol:
        errs.append(f'{name}: the {VOLUME} volume is not an emptyDir: {vol}')
    elif mode == 'pvc':
        claim = (vol.get('persistentVolumeClaim') or {}).get('claimName')
        if not claim:
            errs.append(f'{name}: the {VOLUME} volume is not a claim: {vol}')
        else:
            pvc = _claims(docs).get(claim)
            if pvc is None:
                errs.append(f'{name}: claim {claim} is not in the render')
            else:
                modes = pvc.get('spec', {}).get('accessModes') or []
                if not modes or any(m not in ONE_WRITER_MODES for m in modes):
                    errs.append(f'claim {claim}: accessModes {modes}, not one-writer')
        replicas = d['spec'].get('replicas', 1)
        if replicas != 1:
            errs.append(f'{name}: replicas {replicas} share one state file')
        strategy = (d['spec'].get('strategy') or {}).get('type')
        if strategy != 'Recreate':
            errs.append(f'{name}: strategy {strategy or "RollingUpdate (default)"}, '
                        'so the old and new pod write one file')
    if (pod.get('securityContext') or {}).get('fsGroup') is None:
        errs.append(f'{name}: no pod fsGroup; the non-root udmd cannot write the volume')
    for k in pod.get('initContainers', []) + pod.get('containers', []):
        sc = k.get('securityContext') or {}
        if sc.get('privileged') or sc.get('runAsUser') == 0 or sc.get('allowPrivilegeEscalation'):
            errs.append(f'{name}: container {k.get("name")} securityContext weakened: {sc}')
    return errs


def _synthetic(mode):
    """A udm Deployment and claim as the components render them."""
    dep = {'kind': 'Deployment', 'metadata': {'name': 'udm'}, 'spec': {
        'replicas': 1, 'strategy': {'type': 'Recreate'},
        'template': {'spec': {
            'securityContext': {'fsGroup': 999},
            'initContainers': [{'name': 'wait-nrf'}],
            'containers': [{'name': 'udm',
                            'env': [{'name': ENV, 'value': '/var/lib/nextgcore/udm-state.json'}],
                            'volumeMounts': [{'name': VOLUME, 'mountPath': '/var/lib/nextgcore'}]}],
            'volumes': [{'name': VOLUME, 'persistentVolumeClaim': {'claimName': VOLUME}}
                        if mode == 'pvc' else {'name': VOLUME, 'emptyDir': {}}]}}}}
    pvc = {'kind': 'PersistentVolumeClaim', 'metadata': {'name': VOLUME},
           'spec': {'accessModes': ['ReadWriteOnce']}}
    return [dep, pvc] if mode == 'pvc' else [dep]


def self_test():
    def pod(docs):
        return docs[0]['spec']['template']['spec']

    def mutate(mode, fn):
        docs = copy.deepcopy(_synthetic(mode))
        fn(docs)
        return docs

    off = mutate('emptydir', lambda d: (pod(d)['containers'][0].update(env=[], volumeMounts=[]),
                                        pod(d).update(volumes=[])))
    cases = [
        ('pvc renders pass', check_on(_synthetic('pvc'), 'pvc'), False),
        ('emptydir renders pass', check_on(_synthetic('emptydir'), 'emptydir'), False),
        ('memory-only passes off', check_off(off), False),
        ('enabled render fails off', check_off(_synthetic('pvc')), True),
        ('a stray claim fails off', check_off(off + [_synthetic('pvc')[1]]), True),
        ('no env', check_on(mutate('pvc', lambda d: pod(d)['containers'][0].update(env=[])), 'pvc'), True),
        ('no mount', check_on(mutate('pvc', lambda d: pod(d)['containers'][0].update(volumeMounts=[])), 'pvc'), True),
        ('no volume', check_on(mutate('pvc', lambda d: pod(d).update(volumes=[])), 'pvc'), True),
        ('env outside the mount', check_on(mutate('pvc', lambda d: pod(d)['containers'][0]['env'][0].update(
            value='/tmp/udm-state.json')), 'pvc'), True),
        ('emptyDir where a claim is wanted', check_on(_synthetic('emptydir'), 'pvc'), True),
        ('claim missing from the render', check_on(_synthetic('pvc')[:1], 'pvc'), True),
        ('ReadWriteMany claim', check_on(mutate('pvc', lambda d: d[1]['spec'].update(
            accessModes=['ReadWriteMany'])), 'pvc'), True),
        ('two replicas', check_on(mutate('pvc', lambda d: d[0]['spec'].update(replicas=2)), 'pvc'), True),
        ('RollingUpdate', check_on(mutate('pvc', lambda d: d[0]['spec'].pop('strategy')), 'pvc'), True),
        ('no fsGroup', check_on(mutate('pvc', lambda d: pod(d).pop('securityContext')), 'pvc'), True),
        ('root container', check_on(mutate('emptydir', lambda d: pod(d)['containers'][0].update(
            securityContext={'runAsUser': 0})), 'emptydir'), True),
        ('read-only mount', check_on(mutate('pvc', lambda d: pod(d)['containers'][0]['volumeMounts'][0].update(
            readOnly=True)), 'pvc'), True),
        ('no udm Deployment', check_off([]), True),
    ]
    bad = [f'{name}: expected {"failure" if want else "pass"}, got {errs}'
           for name, errs, want in cases if bool(errs) != want]
    for b in bad:
        print(f'self-test: {b}', file=sys.stderr)
    print(f'self-test: {len(cases) - len(bad)}/{len(cases)} cases as expected')
    return 1 if bad else 0


def main(argv):
    if argv[1:] == ['--self-test']:
        return self_test()
    args, errs, n = argv[1:], [], 0
    if not args or len(args) % 2:
        print(__doc__, file=sys.stderr)
        return 2
    for opt, val in zip(args[::2], args[1::2]):
        if opt == '--off':
            found = check_off(_docs(val))
        elif opt == '--on' and val.split(':', 1)[0] in ('pvc', 'emptydir') and ':' in val:
            mode, path = val.split(':', 1)
            found, val = check_on(_docs(path), mode), path
        else:
            print(__doc__, file=sys.stderr)
            return 2
        errs += [f'{val}: {e}' for e in found]
        n += 1
    for e in errs:
        print(e, file=sys.stderr)
    print(f'{n} render(s) checked, {len(errs)} problem(s)')
    return 1 if errs else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
