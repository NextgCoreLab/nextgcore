"""Read the live install's modes so a re-run of deploy-eks.sh keeps them (#657, #662).

Two deploy-time choices are baked into objects a later run must not silently
change:

* MongoDB storage (EPHEMERAL_STORAGE). The StatefulSet's volumeClaimTemplates
  are IMMUTABLE. An install created with EPHEMERAL_STORAGE=true has none; a
  plain re-run rendered the gp3 claim template and `kubectl apply` failed with
  "spec: Forbidden: updates to statefulset spec for fields other than ...",
  stopping the script before its rollout waits and its image assertion.
* The UPF data plane (ENABLE_DATAPLANE). A re-run without it swapped a working
  privileged UPF back to --no-dataplane and relabelled the namespace baseline:
  UE traffic stopped, with no error anywhere.

So both default to "auto": adopt whatever the live objects say.

Usage:
  live_modes.py storage LIVE_STS_JSON            -> ephemeral | pvc | absent
  live_modes.py dataplane LIVE_DEPLOY_JSON NAME  -> true | false | absent
  live_modes.py sts-diff LIVE_STS_JSON RENDERED_YAML NAME
      prints one line per immutable StatefulSet field that differs; exit 1 if any

An empty or unreadable LIVE_*_JSON means the object does not exist ("absent").
"""

import json
import sys


def _load_json(path):
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return None
    if not text.strip():
        return None
    return json.loads(text)


def storage_mode(sts):
    """ephemeral when the live StatefulSet has no claim templates, else pvc."""
    if not sts:
        return 'absent'
    return 'pvc' if sts.get('spec', {}).get('volumeClaimTemplates') else 'ephemeral'


def dataplane_mode(deploy, container):
    """true when the live UPF container is privileged (the data-plane variant)."""
    if not deploy:
        return 'absent'
    pod = deploy.get('spec', {}).get('template', {}).get('spec', {})
    cont = next((c for c in pod.get('containers', []) if c.get('name') == container),
                (pod.get('containers') or [{}])[0])
    sc = cont.get('securityContext') or {}
    return 'true' if sc.get('privileged') else 'false'


def _claim(t):
    """The parts of a claim template the user sets; drops server-side defaults
    (volumeMode, status, apiVersion/kind) so a live object compares equal to the
    manifest it was created from."""
    spec = t.get('spec', {})
    return {
        'name': t.get('metadata', {}).get('name'),
        'accessModes': sorted(spec.get('accessModes', [])),
        'storageClassName': spec.get('storageClassName'),
        'storage': (spec.get('resources', {}).get('requests', {}) or {}).get('storage'),
    }


def immutable_diff(live, rendered):
    """Immutable StatefulSet spec fields (apps/v1) whose rendered value differs
    from the live one. Server defaults are normalised on both sides."""
    ls, rs = live.get('spec', {}), rendered.get('spec', {})
    fields = {
        'selector': lambda s: s.get('selector'),
        'serviceName': lambda s: s.get('serviceName'),
        'podManagementPolicy': lambda s: s.get('podManagementPolicy') or 'OrderedReady',
        'volumeClaimTemplates': lambda s: [_claim(t) for t in s.get('volumeClaimTemplates') or []],
    }
    out = []
    for name, get in fields.items():
        a, b = get(ls), get(rs)
        if a != b:
            out.append(f'{name}: live={json.dumps(a, sort_keys=True)} '
                       f'rendered={json.dumps(b, sort_keys=True)}')
    return out


def _rendered_sts(path, name):
    import yaml
    with open(path) as f:
        for d in yaml.safe_load_all(f):
            if d and d.get('kind') == 'StatefulSet' and d['metadata']['name'] == name:
                return d
    return None


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ''
    if cmd == 'storage' and len(argv) == 3:
        print(storage_mode(_load_json(argv[2])))
        return 0
    if cmd == 'dataplane' and len(argv) == 4:
        print(dataplane_mode(_load_json(argv[2]), argv[3]))
        return 0
    if cmd == 'sts-diff' and len(argv) == 5:
        live = _load_json(argv[2])
        rendered = _rendered_sts(argv[3], argv[4])
        if not live or not rendered:
            return 0
        diff = immutable_diff(live, rendered)
        for line in diff:
            print(line)
        return 1 if diff else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
