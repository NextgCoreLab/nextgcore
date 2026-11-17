"""Crash-loop detection for the rollout waits (#1651).

A rollout wait (`kubectl rollout status`) only reports a crash-looping pod when
its timeout expires: 300 s per wait, and PROFILE=demo waits on the ue twice, so a
crash loop cost about 11.5 minutes per arm with the EKS demo lock held.
`nextg_rollout_wait` (lib/profile.sh) runs this every few seconds during a wait
and fails the deploy as soon as it reports something.

    crashloop.py WORKLOADS_JSON PODS_JSON [KIND/NAME]

WORKLOADS_JSON is `kubectl get deployments,statefulsets,replicasets -o json`,
PODS_JSON `kubectl get pods -o json`. KIND/NAME (deployment/ue,
statefulset/mongodb) limits the check to that workload; with none, every
Deployment and StatefulSet is checked.

Only the pods of the workload's CURRENT revision count: during a rolling update
the previous ReplicaSet's pods stay up until the new ones are Ready, and a deploy
that fixes a crash loop must not be failed by the crash loop it is replacing.
Terminating pods are skipped. A container (init or regular) is crash-looping when
it waits in CrashLoopBackOff, or when it is not Ready and has restarted more than
NEXTG_ROLLOUT_RESTART_LIMIT times (default 3).

Prints one line per crash-looping container, `pod container reason restarts`,
and exits 1 when there is any; 0 when there is none; 2 when the input does not
parse (no verdict: the wait goes on and its own timeout still applies).
"""

import json
import os
import sys

DEFAULT_RESTART_LIMIT = 3
KINDS = {'deployment': 'Deployment', 'statefulset': 'StatefulSet'}


def _meta(obj):
    return obj.get('metadata') or {}


def _labels(obj):
    return _meta(obj).get('labels') or {}


def current_pods(workload, pods, replicasets):
    """The live pods of `workload`'s current revision."""
    selector = ((workload.get('spec') or {}).get('selector') or {}).get('matchLabels') or {}
    if not selector:
        return []
    live = [p for p in pods
            if not _meta(p).get('deletionTimestamp')
            and all(_labels(p).get(k) == v for k, v in selector.items())]
    if workload.get('kind') == 'Deployment':
        rev = (_meta(workload).get('annotations') or {}).get('deployment.kubernetes.io/revision')
        uid = _meta(workload).get('uid')
        if rev is None or uid is None:
            return []
        hashes = {
            _labels(rs).get('pod-template-hash')
            for rs in replicasets
            if (_meta(rs).get('annotations') or {}).get('deployment.kubernetes.io/revision') == rev
            and any(o.get('uid') == uid for o in _meta(rs).get('ownerReferences') or [])
        }
        hashes.discard(None)
        return [p for p in live if _labels(p).get('pod-template-hash') in hashes]
    if workload.get('kind') == 'StatefulSet':
        rev = (workload.get('status') or {}).get('updateRevision')
        if not rev:
            return []
        return [p for p in live if _labels(p).get('controller-revision-hash') == rev]
    return []


def crash_looping(pod, restart_limit):
    """(container, reason, restarts) for each crash-looping container of `pod`."""
    status = pod.get('status') or {}
    out = []
    for cs in (status.get('initContainerStatuses') or []) + (status.get('containerStatuses') or []):
        waiting = (cs.get('state') or {}).get('waiting') or {}
        restarts = cs.get('restartCount') or 0
        if waiting.get('reason') == 'CrashLoopBackOff':
            out.append((cs.get('name', '?'), 'CrashLoopBackOff', restarts))
        elif restarts > restart_limit and not cs.get('ready'):
            out.append((cs.get('name', '?'), 'Restarting', restarts))
    return out


def classify(workloads, pods, target=None, restart_limit=DEFAULT_RESTART_LIMIT):
    """[(pod, container, reason, restarts)] for the crash-looping containers."""
    items = workloads.get('items') or []
    replicasets = [w for w in items if w.get('kind') == 'ReplicaSet']
    if target:
        kind, _, name = target.partition('/')
        kind = KINDS.get(kind.lower())
        chosen = [w for w in items if w.get('kind') == kind and _meta(w).get('name') == name]
    else:
        chosen = [w for w in items if w.get('kind') in KINDS.values()]
    found = []
    for w in chosen:
        for p in current_pods(w, pods.get('items') or [], replicasets):
            for container, reason, restarts in crash_looping(p, restart_limit):
                found.append((_meta(p).get('name', '?'), container, reason, restarts))
    return found


def main(argv):
    if len(argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        with open(argv[1]) as f:
            workloads = json.load(f)
        with open(argv[2]) as f:
            pods = json.load(f)
        limit = int(os.environ.get('NEXTG_ROLLOUT_RESTART_LIMIT', DEFAULT_RESTART_LIMIT))
    except (OSError, ValueError) as e:
        print(f'crashloop.py: no verdict: {e}', file=sys.stderr)
        return 2
    if not isinstance(workloads, dict) or not isinstance(pods, dict):
        return 2
    found = classify(workloads, pods, argv[3] if len(argv) == 4 else None, limit)
    for pod, container, reason, restarts in found:
        print(f'{pod} {container} {reason} {restarts}')
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
