"""Decide whether a dependent must restart to re-resolve a peer it pins by IP (#436).

The SMF pins the UPF's pod IP, the gNB the AMF's and UPF's, and the UE the gNB's.
Each resolves once, in an init container. Through headless DNS, which lists
READY endpoints only, so until a peer's new pod is Ready the lookup still
returns the OLD pod.

So the question is not "is the dependent older than the peer" -- on devtest1 an
SMF and the new UPF were CREATED IN THE SAME SECOND, and the SMF still pinned
the dying UPF because it resolved before the new UPF was Ready. It is: did the
dependent start (finish resolving) at or before the moment the peer's current
pod became Ready? Ties restart. Timestamps have one-second resolution, and an
extra restart is cheap where a missed one breaks the session path.

Usage: pinned_peers.py DEPENDENT_PODS_JSON PEER_PODS_JSON
Prints ``restart`` or ``ok``.
"""

import json
import sys


def _live(pods):
    return [p for p in pods.get('items', []) if not p['metadata'].get('deletionTimestamp')]


def resolved_at(pods):
    """Earliest main-container start among live pods: the latest moment by which
    every live pod had finished its init-container resolution. None if no pod
    is running."""
    starts = []
    for p in _live(pods):
        for cs in p.get('status', {}).get('containerStatuses', []):
            started = ((cs.get('state') or {}).get('running') or {}).get('startedAt')
            if started:
                starts.append(started)
    return min(starts) if starts else None


def ready_at(pods):
    """Latest Ready=True transition among live pods: when the peer's newest pod
    became resolvable through headless DNS. None if no pod is Ready."""
    times = []
    for p in _live(pods):
        for c in p.get('status', {}).get('conditions', []):
            if c.get('type') == 'Ready' and c.get('status') == 'True':
                times.append(c.get('lastTransitionTime'))
    times = [t for t in times if t]
    return max(times) if times else None


def needs_reresolve(dependent_pods, peer_pods):
    mine, theirs = resolved_at(dependent_pods), ready_at(peer_pods)
    # RFC 3339 UTC timestamps from the API compare correctly as strings.
    return mine is not None and theirs is not None and mine <= theirs


if __name__ == '__main__':
    dep, peer = (json.load(open(f)) for f in sys.argv[1:3])
    print('restart' if needs_reresolve(dep, peer) else 'ok')
