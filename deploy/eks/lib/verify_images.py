"""Verify the running pods carry the images deploy-eks.sh just applied (#436).

Called by deploy-eks.sh after the rollout waits. Kept as a module, not an inline
heredoc, so each rule below has a fixture test in test_verify_images.py.

Rules, each one fixing a misreport observed on devtest1:

* A pod being REPLACED (it has a deletionTimestamp) is not checked. An outgoing
  replica was flagged seconds before it went away, while its successor was
  already Ready on the expected image.
* A pod is judged by its own SPEC image -- which ReplicaSet created it, which is
  exactly the question "did the apply replace this pod". Neither status field
  is trusted. ``status.image`` named a stale tag for an NRF on the right image,
  and ``status.containerStatuses[].imageID`` is no better: when a node already
  holds a content-identical image under an older digest (any rebuild with
  unchanged binaries), containerd reports THAT digest, even for a pod that just
  pulled the new tag. On devtest1 a freshly restarted UE reported the digest of
  the first UE image ever pushed, two days and four pushes earlier.
* A mismatch where a pod ON the expected image exists but is not Ready is a
  FAILING ROLLOUT, not a stale one. The old advice ("rollout restart") would
  only start more crashing pods. Before this, a CrashLoopBackOff caused by a
  missing TLS certificate was reported as "the apply did not replace these
  pods".

Exit status: 0 verified, 1 stale (the apply did not replace pods), 2 failing
rollout (replacements exist but are not Ready).
"""

import json
import re
import sys

import yaml


def norm(ref):
    """Normalise an image reference: drop docker.io/[library/], add :latest."""
    ref = re.sub(r'^docker\.io/(library/)?', '', ref)
    return ref if ':' in ref.rsplit('/', 1)[-1] else ref + ':latest'


def wanted_images(docs):
    """Container name -> set of image refs the applied manifests ask for."""
    wanted = {}
    for d in docs:
        if not d or d.get('kind') not in ('Deployment', 'StatefulSet', 'Job'):
            continue
        for c in d['spec']['template']['spec'].get('containers', []):
            wanted.setdefault(c['name'], set()).add(c['image'])
    return wanted


def _spec_image(pod, container_name):
    for c in pod.get('spec', {}).get('containers', []):
        if c.get('name') == container_name:
            return c.get('image')
    return None


def _runs_wanted(pod, cs, want):
    """Whether this container's pod was created from one of the wanted specs."""
    spec = _spec_image(pod, cs['name'])
    return spec is not None and norm(spec) in {norm(w) for w in want}


def classify(docs, pods):
    """Return (status, checked, mismatched, failing).

    status is 'ok', 'stale' or 'failing'. ``mismatched`` and ``failing`` are
    human-readable lines.
    """
    wanted = wanted_images(docs)
    live = [p for p in pods.get('items', []) if not p['metadata'].get('deletionTimestamp')]

    mismatched, checked = [], 0
    for p in live:
        if p.get('status', {}).get('phase') not in ('Running', 'Succeeded'):
            continue
        for cs in p.get('status', {}).get('containerStatuses', []):
            want = wanted.get(cs['name'])
            if not want:
                continue
            checked += 1
            if not _runs_wanted(p, cs, want):
                mismatched.append(
                    f"{p['metadata']['name']}/{cs['name']}: running "
                    f"{_spec_image(p, cs['name'])}, expected "
                    f"{' or '.join(sorted(want))}"
                )

    # Replacements on the expected image that are not Ready. Checked even when
    # nothing mismatched: rollout status only warns, so a crash-looping
    # replacement would otherwise end in "Deployed." with the old pod serving.
    failing = []
    for p in live:
        # A completed Job pod (mongodb-init) is never Ready, by design.
        if p.get('status', {}).get('phase') in ('Succeeded', 'Failed'):
            continue
        for cs in p.get('status', {}).get('containerStatuses', []):
            want = wanted.get(cs['name'])
            spec = _spec_image(p, cs['name'])
            if not want or spec is None or norm(spec) not in {norm(w) for w in want}:
                continue
            if cs.get('ready'):
                continue
            waiting = (cs.get('state') or {}).get('waiting') or {}
            reason = waiting.get('reason') or p.get('status', {}).get('phase', '?')
            name = p['metadata']['name']
            failing.append(
                f"{name}/{cs['name']}: {reason}, {cs.get('restartCount', 0)} restarts "
                f"-- kubectl logs -n <ns> {name} -c {cs['name']} --previous"
            )

    if failing:
        return 'failing', checked, mismatched, failing
    if mismatched:
        return 'stale', checked, mismatched, failing
    return 'ok', checked, mismatched, failing


def main(argv):
    rendered, pods_json = argv[1], argv[2]
    docs = list(yaml.safe_load_all(open(rendered)))
    pods = json.load(open(pods_json))

    status, checked, mismatched, failing = classify(docs, pods)

    if status == 'failing':
        print('replacement pods on the deployed image are NOT Ready -- the '
              'rollout is failing, not stale:', file=sys.stderr)
        for f in failing:
            print(f'  {f}', file=sys.stderr)
        print('\nDo NOT rollout-restart: it only starts more failing pods. The old '
              'pods keep serving meanwhile.\nRead the logs above, fix the cause, '
              'and re-run this script.', file=sys.stderr)
        return 2
    if status == 'stale':
        print('pods are NOT running the images just deployed:', file=sys.stderr)
        for m in mismatched:
            print(f'  {m}', file=sys.stderr)
        print('\nThis is the stale-image failure mode: the apply did not replace '
              'these pods.\nForce it bottom-up, then re-run this script:\n'
              '  kubectl rollout restart -n <ns> deploy/udr deploy/udm deploy/ausf '
              'deploy/pcf deploy/nssf deploy/bsf\n'
              '  kubectl rollout restart -n <ns> deploy/upf deploy/smf deploy/amf '
              'deploy/gnb deploy/ue', file=sys.stderr)
        return 1
    if not checked:
        # Not a hard failure: an earlier rollout warn already covered the
        # not-ready case. But "0 checked" must not read like a clean bill of
        # health, which a bare success line would.
        print('  WARNING: no running containers matched a deployed container name, '
              'so nothing was verified', file=sys.stderr)
    else:
        print(f'  {checked} running containers all match the deployed images')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
