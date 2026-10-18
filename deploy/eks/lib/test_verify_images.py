"""Fixture tests for verify_images.py (#436). Run: python3 -m unittest -v
from deploy/eks/lib.

Each case is a misreport observed on devtest1, reduced to the pod fields the
verifier reads. Digests are the real ones from those deploys.
"""

import unittest

from verify_images import classify

REG = '376798132683.dkr.ecr.us-west-2.amazonaws.com/nextg'
NEW, OLD = f'{REG}/nrf:c816a03ba7d3', f'{REG}/nrf:8bba39e8ca53'
NEW_D, OLD_D = 'sha256:5d1df8fe', 'sha256:f400ba0a'


def deployment(name, image):
    return {'kind': 'Deployment', 'spec': {'template': {'spec': {
        'containers': [{'name': name, 'image': image}]}}}}


def pod(name, container, spec_image, *, status_image=None, digest=None, ready=True,
        phase='Running', deleting=False, waiting=None, restarts=0):
    cs = {'name': container, 'image': status_image or spec_image, 'ready': ready,
          'restartCount': restarts,
          'imageID': f'{spec_image.rsplit(":", 1)[0]}@{digest}' if digest else ''}
    if waiting:
        cs['state'] = {'waiting': {'reason': waiting}}
    meta = {'name': name}
    if deleting:
        meta['deletionTimestamp'] = '2026-10-07T21:30:00Z'
    return {'metadata': meta, 'spec': {'containers': [{'name': container, 'image': spec_image}]},
            'status': {'phase': phase, 'containerStatuses': [cs]}}


def run(docs, pods):
    return classify(docs, {'items': pods})


class VerifyImages(unittest.TestCase):

    def test_a_correct_deploy_verifies(self):
        status, checked, _, _ = run([deployment('nrf', NEW)],
                                    [pod('nrf-a', 'nrf', NEW, digest=NEW_D)])
        self.assertEqual((status, checked), ('ok', 1))

    def test_a_stale_status_tag_is_not_trusted(self):
        # devtest1, 2026-10-07: status.image said 8bba39e for a pod on c816a03.
        status, _, mismatched, _ = run(
            [deployment('nrf', NEW)],
            [pod('nrf-a', 'nrf', NEW, status_image=OLD, digest=NEW_D)])
        self.assertEqual(status, 'ok', mismatched)

    def test_an_older_deduplicated_image_id_is_not_trusted(self):
        # devtest1, 2026-10-08: a UE restarted onto ue:67a0d792b5b3 reported the
        # digest of the FIRST UE image ever pushed (containerd dedupes
        # content-identical images and reports an older repo digest).
        status, _, mismatched, _ = run(
            [deployment('nrf', NEW)],
            [pod('nrf-a', 'nrf', NEW, digest='sha256:abb18b6d')])
        self.assertEqual(status, 'ok', mismatched)

    def test_a_pod_created_from_the_previous_spec_is_stale(self):
        # The real stale case: the apply did not replace this pod.
        status, _, mismatched, _ = run(
            [deployment('nrf', NEW)],
            [pod('nrf-a', 'nrf', OLD, digest=OLD_D)])
        self.assertEqual(status, 'stale')
        self.assertIn('nrf-a/nrf', mismatched[0])

    def test_an_outgoing_replica_is_not_checked(self):
        # devtest1: the old UPF was flagged while terminating; its successor was Ready.
        status, checked, mismatched, _ = run(
            [deployment('nrf', NEW)],
            [pod('nrf-old', 'nrf', OLD, digest=OLD_D, deleting=True),
             pod('nrf-new', 'nrf', NEW, digest=NEW_D)])
        self.assertEqual((status, checked), ('ok', 1), mismatched)

    def test_a_crash_looping_replacement_is_a_failing_rollout_not_stale(self):
        # devtest1, 2026-10-06: ausf replacements crash-looped on a missing TLS
        # cert while the old pod kept serving; it was reported as stale.
        status, _, _, failing = run(
            [deployment('nrf', NEW)],
            [pod('nrf-old', 'nrf', OLD, digest=OLD_D),
             pod('nrf-new', 'nrf', NEW, digest=NEW_D, ready=False,
                 waiting='CrashLoopBackOff', restarts=6)])
        self.assertEqual(status, 'failing')
        self.assertIn('nrf-new/nrf: CrashLoopBackOff, 6 restarts', failing[0])
        self.assertIn('--previous', failing[0])

    def test_a_completed_job_is_not_a_failing_rollout(self):
        status, _, _, failing = run(
            [{'kind': 'Job', 'spec': {'template': {'spec': {
                'containers': [{'name': 'init', 'image': 'mongo:6.0'}]}}}}],
            [pod('init-x', 'init', 'mongo:6.0', ready=False, phase='Succeeded')])
        self.assertEqual(status, 'ok', failing)

    def test_a_normalised_docker_hub_reference_matches(self):
        # kubelet may report docker.io/... for an unqualified spec reference.
        status, _, _, _ = run([deployment('grafana', 'grafana/grafana:10.4.0')],
                              [pod('g', 'grafana', 'grafana/grafana:10.4.0',
                                   status_image='docker.io/grafana/grafana:9.0.0')])
        self.assertEqual(status, 'ok')


if __name__ == '__main__':
    unittest.main()
