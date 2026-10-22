"""Fixture tests for live_modes.py (#657, #662). Run: python3 -m unittest -v
from deploy/eks/lib."""

import unittest

from live_modes import dataplane_mode, immutable_diff, storage_mode

GP3_CLAIM = {
    'metadata': {'name': 'mongodb-data'},
    'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': 'gp3',
             'resources': {'requests': {'storage': '8Gi'}}},
}


def sts(claims=None, **spec):
    s = {'selector': {'matchLabels': {'app.kubernetes.io/name': 'mongodb'}},
         'serviceName': 'mongodb', 'template': {'spec': {'containers': []}}}
    if claims is not None:
        s['volumeClaimTemplates'] = claims
    s.update(spec)
    return {'kind': 'StatefulSet', 'metadata': {'name': 'mongodb'}, 'spec': s}


def live_claim(claim):
    """A claim template as the API server returns it: defaults filled in."""
    out = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
           'metadata': dict(claim['metadata']),
           'spec': dict(claim['spec'], volumeMode='Filesystem'),
           'status': {'phase': 'Pending'}}
    return out


class StorageMode(unittest.TestCase):

    def test_an_install_created_with_ephemeral_storage_reads_as_ephemeral(self):
        # devtest1: the live StatefulSet has no claim templates at all.
        self.assertEqual(storage_mode(sts(podManagementPolicy='OrderedReady')), 'ephemeral')

    def test_a_claim_template_reads_as_pvc(self):
        self.assertEqual(storage_mode(sts([live_claim(GP3_CLAIM)])), 'pvc')

    def test_no_live_object_is_absent(self):
        self.assertEqual(storage_mode(None), 'absent')


class ImmutableDiff(unittest.TestCase):

    def test_the_devtest1_failure_is_reported_as_a_claim_template_change(self):
        # The exact pair that made `kubectl apply` fail with "spec: Forbidden".
        live = sts(podManagementPolicy='OrderedReady')
        rendered = sts([GP3_CLAIM])
        diff = immutable_diff(live, rendered)
        self.assertEqual(len(diff), 1)
        self.assertTrue(diff[0].startswith('volumeClaimTemplates:'), diff)

    def test_server_defaults_do_not_count_as_a_difference(self):
        # The live object carries volumeMode/status/apiVersion and an explicit
        # podManagementPolicy the manifest never set.
        live = sts([live_claim(GP3_CLAIM)], podManagementPolicy='OrderedReady')
        self.assertEqual(immutable_diff(live, sts([GP3_CLAIM])), [])

    def test_matching_ephemeral_installs_do_not_differ(self):
        self.assertEqual(immutable_diff(sts(), sts([])), [])

    def test_a_resized_claim_is_a_difference(self):
        bigger = {'metadata': GP3_CLAIM['metadata'],
                  'spec': dict(GP3_CLAIM['spec'], resources={'requests': {'storage': '16Gi'}})}
        self.assertEqual(len(immutable_diff(sts([live_claim(GP3_CLAIM)]), sts([bigger]))), 1)

    def test_a_changed_selector_is_a_difference(self):
        other = sts([GP3_CLAIM])
        other['spec']['selector'] = {'matchLabels': {'app': 'mongo'}}
        self.assertEqual(len(immutable_diff(sts([GP3_CLAIM]), other)), 1)


class DataplaneMode(unittest.TestCase):

    def deploy(self, sc):
        c = {'name': 'upf'}
        if sc is not None:
            c['securityContext'] = sc
        return {'spec': {'template': {'spec': {'containers': [c]}}}}

    def test_a_privileged_upf_is_the_dataplane_variant(self):
        self.assertEqual(dataplane_mode(self.deploy({'privileged': True}), 'upf'), 'true')

    def test_an_unprivileged_upf_is_not(self):
        self.assertEqual(dataplane_mode(self.deploy({'runAsNonRoot': True}), 'upf'), 'false')
        self.assertEqual(dataplane_mode(self.deploy(None), 'upf'), 'false')

    def test_no_live_upf_is_absent(self):
        self.assertEqual(dataplane_mode(None, 'upf'), 'absent')


if __name__ == '__main__':
    unittest.main()
