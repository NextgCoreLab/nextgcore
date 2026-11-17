"""Fixture tests for crashloop.py (#1651). Run: python3 -m unittest -v
test_crashloop from deploy/eks/lib.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from crashloop import classify

HERE = os.path.dirname(os.path.abspath(__file__))
UID = 'dep-uid-ue'


def deployment(name='ue', revision='2'):
    return {'kind': 'Deployment',
            'metadata': {'name': name, 'uid': UID,
                         'annotations': {'deployment.kubernetes.io/revision': revision}},
            'spec': {'selector': {'matchLabels': {'app.kubernetes.io/name': name}}}}


def replicaset(pod_hash, revision, owner=UID):
    return {'kind': 'ReplicaSet',
            'metadata': {'name': f'ue-{pod_hash}', 'labels': {'pod-template-hash': pod_hash},
                         'annotations': {'deployment.kubernetes.io/revision': revision},
                         'ownerReferences': [{'uid': owner}]}}


def statefulset(name='mongodb', update='mongodb-new'):
    return {'kind': 'StatefulSet', 'metadata': {'name': name},
            'spec': {'selector': {'matchLabels': {'app': name}}},
            'status': {'updateRevision': update}}


def pod(name, labels, *, waiting=None, restarts=0, ready=False, init=False, deleting=False):
    cs = {'name': 'main', 'restartCount': restarts, 'ready': ready}
    if waiting:
        cs['state'] = {'waiting': {'reason': waiting}}
    meta = {'name': name, 'labels': labels}
    if deleting:
        meta['deletionTimestamp'] = '2026-11-17T10:00:00Z'
    key = 'initContainerStatuses' if init else 'containerStatuses'
    return {'metadata': meta, 'status': {key: [cs]}}


def ue_pod(name, pod_hash, **kw):
    return pod(name, {'app.kubernetes.io/name': 'ue', 'pod-template-hash': pod_hash}, **kw)


CURRENT = [deployment(), replicaset('new', '2'), replicaset('old', '1')]


def run(workloads, pods, target='deployment/ue', limit=3):
    return classify({'items': workloads}, {'items': pods}, target, limit)


class CrashLoop(unittest.TestCase):
    def test_crash_loop_back_off_in_the_current_revision(self):
        self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', waiting='CrashLoopBackOff',
                                              restarts=4)]),
                         [('ue-new-a', 'main', 'CrashLoopBackOff', 4)])

    def test_one_transient_crash_in_back_off_is_not(self):
        # The kubelet enters CrashLoopBackOff after the first exit (#1671 review).
        for restarts in (0, 1, 3):
            self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', waiting='CrashLoopBackOff',
                                                  restarts=restarts)]), [], restarts)

    def test_an_init_container_crash_loop(self):
        self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', waiting='CrashLoopBackOff',
                                              restarts=4, init=True)]),
                         [('ue-new-a', 'main', 'CrashLoopBackOff', 4)])

    def test_restarts_over_the_limit_while_not_ready(self):
        self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', restarts=4)]),
                         [('ue-new-a', 'main', 'Restarting', 4)])

    def test_restarts_at_the_limit_are_not(self):
        self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', restarts=3)]), [])

    def test_restarts_over_the_limit_but_ready_now_are_not(self):
        self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', restarts=9, ready=True)]), [])

    def test_the_limit_is_configurable(self):
        self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', restarts=2)], limit=1),
                         [('ue-new-a', 'main', 'Restarting', 2)])

    def test_the_previous_revision_crash_loop_being_replaced_is_not(self):
        # A deploy that fixes a crash loop: the old ReplicaSet's pod still
        # crash-loops until the new one is Ready.
        pods = [ue_pod('ue-old-a', 'old', waiting='CrashLoopBackOff', restarts=12),
                ue_pod('ue-new-a', 'new')]
        self.assertEqual(run(CURRENT, pods), [])

    def test_a_replicaset_of_another_deployment_is_not_the_current_one(self):
        workloads = [deployment(), replicaset('other', '2', owner='someone-else')]
        self.assertEqual(run(workloads, [ue_pod('x', 'other', waiting='CrashLoopBackOff',
                                                 restarts=9)]), [])

    def test_a_terminating_pod_is_not(self):
        self.assertEqual(run(CURRENT, [ue_pod('ue-new-a', 'new', waiting='CrashLoopBackOff',
                                              restarts=9, deleting=True)]), [])

    def test_another_workloads_pod_is_not(self):
        other = pod('gnb-x', {'app.kubernetes.io/name': 'gnb', 'pod-template-hash': 'new'},
                    waiting='CrashLoopBackOff', restarts=9)
        self.assertEqual(run(CURRENT, [other]), [])

    def test_a_statefulset_current_revision(self):
        workloads = [statefulset()]
        pods = [pod('mongodb-0', {'app': 'mongodb', 'controller-revision-hash': 'mongodb-new'},
                    waiting='CrashLoopBackOff', restarts=4),
                pod('mongodb-1', {'app': 'mongodb', 'controller-revision-hash': 'mongodb-old'},
                    waiting='CrashLoopBackOff', restarts=4)]
        self.assertEqual(run(workloads, pods, 'statefulset/mongodb'),
                         [('mongodb-0', 'main', 'CrashLoopBackOff', 4)])

    def test_no_target_checks_every_workload(self):
        pods = [ue_pod('ue-new-a', 'new', waiting='CrashLoopBackOff', restarts=4)]
        self.assertEqual(run(CURRENT, pods, None), [('ue-new-a', 'main', 'CrashLoopBackOff', 4)])

    def test_an_unknown_target_finds_nothing(self):
        pods = [ue_pod('ue-new-a', 'new', waiting='CrashLoopBackOff', restarts=9)]
        self.assertEqual(run(CURRENT, pods, 'deployment/gnb'), [])


class Cli(unittest.TestCase):
    def cli(self, workloads, pods, *args, env=None):
        with tempfile.TemporaryDirectory() as d:
            w, p = os.path.join(d, 'w.json'), os.path.join(d, 'p.json')
            with open(w, 'w') as f:
                f.write(workloads)
            with open(p, 'w') as f:
                f.write(pods)
            return subprocess.run([sys.executable, os.path.join(HERE, 'crashloop.py'), w, p, *args],
                                  capture_output=True, text=True,
                                  env={**os.environ, **(env or {})})

    def test_found_exits_1_and_names_the_container(self):
        r = self.cli(json.dumps({'items': CURRENT}),
                     json.dumps({'items': [ue_pod('ue-new-a', 'new', waiting='CrashLoopBackOff',
                                                  restarts=5)]}),
                     'deployment/ue')
        self.assertEqual((r.returncode, r.stdout), (1, 'ue-new-a main CrashLoopBackOff 5\n'))

    def test_none_exits_0(self):
        r = self.cli(json.dumps({'items': CURRENT}),
                     json.dumps({'items': [ue_pod('ue-new-a', 'new')]}), 'deployment/ue')
        self.assertEqual((r.returncode, r.stdout), (0, ''))

    def test_unparseable_input_is_no_verdict(self):
        self.assertEqual(self.cli('', '', 'deployment/ue').returncode, 2)

    def test_the_restart_limit_comes_from_the_environment(self):
        r = self.cli(json.dumps({'items': CURRENT}),
                     json.dumps({'items': [ue_pod('ue-new-a', 'new', restarts=2)]}),
                     'deployment/ue', env={'NEXTG_ROLLOUT_RESTART_LIMIT': '1'})
        self.assertEqual(r.returncode, 1)


if __name__ == '__main__':
    unittest.main()
