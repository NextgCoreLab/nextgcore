"""Fixture tests for pinned_peers.py (#436). Run: python3 -m unittest -v
from deploy/eks/lib."""

import unittest

from pinned_peers import needs_reresolve


def pods(*specs):
    items = []
    for started, ready, deleting in specs:
        p = {'metadata': {}, 'status': {'containerStatuses': [], 'conditions': []}}
        if deleting:
            p['metadata']['deletionTimestamp'] = '2026-10-08T20:36:00Z'
        if started:
            p['status']['containerStatuses'].append({'state': {'running': {'startedAt': started}}})
        if ready:
            p['status']['conditions'].append(
                {'type': 'Ready', 'status': 'True', 'lastTransitionTime': ready})
        items.append(p)
    return {'items': items}


class PinnedPeers(unittest.TestCase):

    def test_devtest1_smf_and_upf_created_in_the_same_second(self):
        # 2026-10-08: both created 20:35:39; the SMF started before the new UPF
        # was Ready at 20:35:51, so resolve-upf pinned the dying UPF.
        smf = pods(('2026-10-08T20:35:45Z', '2026-10-08T20:35:54Z', False))
        upf = pods(('2026-10-08T20:35:40Z', '2026-10-08T20:35:51Z', False))
        self.assertTrue(needs_reresolve(smf, upf))

    def test_a_tie_restarts(self):
        dep = pods(('2026-10-08T20:35:51Z', '2026-10-08T20:35:55Z', False))
        peer = pods(('2026-10-08T20:35:40Z', '2026-10-08T20:35:51Z', False))
        self.assertTrue(needs_reresolve(dep, peer))

    def test_a_dependent_that_resolved_after_the_peer_was_ready_is_left_alone(self):
        # The steady state after a re-resolve restart: no restart loop.
        dep = pods(('2026-10-08T20:40:00Z', '2026-10-08T20:40:05Z', False))
        peer = pods(('2026-10-08T20:35:40Z', '2026-10-08T20:35:51Z', False))
        self.assertFalse(needs_reresolve(dep, peer))

    def test_an_outgoing_peer_replica_does_not_count(self):
        # Only the peer's LIVE pods say when its current endpoint became resolvable.
        dep = pods(('2026-10-08T20:40:00Z', '2026-10-08T20:40:05Z', False))
        peer = pods(('2026-10-08T20:35:40Z', '2026-10-08T20:35:51Z', False),
                    ('2026-10-08T20:41:00Z', '2026-10-08T20:41:05Z', True))
        self.assertFalse(needs_reresolve(dep, peer))

    def test_no_running_dependent_or_no_ready_peer_is_not_a_restart(self):
        self.assertFalse(needs_reresolve(pods((None, None, False)),
                                         pods(('2026-10-08T20:35:40Z', '2026-10-08T20:35:51Z', False))))
        self.assertFalse(needs_reresolve(pods(('2026-10-08T20:35:45Z', None, False)),
                                         pods(('2026-10-08T20:35:40Z', None, False))))


if __name__ == '__main__':
    unittest.main()
