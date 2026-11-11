#!/usr/bin/env python3
"""Merge a demo overlay's toggles into the NF configs of a rendered manifest
stream (PROFILE=demo post-render; nextgcore#1395, nextgsim#458).

A demo overlay deploy/eks/overlays/demo-<key>/ declares a ConfigMap:

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: nextg-demo-toggles
    data:
      key: <key>                  # the demo key, [a-z0-9-]+; must equal DEMO_KEY
      targets: amf.yaml gnb.yaml  # config files (ConfigMap data keys) that get the block

Every target file gets the convention's block, with the run's mode (shown as
the YAML lines it adds at the config root):

    > demo:
    >   enabled: true
    >   <key>:
    >     enabled: true
    >     mode: <DEMO_MODE>

The mode is a run parameter, not part of the overlay, so one overlay serves every
mode (k8s/demo-check.sh <key> <mode>). The toggles ConfigMap itself is removed
from the render: it is input to this step, not something the cluster needs.

Fail-closed rules:
  * The demo-off base overlay ("demo") must have no toggles ConfigMap, and the
    render must then contain no `demo:` key in any config. That is the demo-off
    arm's guarantee that it is the 6G profile unchanged.
  * A demo-<key> overlay must have exactly one toggles ConfigMap whose key equals
    DEMO_KEY, a DEMO_MODE, and targets that each exist in exactly one
    ConfigMap. A config that already has a `demo:` block is refused, because a
    second source of truth would make the run ambiguous.

Whether the key and mode are valid is decided by the NF itself at startup
(nextgcore-demo / nextgsim-demo): an unknown one fails the pod, and
demo-check.sh reports it. This step does not keep a second registry.

Usage: demo_toggles.py RENDERED OVERLAY DEMO_KEY DEMO_MODE   (in place)
       demo_toggles.py --self-test
"""
import re
import sys

import yaml

TOGGLES = 'nextg-demo-toggles'
NAME = re.compile(r'^[a-z0-9][a-z0-9-]*$')


def fail(msg):
    sys.exit(f'PROFILE=demo: {msg}')


def has_demo_block(text):
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return False
    return isinstance(doc, dict) and 'demo' in doc


def apply(docs, overlay, key, mode):
    """Return the transformed document list, or exit with a named error."""
    toggles = [d for d in docs if d.get('kind') == 'ConfigMap'
               and d.get('metadata', {}).get('name') == TOGGLES]
    configmaps = [d for d in docs if d.get('kind') == 'ConfigMap'
                  and d.get('metadata', {}).get('name') != TOGGLES]

    if overlay == 'demo':
        if toggles:
            fail(f'the demo-off overlay must not carry a {TOGGLES} ConfigMap')
        if key or mode:
            fail('DEMO_KEY/DEMO_MODE are set but DEMO_OVERLAY is the demo-off base')
        for cm in configmaps:
            for f, text in (cm.get('data') or {}).items():
                if has_demo_block(text):
                    fail(f'demo-off render has a demo: block in '
                         f'{cm["metadata"]["name"]}/{f}')
        return docs

    if len(toggles) != 1:
        fail(f'overlay {overlay} must carry exactly one {TOGGLES} ConfigMap, '
             f'found {len(toggles)}')
    data = toggles[0].get('data') or {}
    tkey = str(data.get('key', ''))
    targets = str(data.get('targets', '')).split()
    if overlay != f'demo-{tkey}':
        fail(f'overlay {overlay} declares key {tkey!r}; the overlay must be demo-<key>')
    if not NAME.match(tkey):
        fail(f'demo key {tkey!r} is not [a-z0-9-]+')
    if key != tkey:
        fail(f'DEMO_KEY={key!r} does not match the overlay key {tkey!r}')
    if not mode or not NAME.match(mode):
        fail(f'DEMO_MODE={mode!r} must be set and [a-z0-9-]+')
    if not targets:
        fail(f'{TOGGLES} names no targets')
    extra = set(data) - {'key', 'targets'}
    if extra:
        fail(f'{TOGGLES} has unknown data keys {sorted(extra)} (expected key, targets)')

    block = {'enabled': True, tkey: {'enabled': True, 'mode': mode}}
    for target in targets:
        owners = [cm for cm in configmaps if target in (cm.get('data') or {})]
        if len(owners) != 1:
            fail(f'target {target} is in {len(owners)} ConfigMaps, expected exactly 1')
        cm = owners[0]
        doc = yaml.safe_load(cm['data'][target])
        if not isinstance(doc, dict):
            fail(f'{cm["metadata"]["name"]}/{target} is not a YAML mapping')
        if 'demo' in doc:
            fail(f'{cm["metadata"]["name"]}/{target} already has a demo: block')
        doc['demo'] = block
        cm['data'][target] = yaml.safe_dump(doc, default_flow_style=False, sort_keys=False)
    return [d for d in docs if d not in toggles]


def self_test():
    base = [
        {'kind': 'ConfigMap', 'metadata': {'name': 'nextgcore-configs'},
         'data': {'amf.yaml': 'amf:\n  sbi: {}\n', 'smf.yaml': 'smf: {}\n'}},
        {'kind': 'ConfigMap', 'metadata': {'name': 'nextgsim-configs'},
         'data': {'gnb.yaml': 'mcc: "999"\n'}},
    ]

    def fresh(*extra):
        return yaml.safe_load(yaml.safe_dump(base)) + [dict(e) for e in extra]

    tog = {'kind': 'ConfigMap', 'metadata': {'name': TOGGLES},
           'data': {'key': 'd1-x', 'targets': 'amf.yaml gnb.yaml'}}

    # demo-off: unchanged.
    docs = fresh()
    assert apply(docs, 'demo', '', '') == fresh()
    # demo-on: both targets get the block, smf does not, toggles removed.
    out = apply(fresh(tog), 'demo-d1-x', 'd1-x', 'closed-loop')
    want = {'enabled': True, 'd1-x': {'enabled': True, 'mode': 'closed-loop'}}
    assert not any(d['metadata']['name'] == TOGGLES for d in out)
    cfg = {d['metadata']['name']: d['data'] for d in out}
    assert yaml.safe_load(cfg['nextgcore-configs']['amf.yaml'])['demo'] == want
    assert yaml.safe_load(cfg['nextgsim-configs']['gnb.yaml'])['demo'] == want
    assert 'demo' not in yaml.safe_load(cfg['nextgcore-configs']['smf.yaml'])
    assert yaml.safe_load(cfg['nextgcore-configs']['amf.yaml'])['amf'] == {'sbi': {}}

    def refused(docs, overlay, key, mode, why):
        try:
            apply(docs, overlay, key, mode)
        except SystemExit as e:
            assert why in str(e), f'{why!r} not in {e}'
            return
        raise AssertionError(f'not refused: {why}')

    planted = fresh()
    planted[0]['data']['amf.yaml'] = 'amf: {}\ndemo:\n  enabled: false\n'
    refused(planted, 'demo', '', '', 'demo-off render has a demo: block')
    refused(fresh(tog), 'demo', '', '', 'must not carry')
    refused(fresh(), 'demo', 'd1-x', 'a', 'demo-off base')
    refused(fresh(), 'demo-d1-x', 'd1-x', 'a', 'exactly one')
    refused(fresh(tog), 'demo-d1-x', 'd1-y', 'a', 'does not match')
    refused(fresh(tog), 'demo-d1-x', 'd1-x', '', 'DEMO_MODE')
    refused(fresh(tog), 'demo-d1-x', 'd1-x', 'Bad Mode', 'DEMO_MODE')
    refused(fresh(tog), 'demo-other', 'd1-x', 'a', 'must be demo-<key>')
    bad_target = dict(tog, data={'key': 'd1-x', 'targets': 'nope.yaml'})
    refused(fresh(bad_target), 'demo-d1-x', 'd1-x', 'a', 'in 0 ConfigMaps')
    extra = dict(tog, data={'key': 'd1-x', 'targets': 'amf.yaml', 'mode': 'a'})
    refused(fresh(extra), 'demo-d1-x', 'd1-x', 'a', 'unknown data keys')
    refused(planted + [tog], 'demo-d1-x', 'd1-x', 'a', 'already has a demo: block')
    print('demo_toggles self-test ok')
    return 0


def main(argv):
    if argv[1:] == ['--self-test']:
        return self_test()
    if len(argv) != 5:
        sys.exit(__doc__)
    path, overlay, key, mode = argv[1:]
    docs = [d for d in yaml.safe_load_all(open(path)) if d]
    out = apply(docs, overlay, key, mode)
    with open(path, 'w') as f:
        yaml.safe_dump_all(out, f, default_flow_style=False)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
