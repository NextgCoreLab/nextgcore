#!/usr/bin/env python3
"""Fail on a `demo:` block in anything nextgcore ships (nextgsim#458, #1394).

The demo toggle convention keeps demos out of production profiles: shipped k8s
manifests, the deploy/ trees (EKS, Helm, observability), the default docker
compose and the configs it mounts, and the configs/ samples carry no `demo:`
block. A demo run uses its own overlay, which is the only place one may appear:

  * deploy/eks/overlays/demo*/     (kustomize overlays, nextgcore#1395)
  * docker/rust/docker-compose.demo*.yml
  * docker/rust/configs/demo*/

The scan is textual, line by line, over every git-tracked file under the
scanned paths (default: k8s deploy docker/rust configs), so it also catches a
`demo:` key inside a ConfigMap's embedded NF config, a Helm values file or a
JSON `"demo":` member. Comment lines and prose (.md, .txt) are ignored.

Usage: check_no_demo_block.py [--path PATH]...
       check_no_demo_block.py --self-test
Exit 0 when clean; 1 listing every hit otherwise.
"""
import argparse
import fnmatch
import os
import re
import subprocess
import sys
import tempfile

DEFAULT_PATHS = ['k8s', 'deploy', 'docker/rust', 'configs']

# Where a demo block belongs. Kept narrow on purpose: everything else is a
# shipped profile.
DEMO_ALLOW = [
    'deploy/eks/overlays/demo*/*',
    'docker/rust/docker-compose.demo*.yml',
    'docker/rust/configs/demo*/*',
]

# `demo:` as a YAML mapping key (optionally quoted), or `"demo":` in JSON.
DEMO_KEY = re.compile(r'''^\s*(-\s+)?["']?demo["']?\s*:(\s|$)''')
PROSE = ('.md', '.txt')


def tracked(paths, root):
    out = subprocess.run(
        ['git', '-C', root, 'ls-files', '--', *paths],
        check=True, capture_output=True, text=True,
    ).stdout
    return [p for p in out.splitlines() if p]


def allowed(path):
    return any(fnmatch.fnmatch(path, g) for g in DEMO_ALLOW)


def scan(files, root):
    hits = []
    for rel in files:
        if rel.endswith(PROSE) or allowed(rel):
            continue
        full = os.path.join(root, rel)
        try:
            with open(full, encoding='utf-8', errors='replace') as f:
                for n, line in enumerate(f, 1):
                    if line.lstrip().startswith('#'):
                        continue
                    if DEMO_KEY.search(line):
                        hits.append(f'{rel}:{n}: {line.rstrip()}')
        except (IsADirectoryError, FileNotFoundError):
            continue
    return hits


def self_test():
    """The scan must catch a planted block in the shapes it claims to cover,
    and must leave the allowed overlay paths, comments and prose alone."""
    with tempfile.TemporaryDirectory() as d:
        def put(rel, text):
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'w') as f:
                f.write(text)
        subprocess.run(['git', 'init', '-q', d], check=True)
        put('k8s/base/nrf.yaml', 'kind: ConfigMap\ndata:\n  nrf.yaml: |\n    demo:\n      enabled: true\n')
        put('docker/rust/configs/5gc/amf.yaml', 'amf: {}\ndemo:\n  enabled: false\n')
        put('deploy/helm/values.json', '{\n  "demo": {"enabled": true}\n}\n')
        put('configs/sample.yaml', '"demo" : {}\n')
        bad = ['k8s/base/nrf.yaml', 'docker/rust/configs/5gc/amf.yaml',
               'deploy/helm/values.json', 'configs/sample.yaml']
        put('deploy/eks/overlays/demo-x/patch.yaml', 'demo:\n  enabled: true\n')
        put('docker/rust/docker-compose.demo-x.yml', 'demo:\n')
        put('k8s/base/comment.yaml', '# demo:\n  # demo: true\ndemolition: 1\nnodemo: x\n')
        put('k8s/README.md', 'demo:\n')
        subprocess.run(['git', '-C', d, 'add', '-A'], check=True)
        hits = scan(tracked(DEFAULT_PATHS, d), d)
        got = sorted({h.split(':', 1)[0] for h in hits})
        if got != sorted(bad):
            print(f'self-test FAILED: flagged {got}, expected {sorted(bad)}')
            for h in hits:
                print(f'  {h}')
            return 1
    print('self-test ok: planted demo blocks are caught, demo overlays/comments/prose are not')
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--path', action='append', help='tracked path to scan (repeatable)')
    ap.add_argument('--root', default='.', help='repository root (default .)')
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    hits = scan(tracked(a.path or DEFAULT_PATHS, a.root), a.root)
    if hits:
        print('A `demo:` block is in a shipped profile (nextgsim#458: demos run only from '
              'their own overlay, e.g. deploy/eks/overlays/demo-<key>/):')
        for h in hits:
            print(f'  {h}')
        return 1
    print('no demo: block in shipped manifests, compose or configs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
