#!/usr/bin/env python3
"""Fail on anything in k8s/, deploy/ or helm/ that publishes a port (#1365).

Private by default: every Service is ClusterIP, nothing binds a node or host
port, and nothing creates an Ingress or Gateway route. Access from a
workstation is `kubectl port-forward`, which listens on 127.0.0.1. The NRF SBI
is unauthenticated in the dev profile and Prometheus, Jaeger and the /metrics
listeners are unauthenticated always, so a NodePort (every node IP), a
LoadBalancer, a hostPort, hostNetwork or an Ingress hands them to whatever can
reach the node or the load balancer.

Two passes:

  * source: every git-tracked file under the scanned dirs (default k8s, deploy,
    helm; a missing dir is skipped), line by line, ignoring comment lines and
    prose (.md, .txt). Catches a NodePort in a manifest, a values file, a
    script (`kubectl expose --type=NodePort`) or a widened port-forward.
  * render: each --render FILE is a rendered manifest stream (kubectl
    kustomize / helm template output), checked structurally. Catches what the
    source pass cannot see: a patch or a values default that produces one.

A privileged pod (the UPF, sgwu/pgwu) is not an exposure by itself: it needs
NET_ADMIN and /dev/net/tun for its N3/N6 (S1-U/SGi) interfaces inside its own
pod network namespace and publishes nothing. It would become one only with
hostNetwork or a hostPort, which this check rejects.

Usage: check_no_exposure.py [--dir DIR]... [--render FILE]...
Exit 0 when clean; 1 listing every hit otherwise.
"""
import argparse
import fnmatch
import os
import re
import subprocess
import sys

# ALLOWLIST: justified exceptions. Each entry needs a reason a reviewer can
# check, and should be as narrow as possible. Empty on purpose: as of #1365
# nothing in the repo needs one.
#
# Source entries: (path glob, rule, reason). Rule is a key of SOURCE_RULES.
#   ('k8s/kind-config.yaml', 'hostPort',
#    'kind extraPortMappings with listenAddress 127.0.0.1: host-local only'),
SOURCE_ALLOW = [
]
# Render entries: (kind, name, rule, reason). Rule is the first word of the
# render error, e.g. 'Service.type' or 'hostNetwork'.
#   ('Deployment', 'upf', 'hostNetwork',
#    'N6 on the node interface; publishes nothing, node SG closes 2152/8805'),
RENDER_ALLOW = [
]

Q = r'["\']?'
SOURCE_RULES = {
    'nodePort': re.compile(rf'{Q}\bnodePort{Q}\s*:'),
    'Service.type': re.compile(rf'{Q}\btype{Q}\s*:\s*{Q}(NodePort|LoadBalancer)\b'),
    'hostPort': re.compile(rf'{Q}\bhostPort{Q}\s*:'),
    'hostNetwork': re.compile(rf'{Q}\bhostNetwork{Q}\s*:\s*{Q}(?!false\b)\w'),
    'externalIPs': re.compile(rf'{Q}\b(externalIPs|loadBalancerIP|loadBalancerSourceRanges){Q}\s*:'),
    'Ingress': re.compile(rf'{Q}\bkind{Q}\s*:\s*{Q}(Ingress|Gateway|HTTPRoute|GRPCRoute|TCPRoute|TLSRoute|UDPRoute)\b'),
    'expose': re.compile(r'\bkubectl\b.*\bexpose\b|--type[= ]{0,1}["\']?(NodePort|LoadBalancer)\b'),
    'port-forward': re.compile(r'\bport-forward\b.*--address'),
}
PROSE = ('.md', '.txt', '.html')
EXPOSING_KINDS = {'Ingress', 'Gateway', 'HTTPRoute', 'GRPCRoute', 'TCPRoute',
                  'TLSRoute', 'UDPRoute'}


def tracked(dirs):
    dirs = [d for d in dirs if os.path.isdir(d)]
    if not dirs:
        return []
    out = subprocess.run(['git', 'ls-files', '--', *dirs], check=True,
                         capture_output=True, text=True).stdout
    return [p for p in out.splitlines() if not p.endswith(PROSE)]


def allowed_source(path, rule):
    return any(fnmatch.fnmatch(path, g) and r == rule for g, r, _ in SOURCE_ALLOW)


def scan_source(paths):
    hits = []
    for path in paths:
        # This file names every pattern it rejects.
        if os.path.abspath(path) == os.path.abspath(__file__):
            continue
        try:
            with open(path, encoding='utf-8') as f:
                lines = f.readlines()
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for n, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith(('#', '//')):
                continue
            for rule, rx in SOURCE_RULES.items():
                if rx.search(line) and not allowed_source(path, rule):
                    hits.append(f'{path}:{n}: {rule}: {s}')
    return hits


def pod_specs(obj):
    """Every dict that is a pod spec (has containers), however deep."""
    if isinstance(obj, dict):
        if isinstance(obj.get('containers'), list):
            yield obj
        for v in obj.values():
            yield from pod_specs(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from pod_specs(v)


def scan_render(path):
    import yaml  # only the render pass needs PyYAML
    hits = []
    with open(path) as f:
        docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
    for d in docs:
        kind = d.get('kind', '?')
        meta = d.get('metadata') or {}
        name = meta.get('name', '?')
        errs = []
        spec = d.get('spec') or {}
        if kind in EXPOSING_KINDS:
            errs.append(f'{kind}: creates external routing')
        if kind == 'Service':
            t = spec.get('type', 'ClusterIP')
            if t != 'ClusterIP':
                errs.append(f'Service.type: {t}, want ClusterIP')
            for p in spec.get('ports') or []:
                if 'nodePort' in p:
                    errs.append(f'nodePort: {p.get("name", p.get("port"))} -> {p["nodePort"]}')
            for k in ('externalIPs', 'loadBalancerIP', 'loadBalancerSourceRanges'):
                if spec.get(k):
                    errs.append(f'externalIPs: {k} set')
        for pod in pod_specs(spec):
            if pod.get('hostNetwork'):
                errs.append('hostNetwork: true')
            for c in pod.get('containers', []) + pod.get('initContainers', []):
                for p in c.get('ports') or []:
                    if 'hostPort' in p:
                        errs.append(f'hostPort: {c.get("name")} {p["hostPort"]}')
        for e in errs:
            rule = e.split(':', 1)[0]
            if not any(k == kind and n == name and r == rule for k, n, r, _ in RENDER_ALLOW):
                hits.append(f'{path}: {kind}/{meta.get("namespace", "-")}/{name}: {e}')
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--dir', action='append', dest='dirs')
    ap.add_argument('--render', action='append', default=[])
    a = ap.parse_args()
    files = tracked(a.dirs or ['k8s', 'deploy', 'helm'])
    hits = scan_source(files)
    for r in a.render:
        hits += scan_render(r)
    for h in hits:
        print(h)
    print(f'{len(files)} source file(s), {len(a.render)} render(s): '
          f'{len(hits)} exposure(s)')
    if hits:
        print('Every Service must be ClusterIP and nothing may publish a node '
              'or host port (#1365). Use kubectl port-forward; a justified '
              'exception goes in the allowlist at the top of '
              'deploy/check_no_exposure.py, with its reason.')
    return 1 if hits else 0


if __name__ == '__main__':
    sys.exit(main())
