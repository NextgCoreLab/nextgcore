#!/usr/bin/env python3
"""Check that an overlay's Service patch did not drop or alter any port.

profiles/5g/patches/monitoring-clusterip.yaml (and the NRF entry in
headless-services.yaml) use `$patch: replace` on `ports`, so the overlay holds
a copy of the base port list. A port later added to the base Service would be
silently dropped on EKS. This compares, for every Service named in the patch
files, the base render's ports with the overlay render's, and requires the
overlay Service to be ClusterIP with no nodePort (#1100 review).

BASE_RENDER is every base the overlay includes (k8s/ and nextgsim/k8s/ for
5g), concatenated. PATCH files may hold other kinds; only Services count.

Usage: check_service_ports.py BASE_RENDER OVERLAY_RENDER PATCH [PATCH...]
Exit 0 when every patched Service matches; 1 with the differences otherwise.
"""
import sys

import yaml


def services(path):
    out = {}
    with open(path) as f:
        for d in yaml.safe_load_all(f):
            if d and d.get('kind') == 'Service':
                out[d['metadata']['name']] = d
    return out


def port_key(p):
    # nodePort is what the overlay removes; everything else must survive.
    return tuple(sorted((k, str(v)) for k, v in p.items() if k != 'nodePort'))


def main(argv):
    if len(argv) < 4:
        sys.exit(__doc__)
    base, overlay = services(argv[1]), services(argv[2])
    names = set()
    for patch in argv[3:]:
        names |= set(services(patch))
    errors = []
    for name in sorted(names):
        if name not in base or name not in overlay:
            errors.append(f'Service {name}: missing from the '
                          f'{"base" if name not in base else "overlay"} render')
            continue
        bspec, ospec = base[name]['spec'], overlay[name]['spec']
        bports = sorted(port_key(p) for p in bspec.get('ports', []))
        oports = sorted(port_key(p) for p in ospec.get('ports', []))
        if bports != oports:
            errors.append(f'Service {name}: ports differ from the base\n'
                          f'  base:    {bports}\n  overlay: {oports}')
        if ospec.get('type', 'ClusterIP') != 'ClusterIP':
            errors.append(f'Service {name}: type {ospec["type"]}, want ClusterIP')
        if any('nodePort' in p for p in ospec.get('ports', [])):
            errors.append(f'Service {name}: overlay still sets a nodePort')
    for e in errors:
        print(e)
    print(f'{len(names)} patched Service(s) checked, {len(errors)} problem(s)')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
