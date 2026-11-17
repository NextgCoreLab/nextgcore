#!/usr/bin/env python3
"""CCA keys of demo d443a-edge-budget (nextgsim#471): one per EAS sidecar and
one for the UE's EEC, so each gets NRF tokens as an nfType AF consumer.

    cca.py keygen DIR ID...   an ES256 key per nfInstanceId: DIR/<ID>.key (the hex
                              P-256 scalar nextgsim's CcaKey reads, 0600) and
                              DIR/<ID>.jwk (the public JWK nextgcore's NRF trusts
                              from its cca_trusted_keys_dir)
    cca.py --self-test        (with `cryptography`) a key and its JWK agree

The same key format as demo d445a-fl-t8's cca.py (nextgsim-sbi-client CcaKey).
keygen needs the `cryptography` package (the operator's machine, never the
cluster). Private keys are written only to DIR, which scenario.sh keeps outside
the artefacts and removes on exit.
"""
import base64
import json
import os
import sys
import tempfile


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def keygen(d, ids):
    from cryptography.hazmat.primitives.asymmetric import ec
    for i in ids:
        k = ec.generate_private_key(ec.SECP256R1())
        scalar = k.private_numbers().private_value.to_bytes(32, 'big')
        pub = k.public_key().public_numbers()
        fd = os.open(os.path.join(d, f'{i}.key'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(scalar.hex() + '\n')
        jwk = {'kty': 'EC', 'crv': 'P-256', 'alg': 'ES256', 'use': 'sig', 'kid': i,
               'x': b64(pub.x.to_bytes(32, 'big')), 'y': b64(pub.y.to_bytes(32, 'big'))}
        with open(os.path.join(d, f'{i}.jwk'), 'w') as f:
            json.dump(jwk, f)
        print(f'{i}: key and JWK written')


def self_test():
    from cryptography.hazmat.primitives.asymmetric import ec
    with tempfile.TemporaryDirectory() as d:
        keygen(d, ['6b1d7e3c-0000-4000-8000-0000000471a1'])
        p = os.path.join(d, '6b1d7e3c-0000-4000-8000-0000000471a1')
        assert oct(os.stat(p + '.key').st_mode & 0o777) == '0o600'
        k = ec.derive_private_key(int(open(p + '.key').read(), 16), ec.SECP256R1())
        jwk = json.load(open(p + '.jwk'))
        pub = k.public_key().public_numbers()
        assert jwk['x'] == b64(pub.x.to_bytes(32, 'big')) and jwk['y'] == b64(pub.y.to_bytes(32, 'big'))
        assert jwk['kid'] == '6b1d7e3c-0000-4000-8000-0000000471a1' and 'd' not in jwk
    print('ok')


if __name__ == '__main__':
    if sys.argv[1:2] == ['keygen'] and len(sys.argv) > 3:
        keygen(sys.argv[2], sys.argv[3:])
    elif sys.argv[1:] == ['--self-test']:
        self_test()
    else:
        sys.exit(__doc__)
