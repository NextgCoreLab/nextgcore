#!/usr/bin/env python3
"""CCA keys and the per-arm AF config of demo d445a-fl-t8 (nextgsim#480).

    cca.py keygen DIR ID...        an ES256 key per nfInstanceId: DIR/<ID>.key (the
                                   hex P-256 scalar nextgsim's CcaKey reads, 0600)
                                   and DIR/<ID>.jwk (the public JWK nextgcore's
                                   NRF trusts from its cca_trusted_keys_dir)
    cca.py cca DIR ID              a Client Credentials Assertion (TS 33.501
                                   §13.3.8.2) signed with DIR/<ID>.key, for an NRF
                                   token request: sub = iss = ID, aud NRF, 5 min
    cca.py af-config ARM MODE      the AF's config for an arm: the rendered
                                   af.yaml on stdin (with its demo: block), the
                                   arm's on stdout
    cca.py --self-test

keygen and cca need the `cryptography` package (the operator's machine, never
the cluster); af-config needs PyYAML.
"""
import base64
import json
import os
import sys
import time


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def keygen(d, ids):
    from cryptography.hazmat.primitives.asymmetric import ec
    for i in ids:
        k = ec.generate_private_key(ec.SECP256R1())
        scalar = k.private_numbers().private_value.to_bytes(32, 'big')
        pub = k.public_key().public_numbers()
        path = os.path.join(d, f'{i}.key')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(scalar.hex() + '\n')
        jwk = {'kty': 'EC', 'crv': 'P-256', 'alg': 'ES256', 'use': 'sig', 'kid': i,
               'x': b64(pub.x.to_bytes(32, 'big')), 'y': b64(pub.y.to_bytes(32, 'big'))}
        with open(os.path.join(d, f'{i}.jwk'), 'w') as f:
            json.dump(jwk, f)
        print(f'{i}: key and JWK written')


def cca(d, i, now=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    scalar = int(open(os.path.join(d, f'{i}.key')).read().strip(), 16)
    k = ec.derive_private_key(scalar, ec.SECP256R1())
    now = int(now or time.time())
    head = b64(json.dumps({'alg': 'ES256', 'typ': 'JWT'}, separators=(',', ':')).encode())
    body = b64(json.dumps({'sub': i, 'iss': i, 'aud': 'NRF', 'iat': now, 'exp': now + 300},
                          separators=(',', ':')).encode())
    r, s = decode_dss_signature(k.sign(f'{head}.{body}'.encode(), ec.ECDSA(hashes.SHA256())))
    return f'{head}.{body}.{b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}'


def af_config(arm, mode, text):
    import yaml
    c = yaml.safe_load(text)
    if not isinstance(c, dict) or c.get('demo', {}).get('d445a-fl-t8', {}).get('mode') != mode:
        sys.exit(f'af-config: the rendered af.yaml is not in mode {mode}')
    # scenario.sh starts the UEs one at a time after the AF (serialised joins):
    # five can take several minutes.
    c['join_timeout_s'] = 900
    if arm in ('main', 'no-t8', 'nefd-down', 'udm-fallback', 'eth0'):
        pass                     # the overlay's holds: before 4 (excluded), before 7 (full)
    elif arm == 'probe':
        c['rounds'] = 22
        c['holds'] = []
        for i in range(1, 11):
            c['holds'].append({'before_round': 2 * i, 'until': 'member-excluded', 'timeout_s': 240})
            c['holds'].append({'before_round': 2 * i + 1, 'until': 'members-full', 'timeout_s': 360})
    elif arm == 'gates':
        c['holds'] = [{'before_round': 2, 'until': 'member-excluded', 'timeout_s': 900}]
    elif arm in ('poisoned', 'leak-raw', 'freeze-global', 'nat-on'):
        c.pop('holds', None)
    else:
        sys.exit(f'af-config: unknown arm {arm}')
    return yaml.safe_dump(c, default_flow_style=False, sort_keys=False)


def self_test():
    import tempfile
    base = ('listen: 10.46.0.10:7480\nseed: 480\nholds:\n- {before_round: 4, until: member-excluded, timeout_s: 240}\n'
            'demo:\n  enabled: true\n  d445a-fl-t8:\n    enabled: true\n    mode: t8-exclusion\n')
    import yaml
    p = yaml.safe_load(af_config('probe', 't8-exclusion', base))
    assert p['rounds'] == 22 and len(p['holds']) == 20 and p['holds'][-1]['before_round'] == 21, p
    assert 'holds' not in yaml.safe_load(af_config('poisoned', 't8-exclusion', base))
    assert yaml.safe_load(af_config('main', 't8-exclusion', base))['holds'][0]['before_round'] == 4
    assert yaml.safe_load(af_config('eth0', 't8-exclusion', base))['join_timeout_s'] == 900
    try:
        af_config('main', 'poisoned-ue', base)
        raise AssertionError('a mode mismatch passed')
    except SystemExit:
        pass
    print('ok 1 - af-config')
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print('ok 2 # SKIP cryptography not installed')
        return
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    with tempfile.TemporaryDirectory() as d:
        keygen(d, ['id-1'])
        assert oct(os.stat(os.path.join(d, 'id-1.key')).st_mode & 0o777) == '0o600'
        jwk = json.load(open(os.path.join(d, 'id-1.jwk')))
        tok = cca(d, 'id-1', now=1000)
        h, b, s = tok.split('.')
        pad = lambda x: base64.urlsafe_b64decode(x + '=' * (-len(x) % 4))
        claims = json.loads(pad(b))
        assert claims == {'sub': 'id-1', 'iss': 'id-1', 'aud': 'NRF', 'iat': 1000, 'exp': 1300}, claims
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(pad(jwk['x']), 'big'),
                                            int.from_bytes(pad(jwk['y']), 'big'), ec.SECP256R1()).public_key()
        sig = pad(s)
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')),
                   f'{h}.{b}'.encode(), ec.ECDSA(hashes.SHA256()))
        bad = f'{h}.{b}.{b64(bytes(64))}'
        try:
            pub.verify(encode_dss_signature(1, 1), f'{h}.{b}'.encode(), ec.ECDSA(hashes.SHA256()))
            raise AssertionError('a forged signature verified')
        except Exception as e:  # InvalidSignature
            assert 'forged' not in str(e), bad
    print('ok 2 - keygen and CCA verify against the JWK')


if __name__ == '__main__':
    a = sys.argv[1:]
    if a == ['--self-test']:
        self_test()
    elif len(a) >= 3 and a[0] == 'keygen':
        keygen(a[1], a[2:])
    elif len(a) == 3 and a[0] == 'cca':
        print(cca(a[1], a[2]))
    elif len(a) == 3 and a[0] == 'af-config':
        sys.stdout.write(af_config(a[1], a[2], sys.stdin.read()))
    else:
        sys.exit(__doc__)
