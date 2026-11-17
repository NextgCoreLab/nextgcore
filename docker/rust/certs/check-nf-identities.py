#!/usr/bin/env python3
"""Fail when a compose stack pins an NF instance ID its certificate does not name.

The dev PKI (generate-dev-certs.sh) issues <name>.crt with the URI SAN
urn:uuid:<nfInstanceId> and the RFC 9310 NFTypes of its nf-identities.txt row
(TS 33.310 §6.1.3c.3). The NRF binds NFRegister / NFUpdate / NFDeregister to
that identity (#1611), so an NF that registers under any other ID is refused
once it talks to the NRF over mTLS (#1617). This check keeps the table and the
compose files in step:

1. In every docker/rust/docker-compose*.yml, a service named after a table row
   that sets NEXTGCORE_NF_INSTANCE_ID or NEXTGCORE_<TYPE>_INSTANCE_ID must set
   it to that row's nfInstanceId, and a per-type variable must be the one for
   the row's nfType.
2. docker-compose.yml (the default stack) must pin every table row it runs,
   except the NFs that never register (SCP, SEPP).
3. A service that mounts a certificate volume tls-<name> (the stack's NRF
   clients, #1617 step d) presents <name>.crt to the NRF, so:
   - <name> is a table row, and the stack's sbi-tls service fills that volume
     (mounts it at /tls/<name>) and the service waits for it;
   - every UUID the service configures (its environment, its command, the
     host files it bind-mounts) is that row's nfInstanceId, and there is one:
     whatever pins its ID, the certificate names the same;
   - an NRF client other than the NRF names its pair and the trust anchor
     with NEXTGCORE_NRF_TLS_CLIENT_CERT / _KEY / NEXTGCORE_NRF_TLS_CA.
4. Only sbi-tls mounts the host's certs/ directory (which may hold a host
   run's ca.key) or the sbi_pki volume (which holds the stack's CA key).

Usage: check-nf-identities.py [--self-test]
"""

import glob
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE_DIR = os.path.dirname(HERE)
TABLE = os.path.join(HERE, 'nf-identities.txt')
DEFAULT_STACK = 'docker-compose.yml'
NOT_REGISTERING = {'SCP', 'SEPP'}
ANY_VAR = 'NEXTGCORE_NF_INSTANCE_ID'
PIN_VAR = re.compile(r'^NEXTGCORE_([A-Z0-9_]+)_INSTANCE_ID$')
INIT = 'sbi-tls'
PKI_VOLUME = 'sbi_pki'
CERT_DIR = '/etc/nextgcore/certs'
TLS_VOLUME = re.compile(r'^tls-([a-z0-9-]+)$')
UUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
INTERP = re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-([^}]*))?\}')


# The table names each nfType in the TS 29.510 §6.1.6.3.3 spelling the
# certificate carries; the instance-ID variable is derived from
# nextgcore_sbi::NfType::to_str(), which still spells MB_SMF "MBSMF" (#1680).
SBI_TYPE_SPELLING = {'MB_SMF': 'MBSMF'}


def type_env_var(nf_type):
    """nextgcore_sbi::nf_instance_id::type_env_var."""
    nf_type = SBI_TYPE_SPELLING.get(nf_type, nf_type)
    return 'NEXTGCORE_%s_INSTANCE_ID' % re.sub(r'[^A-Za-z0-9]', '_', nf_type)


def read_table(path):
    rows = {}
    with open(path) as f:
        for line in f:
            fields = line.split()
            if not fields or fields[0].startswith('#'):
                continue
            rows[fields[0]] = (fields[1], fields[2])
    return rows


def environment(service):
    env = service.get('environment') or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            key, _, value = str(item).partition('=')
            out[key] = value
        return out
    return {str(k): '' if v is None else str(v) for k, v in env.items()}


def mounts(service):
    """[(source, target)] of the service's volumes, short or long syntax."""
    out = []
    for v in service.get('volumes') or []:
        if isinstance(v, dict):
            out.append((str(v.get('source', '')), str(v.get('target', ''))))
        else:
            parts = interpolate(str(v)).split(':')
            if len(parts) >= 2:
                out.append((parts[0], parts[1]))
    return out


def interpolate(text):
    """${VAR:-default} -> default (the value with nothing set)."""
    return INTERP.sub(lambda m: m.group(1) or '', text)


def configured_text(service, read_file):
    """The environment values, the command and the bind-mounted host files."""
    parts = list(environment(service).values())
    cmd = service.get('command') or []
    parts += [cmd] if isinstance(cmd, str) else [str(c) for c in cmd]
    for source, _ in mounts(service):
        source = interpolate(source)
        if source.startswith(('.', '/')):
            text = read_file(source)
            if text is not None:
                parts.append(text)
    return '\n'.join(parts)


def depends_on(service):
    deps = service.get('depends_on') or {}
    return set(deps) if isinstance(deps, (dict, list)) else set()


def check_certificates(table, fname, services, read_file):
    """Rules 3 and 4 for one compose file."""
    errors = []
    init = services.get(INIT) if isinstance(services.get(INIT), dict) else {}
    filled = {t: s for s, t in mounts(init)}
    for name, service in sorted(services.items()):
        if not isinstance(service, dict):
            continue
        for source, target in mounts(service):
            if name == INIT:
                continue
            if os.path.normpath(interpolate(source)) in ('certs', './certs') \
                    or source.rstrip('/').endswith('/certs') and source.startswith('.'):
                errors.append('%s: service %s mounts the host certs/ directory at %s; only %s '
                              'may (it can hold a CA key), an NF mounts its own tls-<name> '
                              'volume' % (fname, name, target, INIT))
            if source == PKI_VOLUME:
                errors.append('%s: service %s mounts %s (the CA key); only %s may'
                              % (fname, name, PKI_VOLUME, INIT))
        if name == INIT:
            continue
        certs = [(TLS_VOLUME.match(s), t) for s, t in mounts(service) if TLS_VOLUME.match(s)]
        for m, target in certs:
            row = m.group(1)
            where = '%s: service %s (tls-%s)' % (fname, name, row)
            if row not in table:
                errors.append('%s: no row %s in certs/nf-identities.txt' % (where, row))
                continue
            nf_type, want = table[row]
            if target != CERT_DIR:
                errors.append('%s is mounted at %s, not %s' % (where, target, CERT_DIR))
            if filled.get('/tls/' + row) != 'tls-' + row:
                errors.append('%s: %s does not fill it (mount tls-%s:/tls/%s there)'
                              % (where, INIT, row, row))
            if INIT not in depends_on(service):
                errors.append('%s does not depend on %s' % (where, INIT))
            ids = {u.lower() for u in UUID.findall(configured_text(service, read_file))}
            if not ids:
                errors.append('%s pins no nfInstanceId; its certificate names urn:uuid:%s'
                              % (where, want))
            for other in sorted(ids - {want}):
                errors.append('%s configures %s, but its certificate names urn:uuid:%s'
                              % (where, other, want))
            if nf_type == 'NRF':
                continue
            env = environment(service)
            for var, value in (('NEXTGCORE_NRF_TLS_CLIENT_CERT', '%s/%s.crt' % (CERT_DIR, row)),
                               ('NEXTGCORE_NRF_TLS_CLIENT_KEY', '%s/%s.key' % (CERT_DIR, row)),
                               ('NEXTGCORE_NRF_TLS_CA', '%s/ca.crt' % CERT_DIR)):
                if env.get(var) != value:
                    errors.append('%s: %s is %r, not %s' % (where, var, env.get(var), value))
        if len(certs) > 1:
            errors.append('%s: service %s mounts %d certificate volumes'
                          % (fname, name, len(certs)))
    return errors


def check(table, stacks, read_file=lambda path: None):
    """stacks: {file name: parsed compose document}. Returns error strings."""
    errors = []
    for fname, doc in sorted(stacks.items()):
        services = (doc or {}).get('services') or {}
        for name, service in services.items():
            if name not in table or not isinstance(service, dict):
                continue
            nf_type, want = table[name]
            env = environment(service)
            pins = {k: v for k, v in env.items() if k == ANY_VAR or PIN_VAR.match(k)}
            for var, value in sorted(pins.items()):
                if var != ANY_VAR and var != type_env_var(nf_type):
                    errors.append('%s: service %s sets %s, but its nfType is %s (%s)'
                                  % (fname, name, var, nf_type, type_env_var(nf_type)))
                elif value.strip().lower() != want:
                    errors.append('%s: service %s pins %s=%s, but certs/%s.crt names '
                                  'urn:uuid:%s (certs/nf-identities.txt)'
                                  % (fname, name, var, value, name, want))
            if fname == DEFAULT_STACK and not pins and nf_type not in NOT_REGISTERING:
                errors.append('%s: service %s does not pin its nfInstanceId; set %s: %s '
                              '(the ID certs/%s.crt names)'
                              % (fname, name, type_env_var(nf_type), want, name))
        errors += check_certificates(table, fname, services, read_file)
    return errors


def self_test():
    table = {'amf': ('AMF', 'a'), 'scp': ('SCP', 's'), 'ees': ('AF', 'e')}
    ok = {DEFAULT_STACK: {'services': {
        'amf': {'environment': {'NEXTGCORE_AMF_INSTANCE_ID': 'A'}},
        'ees': {'environment': ['NEXTGCORE_NF_INSTANCE_ID=e']},
        'scp': {'environment': {}},
        'mongodb': {}}}}
    assert check(table, ok) == [], check(table, ok)
    cases = [
        ({'amf': {'environment': {'NEXTGCORE_AMF_INSTANCE_ID': 'b'}}}, 'names urn:uuid:a'),
        ({'amf': {'environment': {'NEXTGCORE_SMF_INSTANCE_ID': 'a'}}}, 'its nfType is AMF'),
        ({'amf': {'environment': {}}}, 'does not pin'),
    ]
    for services, needle in cases:
        errs = check(table, {DEFAULT_STACK: {'services': services}})
        assert len(errs) == 1 and needle in errs[0], (services, errs)
    # Another stack may leave an NF unpinned, but not pin it wrongly.
    assert check(table, {'docker-compose.other.yml': {'services': {'amf': {}}}}) == []
    errs = check(table, {'docker-compose.other.yml': {'services': {
        'amf': {'environment': ['NEXTGCORE_AMF_INSTANCE_ID=x']}}}})
    assert len(errs) == 1, errs
    # MB_SMF (TS 29.510 spelling on the certificate) is pinned through the
    # variable nextgcore's NfType derives, NEXTGCORE_MBSMF_INSTANCE_ID (#1680).
    mb = {'mbsmf': ('MB_SMF', 'm')}
    assert check(mb, {DEFAULT_STACK: {'services': {
        'mbsmf': {'environment': {'NEXTGCORE_MBSMF_INSTANCE_ID': 'm'}}}}}) == []
    errs = check(mb, {DEFAULT_STACK: {'services': {
        'mbsmf': {'environment': {'NEXTGCORE_MB_SMF_INSTANCE_ID': 'm'}}}}})
    assert len(errs) == 1 and 'NEXTGCORE_MBSMF_INSTANCE_ID' in errs[0], errs
    # Rule 3: a certificate volume names the row, is filled, and matches the pin.
    good_init = {'image': 'nrf', 'volumes': ['./certs:/opt/sbi-tls:ro', 'sbi_pki:/pki',
                                             'tls-amf:/tls/amf', 'tls-eec:/tls/eec']}
    nrf_env = {'NEXTGCORE_NRF_TLS_CLIENT_CERT': '/etc/nextgcore/certs/amf.crt',
               'NEXTGCORE_NRF_TLS_CLIENT_KEY': '/etc/nextgcore/certs/amf.key',
               'NEXTGCORE_NRF_TLS_CA': '/etc/nextgcore/certs/ca.crt'}
    table3 = dict(table, eec=('AF', '6b1d7e3c-0000-4000-8000-0000000471ec'),
                  amf=('AMF', '6b1d7e3c-0000-4000-8000-000000000af0'))
    amf = {'environment': dict(nrf_env, NEXTGCORE_AMF_INSTANCE_ID=table3['amf'][1]),
           'volumes': ['tls-amf:/etc/nextgcore/certs:ro'], 'depends_on': {INIT: {}}}
    files = {'./configs/ue-entry.sh': 'nf_instance_id: 6b1d7e3c-0000-4000-8000-0000000471ec\n'}
    eec = {'environment': {'NEXTGCORE_NRF_TLS_CLIENT_CERT': '/etc/nextgcore/certs/eec.crt',
                           'NEXTGCORE_NRF_TLS_CLIENT_KEY': '/etc/nextgcore/certs/eec.key',
                           'NEXTGCORE_NRF_TLS_CA': '/etc/nextgcore/certs/ca.crt'},
           'volumes': ['${X:-./configs}/ue-entry.sh:/e.sh:ro', 'tls-eec:/etc/nextgcore/certs:ro'],
           'depends_on': [INIT]}
    other = 'docker-compose.other.yml'
    ok3 = {other: {'services': {INIT: good_init, 'amf': amf, 'ue': eec}}}
    assert check(table3, ok3, files.get) == [], check(table3, ok3, files.get)

    def broken(service, change):
        doc = {INIT: dict(good_init), 'amf': dict(amf), 'ue': dict(eec)}
        doc[service] = dict(doc[service], **change)
        return check(table3, {other: {'services': doc}}, files.get)
    cases3 = [
        ('ue', {'volumes': ['tls-eec:/etc/nextgcore/certs:ro']}, 'pins no nfInstanceId'),
        ('amf', {'environment': dict(nrf_env, NEXTGCORE_NF_INSTANCE_ID='6b1d7e3c-0000-4000-8000-0000000005f0')},
         'configures 6b1d7e3c-0000-4000-8000-0000000005f0'),
        ('amf', {'volumes': ['tls-zzz:/etc/nextgcore/certs:ro']}, 'no row zzz'),
        ('amf', {'volumes': ['tls-amf:/etc/other:ro']}, 'not /etc/nextgcore/certs'),
        ('amf', {'depends_on': {'nrf': {}}}, 'does not depend on sbi-tls'),
        ('amf', {'environment': {'NEXTGCORE_AMF_INSTANCE_ID': table3['amf'][1]}},
         'NEXTGCORE_NRF_TLS_CLIENT_CERT'),
        (INIT, {'volumes': ['./certs:/opt/sbi-tls:ro', 'tls-eec:/tls/eec']}, 'does not fill it'),
        ('ue', {'volumes': eec['volumes'] + ['./certs:/etc/nextgcore/certs:ro']},
         'mounts the host certs/'),
        ('ue', {'volumes': eec['volumes'] + ['sbi_pki:/pki']}, 'mounts sbi_pki'),
    ]
    for service, change, needle in cases3:
        errs = broken(service, change)
        assert any(needle in e for e in errs), (service, change, errs)
    print('check-nf-identities self-test: ok')


def main(argv):
    if argv[1:] == ['--self-test']:
        self_test()
        return 0
    if argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2
    table = read_table(TABLE)
    stacks = {}
    for path in sorted(glob.glob(os.path.join(COMPOSE_DIR, 'docker-compose*.yml'))):
        with open(path) as f:
            stacks[os.path.basename(path)] = yaml.safe_load(f)
    if DEFAULT_STACK not in stacks:
        print('check-nf-identities: %s not found' % DEFAULT_STACK, file=sys.stderr)
        return 1
    def read_file(path):
        full = os.path.normpath(os.path.join(COMPOSE_DIR, path))
        if not os.path.isfile(full):
            return None
        with open(full, encoding='utf-8', errors='replace') as f:
            return f.read()
    errors = check(table, stacks, read_file)
    for e in errors:
        print('check-nf-identities: ' + e, file=sys.stderr)
    if errors:
        return 1
    print('check-nf-identities: %d compose files agree with %d certificate identities'
          % (len(stacks), len(table)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
