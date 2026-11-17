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


def type_env_var(nf_type):
    """nextgcore_sbi::nf_instance_id::type_env_var."""
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


def check(table, stacks):
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
    assert check(table, {'docker-compose.demo.yml': {'services': {'amf': {}}}}) == []
    errs = check(table, {'docker-compose.demo.yml': {'services': {
        'amf': {'environment': ['NEXTGCORE_AMF_INSTANCE_ID=x']}}}})
    assert len(errs) == 1, errs
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
    errors = check(table, stacks)
    for e in errors:
        print('check-nf-identities: ' + e, file=sys.stderr)
    if errors:
        return 1
    print('check-nf-identities: %d compose files agree with %d certificate identities'
          % (len(stacks), len(table)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
