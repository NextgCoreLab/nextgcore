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
5. No NF -> NRF URI in the compose files or under configs/ is http://: every
   compose NRF serves TLS (#1617 step d), and an http:// NRF URI would put that
   NF's registration, heartbeats and token requests back on h2c. Checked are
   the `uri`s of an `nrf:` block, and any nrf-named flag, variable or key
   (--nrf-uri, NRF_URI, nrf_uri) set to an http:// value.

6. Kubernetes (k8s/, deploy/eks; --k8s): in each rendered kustomization, a
   pod that mounts a Secret nf-tls-<name> (k8s/nf-tls-secrets.sh issues it at
   deploy time) presents <name>.crt to the NRF, so:
   - <name> is a table row (or ca: the CA certificate alone, for a client
     that only discovers);
   - the container mounting it pins that row's nfInstanceId and no other
     UUID (its env, args, command and the ConfigMap keys it reads), or, when
     one container hands several rows to processes of their own (the d443a
     EAS sidecar), each mounted row's ID is in what it configures;
   - a client other than the NRF names its pair and the CA with
     NEXTGCORE_NRF_TLS_CLIENT_CERT / _KEY / _CA (files <name>.crt, <name>.key,
     ca.crt) and sets NEXTGCORE_NRF_TLS_SERVER_NAME=nrf: the URIs dial the
     cluster FQDN or a ClusterIP, nrf.crt names DNS:nrf;
   - the key is mode 0400 or 0440, and a nextgcore image (non-root) reading it
     gets it through the pod's fsGroup with 0440;
   - the NRF's nrf.yaml serves TLS from its Secret with client_auth optional;
   - a container that names an NRF URI mounts an nf-tls Secret, and no NRF
     URI is http://;
   - nothing committed is an nf-tls Secret or holds a ca.key.
   Rule 5 also covers every file under k8s/, deploy/eks and deploy/helm,
   including scripts that curl the NRF (http://nrf..., any http://
   .../nnrf-... path).

7. Helm (deploy/helm/nextgcore; --helm): the chart derives each NF's
   nfInstanceId and lists it in the rendered <release>-nf-identities
   ConfigMap, the table deploy/helm/nf-tls-secrets.sh issues the certificates
   from. In `helm template` renders:
   - the table is well formed (one UUID version 4 per row, no ID twice) and
     every row is a Deployment <release>-<row> whose container pins
     NEXTGCORE_<TYPE>_INSTANCE_ID (the row's nfType) to the row's ID;
   - rule 6 holds with that table (own Secret, IDs, NRF TLS env, 0440 +
     fsGroup, the NRF's nrf.yaml TLS with client_auth optional);
   - each NRF client runs one pod, Recreate (one ID, one certificate);
   - with global.nrfTls.secretVersion set, each pod mounts
     nf-tls-<row>-<version> and nothing else of nf-tls-*;
   - the chart refuses to render with an empty global.siteId and an unpinned
     ID, a non-https global.sbi.scheme, a malformed secretVersion or
     nfInstanceId, and replicas > 1, and renders with an empty siteId once
     every ID is pinned;
   - rule 5 holds over `helm install --dry-run=client`, NOTES.txt included
     (a templated http:// URL is only recognisable rendered).

Usage: check-nf-identities.py [--self-test] [--k8s] [--helm]
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
NRF_BLOCK = re.compile(r'^(\s*)(?:-\s+)?nrf:\s*(?:#.*)?$')
NRF_SETTING = re.compile(r'nrf[a-z0-9_-]*["\']?[ \t:=,]+["\']?http://', re.I)
NRF_PATH = re.compile(r'http://(?:nrf[.:]|[^\s"\'`]*/nnrf-)', re.I)
REPO_DIR = os.path.dirname(os.path.dirname(COMPOSE_DIR))
K8S_DIRS = ('k8s', os.path.join('deploy', 'eks'))
HELM_DIR = os.path.join('deploy', 'helm')
HELM_CHART = os.path.join(REPO_DIR, HELM_DIR, 'nextgcore')
HELM_RELEASE = 'ci'
HELM_VERSION = '0123456789abcdef'
UUID4 = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
K8S_SECRET = re.compile(r'^nf-tls-([a-z0-9-]+)$')
K8S_URI = re.compile(r'(https?)://([^\s"\'/]*nrf[^\s"\'/]*)', re.I)
POD_KINDS = ('Deployment', 'StatefulSet', 'DaemonSet', 'Job')
INTERP = re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*(?::?-([^}]*))?\}')


# The table names each nfType in the TS 29.510 §6.1.6.3.3 spelling the
# certificate carries, which nextgcore_sbi::NfType::to_str() also uses since
# #1680, so the instance-ID variable derives from it directly.
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


def plaintext_nrf_uris(fname, text):
    """Rule 5: the lines of one file that point an NF at an http:// NRF."""
    errors = []
    block = None
    for num, line in enumerate(text.splitlines(), 1):
        code = line.split(' #')[0] if not line.lstrip().startswith('#') else ''
        if not code.strip():
            continue
        indent = len(code) - len(code.lstrip())
        if block is not None and indent <= block:
            block = None
        m = NRF_BLOCK.match(code)
        if m:
            block = len(m.group(1))
            continue
        if (block is not None and 'http://' in code) or NRF_SETTING.search(code) \
                or NRF_PATH.search(code):
            errors.append('%s:%d: NRF URI over plaintext http:// (every shipped NRF serves '
                          'TLS, #1617): %s' % (fname, num, code.strip()))
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



def k8s_texts(container, pod, configmaps):
    """What one container configures, as a list of texts: env (with ConfigMap
    refs), args, command, and the ConfigMap keys it reads -- directly, or
    through an emptyDir that an init container fills from a ConfigMap (the
    rewrite-advertise-addr / resolve-dns pattern)."""
    parts = []
    for e in container.get('env') or []:
        if 'value' in e:
            parts.append(str(e['value']))
        ref = ((e.get('valueFrom') or {}).get('configMapKeyRef') or {})
        if ref:
            parts.append(str((configmaps.get(ref.get('name')) or {}).get(ref.get('key'), '')))
    for k in ('command', 'args'):
        v = container.get(k) or []
        parts += [v] if isinstance(v, str) else [str(x) for x in v]
    vols = {v.get('name'): v for v in pod.get('volumes') or []}

    def cm_keys(mount, subpath=None):
        cm = (vols.get(mount.get('name')) or {}).get('configMap')
        if not cm:
            return []
        data = configmaps.get(cm.get('name')) or {}
        key = subpath or mount.get('subPath')
        return [str(data.get(key, ''))] if key else [str(x) for x in data.values()]
    for m in container.get('volumeMounts') or []:
        v = vols.get(m.get('name')) or {}
        if 'configMap' in v:
            parts += cm_keys(m)
        elif 'emptyDir' in v:
            for ic in pod.get('initContainers') or []:
                ims = ic.get('volumeMounts') or []
                if not any(x.get('name') == m.get('name') for x in ims):
                    continue
                for x in ims:
                    parts += cm_keys(x, m.get('subPath') if not x.get('subPath') else None)
    return parts


def k8s_text(container, pod, configmaps):
    return '\n'.join(k8s_texts(container, pod, configmaps))


def k8s_env(container):
    return {e.get('name'): str(e.get('value', '')) for e in container.get('env') or []
            if 'value' in e}


def check_k8s(table, fname, docs):
    """Rule 6 for one rendered kustomization (a list of documents)."""
    errors = []
    configmaps = {}
    for d in docs:
        if d.get('kind') == 'ConfigMap':
            configmaps[d['metadata']['name']] = d.get('data') or {}
        if d.get('kind') == 'Secret':
            name = d['metadata'].get('name', '')
            if K8S_SECRET.match(name) or 'ca.key' in (d.get('data') or {}) \
                    or 'ca.key' in (d.get('stringData') or {}):
                errors.append('%s: Secret %s is committed; nf-tls Secrets are issued at deploy '
                              'time (k8s/nf-tls-secrets.sh) and no CA key is ever a Secret'
                              % (fname, name))
    for d in docs:
        if d.get('kind') not in POD_KINDS:
            continue
        pod = ((d.get('spec') or {}).get('template') or {}).get('spec') or {}
        where0 = '%s: %s/%s' % (fname, d['kind'], d['metadata'].get('name'))
        fs_group = (pod.get('securityContext') or {}).get('fsGroup')
        secrets = {}
        for v in pod.get('volumes') or []:
            m = K8S_SECRET.match(((v.get('secret') or {}).get('secretName')) or '')
            if m:
                secrets[v['name']] = (m.group(1), v['secret'])
            hp = ((v.get('hostPath') or {}).get('path')) or ''
            if 'certs' in hp:
                errors.append('%s: hostPath volume %s (%s); the certificates come from '
                              'nf-tls Secrets only' % (where0, v['name'], hp))
        for c in (pod.get('containers') or []) + (pod.get('initContainers') or []):
            where = '%s container %s' % (where0, c.get('name'))
            text = k8s_text(c, pod, configmaps)
            for scheme, host in K8S_URI.findall(text):
                if scheme.lower() == 'http':
                    errors.append('%s: NRF URI http://%s over plaintext (the NRF serves TLS, '
                                  '#1617)' % (where, host))
            mounted = [(secrets[m['name']], m) for m in c.get('volumeMounts') or []
                       if m.get('name') in secrets]
            if not mounted:
                # An init container that only copies a config is not a client.
                if c in (pod.get('containers') or []) and K8S_URI.search(text):
                    errors.append('%s names an NRF URI but mounts no nf-tls Secret (its '
                                  'certificate, or nf-tls-ca to discover only)' % where)
                continue
            env = k8s_env(c)
            ids = {u.lower() for u in UUID.findall(text)}
            image = str(c.get('image', ''))
            uid = (c.get('securityContext') or {}).get(
                'runAsUser', (pod.get('securityContext') or {}).get('runAsUser'))
            nonroot = image.split('/')[-2:-1] == ['nextgcore-rust'] or 'nextgcore-rust/' in image \
                or (uid is not None and uid != 0)
            for (row, secret), m in mounted:
                w = '%s (nf-tls-%s)' % (where, row)
                if row != 'ca' and row not in table:
                    errors.append('%s: no row %s in certs/nf-identities.txt' % (w, row))
                    continue
                modes = [secret.get('defaultMode')] + [
                    i.get('mode') for i in secret.get('items') or [] if str(i.get('key', '')).endswith('.key')]
                key_mode = next((x for x in reversed(modes) if x is not None), 0o644)
                if row != 'ca' and key_mode not in (0o400, 0o440):
                    errors.append('%s: the key is mode %o, not 0400 or 0440' % (w, key_mode))
                if row != 'ca' and nonroot and not (key_mode == 0o440 and fs_group is not None):
                    errors.append('%s: a non-root container reads the key only as mode 0440 '
                                  'through the pod\'s securityContext.fsGroup' % w)
                if not m.get('readOnly'):
                    errors.append('%s is not mounted readOnly' % w)
            rows = [r for (r, _), _ in mounted]
            if len(mounted) > 1:
                for (row, _), m in mounted:
                    if m.get('mountPath') != '%s/%s' % (CERT_DIR, row):
                        errors.append('%s (nf-tls-%s) is mounted at %s, not %s/%s (one '
                                      'directory per row)' % (where, row, m.get('mountPath'),
                                                              CERT_DIR, row))
                    if row in table and table[row][1] not in ids:
                        errors.append('%s (nf-tls-%s): urn:uuid:%s is not among the IDs it '
                                      'configures' % (where, row, table[row][1]))
                for u in sorted(ids - {table[r][1] for r in rows if r in table}):
                    errors.append('%s configures %s, which none of its certificates names'
                                  % (where, u))
                if env.get('NEXTGCORE_NRF_TLS_SERVER_NAME') != 'nrf':
                    errors.append('%s: NEXTGCORE_NRF_TLS_SERVER_NAME is %r, not nrf'
                                  % (where, env.get('NEXTGCORE_NRF_TLS_SERVER_NAME')))
                continue
            (row, _), m = mounted[0]
            if row not in table and row != 'ca':
                continue
            w = '%s (nf-tls-%s)' % (where, row)
            if m.get('mountPath') != CERT_DIR:
                errors.append('%s is mounted at %s, not %s' % (w, m.get('mountPath'), CERT_DIR))
            want_files = {'NEXTGCORE_NRF_TLS_CA': 'ca.crt'}
            if row == 'ca':
                for u in sorted(ids):
                    errors.append('%s configures %s but presents no certificate' % (w, u))
            else:
                nf_type, want = table[row]
                if not ids:
                    errors.append('%s pins no nfInstanceId; its certificate names urn:uuid:%s'
                                  % (w, want))
                for u in sorted(ids - {want}):
                    errors.append('%s configures %s, but its certificate names urn:uuid:%s'
                                  % (w, u, want))
                if nf_type == 'NRF':
                    errors += check_k8s_nrf(w, k8s_texts(c, pod, configmaps))
                    continue
                want_files.update({'NEXTGCORE_NRF_TLS_CLIENT_CERT': row + '.crt',
                                   'NEXTGCORE_NRF_TLS_CLIENT_KEY': row + '.key'})
            for var, base in sorted(want_files.items()):
                if os.path.basename(env.get(var, '')) != base:
                    errors.append('%s: %s is %r, not <dir>/%s' % (w, var, env.get(var), base))
            if env.get('NEXTGCORE_NRF_TLS_SERVER_NAME') != 'nrf':
                errors.append('%s: NEXTGCORE_NRF_TLS_SERVER_NAME is %r, not nrf'
                              % (w, env.get('NEXTGCORE_NRF_TLS_SERVER_NAME')))
    return errors


def check_k8s_nrf(where, texts):
    """The NRF container's nrf.yaml serves TLS from its Secret, client auth optional."""
    want = {'enabled': True, 'cert': CERT_DIR + '/nrf.crt', 'key': CERT_DIR + '/nrf.key',
            'ca': CERT_DIR + '/ca.crt', 'client_auth': 'optional'}
    for chunk in texts:
        try:
            doc = yaml.safe_load(chunk)
        except yaml.YAMLError:
            continue
        servers = (((doc or {}).get('nrf') or {}).get('sbi') or {}).get('server') \
            if isinstance(doc, dict) else None
        if servers:
            tls = (servers[0] or {}).get('tls') or {}
            return ['%s: nrf.yaml nrf.sbi.server[0].tls.%s is %r, not %r'
                    % (where, k, tls.get(k), v) for k, v in want.items() if tls.get(k) != v]
    return ['%s: no nrf.yaml with nrf.sbi.server among what it reads' % where]


def k8s_renders():
    """{kustomization dir: [documents]} for every tracked kustomization under K8S_DIRS."""
    import subprocess
    listed = subprocess.run(['git', '-C', REPO_DIR, 'ls-files', '--'] +
                            ['%s/*kustomization.yaml' % d for d in K8S_DIRS] +
                            ['%s/kustomization.yaml' % d for d in K8S_DIRS],
                            check=True, capture_output=True, text=True).stdout.split()
    out = {}
    for k in sorted(set(listed)):
        d = os.path.dirname(k)
        r = subprocess.run(['kubectl', 'kustomize', '--load-restrictor', 'LoadRestrictionsNone',
                            os.path.join(REPO_DIR, d)], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit('check-nf-identities: kubectl kustomize %s failed:\n%s' % (d, r.stderr))
        out[d] = [x for x in yaml.safe_load_all(r.stdout) if isinstance(x, dict)]
    return out

def helm_table(release, docs):
    """The rendered <release>-nf-identities table: {row: (nfType, id)}, or an error string."""
    want = release + '-nf-identities'
    for d in docs:
        if d.get('kind') == 'ConfigMap' and (d.get('metadata') or {}).get('name') == want:
            rows, seen = {}, set()
            for line in ((d.get('data') or {}).get('nf-identities.txt') or '').splitlines():
                f = line.split()
                if not f:
                    continue
                if len(f) != 4 or not UUID4.match(f[2]) or f[0] in rows or f[2] in seen:
                    return '%s: malformed or repeated line %r' % (want, line)
                rows[f[0]] = (f[1], f[2])
                seen.add(f[2])
            return rows or '%s lists no NF' % want
    return 'no ConfigMap %s' % want


def helm_derived_id(site, namespace, release, nf):
    """_helpers.tpl nextgcore.nfInstanceId with nothing pinned: the AMF's is the
    #753 derivation, so an existing release keeps its AMF ID."""
    import hashlib
    h = hashlib.sha256(('%s/%s/%s/%s' % (site, namespace, release, nf)).encode()).hexdigest()
    return '%s-%s-4%s-8%s-%s' % (h[0:8], h[8:12], h[13:16], h[17:20], h[20:32])


def check_helm(release, docs, version=None, types=None, derived=None):
    """Rule 7 for one `helm template` render (a list of documents). types: the
    nfType of each row of nf-identities.txt, which the render's must match (it
    is what the daemon registers); derived: (siteId, namespace) when nothing is
    pinned, to check each ID is the documented derivation."""
    where = 'helm %s' % release
    table = helm_table(release, docs)
    if isinstance(table, str):
        return ['%s: %s' % (where, table)]
    errors = []
    for row, (nf_type, got) in sorted(table.items()):
        if types is not None and types.get(row) != nf_type:
            errors.append('%s: row %s has nfType %s; nf-identities.txt row %s registers as %s'
                          % (where, row, nf_type, row, types.get(row)))
        if derived is not None and got != helm_derived_id(derived[0], derived[1], release, row):
            errors.append('%s: row %s ID %s is not the derivation sha256(%s/%s/%s/%s)'
                          % (where, row, got, derived[0], derived[1], release, row))
    deps = {d['metadata'].get('name'): d for d in docs if d.get('kind') == 'Deployment'}
    for row, (nf_type, want) in sorted(table.items()):
        d = deps.get('%s-%s' % (release, row))
        if d is None:
            errors.append('%s: row %s has no Deployment %s-%s' % (where, row, release, row))
            continue
        spec = d.get('spec') or {}
        pod = (spec.get('template') or {}).get('spec') or {}
        c = next((c for c in pod.get('containers') or [] if c.get('name') == row), None)
        var = type_env_var(nf_type)
        got = k8s_env(c or {}).get(var)
        if got != want:
            errors.append('%s: Deployment %s-%s pins %s=%r, not the table\'s %s'
                          % (where, release, row, var, got, want))
        if nf_type != 'NRF' and (spec.get('replicas') != 1
                                 or (spec.get('strategy') or {}).get('type') != 'Recreate'):
            errors.append('%s: Deployment %s-%s must run one pod, strategy Recreate (one '
                          'nfInstanceId, one certificate)' % (where, release, row))
    if version is None:
        return errors + check_k8s(table, where, docs)
    for name, d in sorted(deps.items()):
        row = name[len(release) + 1:]
        for v in ((d.get('spec') or {}).get('template') or {}).get('spec', {}).get('volumes') or []:
            sn = (v.get('secret') or {}).get('secretName') or ''
            if sn.startswith('nf-tls-') and sn != 'nf-tls-%s-%s' % (row, version):
                errors.append('%s: Deployment %s mounts %s, not nf-tls-%s-%s'
                              % (where, name, sn, row, version))
    return errors


def helm_template(release, sets):
    import subprocess
    args = ['helm', 'template', release, HELM_CHART, '-n', 'ns']
    for x in sets:
        args += ['--set', x]
    return subprocess.run(args, capture_output=True, text=True)


HELM_REFUSALS = [
    (['global.siteId='], 'global.siteId is empty'),
    (['global.siteId=ci', 'global.sbi.scheme=http'], 'the NRF serves TLS only'),
    (['global.siteId=ci', 'global.nrfTls.secretVersion=v1'], 'is not the 16 hex digits'),
    (['global.siteId=ci', 'udm.nfInstanceId=UDM-1'], 'is not a lower-case UUID version 4'),
    (['global.siteId=ci', 'ausf.replicas=2'], 'ausf.replicas > 1 is not supported'),
    (['global.siteId=ci', 'amf.replicas=2'], 'amf.replicas > 1 is not supported'),
    (['global.siteId=ci', 'nrf.replicas=2'], 'nrf.replicas > 1 is not supported'),
]


def helm_checks(table):
    """Rule 7 over the chart: two renders and the refusals."""
    errors = []
    types = {row: t for row, (t, _) in table.items()}
    for sets, version in ((['global.siteId=ci'], None),
                          (['global.siteId=ci', 'global.nrfTls.secretVersion=' + HELM_VERSION],
                           HELM_VERSION)):
        r = helm_template(HELM_RELEASE, sets)
        if r.returncode != 0:
            errors.append('helm template %s failed:\n%s' % (' '.join(sets), r.stderr))
            continue
        docs = [x for x in yaml.safe_load_all(r.stdout) if isinstance(x, dict)]
        errors += check_helm(HELM_RELEASE, docs, version, types, ('ci', 'ns'))
    for sets, needle in HELM_REFUSALS:
        r = helm_template(HELM_RELEASE, sets)
        if r.returncode == 0:
            errors.append('helm template --set %s rendered; it must fail (%s)'
                          % (' --set '.join(sets), needle))
        elif needle not in r.stderr:
            errors.append('helm template --set %s failed for another reason: %s'
                          % (' --set '.join(sets), r.stderr.strip()))
    # Rule 5 over the rendered chart, NOTES included: a templated URL
    # (http://{{ ... }}/nnrf-...) is only recognisable once rendered, and
    # `helm template` does not render NOTES.txt.
    import subprocess
    r = subprocess.run(['helm', 'install', '--dry-run=client', HELM_RELEASE, HELM_CHART,
                        '-n', 'ns', '--set', 'global.siteId=ci'], capture_output=True, text=True)
    if r.returncode != 0:
        errors.append('helm install --dry-run=client failed:\n%s' % r.stderr)
    else:
        errors += plaintext_nrf_uris('helm install --dry-run=client (manifests and NOTES)',
                                     r.stdout)
    # An empty siteId is fine once nothing is derived.
    pins = ['%s.nfInstanceId=6b1d7e3c-0000-4000-8000-%012x' % (nf, i) for i, nf in enumerate(
        'nrf amf smf ausf udm udr pcf nssf bsf'.split())]
    r = helm_template(HELM_RELEASE, ['global.siteId='] + pins)
    if r.returncode != 0:
        errors.append('helm template with every nfInstanceId pinned and no siteId failed:\n%s'
                      % r.stderr)
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
    # MB_SMF (TS 29.510 spelling, on the certificate and in NfType since #1680)
    # is pinned through NEXTGCORE_MB_SMF_INSTANCE_ID; the stack sets the new name.
    mb = {'mbsmf': ('MB_SMF', 'm')}
    assert check(mb, {DEFAULT_STACK: {'services': {
        'mbsmf': {'environment': {'NEXTGCORE_MB_SMF_INSTANCE_ID': 'm'}}}}}) == []
    errs = check(mb, {DEFAULT_STACK: {'services': {
        'mbsmf': {'environment': {'NEXTGCORE_MBSMF_INSTANCE_ID': 'm'}}}}})
    assert len(errs) == 1 and 'NEXTGCORE_MB_SMF_INSTANCE_ID' in errs[0], errs
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
    # Rule 5: an http:// NRF URI, in a block or a setting, is refused.
    bad = {
        'nrf:\n  - uri: http://nrf:7777\n': ':2:',
        'amf:\n  sbi:\n    client:\n      nrf:\n        - uri: http://10.0.0.1:7777\n': ':5:',
        'command: ["--sbi-port", "7777", "--nrf-uri", "http://172.23.0.10:7777"]\n': ':1:',
        'command: --nrf-uri http://nrf:7777\n': ':1:',
        'environment:\n  NRF_URI: "http://nrf:7777"\n': ':2:',
        'cat <<EOF\nnrf_uri: http://nrf:7777\nEOF\n': ':2:',
    }
    for text, line in bad.items():
        errs = plaintext_nrf_uris('f', text)
        assert len(errs) == 1 and line in errs[0], (text, errs)
    good = [
        'nrf:\n  - uri: https://nrf:7777\nscp:\n  - uri: http://scp:7777\n',
        'client:\n  nrf:\n    - uri: https://nrf:7777\n  scp:\n    - uri: http://scp:7777\n',
        '# nrf: http://old:7777\n--nrf-uri https://172.23.0.10:7777 --udm-uri http://udm:7777\n',
        'nrf:\n  - uri: https://nrf:7777  # was http://nrf:7777\n',
    ]
    for text in good:
        assert plaintext_nrf_uris('f', text) == [], (text, plaintext_nrf_uris('f', text))
    # Rule 6: rendered Kubernetes documents.
    import copy
    t6 = {'amf': ('AMF', '6b1d7e3c-0000-4000-8000-000000000af0'),
          'nrf': ('NRF', '6b1d7e3c-0000-4000-8000-0000000000f0'),
          'eas-a': ('AF', '6b1d7e3c-0000-4000-8000-0000000471a1'),
          'eas-b': ('AF', '6b1d7e3c-0000-4000-8000-0000000471a2')}
    cm = {'kind': 'ConfigMap', 'metadata': {'name': 'cfg'}, 'data': {
        'amf.yaml': 'amf:\n  sbi:\n    client:\n      nrf:\n        - uri: https://nrf.ns.svc:7777\n',
        'nrf.yaml': yaml.safe_dump({'nrf': {'sbi': {'server': [{'address': '0.0.0.0', 'tls': {
            'enabled': True, 'cert': CERT_DIR + '/nrf.crt', 'key': CERT_DIR + '/nrf.key',
            'ca': CERT_DIR + '/ca.crt', 'client_auth': 'optional'}}]}}}),
        'eases': 'eas-a 6b1d7e3c-0000-4000-8000-0000000471a1\neas-b 6b1d7e3c-0000-4000-8000-0000000471a2\n'}}

    def dep(name, containers, volumes, fs=999):
        spec = {'containers': containers, 'volumes': volumes}
        if fs is not None:
            spec['securityContext'] = {'fsGroup': fs}
        return {'kind': 'Deployment', 'metadata': {'name': name},
                'spec': {'template': {'spec': spec}}}

    def tls_vol(row, mode=0o440, name='nf-tls'):
        return {'name': name, 'secret': {'secretName': 'nf-tls-' + row, 'defaultMode': mode}}
    tls_mount = {'name': 'nf-tls', 'mountPath': CERT_DIR, 'readOnly': True}
    cfg_vol = {'name': 'config', 'configMap': {'name': 'cfg'}}
    amf_env = [{'name': 'NEXTGCORE_AMF_INSTANCE_ID', 'value': t6['amf'][1]},
               {'name': 'NEXTGCORE_NRF_TLS_CA', 'value': CERT_DIR + '/ca.crt'},
               {'name': 'NEXTGCORE_NRF_TLS_CLIENT_CERT', 'value': CERT_DIR + '/amf.crt'},
               {'name': 'NEXTGCORE_NRF_TLS_CLIENT_KEY', 'value': CERT_DIR + '/amf.key'},
               {'name': 'NEXTGCORE_NRF_TLS_SERVER_NAME', 'value': 'nrf'}]
    amf_c = {'name': 'amf', 'image': 'nextgcore-rust/amf:latest', 'env': amf_env,
             'volumeMounts': [tls_mount, {'name': 'config', 'mountPath': '/etc/nextgcore/amf.yaml',
                                          'subPath': 'amf.yaml'}]}
    nrf_c = {'name': 'nrf', 'image': 'nextgcore-rust/nrf:latest',
             'env': [{'name': 'NEXTGCORE_NRF_INSTANCE_ID', 'value': t6['nrf'][1]}],
             'volumeMounts': [tls_mount, {'name': 'config', 'mountPath': '/etc/nextgcore/nrf.yaml',
                                          'subPath': 'nrf.yaml'}]}
    side = {'name': 'side', 'image': 'nextgsim-ue:latest',
            'env': [{'name': 'EASES', 'valueFrom': {'configMapKeyRef': {'name': 'cfg', 'key': 'eases'}}},
                    {'name': 'NEXTGCORE_NRF_TLS_SERVER_NAME', 'value': 'nrf'}],
            'volumeMounts': [{'name': 'a', 'mountPath': CERT_DIR + '/eas-a', 'readOnly': True},
                             {'name': 'b', 'mountPath': CERT_DIR + '/eas-b', 'readOnly': True}]}
    good6 = [cm, dep('amf', [amf_c], [tls_vol('amf'), cfg_vol]),
             dep('nrf', [nrf_c], [tls_vol('nrf'), cfg_vol]),
             dep('upf', [side], [tls_vol('eas-a', 0o400, 'a'), tls_vol('eas-b', 0o400, 'b')], None)]
    assert check_k8s(t6, 'r', good6) == [], check_k8s(t6, 'r', good6)

    def broken6(edit):
        docs = copy.deepcopy(good6)
        edit(docs)
        return check_k8s(t6, 'r', docs)
    def amf_env_set(var, value):
        return lambda d: [e.update(value=value) for e in d[1]['spec']['template']['spec']
                          ['containers'][0]['env'] if e['name'] == var]
    cases6 = [
        (amf_env_set('NEXTGCORE_AMF_INSTANCE_ID', '6b1d7e3c-0000-4000-8000-0000000005f0'),
         'configures 6b1d7e3c-0000-4000-8000-0000000005f0'),
        (amf_env_set('NEXTGCORE_NRF_TLS_CLIENT_KEY', CERT_DIR + '/smf.key'), 'NEXTGCORE_NRF_TLS_CLIENT_KEY'),
        (amf_env_set('NEXTGCORE_NRF_TLS_SERVER_NAME', 'nrf.ns.svc'), 'SERVER_NAME'),
        (lambda d: d[1]['spec']['template']['spec']['volumes'][0]['secret'].update(secretName='nf-tls-zzz'),
         'no row zzz'),
        (lambda d: d[1]['spec']['template']['spec'].pop('securityContext'), 'fsGroup'),
        (lambda d: d[1]['spec']['template']['spec']['volumes'][0]['secret'].update(defaultMode=0o444),
         'mode 444'),
        (lambda d: d[0]['data'].update({'amf.yaml': 'nrf:\n  - uri: http://nrf.ns.svc:7777\n'}),
         'over plaintext'),
        (lambda d: d[1]['spec']['template']['spec']['containers'][0].update(
            volumeMounts=d[1]['spec']['template']['spec']['containers'][0]['volumeMounts'][1:]),
         'mounts no nf-tls Secret'),
        (lambda d: d[0]['data'].update({'nrf.yaml': d[0]['data']['nrf.yaml'].replace('optional', 'required')}),
         'client_auth'),
        (lambda d: d[0]['data'].update({'eases': 'eas-a 6b1d7e3c-0000-4000-8000-0000000471a1\n'}),
         'urn:uuid:6b1d7e3c-0000-4000-8000-0000000471a2 is not among'),
        (lambda d: d[3]['spec']['template']['spec']['containers'][0]['volumeMounts'][1].update(
            mountPath=CERT_DIR), 'one directory per row'),
        (lambda d: d.append({'kind': 'Secret', 'metadata': {'name': 'nf-tls-amf'}, 'data': {}}),
         'is committed'),
        (lambda d: d.append({'kind': 'Secret', 'metadata': {'name': 'pki'}, 'data': {'ca.key': 'x'}}),
         'is committed'),
    ]
    for edit, needle in cases6:
        errs = broken6(edit)
        assert any(needle in e for e in errs), (needle, errs)
    # Rule 7: a Helm render, as rule 6 plus the rendered identity table.
    t7 = {'amf': t6['amf'], 'nrf': t6['nrf']}
    ids = {'kind': 'ConfigMap', 'metadata': {'name': 'r-nf-identities'}, 'data': {
        'nf-identities.txt': ''.join('%s %s %s -\n' % (k, v[0], v[1]) for k, v in t7.items())}}
    good7 = copy.deepcopy(good6[:3]) + [ids]
    good7[1]['metadata']['name'] = 'r-amf'
    good7[1]['spec'].update(replicas=1, strategy={'type': 'Recreate'})
    good7[2]['metadata']['name'] = 'r-nrf'
    assert check_helm('r', good7) == [], check_helm('r', good7)
    versioned = copy.deepcopy(good7)
    for d in versioned[1:3]:
        v = d['spec']['template']['spec']['volumes'][0]['secret']
        v['secretName'] += '-' + HELM_VERSION
    assert check_helm('r', versioned, HELM_VERSION) == [], check_helm('r', versioned, HELM_VERSION)

    def broken7(edit, version=None):
        docs = copy.deepcopy(versioned if version else good7)
        edit(docs)
        return check_helm('r', docs, version)
    amf7 = lambda d: d[1]['spec']['template']['spec']['containers'][0]['env'][0]
    cases7 = [
        (lambda d: amf7(d).update(name='NEXTGCORE_SMF_INSTANCE_ID'), None,
         'pins NEXTGCORE_AMF_INSTANCE_ID=None'),
        (lambda d: d[1]['spec'].pop('strategy'), None, 'strategy Recreate'),
        (lambda d: d[1]['spec'].update(replicas=2), None, 'one pod'),
        (lambda d: d[1]['metadata'].update(name='r-amf2'), None, 'no Deployment r-amf'),
        (lambda d: d[3]['data'].update({'nf-identities.txt': 'amf AMF %s -\nnrf NRF %s -\n'
                                        % (t6['amf'][1], t6['amf'][1])}), None, 'repeated'),
        (lambda d: d[3]['data'].update({'nf-identities.txt': 'amf AMF not-a-uuid -\n'}), None,
         'malformed'),
        (lambda d: d.pop(3), None, 'no ConfigMap r-nf-identities'),
        (lambda d: amf7(d).update(value=t6['nrf'][1]), None, 'pins NEXTGCORE_AMF_INSTANCE_ID'),
        (lambda d: d[1]['spec']['template']['spec'].pop('securityContext'), None, 'fsGroup'),
        (lambda d: d[2]['spec']['template']['spec']['volumes'][0]['secret'].update(
            secretName='nf-tls-amf-' + HELM_VERSION), HELM_VERSION, 'mounts nf-tls-amf-'),
        (lambda d: d[1]['spec']['template']['spec']['volumes'][0]['secret'].update(
            secretName='nf-tls-amf'), HELM_VERSION, 'mounts nf-tls-amf, not'),
    ]
    for edit, version, needle in cases7:
        errs = broken7(edit, version)
        assert any(needle in e for e in errs), (needle, errs)
    errs = check_helm('r', good7, types={'amf': 'SMF', 'nrf': 'NRF'})
    assert any('registers as SMF' in e for e in errs), errs
    errs = check_helm('r', good7, derived=('s', 'ns'))
    assert any('is not the derivation' in e for e in errs), errs
    # The derivation of #753 (the AMF ID a release already registered).
    assert helm_derived_id('ci', 'default', 't', 'amf') == '03380045-d486-4346-85eb-95c03918bf9f'
    print('check-nf-identities self-test: ok')


def main(argv):
    if argv[1:] == ['--self-test']:
        self_test()
        return 0
    flags = set(argv[1:])
    if not flags <= {'--k8s', '--helm'} or len(flags) != len(argv[1:]):
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
    shipped = sorted(glob.glob(os.path.join(COMPOSE_DIR, 'docker-compose*.yml'))) + sorted(
        p for p in glob.glob(os.path.join(COMPOSE_DIR, 'configs', '**', '*'), recursive=True)
        if os.path.isfile(p))
    for path in shipped:
        with open(path, encoding='utf-8', errors='replace') as f:
            errors += plaintext_nrf_uris(os.path.relpath(path, COMPOSE_DIR), f.read())
    k8s_files = sorted(p for d in K8S_DIRS + (HELM_DIR,)
                       for p in glob.glob(os.path.join(REPO_DIR, d, '**', '*'), recursive=True)
                       if os.path.isfile(p) and not p.endswith('.dryrun.yaml')
                       and '.dryrun.' not in os.path.basename(p))
    for path in k8s_files:
        with open(path, encoding='utf-8', errors='replace') as f:
            errors += plaintext_nrf_uris(os.path.relpath(path, REPO_DIR), f.read())
    renders = k8s_renders() if '--k8s' in flags else {}
    for d, docs in sorted(renders.items()):
        errors += check_k8s(table, d, docs)
    if '--helm' in flags:
        errors += helm_checks(table)
    for e in errors:
        print('check-nf-identities: ' + e, file=sys.stderr)
    if errors:
        return 1
    print('check-nf-identities: %d compose files agree with %d certificate identities; '
          'no http:// NRF URI in %d shipped files' % (len(stacks), len(table),
                                                      len(shipped) + len(k8s_files)))
    if renders:
        print('check-nf-identities: %d rendered kustomizations mount only their own nf-tls '
              'Secrets' % len(renders))
    if '--helm' in flags:
        print('check-nf-identities: the Helm chart pins the IDs of its rendered identity table, '
              'mounts only each NF\'s own nf-tls Secret and refuses %d bad value sets'
              % len(HELM_REFUSALS))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
