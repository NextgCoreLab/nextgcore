'use strict';
// node webui/server/lib/mongoose-debug.check.js  -- exits non-zero on failure (#1970).
const assert = require('assert');
const { mongooseDebug, redact, REDACTED } = require('./mongoose-debug');

// Off under the production SBI profile, whatever NODE_ENV says, and off under
// NODE_ENV=production.
for (const env of [
  {},
  { NODE_ENV: 'development' },
  { NODE_ENV: 'development', NEXTGCORE_SBI_PROFILE: 'production' },
  { NODE_ENV: 'development', NEXTGCORE_SBI_PROFILE: 'staging' },
  { NODE_ENV: 'production', NEXTGCORE_SBI_PROFILE: 'dev' },
]) {
  assert.strictEqual(mongooseDebug(env), false, `off for ${JSON.stringify(env)}`);
}

// On only for a dev profile outside NODE_ENV=production, and redacting.
const lines = [];
const dbg = mongooseDebug({ NODE_ENV: 'development', NEXTGCORE_SBI_PROFILE: 'dev' }, (l) =>
  lines.push(l));
assert.strictEqual(typeof dbg, 'function');
const K = '465b5ce8b199b49faa5f0a2ee238a6bc';
const OPC = 'e8ed289deba952e4283b54e88e6183ca';
dbg('subscribers', 'insertOne', { imsi: '001010000000001', security: { k: K, opc: OPC, amf: '8000' } });
dbg('subscribers', 'updateOne', { imsi: '1' }, { $set: { 'security.k': K, 'security.OP': OPC } });
dbg('subscribers', 'insertMany', [{ security: { K: K } }]);
const out = lines.join('\n');
assert.ok(!out.includes(K) && !out.includes(OPC), `key material logged: ${out}`);
assert.ok(out.includes('001010000000001') && out.includes('8000'), 'other fields still shown');
assert.strictEqual(out.split(REDACTED).length - 1, 5, `every key field redacted: ${out}`);

// redact is a copy: the document mongoose writes is untouched.
const doc = { security: { k: K } };
assert.strictEqual(redact(doc).security.k, REDACTED);
assert.strictEqual(doc.security.k, K);
// #1983: index-suffixed and positional paths, off-schema names, BigInt.
const { sanitizeDebugEnv, isKeyField } = require('./mongoose-debug');
for (const k of ['security.k.0', 'security.opc.$', 'security.k.$[]', 'ki', 'permanentKeyValue',
  'encPermanentKey', 'OPcKey', 'clientSecret']) {
  assert.ok(isKeyField(k), `${k} is key material`);
}
for (const k of ['security.amf', 'security.sqn', 'imsi', 'key_id', 'kind']) {
  assert.ok(!isKeyField(k), `${k} is not key material`);
}
const more = [];
const dbg2 = mongooseDebug({ NODE_ENV: 'development', NEXTGCORE_SBI_PROFILE: 'dev' }, (l) =>
  more.push(l));
dbg2('subscribers', 'updateOne', { imsi: '1' },
  { $set: { 'security.k.0': K, ki: K, permanentKeyValue: OPC, 'security.sqn': 10n } });
assert.ok(!more[0].includes(K) && !more[0].includes(OPC), `leaked: ${more[0]}`);
assert.ok(more[0].includes('"10"'), `the BigInt is shown, not thrown: ${more[0]}`);

// #1983: DEBUG never enables mquery/mongoose query logging.
assert.strictEqual(sanitizeDebugEnv({}), undefined);
for (const raw of ['mquery', '*', 'mquery*,express:*', 'mongoose:*']) {
  const out = sanitizeDebugEnv({ DEBUG: raw });
  assert.ok(/-mquery\*/.test(out) && /-mongoose\*/.test(out), `${raw} -> ${out}`);
  assert.ok(!out.split(',').some((ns) => /^(mquery|mongoose)/.test(ns)), `${raw} -> ${out}`);
}
assert.ok(sanitizeDebugEnv({ DEBUG: 'express:*' }).startsWith('express:*,'));

console.log('mongoose-debug: ok');
