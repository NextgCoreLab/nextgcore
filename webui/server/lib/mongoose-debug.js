'use strict';

/**
 * Mongoose debug logging for the provisioning UI (#1970).
 *
 * `mongoose.set('debug', true)` writes every query to the log, and the
 * subscriber documents hold the long-term key K and OPc/OP (TS 33.501 §6.1.1
 * keeps K in the ARPF; it never belongs in a log). It used to be on whenever
 * NODE_ENV was not 'production', whatever NEXTGCORE_SBI_PROFILE said, so a
 * dev-mode or custom deployment wrote key material to its logs.
 *
 * Now it is on only when NODE_ENV is not 'production' AND the SBI profile is
 * `dev` (resolved as `SbiProfile::from_env_value`, see ./insecure-dev), and even
 * then it logs through a redacting function: key fields are replaced by
 * REDACTED at any depth, including dotted update paths (`security.k`) and
 * `$set` documents.
 */

const { sbiProfile } = require('./insecure-dev');

const REDACTED = '<redacted>';
// The long-term key, the operator variant and its derived OPc, and common
// spellings of them (#1983): `ki` (2G/3G), and any name that says it holds a
// permanent key, an OP(c) key, an encrypted key or a secret. #2021: and an
// account's password `hash` and `salt` (passport-local-mongoose's fields).
const KEY_FIELDS = new Set(['k', 'ki', 'op', 'opc', 'encpermanentkey', 'encopckey', 'hash',
  'salt']);
const KEY_WORDS = ['permanentkey', 'opckey', 'opkey', 'enckey', 'secret'];

/** Whether a single field name names key material. */
function isKeyName(name) {
  const n = String(name).toLowerCase();
  return KEY_FIELDS.has(n) || KEY_WORDS.some((w) => n.includes(w));
}

/**
 * Whether `key` (a field name or a dotted path) names key material. #1983: an
 * array index (`security.k.0`) or a positional operator (`$`, `$[]`,
 * `$[elem]`) after the field still names it, so each path segment is checked.
 */
function isKeyField(key) {
  return String(key)
    .split('.')
    .some((seg) => !/^(\d+|\$|\$\[[^\]]*\])$/.test(seg) && isKeyName(seg));
}

/** A copy of `value` with every key field's value replaced by REDACTED. */
function redact(value, seen = new WeakSet()) {
  if (Array.isArray(value)) {
    return value.map((v) => redact(v, seen));
  }
  if (value && typeof value === 'object') {
    if (seen.has(value)) {
      return '[circular]';
    }
    seen.add(value);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      // #2006: a function is never data, and an own `toJSON` would run in
      // JSON.stringify on the copy and could return K unredacted.
      if (typeof v === 'function') {
        continue;
      }
      out[k] = isKeyField(k) ? REDACTED : redact(v, seen);
    }
    return out;
  }
  return value;
}

/**
 * The value to hand `mongoose.set('debug', ...)`: `false` (off), or a logger
 * that prints each query with key fields redacted. `log` defaults to
 * console.log (injectable for the check).
 */
function mongooseDebug(env, log = console.log) {
  const e = env || {};
  if (e.NODE_ENV === 'production' || sbiProfile(e) !== 'dev') {
    return false;
  }
  return function debugQuery(collection, method, ...args) {
    // #1983: a BigInt (mongoose-long, an SQN) made JSON.stringify throw, and
    // the logger with it. #2006: no toJSON runs on the redacted copy: `redact`
    // rebuilds every object from its own data properties (so a prototype's
    // toJSON is gone) and drops functions (so an own one is too).
    const shown = args.map((a) =>
      JSON.stringify(redact(a), (_k, v) => (typeof v === 'bigint' ? v.toString() : v)));
    log(`Mongoose: ${collection}.${method}(${shown.join(', ')})`);
  };
}

/**
 * #1983: the `debug` package's namespaces with mquery's (and mongoose's own)
 * query logging excluded. `DEBUG=mquery` (or `*`) made mquery print every query
 * with its documents, K and OPc included, past the redacting logger. `debug`
 * reads DEBUG when first required, so this runs before mongoose is loaded.
 * Exclusions (`-ns`) win over inclusions in `debug`, so they are appended.
 */
function sanitizeDebugEnv(env) {
  const e = env || {};
  const raw = e.DEBUG;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return raw;
  }
  const kept = String(raw)
    .split(/[\s,]+/)
    .filter((ns) => ns !== '' && !/^(mquery|mongoose)(:|\*|$)/i.test(ns));
  return [...kept, '-mquery*', '-mongoose*'].join(',');
}

module.exports = { mongooseDebug, redact, REDACTED, sanitizeDebugEnv, isKeyField };
