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
// The long-term key, the operator variant and its derived OPc, and the
// encrypted spellings the UDR uses.
const KEY_FIELDS = new Set(['k', 'op', 'opc', 'encpermanentkey', 'encopckey']);

/** Whether `key` (a field name or a dotted path) names key material. */
function isKeyField(key) {
  const last = String(key).split('.').pop().toLowerCase();
  return KEY_FIELDS.has(last);
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
    const shown = args.map((a) => JSON.stringify(redact(a)));
    log(`Mongoose: ${collection}.${method}(${shown.join(', ')})`);
  };
}

module.exports = { mongooseDebug, redact, REDACTED };
