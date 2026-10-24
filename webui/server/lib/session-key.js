'use strict';

/**
 * The express-session signing key (#913).
 *
 * `server/index.js` used `process.env.SECRET_KEY || 'change-me'`, so any
 * deployment that did not set SECRET_KEY signed sessions with a value
 * published in this repository, and anyone could forge a session cookie for
 * the provisioning UI. There is no fallback any more: the server refuses to
 * start unless SECRET_KEY is set to a non-placeholder value of at least
 * MIN_LENGTH characters. Supply it from the environment (a gitignored .env,
 * a Kubernetes Secret, ...), never from a committed file.
 */

const MIN_LENGTH = 32;
const PLACEHOLDERS = new Set(['change-me', 'changeme', 'secret', 'nextgcore']);

function sessionKey(env) {
  const raw = (env || {}).SECRET_KEY;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    throw new Error(
      'SECRET_KEY is not set. The provisioning UI refuses to start without a ' +
        'session-signing key; set SECRET_KEY to a random value of at least ' +
        `${MIN_LENGTH} characters (for example: openssl rand -base64 48).`
    );
  }
  const key = String(raw);
  if (PLACEHOLDERS.has(key.trim().toLowerCase())) {
    throw new Error(`SECRET_KEY is the placeholder value "${key}"; set a random one.`);
  }
  if (key.length < MIN_LENGTH) {
    throw new Error(
      `SECRET_KEY is ${key.length} characters; at least ${MIN_LENGTH} are required.`
    );
  }
  return key;
}

module.exports = { sessionKey, MIN_LENGTH };
