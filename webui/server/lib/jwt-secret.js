/*
 * JWT signing/verification secret for the provisioning UI (issue #118).
 *
 * Both the signing side (routes/auth.js) and the verifying side (routes/index.js)
 * used `process.env.JWT_SECRET_KEY || 'change-me'`. With that fallback in place an
 * attacker did not need an account at all: signing `{user:{roles:['admin']}}` with
 * the well-known constant produced a token the /api/db gate accepted, giving full
 * read/write access to every subscriber's permanent key material.
 *
 * TS 33.117 §4.2.3.4.2.2 forbids shipping predefined credentials usable to gain
 * privileged access, and a hardcoded signing secret is exactly that.
 *
 * There is deliberately NO fallback here. A missing or placeholder secret is a
 * startup failure, not a warning: the process must not reach a state where it
 * accepts forgeable tokens. Both call sites load this module at require time, so
 * the failure happens before the server can listen.
 */

// Values that are not credentials, whatever else they may be. `change-me` is the
// historical default; the rest are the obvious things someone reaches for when a
// start-up check demands "any value".
const REJECTED = new Set([
  'change-me',
  'changeme',
  'secret',
  'password',
  'jwt-secret',
  'test',
  'dev',
]);

const MIN_LENGTH = 32;

function loadJwtSecret() {
  const raw = process.env.JWT_SECRET_KEY;

  if (raw === undefined || raw.trim() === '') {
    throw new Error(
      'JWT_SECRET_KEY is not set. The provisioning UI refuses to start without a ' +
      'signing secret, because the previous default made admin tokens forgeable. ' +
      'Generate one with: openssl rand -hex 32'
    );
  }

  const secret = raw.trim();

  if (REJECTED.has(secret.toLowerCase())) {
    throw new Error(
      `JWT_SECRET_KEY is the placeholder value "${secret}". Any party who knows it ` +
      'can mint an admin token for this deployment. Generate one with: openssl rand -hex 32'
    );
  }

  if (secret.length < MIN_LENGTH) {
    throw new Error(
      `JWT_SECRET_KEY is ${secret.length} characters; at least ${MIN_LENGTH} are ` +
      'required. Generate one with: openssl rand -hex 32'
    );
  }

  return secret;
}

module.exports = { loadJwtSecret, REJECTED, MIN_LENGTH };
