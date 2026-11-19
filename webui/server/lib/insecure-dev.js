'use strict';

/**
 * Whether the session cookie may go over plaintext (#1913, TS 33.117 §4.2.5.1).
 *
 * `WEBUI_INSECURE_DEV=1` drops the cookie's `secure` flag so a local dev run
 * over http:// can log in. It used to be honoured whatever the deployment's
 * profile, so a production deployment that set it sent the session cookie for
 * the subscriber-provisioning UI (K, OPc) over plaintext HTTP. It is now honoured
 * only under the `dev` SBI profile, and under `production` the UI refuses to
 * start, as the Rust WebUI refuses `--insecure-dev` (#1908).
 *
 * The profile is resolved exactly as `SbiProfile::from_env_value` resolves
 * `NEXTGCORE_SBI_PROFILE` (src/libs/nextgcore-sbi/src/security.rs): unset,
 * empty or unrecognised is `production`; dev, development, insecure, local and
 * test (any case, trimmed) are `dev`.
 */

const DEV_VALUES = new Set(['dev', 'development', 'insecure', 'local', 'test']);

/** `'dev'` or `'production'`, as `SbiProfile::from_env_value`. */
function sbiProfile(env) {
  const raw = (env || {}).NEXTGCORE_SBI_PROFILE;
  const v = raw === undefined || raw === null ? '' : String(raw).trim().toLowerCase();
  return DEV_VALUES.has(v) ? 'dev' : 'production';
}

/**
 * Whether the session cookie is sent without `secure`. Throws (the UI refuses to
 * start) when `WEBUI_INSECURE_DEV=1` is set under the production profile.
 */
function insecureDev(env) {
  const asked = (env || {}).WEBUI_INSECURE_DEV === '1';
  if (!asked) {
    return false;
  }
  if (sbiProfile(env) !== 'dev') {
    throw new Error(
      'WEBUI_INSECURE_DEV=1 sends the session cookie over plaintext HTTP, which the ' +
        'production SBI profile does not allow (TS 33.117 §4.2.5.1). Serve the UI ' +
        'over HTTPS, or set NEXTGCORE_SBI_PROFILE=dev for a local development run.'
    );
  }
  return true;
}

module.exports = { insecureDev, sbiProfile };
