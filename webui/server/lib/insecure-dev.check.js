'use strict';
// node webui/server/lib/insecure-dev.check.js  -- exits non-zero on failure (#1913).
const assert = require('assert');
const { insecureDev, sbiProfile } = require('./insecure-dev');

// The profile resolves as SbiProfile::from_env_value does.
for (const v of [undefined, '', '  ', 'production', 'PROD', 'staging', 'devel']) {
  assert.strictEqual(sbiProfile({ NEXTGCORE_SBI_PROFILE: v }), 'production', `${v}`);
}
for (const v of ['dev', ' Dev ', 'development', 'insecure', 'local', 'TEST']) {
  assert.strictEqual(sbiProfile({ NEXTGCORE_SBI_PROFILE: v }), 'dev', `${v}`);
}

// Not asked for: secure, under either profile.
assert.strictEqual(insecureDev({}), false);
assert.strictEqual(insecureDev({ NEXTGCORE_SBI_PROFILE: 'dev' }), false);
assert.strictEqual(insecureDev({ WEBUI_INSECURE_DEV: '0', NEXTGCORE_SBI_PROFILE: 'dev' }), false);

// Asked for under dev: honoured.
assert.strictEqual(insecureDev({ WEBUI_INSECURE_DEV: '1', NEXTGCORE_SBI_PROFILE: 'dev' }), true);

// Asked for under production, including an unset or unrecognised profile: refused.
for (const p of [undefined, 'production', 'prod', 'staging']) {
  assert.throws(
    () => insecureDev({ WEBUI_INSECURE_DEV: '1', NEXTGCORE_SBI_PROFILE: p }),
    /production SBI profile does not allow/,
    `profile ${p}`
  );
}
console.log('insecure-dev: ok');
