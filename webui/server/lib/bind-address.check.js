'use strict';
// node webui/server/lib/bind-address.check.js  -- exits non-zero on failure (#850).
const assert = require('assert');
const { bindAddress, LOOPBACK } = require('./bind-address');

// HOSTNAME is set by every container runtime; it must never pick the bind.
for (const env of [{}, { WEBUI_BIND_ADDR: '' }, { WEBUI_BIND_ADDR: '  ' },
  { HOSTNAME: 'webui-7d9f' }, { HOSTNAME: '0.0.0.0' }]) {
  assert.strictEqual(bindAddress(env), LOOPBACK, `not loopback for ${JSON.stringify(env)}`);
}
assert.strictEqual(bindAddress({ WEBUI_BIND_ADDR: '0.0.0.0', HOSTNAME: 'x' }), '0.0.0.0');
console.log('bind-address: ok');
