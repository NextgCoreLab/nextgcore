'use strict';
// node webui/server/lib/session-key.check.js  -- exits non-zero on failure (#913).
const assert = require('assert');
const { sessionKey, MIN_LENGTH } = require('./session-key');

for (const env of [{}, { SECRET_KEY: '' }, { SECRET_KEY: '   ' }, { SECRET_KEY: 'change-me' },
  { SECRET_KEY: 'x'.repeat(MIN_LENGTH - 1) }]) {
  assert.throws(() => sessionKey(env), `accepted ${JSON.stringify(env)}`);
}
const good = 'k'.repeat(MIN_LENGTH);
assert.strictEqual(sessionKey({ SECRET_KEY: good }), good);
console.log('session-key: ok');
