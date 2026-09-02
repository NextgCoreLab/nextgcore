#!/usr/bin/env node
/*
 * Create the first provisioning admin account (issue #118).
 *
 * Replaces two predefined-credential paths that TS 33.117 §4.2.3.4.2.2 forbids:
 *   - the unconditional admin/1423 seed in docs/assets/webui/mongo-init.js, and
 *   - the dev-mode auto-registration in server/index.js.
 *
 * The password is read from the terminal with echo suppressed, or from
 * WEBUI_ADMIN_PASSWORD for an automated install. It is never a default and never
 * a command-line argument, so it does not land in `ps` output or shell history.
 *
 *   node server/bin/create-admin.js <username>
 */

// Resolve DB_URI exactly as server/index.js does, including its default. If this
// script and the server disagreed, the account would be created in a database the
// server never reads and login would fail with no visible reason.
process.env.DB_URI = process.env.DB_URI || 'mongodb://127.0.0.1/nextgcore';

const mongoose = require('mongoose');
const readline = require('readline');
const Account = require('../models/account');

const MIN_PASSWORD_LENGTH = 12;

function readPasswordFromTty(prompt) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(new Error(
        'stdin is not a terminal; set WEBUI_ADMIN_PASSWORD instead of piping a password'
      ));
      return;
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    // Suppress echo so the password is not printed or left on screen.
    const onData = () => { rl.output.write('\x1B[2K\x1B[200D' + prompt); };
    process.stdout.write(prompt);
    rl.input.on('data', onData);
    rl.question('', answer => {
      rl.input.removeListener('data', onData);
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function main() {
  const username = process.argv[2];
  if (!username) {
    console.error('usage: node server/bin/create-admin.js <username>');
    process.exit(2);
  }

  const password = process.env.WEBUI_ADMIN_PASSWORD
    || await readPasswordFromTty('Password for ' + username + ': ');

  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    console.error(
      'password must be at least ' + MIN_PASSWORD_LENGTH + ' characters'
    );
    process.exit(2);
  }

  await mongoose.connect(process.env.DB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000
  });

  const existing = await Account.findOne({ username });
  if (existing) {
    console.error('account "' + username + '" already exists');
    await mongoose.disconnect();
    process.exit(1);
  }

  const account = new Account();
  account.username = username;
  account.roles = ['admin'];
  await new Promise((resolve, reject) => {
    Account.register(account, password, err => (err ? reject(err) : resolve()));
  });

  console.log('created admin account "' + username + '"');
  await mongoose.disconnect();
}

main().catch(err => {
  console.error(err.message || err);
  process.exit(1);
});
