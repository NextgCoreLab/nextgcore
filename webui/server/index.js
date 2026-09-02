// Database name is `nextgcore`, matching the single source of truth in
// src/libs/nextgcore-dbi/src/types.rs (NEXTGCORE_DEFAULT_DB_NAME), the Rust
// WebUI's --db-name, docs/assets/webui/mongo-init.js and the compose stack's
// MONGO_INITDB_DATABASE.
//
// This said `open5gs` -- a leftover from the upstream project this was forked
// from. Not merely branding: mongo-init.js seeds subscribers into `nextgcore`, so
// this UI was reading a database nothing populates. Anything provisioned here was
// invisible to the UDR, and anything seeded was invisible here. The Rust side was
// already corrected for exactly this reason; this was the last holdout.
process.env.DB_URI = process.env.DB_URI || 'mongodb://127.0.0.1/nextgcore';

const _hostname = process.env.HOSTNAME || 'localhost';
const port = process.env.PORT || 9999;

const co = require('co');
const next = require('next');

const dev = process.env.NODE_ENV !== 'production';
const app = next({ dev });
const handle = app.getRequestHandler();

const express = require('express');
const bodyParser = require('body-parser');
const methodOverride = require('method-override');
const morgan = require('morgan');
const session = require('express-session');

const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const csrf = require('lusca').csrf();
const secret = process.env.SECRET_KEY || 'change-me';

const api = require('./routes');

const Account = require('./models/account.js');

co(function* () {
  yield app.prepare();

  mongoose.Promise = global.Promise;
  if (dev) {
    mongoose.set('debug', true);
  }
  const db = yield mongoose.connect(process.env.DB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 1000
    /* other options */
  })

  // Issue #118: the dev-mode auto-registration of admin/1423 is REMOVED.
  // TS 33.117 §4.2.3.4.2.2 / TR 33.926 §5.3.6.8: no predefined credential may
  // grant privileged access. A first admin is now an explicit provisioning step:
  //   node server/bin/create-admin.js <username>
  // which prompts for a password rather than baking one in.
  Account.count((err, count) => {
    if (err) {
      console.error(err);
      throw err;
    }
    if (!count) {
      console.warn(
        '> No provisioning accounts exist. Create one with: ' +
        'node server/bin/create-admin.js <username>'
      );
    }
  })

  const server = express();
  
  server.use(bodyParser.json());
  server.use(bodyParser.urlencoded({ extended: true }));
  server.use(methodOverride());

  server.use(session({
    secret: secret,
    store: MongoStore.create({
      mongoUrl: process.env.DB_URI,
      ttl: 60 * 60 * 24 * 7 * 2
    }),
    resave: false,
    rolling: true,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7 * 2,  // 2 weeks
      // Issue #118 / TS 33.117 §4.2.5.1. `httpOnly` was set on the session
      // OPTIONS object rather than inside `cookie`, where express-session reads
      // it -- so it had no effect and the cookie was scriptable. `secure` was
      // absent entirely, so the session cookie was sent over plaintext HTTP.
      httpOnly: true,
      sameSite: 'strict',
      // Secure by default; only a deliberate insecure-dev run may send the
      // session cookie over plaintext.
      secure: process.env.WEBUI_INSECURE_DEV !== '1'
    }
  }));

  server.use((req, res, next) => {
    req.db = db;
    next();
  })

  server.use(csrf);

  server.use(passport.initialize());
  server.use(passport.session());

  passport.use(new LocalStrategy(Account.authenticate()));
  passport.serializeUser(Account.serializeUser());
  passport.deserializeUser(Account.deserializeUser());

  server.use('/api', api);

  server.get('*', (req, res) => {
    return handle(req, res);
  });

  if (dev) {
    server.use(morgan('tiny'));
  }

  server.listen(port, _hostname, err => {
    if (err) throw err;
    console.log('> Ready on http://' + _hostname + ':' + port);
  });
})
.catch(error => console.error(error.stack));
