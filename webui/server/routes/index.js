const express = require('express');
const auth = require('./auth');
const db = require('./db')

const router = express.Router();

// Issue #118: same fail-fast secret as the signing side (routes/auth.js). A token
// signed with the old `change-me` default no longer verifies, because that value
// can never be the secret.
const { loadJwtSecret } = require('../lib/jwt-secret');
const secret = loadJwtSecret();
const passport = require('passport');
const JWTstrategy = require('passport-jwt').Strategy;
const ExtractJWT = require('passport-jwt').ExtractJwt;

passport.use(
  new JWTstrategy(
    {
      secretOrKey: secret,
      jwtFromRequest: ExtractJWT.fromAuthHeaderWithScheme('bearer')
    },
    async (token, done) => {
      try {
        return done(null, token.user);
      } catch (error) {
        done(error);
      }
    }
  )
);

router.use('/auth', auth);
router.use('/db', passport.authenticate('jwt', { session: false }), db);

module.exports = router;