const express = require('express');
const router = express.Router();

const passport = require('passport');

const jwt = require('jsonwebtoken');
// Issue #118: no `|| 'change-me'` fallback -- a known signing secret makes admin
// tokens forgeable. Throws at require time if unset/placeholder/too short.
const { loadJwtSecret } = require('../lib/jwt-secret');
const secret = loadJwtSecret();

router.get('/csrf', (req, res) => {
  return res.json({csrfToken: res.locals._csrf});
})

router.get('/session', (req, res) => {
  let session = {
    clientMaxAge: 60000, // 60 seconds
    csrfToken: res.locals._csrf
  }
  if (req.user) {
    session.user = req.user
    const body = { '_id': req.user._id, 'username': req.user.username, 'roles':req.user.roles };
    const token = jwt.sign({ user: body }, secret);
    session.authToken = token
  }

  return res.json(session)
})

router.post('/login', 
  passport.authenticate('local', { successRedirect: '/' }));

router.post('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

module.exports = router;
