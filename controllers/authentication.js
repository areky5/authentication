const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

// Logic for auth

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub:user.id, iat:timestamp },config.secret);
}

exports.signin = function(req, res, next) {
  // User had already their email and password auth'd
  // We just need to give them a token
  res.send({ token:tokenForUser(req.user) }); 
}

// req = request, res = response, next = error handling
exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({error:'You must provide email and password'});
  }

  // See if a user with a given email exists
  User.findOne({ email: email }, function(err, existingUser) {
    if (err) { return next(err); }

    // if a user with email does exist, return error
    if (existingUser) {
      // 422 - unproccesable entity
      return res.status(422).send({error:'Email is in use'});
    }
    // if a user with email does not exist, create and save user record
    const user = new User({
      email: email,
      password: password
    });
    user.save(function(err) {
      if (err) { return next(err); }

      // respond to request indicating the user was created
      res.json({ token:tokenForUser(user) });
    });
  });
}
