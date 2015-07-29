var Account = require('../models/user');
var passport = require('passport');

/*
 * GET users listing.
 */

exports.list = function(req, res){
  res.send('respond with a resource');
};


/*
 * GET login page.
 */

exports.login = function(req, res, next) {
  res.render('login', { user : req.user });
};

/*
 * GET logout route.
 */

exports.logout = function(req, res, next) {
    //req.session.destroy();
    req.logout();
    res.redirect('/');
};


exports.registerView = function (req, res) {
    res.render('register', {});
};

exports.register = function (req, res){
    Account.register(new Account({ username : req.body.username }), req.body.password, function (err, account) {
        if (err) {
            return res.render('register', { info: "Sorry. That username already exists. Try again." });
        }
        
        passport.authenticate('local')(req, res, function () {
            res.redirect('/');
        });
    });
} 


/*
 * POST authenticate route.
 */

exports.authenticate = function(req, res, next) {
  //if (!req.body.email || !req.body.password)
  //  return res.render('login', {error: 'Please enter your email and password.'});
  //req.models.User.findOne({
  //  email: req.body.email,
  //  password: req.body.password
  //}, function(error, user){
  //  if (error) return next(error);
  //  if (!user) return res.render('login', {error: 'Incorrect email&password combination.'});
  //  req.session.user = user;
  //  req.session.admin = user.admin;
    res.redirect('/admin');
};
