
var User = require('../models/user');
var bCrypt = require('bcrypt-nodejs');
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

//exports.register = function (req, res, next) {
//    if (!req.body.email || !req.body.password)
//        return res.render('login', { error: "Please enter your email and password." });
    
//    req.models.User.findOne({
//        email: req.body.email
//    }, function (error, user) {
//        if (error) return next(error);
//        if (user != null) return res.render('register', { info: "Sorry. That username already exists. Try again." });
        
//        var user = new User();
//        user.email = req.body.email;
//        user.password = createHash(req.body.password);
//        user.admin = false;
//        user.save(function (err) {
//            if (err)
//                throw err;
//            return done(null, user);
//        });
//    });
//};

exports.register = function (req, res, next) {
    res.render('login', { user : req.user });
};

exports.authenticate = function (req, res, next) {
    if (req.user != undefined) {
        req.session.user = req.user;
        req.session.admin = req.user.admin;
    }
    res.redirect('/');
}