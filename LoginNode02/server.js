var TWITTER_CONSUMER_KEY = process.env.TWITTER_CONSUMER_KEY || 'ABC'
var TWITTER_CONSUMER_SECRET = process.env.TWITTER_CONSUMER_SECRET || 'XYZXYZ'

var express = require('express'),
    routes = require('./routes'),
    http = require('http'),
    path = require('path'),
    mongoose = require('mongoose'),
    passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    flash = require('connect-flash'),
    models = require('./models'),
    bCrypt = require('bcrypt-nodejs'),

    dbUrl = process.env.MONGOHQ_URL || 'mongodb://@localhost:27017/blog',
    db = mongoose.connect(dbUrl, { safe: true }),
    
    session = require('express-session'),
    logger = require('morgan'),
    errorHandler = require('errorhandler'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    methodOverride = require('method-override');


var app = express();
app.locals.appTitle = "language";

// passport config
var User = require('./models/user');
passport.use('local-signin', new LocalStrategy({
    usernameField : 'email',
    passwordField : 'password',
}, function (username, password, done) {
    User.findOne({ 'email' : username }, function (err, user) {
        if (err) { return done(err); }
        if (!user) {
            return done(null, false, { message: 'Incorrect username.' });
        }
        // User exists but wrong password, log the error 
        if (!isValidPassword(user, password)) {
            console.log('Invalid Password');
            return done(null, false, 
              req.flash('message', 'Invalid Password'));
        }
        return done(null, user);
    });
}
));

var isValidPassword = function (user, password) {
    return bCrypt.compareSync(password, user.password);
}

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use('local-signup', new LocalStrategy({
    usernameField : 'email',
    passwordField : 'password',
    passReqToCallback : true,
},
  function (req, username, password, done) {
    // asynchronous
    // User.findOne wont fire unless data is sent back
    process.nextTick(function () {
        
        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'email' : username }, function (err, user) {
            // if there are any errors, return the error
            if (err)
                return done(err);
            
            // check to see if theres already a user with that email
            if (user) {
                return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
            } else {
                
                // if there is no user with that email
                // create the user
                var newUser = new User();
                
                // set the user's local credentials
                newUser.email = username;
                newUser.password = newUser.generateHash(password);
                
                // save the user
                newUser.save(function (err) {
                    if (err)
                        throw err;
                    return done(null, newUser);
                });
            }

        });

    });

}));

app.use(function (req, res, next) {
    if (!models.Article || !models.User) return next(new Error("No models."))
    req.models = models;
    return next();
});

app.use(function (req, res, next) {
    if (req.session && req.session.admin)
        res.locals.admin = true;
    next();
});

// All environments
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({ secret: '2C44774A-D649-4D44-9535-46E296EF984F' }))
app.use(bodyParser.urlencoded());
app.use(methodOverride());
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(require('stylus').middleware(__dirname + '/public'));
app.use(express.static(path.join(__dirname, 'public')));

// Authorization
var authorize = function (req, res, next) {
if (req.session && req.session.admin)
return next();
else
return res.send(401);
};

// Development only
if ('development' === app.get('env')) {
app.use(errorHandler());
}


// Pages and routes
app.get('/', routes.index);
app.get('/login', routes.user.login);
app.post('/login', passport.authenticate('local-signin'), routes.user.authenticate);
app.get('/logout', routes.user.logout); //if you use everyauth, this /logout route is overwriting by everyauth automatically, therefore we use custom/additional handleLogout
app.get('/admin', authorize, routes.article.admin);
app.get('/post', authorize, routes.article.post);
app.post('/post', authorize, routes.article.postArticle);
app.get('/register', routes.user.registerView);
app.post('/register', passport.authenticate('local-signup'), routes.index);
app.get('/articles/:slug', routes.article.show);

// REST API routes
app.all('/api', authorize);
app.get('/api/articles', routes.article.list);
app.post('/api/articles', routes.article.add);
app.put('/api/articles/:id', routes.article.edit);
app.del('/api/articles/:id', routes.article.del);



app.all('*', function (req, res) {
res.send(404);
})

// http.createServer(app).listen(app.get('port'), function(){
// console.log('Express server listening on port ' + app.get('port'));
// });

var server = http.createServer(app);
var boot = function () {
server.listen(app.get('port'), function () {
console.info('Express server listening on port ' + app.get('port'));
});
}
var shutdown = function () {
server.close();
}
if (require.main === module) {
boot();
} else {
console.info('Running app as a module')
exports.boot = boot;
exports.shutdown = shutdown;
exports.port = app.get('port');
}
