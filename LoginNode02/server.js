var TWITTER_CONSUMER_KEY = process.env.TWITTER_CONSUMER_KEY || 'ABC'
var TWITTER_CONSUMER_SECRET = process.env.TWITTER_CONSUMER_SECRET || 'XYZXYZ'

var express = require('express'),
    routes = require('./routes'),
    http = require('http'),
    path = require('path'),
    mongoose = require('mongoose'),
    passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,

    models = require('./models'),
    dbUrl = process.env.MONGOHQ_URL || 'mongodb://@localhost:27017/blog',
    db = mongoose.connect(dbUrl, { safe: true }),

    session = require('express-session'),
    logger = require('morgan'),
    errorHandler = require('errorhandler'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    methodOverride = require('method-override');


var app = express();
app.locals.appTitle = "blog-express";

// passport config
var User = require('./models/user');
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.use(function (req, res, next) {
    if (!models.Article || !models.User) return next(new Error("No models."))
    req.models = models;
    return next();
});



// All environments
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(bodyParser.json());
app.use(cookieParser('3CCC4ACD-6ED1-4844-9217-82131BDCB239'));
app.use(session({ secret: '2C44774A-D649-4D44-9535-46E296EF984F' }))
app.use(bodyParser.urlencoded());
app.use(methodOverride());
app.use(passport.initialize());
app.use(passport.session());
app.use(require('stylus').middleware(__dirname + '/public'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(function (req, res, next) {
    if (req.session && req.session.admin)
        res.locals.admin = true;
    next();
});

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
app.post('/login', passport.authenticate('local'), routes.user.authenticate);
app.get('/logout', routes.user.logout); //if you use everyauth, this /logout route is overwriting by everyauth automatically, therefore we use custom/additional handleLogout
app.get('/admin', authorize, routes.article.admin);
app.get('/post', authorize, routes.article.post);
app.post('/post', authorize, routes.article.postArticle);
app.get('/register', routes.user.registerView);
app.post('/register', routes.user.register);
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