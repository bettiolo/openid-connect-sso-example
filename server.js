/**
 * Module dependencies.
 */
var express = require('express')
    , passport = require('passport')
    , site = require('./site')
    , oauth2 = require('./oauth2')
    , user = require('./user')
    , client = require('./client')
    , util = require('util');

var bodyParser = require('body-parser');
var session = require('express-session');
var errorhandler = require('errorhandler');

var log = require('debug')('app');
var warn = require('debug')('app:warn');

// Express configuration

var app = express();
app.set('view engine', 'ejs');

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());

app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,
}));
/*
 app.use(function(req, res, next) {
 console.log('-- session --');
 console.dir(req.session);
 //console.log(util.inspect(req.session, true, 3));
 console.log('-------------');
 next()
 });
 */
app.use(passport.initialize());
app.use(passport.session());
app.use(errorhandler({ dumpExceptions: true, showStack: true }));

// Passport configuration

require('./auth');

app.get('/', site.index);
app.get('/login', site.loginForm);
app.post('/login', site.login);
app.get('/logout', site.logout);
app.get('/account', site.account);

app.get('/dialog/authorize', oauth2.authorization);
app.post('/dialog/authorize/decision', oauth2.decision);
app.post('/oauth/token', oauth2.token);

app.get('/api/userinfo', user.info);
app.get('/api/clientinfo', client.info);

app.listen(3000);