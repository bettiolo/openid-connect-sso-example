import express from 'express';
import passport from 'passport';
import site from './site';
import oauth2 from './oauth2';
import user from './user';
import client from './client';
import util from 'util';

import path from 'path';
import bodyParser from 'body-parser';
import session from 'express-session';
import errorhandler from 'errorhandler';

import debug from 'debug';
const log = debug('app');
const warn = debug('app:warn');

const app = express();
app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: false }));
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

app.set('port', process.env.PORT || 3000);
app.listen(app.get('port'), () => log(process.env.npm_package_name + ' PROVIDER listening on port ' + app.get('port')));
