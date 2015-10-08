import express from 'express';
import passport from 'passport';
import oauth2orize from 'oauth2orize';

import api from './api';
import site from './site';
import openidConnect from './openid-connect';
import user from './user';
import client from './client';

import path from 'path';
import bodyParser from 'body-parser';
import session from 'express-session';
import errorhandler from 'errorhandler';

import debug from 'debug';
const log = debug('app');

const app = express();
app.use(errorhandler({ dumpExceptions: true, showStack: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
}));
/*
 import util from 'util';
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

const server = oauth2orize.createServer();
openidConnect(server);

import './auth';

app.get('/', site.index);
app.get('/login', site.loginForm);
app.post('/login', site.login);
app.get('/logout', site.logout);
app.get('/account', site.account);

app.get('/dialog/authorize', api.authorization(server));
app.post('/dialog/authorize/decision', api.decision(server));
app.post('/oauth/token', api.token(server));

app.get('/api/userinfo', user.info);
app.get('/api/clientinfo', client.info);

app.set('port', process.env.PORT || 3000);
app.listen(app.get('port'), () => log(process.env.npm_package_name + ' PROVIDER listening on port ' + app.get('port')));
