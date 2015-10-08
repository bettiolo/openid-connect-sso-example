import oauth2orize from 'oauth2orize';
import oauth2orizeOpenId from 'oauth2orize-openid';
import passport from 'passport';
import login from 'connect-ensure-login';
import db from './db';
import utils from './utils';

import codeGrant from './grants/code-grant.js';
import tokenGrant from './grants/token-grant.js';
import idTokenGrant from './grants/id-token-grant.js';
import idTokenTokenGrant from './grants/id-token-token-grant.js';

import codeExchange from './exchanges/code-exchange.js';
import passwordExchange from './exchanges/password-exchange.js';

// create OAuth 2.0 server
var server = oauth2orize.createServer();

// Register serialization and deserialization functions.
//
// When a client redirects a user to user authorization endpoint, an
// authorization transaction is initiated. To complete the transaction, the
// user must authenticate and approve the authorization request. Because this
// may involve multiple HTTP request/response exchanges, the transaction is
// stored in the session.
//
// An application must supply serialization functions, which determine how the
// client object is serialized into the session. Typically this will be a
// simple matter of serializing the client's ID, and deserializing by finding
// the client by ID from the database.

server.serializeClient((client, done) => done(null, client.id));

server.deserializeClient((id, done) => {
  db.clients.find(id, (err, client) => {
    if (err) { return done(err); }
    return done(null, client);
  });
});

// Register supported OpenID Connect 1.0 grant types.

// Implicit Flow

// id_token grant type.
server.grant(idTokenGrant);

// 'id_token token' grant type.
server.grant(idTokenTokenGrant);

// Hybrid Flow

// 'code id_token' grant type.
server.grant(oauth2orizeOpenId.grant.codeIdToken(
  function (client, redirect_uri, user, done) {
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  },
  function (client, user, done) {
    var id_token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, id_token);
  }
));

// 'code token' grant type.
server.grant(oauth2orizeOpenId.grant.codeToken(
  function (client, user, done) {
    var token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, token);
  },
  function (client, redirect_uri, user, done) {
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  }
));

// 'code id_token token' grant type.
server.grant(oauth2orizeOpenId.grant.codeIdTokenToken(
  function (client, user, done) {
    var token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, token);
  },
  function (client, redirect_uri, user, done) {
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  },
  function (client, user, done) {
    var id_token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, id_token);
  }
));


// Register supported Oauth 2.0 grant types.
//
// OAuth 2.0 specifies a framework that allows users to grant client
// applications limited access to their protected resources.  It does this
// through a process of the user granting access, and the client exchanging
// the grant for an access token.

server.grant(codeGrant);
server.grant(tokenGrant);

server.exchange(codeExchange);

// Exchange user id and password for access tokens.  The callback accepts the
// `client`, which is exchanging the user's name and password from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the user who authorized the code.

server.exchange(passwordExchange);

// Exchange the client id and password/secret for an access token.  The callback accepts the
// `client`, which is exchanging the client's id and password/secret from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the client who authorized the code.

server.exchange(oauth2orize.exchange.clientCredentials(function (client, scope, done) {

  //Validate the client
  db.clients.findByClientId(client.clientId, function (err, localClient) {
    if (err) {
      return done(err);
    }
    if (localClient === null) {
      return done(null, false);
    }
    if (localClient.clientSecret !== client.clientSecret) {
      return done(null, false);
    }
    var token = utils.uid(256);
    //Pass in a null for user id since there is no user with this grant type
    db.accessTokens.save(token, null, client.clientId, function (err) {
      if (err) {
        return done(err);
      }
      done(null, token);
    });
  });
}));

// user authorization endpoint
//
// `authorization` middleware accepts a `validate` callback which is
// responsible for validating the client making the authorization request.  In
// doing so, is recommended that the `redirectURI` be checked against a
// registered value, although security requirements may vary accross
// implementations.  Once validated, the `done` callback must be invoked with
// a `client` instance, as well as the `redirectURI` to which the user will be
// redirected after an authorization decision is obtained.
//
// This middleware simply initializes a new authorization transaction.  It is
// the application's responsibility to authenticate the user and render a dialog
// to obtain their approval (displaying details about the client requesting
// authorization).  We accomplish that here by routing through `ensureLoggedIn()`
// first, and rendering the `dialog` view.

exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization(function (clientID, redirectURI, done) {
    db.clients.findByClientId(clientID, function (err, client) {
      if (err) {
        return done(err);
      }
      // WARNING: For security purposes, it is highly advisable to check that
      //          redirectURI provided by the client matches one registered with
      //          the server.  For simplicity, this example does not.  You have
      //          been warned.
      return done(null, client, redirectURI);
    });
  }),
  function (req, res) {
    res.render('dialog', {transactionID: req.oauth2.transactionID, user: req.user, client: req.oauth2.client});
  }
]

// user decision endpoint
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application.  Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

exports.decision = [
  login.ensureLoggedIn(),
  server.decision(),
];


// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens.  Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.

exports.token = [
  passport.authenticate(['basic', 'oauth2-client-password'], {session: false}),
  server.token(),
  server.errorHandler(),
];
