import login from 'connect-ensure-login';
import db from '../db';

// Implementation of http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

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

export default (server) => [
  login.ensureLoggedIn(),
  server.authorization((clientId, redirectUri, cb) => {
    db.clients.findByClientId(clientId, (err, client) => {
      if (err) {
        return cb(err);
      }

      // WARNING: For security purposes, it is highly advisable to check that
      //          redirectUri provided by the client matches one registered with
      //          the server. For simplicity, this example does not. You have
      //          been warned.
      return cb(null, client, redirectUri);
    });
  }),
  (req, res) => {
    res.render('dialog', { transactionID: req.oauth2.transactionID, user: req.user, client: req.oauth2.client });
  },
];
