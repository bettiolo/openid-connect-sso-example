import login from 'connect-ensure-login';
import passport from 'passport';
import db from './db';

export default {
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
  authorization(server) {
    return [
      login.ensureLoggedIn(),
      server.authorization((clientID, redirectURI, cb) => {
        db.clients.findByClientId(clientID, (err, client) => {
          if (err) {
            return cb(err);
          }

          // WARNING: For security purposes, it is highly advisable to check that
          //          redirectURI provided by the client matches one registered with
          //          the server. For simplicity, this example does not. You have
          //          been warned.
          return cb(null, client, redirectURI);
        });
      }),
      (req, res) => {
        res.render('dialog', {transactionID: req.oauth2.transactionID, user: req.user, client: req.oauth2.client});
      },
    ];
  },

  // user decision endpoint
  //
  // `decision` middleware processes a user's decision to allow or deny access
  // requested by a client application.  Based on the grant type requested by the
  // client, the above grant middleware configured above will be invoked to send
  // a response.
  decision(server) {
    return [
      login.ensureLoggedIn(),
      server.decision(),
    ];
  },

  // token endpoint
  //
  // `token` middleware handles client requests to exchange authorization grants
  // for access tokens. Based on the grant type being exchanged, the above
  // exchange middleware will be invoked to handle the request.  Clients must
  // authenticate when making requests to this endpoint.
  token(server) {
    return [
      passport.authenticate(['basic', 'oauth2-client-password'], {session: false}),
      server.token(),
      server.errorHandler(),
    ];
  },
};
