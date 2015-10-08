import oauth2orize from 'oauth2orize';
import db from '../db';
import utils from '../utils';

// Exchange the client id and password/secret for an access token.  The callback accepts the
// `client`, which is exchanging the client's id and password/secret from the
// authorization request for verification. If these values are validated, the
// application issues an access token on behalf of the client who authorized the code.

export default oauth2orize.exchange.clientCredentials((client, scope, done) => {
  // Validate the client
  db.clients.findByClientId(client.clientId, (findByClientIdErr, localClient) => {
    if (findByClientIdErr) { return done(findByClientIdErr); }

    if (localClient === null) {
      return done(null, false);
    }
    if (localClient.clientSecret !== client.clientSecret) {
      return done(null, false);
    }

    // Pass in a null for user id since there is no user with this grant type
    const token = utils.uid(256);
    db.accessTokens.save(token, null, client.clientId, (saveErr) => {
      if (saveErr) { return done(saveErr); }

      done(null, token);
    });
  });
});
