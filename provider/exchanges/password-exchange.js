import oauth2orize from 'oauth2orize';
import db from '../db';
import utils from '../utils';

export default oauth2orize.exchange.password((client, username, password, scope, done) => {
  // Validate the client
  db.clients.findByClientId(client.clientId, (findByClientIdErr, localClient) => {
    if (findByClientIdErr) { return done(findByClientIdErr); }

    if (localClient === null) {
      return done(null, false);
    }
    if (localClient.clientSecret !== client.clientSecret) {
      return done(null, false);
    }

    // Validate the user
    db.users.findByUsername(username, (findByUsernameErr, user) => {
      if (findByUsernameErr) { return done(findByUsernameErr); }

      if (user === null) {
        return done(null, false);
      }
      if (password !== user.password) {
        return done(null, false);
      }

      // Everything validated, return the token
      const token = utils.uid(256);
      db.accessTokens.save(token, user.id, client.clientId, (saveErr) => {
        if (saveErr) { return done(saveErr); }

        done(null, token);
      });
    });
  });
});
