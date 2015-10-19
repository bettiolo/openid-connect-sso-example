import oauth2orize from 'oauth2orize';
import db from '../db';
import utils from '../utils';

// Grant authorization codes. The callback takes the `client` requesting
// authorization, the `redirectURI` (which is used as a verifier in the
// subsequent exchange), the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application. The application issues a code, which is bound to these
// values, and will be exchanged for an access token.

export default oauth2orize.grant.code((client, redirectURI, user, ares, done) => {
  const code = utils.uid(16);

  db.authorizationCodes.save(code, client.clientId, redirectURI, user.id, (err) => {
    if (err) { return done(err); }

    done(null, code);
  });
});
