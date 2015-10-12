import oauth2orize from 'oauth2orize';
import db from '../db';
import utils from '../utils';

// Grant implicit authorization.  The callback takes the `client` requesting
// authorization, the authenticated `user` granting access, and
// their response, which contains approved scope, duration, etc. as parsed by
// the application.  The application issues a token, which is bound to these
// values.

export default oauth2orize.grant.token((client, user, ares, cb) => {
  const token = utils.uid(256);

  db.accessTokens.save(token, user.id, client.clientId, (err) => {
    if (err) { return cb(err); }

    cb(null, token);
  });
});
