import oauth2orize from 'oauth2orize';
import db from '../db';
import utils from '../utils';

// Exchange authorization codes for access tokens.  The callback accepts the
// `client`, which is exchanging `code` and any `redirectURI` from the
// authorization request for verification.  If these values are validated, the
// application issues an access token on behalf of the user who authorized the
// code.

export default oauth2orize.exchange.code((client, code, redirectURI, cb) => {
  db.authorizationCodes.find(code, (authorizationCodeErr, authCode) => {
    if (authorizationCodeErr) { return cb(authorizationCodeErr); }

    if (client.id !== authCode.clientID) {
      return cb(null, false);
    }
    if (redirectURI !== authCode.redirectURI) {
      return cb(null, false);
    }

    const token = utils.uid(256);
    db.accessTokens.save(token, authCode.userID, authCode.clientID, (accessTokenErr) => {
      if (accessTokenErr) { return cb(accessTokenErr); }

      cb(null, token);
    });
  });
});
