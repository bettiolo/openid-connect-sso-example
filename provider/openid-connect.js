import db from './db';

import codeGrant from './grants/code-grant.js';
import tokenGrant from './grants/token-grant.js';
import idTokenGrant from './grants/id-token-grant.js';
import idTokenTokenGrant from './grants/id-token-token-grant.js';
import codeIdTokenGrant from './grants/code-id-token-grant';
import codeTokenGrant from './grants/code-token-grant';
import codeIdTokenTokenGrant from './grants/code-id-token-token-grant';

import codeExchange from './exchanges/code-exchange.js';
import passwordExchange from './exchanges/password-exchange.js';
import clientCredentialsExchange from './exchanges/client-credentials-exchange.js';

export default (server) => {
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
      if (err) {
        return done(err);
      }
      return done(null, client);
    });
  });

  // Register supported OpenID Connect 1.0 grant types.

  // Implicit Flow
  server.grant(idTokenGrant);
  server.grant(idTokenTokenGrant);

  // Hybrid Flow
  server.grant(codeIdTokenGrant);
  server.grant(codeTokenGrant);
  server.grant(codeIdTokenTokenGrant);

  // Register supported Oauth 2.0 grant types.
  //
  // OAuth 2.0 specifies a framework that allows users to grant client
  // applications limited access to their protected resources.  It does this
  // through a process of the user granting access, and the client exchanging
  // the grant for an access token.

  server.grant(codeGrant);
  server.grant(tokenGrant);

  server.exchange(codeExchange);
  server.exchange(passwordExchange);
  server.exchange(clientCredentialsExchange);
}
