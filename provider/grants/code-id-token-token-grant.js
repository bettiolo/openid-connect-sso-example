import oauth2orizeOpenId from 'oauth2orize-openid';

// 'code id_token token' grant type.

export default oauth2orizeOpenId.grant.codeIdTokenToken(
  (client, user, done) => {
    var token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, token);
  },
  (client, redirect_uri, user, done) => {
    var code;
    // Do your lookup/token generation.
    // ... code =

    done(null, code);
  },
  (client, user, done) => {
    var id_token;
    // Do your lookup/token generation.
    // ... id_token =
    done(null, id_token);
  }
);
