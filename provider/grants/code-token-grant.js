import oauth2orizeOpenId from 'oauth2orize-openid';

// 'code token' grant type.

export default oauth2orizeOpenId.grant.codeToken(
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
  }
);
