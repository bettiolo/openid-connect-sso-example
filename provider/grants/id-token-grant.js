import oauth2orizeOpenId from 'oauth2orize-openid';

// id_token grant type.

export default oauth2orizeOpenId.grant.idToken((client, user, done) => {
  var id_token;
  // Do your lookup/token generation.
  // ... id_token =

  done(null, id_token);
});
