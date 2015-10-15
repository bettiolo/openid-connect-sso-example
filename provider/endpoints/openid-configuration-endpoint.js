export default (issuer) => [
  (req, res) => {
    const scheme = 'http';
    res.json({
      'issuer': `${scheme}://${issuer}`,
      'authorization_endpoint': `${scheme}://${issuer}/dialog/auth`,
      'token_endpoint': `${scheme}://${issuer}/oauth/token`,
      'userinfo_endpoint': `${scheme}://${issuer}/api/userinfo`,
      // 'revocation_endpoint': 'http://localhost:3000oauth2/revoke',
      // 'jwks_uri': 'http://localhost:3000/oauth2/certs',
      //'response_types_supported': [
      //  'code',
      //  //"token",
      //  //"id_token",
      //  //"code token",
      //  //"code id_token",
      //  //"token id_token",
      //  //"code token id_token",
      //  //"none"
      //],
      // 'subject_types_supported': [
      //   'public'
      // ],
      //'id_token_signing_alg_values_supported': [
      //  'RS256',
      //],
      //'scopes_supported': [
      //  'openid',
      //  // 'email',
      //  // 'profile',
      //],
      // 'token_endpoint_auth_methods_supported': [
      //   'client_secret_post',
      //   'client_secret_basic'
      // ],
      // 'claims_supported': [
      //   'aud',
      //   'email',
      //   'email_verified',
      //   'exp',
      //   'family_name',
      //   'given_name',
      //   'iat',
      //   'iss',
      //   'locale',
      //   'name',
      //   'picture',
      //   'sub',
      // ],
    });
  },
];
