import passport from 'passport';

// Implementation of http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

// token endpoint
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens. Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request.  Clients must
// authenticate when making requests to this endpoint.
export default (server) => [
  passport.authenticate(['basic', 'oauth2-client-password'], {session: false}),
  server.token(),
  server.errorHandler(),
];
