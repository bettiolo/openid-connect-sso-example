import debug from 'debug';
import uuid from 'node-uuid';
import config from './config';
import authorisationCodeFlow from './flows/authorisation-code-flow';

const log = debug('app:site');

function getAuthorizationEndpointHref(responseType, provider, state, nonce) {
  let authorizationEndpointHref = `${provider.authorization_endpoint}` +
    `?response_type=${encodeURIComponent(responseType)}` +
    `&scope=${encodeURIComponent(provider.scope)}` +
    `&client_id=${encodeURIComponent(provider.clientId)}` +
    `&redirect_uri=${encodeURIComponent(provider.redirectUri)}` +
    `&state=${encodeURIComponent(state)}` + // Should be checked server side to match the session / CSRF protection
    `&display=page`;
  if (nonce) {
    // Required only for Implicit Flow only
    authorizationEndpointHref += `&nonce=${encodeURIComponent(nonce)}`;
  }
  return authorizationEndpointHref;
}

export default (googleOpenidConfig, googleJwks) => {
  const providers = {
    local: {
      authorization_endpoint: 'http://localhost:3000/dialog/auth',
      token_endpoint: 'http://localhost:3000/oauth/token',
      userinfo_endpoint: 'http://localhost:3000/api/userinfo',
      scope: 'openid',
      clientId: 'abc123',
      clientSecret: 'secret1',
      redirectUri: 'http://localhost:3001/cb',
    },
    google: {
      authorization_endpoint: googleOpenidConfig.authorization_endpoint,
      token_endpoint: googleOpenidConfig.token_endpoint,
      userinfo_endpoint: googleOpenidConfig.userinfo_endpoint,
      jwks_uri: googleOpenidConfig.jwks_uri,
      scope: 'openid profile email',
      clientId: config.GOOGLE_CLIENT_ID,
      clientSecret: config.GOOGLE_CLIENT_SECRET,
      redirectUri: 'http://localhost:3001/cb?provider=google',
      jwks: googleJwks,
    },
  };

  log('Providers', providers);

  return {
    index(req, res) {
      const state = '';
      const localAuthorizationCodeFlowHref = getAuthorizationEndpointHref('code', providers.local, state);
      const googleAuthorizationCodeFlowHref = getAuthorizationEndpointHref('code', providers.google, state);
      const googleImplicitFlowHref = getAuthorizationEndpointHref('token id_token', providers.google, state, uuid.v4());

      res.render('index', {
        localAuthorizationCodeFlowHref,
        googleAuthorizationCodeFlowHref,
        googleImplicitFlowHref,
      });
    },

    cb(req, res, next) {
      const provider = providers[req.query.provider || 'local'];
      const authorizationCode = req.query.code;
      authorisationCodeFlow(
        provider.token_endpoint,
        provider.clientId,
        provider.clientSecret,
        provider.redirectUri,
        authorizationCode,
        provider.userinfo_endpoint,
        provider.jwks,
        (err, userinfoClaims, idToken) => {
          if (err) return next(err);

          res.render('cb', {
            err,
            userinfoClaims: JSON.stringify(userinfoClaims, null, 2),
            idToken: JSON.stringify(idToken, null, 2),
          });
        });
    },
  };
};
