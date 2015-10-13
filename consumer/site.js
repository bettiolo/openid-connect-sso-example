import uuid from 'node-uuid';
import authorisationCodeFlow from './flows/authorisation-code-flow';
import config from './config';

// Google autodiscovery config: https://accounts.google.com/.well-known/openid-configuration
// authorization_endpoint, token_endpoint, userinfo_endpoint
// response_types_supported
// scopes_supported
// jwks_uri - Keys to validate the JWT singnature

const providers = {
  local: {
    authorizeEndpoint: 'http://localhost:3000/dialog/authorize',
    tokenEndpoint: 'http://localhost:3000/oauth/token',
    userinfoEndpoint: 'http://localhost:3000/api/userinfo',
    scope: 'openid',
    clientId: 'abc123',
    clientSecret: 'secret1',
    redirectUri: 'http://localhost:3001/cb',
  },
  google: {
    authorizeEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://www.googleapis.com/oauth2/v4/token',
    userinfoEndpoint: 'https://www.googleapis.com/oauth2/v3/userinfo',
    scope: 'openid profile email',
    clientId: config.GOOGLE_CLIENT_ID,
    clientSecret: config.GOOGLE_CLIENT_SECRET,
    redirectUri: 'http://localhost:3001/cb?provider=google',
  },
};

function getAuthorizeEndpointHref(responseType, provider, state) {
  return `${provider.authorizeEndpoint}` +
    `?response_type=${encodeURIComponent(responseType)}` +
    `&scope=${encodeURIComponent(provider.scope)}` +
    `&client_id=${encodeURIComponent(provider.clientId)}` +
    `&redirect_uri=${encodeURIComponent(provider.redirectUri)}` +
    `&state=${encodeURIComponent(state)}` +
    `&display=page` +
    `&nonce=${encodeURIComponent(uuid.v4())}`;
}

export default {
  index(req, res) {
    const state = '';
    const localAuthorizationCodeFlowHref = getAuthorizeEndpointHref('code', providers.local, state);
    const googleAuthorizationCodeFlowHref = getAuthorizeEndpointHref('code', providers.google, state);
    const googleImplicitFlowHref = getAuthorizeEndpointHref('id_token token', providers.google, state);

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
      provider.tokenEndpoint,
      provider.clientId,
      provider.clientSecret,
      provider.redirectUri,
      authorizationCode,
      provider.userinfoEndpoint,
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
