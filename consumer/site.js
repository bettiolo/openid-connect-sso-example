import debug from 'debug';
import uuid from 'node-uuid';
import config from './config';
import authorisationCodeFlow from './flows/authorisation-code-flow';

const log = debug('app:site');

function getAuthorizationEndpointHref(responseType, rpConfig, opConfig, state, nonce) {
  let authorizationEndpointHref = `${opConfig.authorization_endpoint}` +
    `?response_type=${encodeURIComponent(responseType)}` +
    `&scope=${encodeURIComponent(rpConfig.scope)}` +
    `&client_id=${encodeURIComponent(rpConfig.clientId)}` +
    `&redirect_uri=${encodeURIComponent(rpConfig.redirectUri)}` +
    `&state=${encodeURIComponent(state)}` + // Should be checked server side to match the session / CSRF protection
    `&display=page`;
  if (nonce) {
    // Required only for Implicit Flow only
    authorizationEndpointHref += `&nonce=${encodeURIComponent(nonce)}`;
  }
  return authorizationEndpointHref;
}

export default (openidProviders) => {
  log('OpenID Providers', openidProviders);
  return {
    index(req, res) {
      const state = '';
      const localAuthorizationCodeFlowHref =
        getAuthorizationEndpointHref('code', config.relayingParty.local, openidProviders.local.config, state);
      const googleAuthorizationCodeFlowHref =
        getAuthorizationEndpointHref('code', config.relayingParty.google, openidProviders.google.config, state);
      const googleImplicitFlowHref =
        getAuthorizationEndpointHref('token id_token', config.relayingParty.google, openidProviders.google.config, state, uuid.v4());

      res.render('index', {
        localAuthorizationCodeFlowHref,
        googleAuthorizationCodeFlowHref,
        googleImplicitFlowHref,
      });
    },

    cb(req, res, next) {
      const providerName = [req.query.provider || 'local'];
      const rpConfig = config.relayingParty[providerName];
      const op = openidProviders[providerName];
      const authorizationCode = req.query.code;
      authorisationCodeFlow(
        op.config.token_endpoint,
        rpConfig.clientId,
        rpConfig.clientSecret,
        rpConfig.redirectUri,
        authorizationCode,
        op.config.userinfo_endpoint,
        op.jwks,
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
