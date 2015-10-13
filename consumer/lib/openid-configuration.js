import request from 'request';
import debug from 'debug';
const log = debug('app:openid-configuration');

const autodiscoveryEndpoints = {
  google: 'https://accounts.google.com/.well-known/openid-configuration',
  microsoft: 'https://login.windows.net/common/.well-known/openid-configuration',
  salesforce: 'https://login.windows.net/common/.well-known/openid-configuration',
};

const configCache = {};
const jwksCache = {};

function getOpenidConfig(autodiscoveryEndpoint, cb) {
  request.get({ url: autodiscoveryEndpoint, json: true }, (err, res, openidConfig) => cb(err, openidConfig));
}

function getJwks(jwksUri, cb) {
  request.get({ url: jwksUri, json: true }, (err, res, jwks) => cb(err, jwks));
}

export default {
  get(provider, cb) {
    if (configCache[provider]) {
      log('Cache HIT', 'Provider:', provider);

      return cb(null, configCache[provider]);
    }

    log('Cache MISS', 'Provider:', provider);
    getOpenidConfig(autodiscoveryEndpoints[provider], (openidConfigErr, openidConfig) => {
      if (openidConfigErr) { return cb(openidConfigErr); }

      log('OpenID Config', 'Provider:', provider, openidConfig);
      getJwks(openidConfig.jwks_uri, (jwksErr, jwks) => {
        if (jwksErr) { return cb(jwksErr); }

        log('JWKS', 'Provider:', provider, jwks);
        configCache[provider] = openidConfig;
        jwksCache[provider] = jwks.keys;

        cb(null, openidConfig, jwks.keys);
      });
    });
  },

  getGoogle(cb) {
    this.get('google', cb);
  },
};
