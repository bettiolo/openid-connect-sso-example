import request from 'request';
import debug from 'debug';

const log = debug('app:openid-configuration');

const autodiscoveryEndpoints = {
  google: 'https://accounts.google.com/.well-known/openid-configuration',
  microsoft: 'https://login.windows.net/common/.well-known/openid-configuration',
  salesforce: 'https://login.salesforce.com/.well-known/openid-configuration',
};

const configCache = {};

function getOpenidConfig(autodiscoveryEndpoint, cb) {
  request.get({ url: autodiscoveryEndpoint, json: true }, (err, res, openidConfig) => cb(err, openidConfig));
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
      configCache[provider] = openidConfig;
      cb(null, configCache[provider]);
    });
  },

  getGoogle(cb) {
    this.get('google', cb);
  },
};
