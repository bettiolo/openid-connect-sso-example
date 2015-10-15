import request from 'request';
import debug from 'debug';

const log = debug('app:openid-configuration');

const autodiscoveryEndpoints = {
  google: {
    issuer: 'accounts.google.com',
    prefix: '',
  },
  microsoft: {
    issuer: 'login.windows.net',
    prefix: 'common/',
  },
  salesforce: {
    issuer: 'login.salesforce.com',
    prefix: '',
  },
};

const configCache = {};

function getOpenidConfig(issuer, prefix, cb) {
  const autodiscoveryEndpoint = `https://${issuer}${prefix || ''}/.well-known/openid-configuration`;
  log('GET', 'Issuer:', issuer, autodiscoveryEndpoint);
  request.get({ url: autodiscoveryEndpoint, json: true }, (err, res, openidConfig) => cb(err, openidConfig));
}

export default {
  get(issuer, prefix, cb) {
    if (configCache[issuer]) {
      log('Cache HIT', 'Issuer:', issuer);

      return cb(null, configCache[issuer]);
    }

    log('Cache MISS', 'Issuer:', issuer);
    getOpenidConfig(issuer, prefix, (openidConfigErr, openidConfig) => {
      if (openidConfigErr) { return cb(openidConfigErr); }

      log('OpenID Config', 'Issuer:', issuer, openidConfig);
      configCache[issuer] = openidConfig;
      cb(null, configCache[issuer]);
    });
  },
  getByIdentityProvider(provider, cb) {
    const { issuer, suffix } = autodiscoveryEndpoints[provider];
    this.get(issuer, suffix, cb);
  },
};
