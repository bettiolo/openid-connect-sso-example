import request from 'request';
import debug from 'debug';

const log = debug('app:openid-configuration');

const issuers = {
  google: 'https://accounts.google.com',
  microsoft: 'https://login.windows.net/common',
  salesforce: 'https://login.salesforce.com',
};

const configCache = {};

function getOpenidConfig(issuer, cb) {
  const autodiscoveryEndpoint = `${issuer}/.well-known/openid-configuration`;
  log('GET', 'Issuer:', issuer, autodiscoveryEndpoint);
  request.get({ url: autodiscoveryEndpoint, json: true }, (err, res, openidConfig) => cb(err, openidConfig));
}

export default {
  get(issuer, cb) {
    if (configCache[issuer]) {
      log('Cache HIT', 'Issuer:', issuer);

      return cb(null, configCache[issuer]);
    }

    log('Cache MISS', 'Issuer:', issuer);
    getOpenidConfig(issuer, (openidConfigErr, openidConfig) => {
      if (openidConfigErr) { return cb(openidConfigErr); }

      log('OpenID Config', 'Issuer:', issuer, openidConfig);
      configCache[issuer] = openidConfig;
      cb(null, configCache[issuer]);
    });
  },
  getByName(provider, cb) {
    this.get(issuers[provider], cb);
  },
};
