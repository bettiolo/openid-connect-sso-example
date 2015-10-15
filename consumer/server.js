import express from 'express';
import path from 'path';
import errorhandler from 'errorhandler';
import debug from 'debug';
const log = debug('app');

import config from './config';
import opConfig from './lib/openid-provider-config';
import jwks from './lib/jwks';
import site from './site';

const app = express();
app.use(errorhandler());

app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');

const openIdProviders = {};
opConfig.getByName('google', (googleOpErr, googleOpConfig) => {
  if (googleOpErr) { throw googleOpErr; }

  openIdProviders.google = {
    config: googleOpConfig,
    jwks: jwks(googleOpConfig.jwks_uri),
  };

  const localIssuer = config.relayingParty.local.issuer;
  opConfig.get(localIssuer, (localOpErr, localOpConfig) => {
    if (localOpErr) { throw localOpErr; }

    openIdProviders.local = {
      config: localOpConfig,
      jwks: jwks(localOpConfig.jwks_uri),
    };

    const { index, cb } = site(openIdProviders);
    app.get('/', index);
    app.get('/cb', cb);
  });
});

app.set('port', process.env.PORT || 3001);
app.listen(app.get('port'), () => log(process.env.npm_package_name + ' CONSUMER listening on port ' + app.get('port')));
