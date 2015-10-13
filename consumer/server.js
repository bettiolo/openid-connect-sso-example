import express from 'express';
import path from 'path';
import errorhandler from 'errorhandler';
import debug from 'debug';
const log = debug('app');

import openidConfig from './lib/openid-configuration';
import site from './site';

const app = express();
app.use(errorhandler());

app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');

openidConfig.getGoogle((err, googleOpenidConfig, googleJwks) => {
  if (err) { throw err; }

  const { index, cb } = site(googleOpenidConfig, googleJwks);
  app.get('/', index);
  app.get('/cb', cb);
});

app.set('port', process.env.PORT || 3001);
app.listen(app.get('port'), () => log(process.env.npm_package_name + ' CONSUMER listening on port ' + app.get('port')));
