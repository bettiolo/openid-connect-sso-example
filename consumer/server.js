import express from 'express';
import path from 'path';
import errorhandler from 'errorhandler';
import debug from 'debug';
const log = debug('app');

import site from './site.js';

const app = express();
app.use(errorhandler());

app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');

app.get('/', site.index);
app.get('/cb', site.cb);

app.set('port', process.env.PORT || 3001);
app.listen(app.get('port'), () => log(process.env.npm_package_name + ' CONSUMER listening on port ' + app.get('port')));
