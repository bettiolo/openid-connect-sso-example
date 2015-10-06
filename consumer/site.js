import request from 'request';
import debug from 'debug';

const log = debug('app:site');
const logError = debug('app:site:err');

exports.index = (req, res) => res.render('index');

exports.loginRedirect = (req, res) => {
  const tokenOpts = {
    form: {
      client_id: 'abc123',
      client_secret: 'ssh-secret',
      grant_type: 'authorization_code',
      code: req.query.code,
      redirect_uri: 'http://localhost:3001/login-redirect',
    },
  };
  request.post(`http://localhost:3000/oauth/token`, tokenOpts, (oauthErr, oauthRes, oauthBody) => {
    let parsedBody = oauthBody;
    let bearerToken;

    if (oauthErr) {
      logError(oauthErr);
    }
    if (!oauthErr && oauthRes.statusCode === 200) {
      log(oauthBody);
      parsedBody = JSON.parse(oauthBody);
      bearerToken = parsedBody.access_token;
      parsedBody =  JSON.stringify(parsedBody, null, 2);
    }

    const userinfoOpts = {
      headers: {'Authorization': `Bearer ${bearerToken}`},
    };
    request(`http://localhost:3000/api/userinfo`, userinfoOpts, (userinfoErr, userinfoRes, userinfoBody) => {
      if (userinfoErr) {
        logError(userinfoErr);
      }

      res.render('login-redirect', {
        oauthErr,
        oauthRes: JSON.stringify(oauthRes, null, 2),
        oauthBody: parsedBody,
        userinfoErr,
        userinfoRes:  JSON.stringify(userinfoRes, null, 2),
        userinfoBody,
      });
    });
  });
};
