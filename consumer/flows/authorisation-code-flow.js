import request from 'request';
import debug from 'debug';
const log = debug('app:authorisation-code-flow');

function tokenRequest(tokenRequestEndpoint, clientId, clientSecret, redirectUri, authorizationCode, cb) {
  // Requesting http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
  const tokenRequestOptions = {
    uri: tokenRequestEndpoint,
    method: 'POST',
    form: {
      client_id: clientId,
      client_secret: clientSecret,
      code: authorizationCode,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    },
  };
  request(tokenRequestOptions, (err, res, body) => {
    if (err) return cb(err);
    if (res.statusCode !== 200) {
      return cb(new Error(body));
    }
    log('Token response', body);

    const accessToken = JSON.parse(body).access_token;
    cb(null, accessToken);
  });
}

function userInfoRequest(userInfoEndpoint, accessToken, cb) {
  // Requesting http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
  const userInfoRequestOptions = {
    uri: userInfoEndpoint,
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  };
  request(userInfoRequestOptions, (err, res, body) => {
    if (err) return cb(err);
    if (res.statusCode !== 200) {
      return cb(new Error(body));
    }
    log('UserInfo response', body);

    const userInfoClaims = JSON.parse(body);
    cb(null, userInfoClaims);
  });
}

export default (authorizationCode, cb) => {
  tokenRequest(
    'http://localhost:3000/oauth/token',
    'abc123', 'ssh-secret',
    'http://localhost:3001/cb',
    authorizationCode,
    (tokenRequestErr, accessToken) => {
      if (tokenRequestErr) return cb(tokenRequestErr);

      userInfoRequest(
        'http://localhost:3000/api/userinfo',
        accessToken, (userInfoRequestErr, userInfoClaims) => {
          if (userInfoRequestErr) return cb(userInfoRequestErr);

          cb(null, userInfoClaims);
        });
    });
};
