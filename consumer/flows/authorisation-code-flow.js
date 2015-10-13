import request from 'request';
import debug from 'debug';
import jwt from 'jsonwebtoken';
const log = debug('app:authorisation-code-flow');

function tokenRequest(tokenEndpoint, clientId, clientSecret, redirectUri, authorizationCode, cb) {
  // Implementing http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
  const tokenRequestOptions = {
    uri: tokenEndpoint,
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

    const parsedBody = JSON.parse(body);
    const accessToken = parsedBody.access_token;
    const idToken = jwt.decode(parsedBody.id_token);
    cb(null, accessToken, idToken);
  });
}

function userinfoRequest(userinfoEndpoint, accessToken, cb) {
  // Implementing http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
  const userinfoRequestOptions = {
    uri: userinfoEndpoint,
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  };
  request(userinfoRequestOptions, (err, res, body) => {
    if (err) return cb(err);
    if (res.statusCode !== 200) {
      return cb(new Error(body));
    }
    log('UserInfo response', body);

    const userinfoClaims = JSON.parse(body);
    cb(null, userinfoClaims);
  });
}

export default (tokenEndpoint, clientId, clientSecret, redirectUri, authorizationCode, userinfoEndpoint, cb) => {
  tokenRequest(tokenEndpoint, clientId, clientSecret, redirectUri, authorizationCode,
    (tokenRequestErr, accessToken, idToken) => {
      if (tokenRequestErr) return cb(tokenRequestErr);

      userinfoRequest(userinfoEndpoint, accessToken,
        (userinfoRequestErr, userinfoClaims) => {
          if (userinfoRequestErr) return cb(userinfoRequestErr);

          cb(null, userinfoClaims, idToken);
        });
    });
};
