import request from 'request';
import debug from 'debug';
import jwt from 'jsonwebtoken';
const log = debug('app:authorisation-code-flow');

function tokenRequest(tokenEndpoint, clientId, clientSecret, redirectUri, authorizationCode, jwks, cb) {
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
    json: true,
  };
  request(tokenRequestOptions, (err, res, tokenResponse) => {
    if (err) return cb(err);
    if (res.statusCode !== 200) {
      return cb(new Error(tokenResponse));
    }
    // TODO: Check errors in WWW-Authenticate header

    log('Token response', tokenResponse);
    const accessToken = tokenResponse.access_token;
    const completeIdToken = jwt.decode(tokenResponse.id_token, { complete: true });

    log('Complete JWT ID Token', completeIdToken);
    jwks.getPem(completeIdToken.header.kid, (pemErr, pem) => {
      if (pemErr) return cb(pemErr);

      log('PEM', pem);
      // TODO: Specify algorithm?
      jwt.verify(tokenResponse.id_token, pem, (jwtErr, validatedIdToken) => {
        if (jwtErr) return cb(jwtErr);
        if (!validatedIdToken) { return cb(new Error('JWT ID Token validation failed')); }

        log('JWT ID Token valid', validatedIdToken);
        cb(null, accessToken, validatedIdToken);
      });
    });
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
    json: true,
  };
  request(userinfoRequestOptions, (err, res, userinfoResponse) => {
    if (err) return cb(err);
    if (res.statusCode !== 200) {
      return cb(new Error(userinfoResponse));
    }
    // TODO: Check errors in WWW-Authenticate header

    log('UserInfo response', userinfoResponse);
    cb(null, userinfoResponse);
  });
}

export default (tokenEndpoint, clientId, clientSecret, redirectUri, authorizationCode, userinfoEndpoint, jwks, cb) => {
  tokenRequest(tokenEndpoint, clientId, clientSecret, redirectUri, authorizationCode, jwks,
    (tokenRequestErr, accessToken, idToken) => {
      if (tokenRequestErr) return cb(tokenRequestErr);

      userinfoRequest(userinfoEndpoint, accessToken,
        (userinfoRequestErr, userinfoResponse) => {
          if (userinfoRequestErr) return cb(userinfoRequestErr);

          cb(null, userinfoResponse, idToken);
        });
    });
};
