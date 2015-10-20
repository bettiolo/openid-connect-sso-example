import debug from 'debug';
import getPem from 'rsa-pem-from-mod-exp';
import request from 'request';

const log = debug('app:jwks');
const logError = debug('app:jwks:error');

let jwksCache = { }; // TODO: jwksCache TTL should respect HTTP cache headers

function getJwks(jwksUri, cb) {
  if (!jwksCache[jwksUri]) {
    log('Cache MISS', jwksUri);
    request.get({ url: jwksUri, json: true }, (err, res, jwks) => {
      if (err) {
        logError(err);
        return cb(err);
      }

      log('JWKS', jwks);
      jwksCache[jwksUri] = jwks.keys;
      return cb(null, jwksCache[jwksUri]);
    });
  } else {
    log('Cache HIT', jwksUri);
    cb(null, jwksCache);
  }
}

export default (jwksUri) => ({
  get(kid, cb) {
    getJwks(jwksUri, (err, jwks) => {
      if (err) { return cb(err); }

      cb(null, jwks.find((jwk) => jwk.kid === kid));
    });
  },

  getPem(kid, cb) {
    this.get(kid, (err, jwk) => {
      if (err) { return cb(err); }

      const { n: modulus, e: exponent } = jwk;
      cb(null, getPem(modulus, exponent));
    });
  },
});
