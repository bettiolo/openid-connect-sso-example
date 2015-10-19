import crypto from 'crypto';
const tokenBytes = 256;

export function createTokenSha(cb) {
  crypto.randomBytes(tokenBytes, (ex, buf) => {
    if (ex) { return cb(ex); }

    const token = crypto
      .createHash('sha1')
      .update(buf)
      .digest('hex');

    cb(false, token);
  });
}

export function createToken(cb) {
  crypto.randomBytes(tokenBytes, (ex, buf) => {
    cb(null, buf.toString('hex'));
  });
}

export default {
  createTokenSha,
  createToken,
};
