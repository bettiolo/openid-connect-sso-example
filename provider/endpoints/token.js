import crypto from 'crypto';
const tokenBytes = 256;

export default {
  create(cb) {
    crypto.randomBytes(tokenBytes, (ex, buf) => {
      cb(null, buf.toString('hex'));
    });
  },
};
