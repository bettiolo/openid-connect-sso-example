const codes = {};

export default {
  find: (code, cb) => cb(null, codes[code]),

  save: (code, clientId, redirectUri, userId, cb) => {
    codes[code] = { clientId, redirectUri, userId };
    return cb();
  },
};
