const codes = {};

export default {
  find: (code, cb) => cb(null, codes[code]),

  save: (code, clientID, redirectURI, userID, cb) => {
    codes[code] = { clientID: clientID, redirectURI: redirectURI, userID: userID };
    return cb();
  },
};
