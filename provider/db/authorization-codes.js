const codes = {};

export default {
  find: (key, cb) => cb(null, codes[key]),

  save: (code, clientID, redirectURI, userID, cb) => {
    codes[code] = { clientID: clientID, redirectURI: redirectURI, userID: userID };
    return cb();
  },
};
