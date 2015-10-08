const tokens = {};

export default {
  find: (key, cb) => cb(null, tokens[key]),

  save: (token, userID, clientID, cb) => {
    tokens[token] = {userID: userID, clientID: clientID};
    return cb();
  },
};
