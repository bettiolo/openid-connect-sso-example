const tokens = {};

export default {
  find: (key, cb) => cb(null, tokens[key]),

  save: (token, userId, clientId, cb) => {
    tokens[token] = { userId, clientId };
    return cb();
  },
};
