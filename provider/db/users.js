const users = [
  {id: '1', username: 'bob', password: 'secret', name: 'Bob Smith'},
  {id: '2', username: 'joe', password: 'password', name: 'Joe Davis'},
];

export default {
  find: (id, cb) => {
    for (let i = 0, len = users.length; i < len; i++) {
      const user = users[i];
      if (user.id === id) {
        return cb(null, user);
      }
    }
    return cb(null, null);
  },

  findByUsername: (username, cb) => {
    for (let i = 0, len = users.length; i < len; i++) {
      const user = users[i];
      if (user.username === username) {
        return cb(null, user);
      }
    }
    return cb(null, null);
  },
};
