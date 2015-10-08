const clients = [
    { id: '1', name: 'Example App', clientId: 'abc123', clientSecret: 'secret1' },
    { id: '2', name: 'Example App 2', clientId: 'xyz123', clientSecret: 'secret2' },
];

export default {
  find: (id, cb) => {
    for (let i = 0, len = clients.length; i < len; i++) {
      const client = clients[i];
      if (client.id === id) {
        return cb(null, client);
      }
    }
    return cb(null, null);
  },

  findByClientId: (clientId, cb) => {
    for (let i = 0, len = clients.length; i < len; i++) {
      const client = clients[i];
      if (client.clientId === clientId) {
        return cb(null, client);
      }
    }
    return cb(null, null);
  },
};
