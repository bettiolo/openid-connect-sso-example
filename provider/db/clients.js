const clients = [
    { clientId: 'abc123', name: 'Example App', clientSecret: 'secret1' },
    { clientId: 'xyz123', name: 'Example App 2', clientSecret: 'secret2' },
];

export default {
  findByClientId: (clientId, cb) => {
    for (const client of clients) {
      if (client.clientId === clientId) {
        return cb(null, client);
      }
    }
    return cb(null, null);
  },
};
