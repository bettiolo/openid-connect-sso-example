import dotenv from 'dotenv';
dotenv.load();

function checkAndLoadEnvironment(name) {
  if (!process.env[name]) {
    throw new Error(name + ' environment variable not set!');
  }
  return process.env[name];
}

export default {
  relayingParty: {
    local: {
      issuer: 'http://localhost:3000',
      scope: 'openid',
      clientId: 'abc123',
      clientSecret: 'secret1',
      redirectUri: 'http://localhost:3001/cb?provider=local',
    },
    google: {
      scope: 'openid profile email',
      clientId: checkAndLoadEnvironment('GOOGLE_CLIENT_ID'),
      clientSecret: checkAndLoadEnvironment('GOOGLE_CLIENT_SECRET'),
      redirectUri: 'http://localhost:3001/cb?provider=google',
    },
  },
};
