import dotenv from 'dotenv';
dotenv.load();

function checkAndLoadEnvironment(name) {
  if (!process.env[name]) {
    throw new Error(name + ' environment variable not set!');
  }
  return process.env[name];
}

export default {
  GOOGLE_CLIENT_ID: checkAndLoadEnvironment('GOOGLE_CLIENT_ID'),
  GOOGLE_CLIENT_SECRET: checkAndLoadEnvironment('GOOGLE_CLIENT_SECRET'),
};
