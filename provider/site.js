import passport from 'passport';
import login from 'connect-ensure-login';

export default {
  index(req, res) {
    res.send('OAuth 2.0 Server');
  },

  loginForm(req, res) {
    res.render('login');
  },

  login: passport.authenticate('local', { successReturnToOrRedirect: '/', failureRedirect: '/login' }),

  logout(req, res) {
    req.logout();
    res.redirect('/');
  },

  account: [
    login.ensureLoggedIn(),
    (req, res) => res.render('account', { user: req.user }),
  ],

  // user decision endpoint
  //
  // `decision` middleware processes a user's decision to allow or deny access
  // requested by a client application.  Based on the grant type requested by the
  // client, the above grant middleware configured above will be invoked to send
  // a response.
  decision(server) {
    return [
      login.ensureLoggedIn(),
      server.decision(),
    ];
  },
};
