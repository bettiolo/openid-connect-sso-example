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
};
