import passport from 'passport';

// Implementation of http://openid.net/specs/openid-connect-core-1_0.html#UserInfo

export default [
  passport.authenticate('bearer', {session: false}),
  (req, res) => {
    // req.authInfo is set using the `info` argument supplied by
    // `BearerStrategy`. It is typically used to indicate scope of the token,
    // and used in access control checks. For illustrative purposes, this
    // example simply returns the scope in the response.
    res.json({user_id: req.user.id, name: req.user.name, scope: req.authInfo.scope});
  },
];
