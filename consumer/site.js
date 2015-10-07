import authorisationCodeFlow from './flows/authorisation-code-flow.js';

exports.index = (req, res) => res.render('index');

exports.cb = (req, res, next) => {
  const authorizationCode = req.query.code;
  authorisationCodeFlow(authorizationCode, (err, userInfoClaims) => {
    if (err) return next(err);

    res.render('cb', {
      err,
      userInfoClaims: JSON.stringify(userInfoClaims, null, 2),
    });
  });
};
