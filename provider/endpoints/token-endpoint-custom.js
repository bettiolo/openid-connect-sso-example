import passport from 'passport';
import clients from '../db/clients';
import authorizationCodes from '../db/authorization-codes';

// Implementation of http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

function generateError(message) {
  // OpenID Connect Core 1.0:  3.1.3.4.  Token Error Response
  // If the Token Request is invalid or unauthorized, the Authorization Server constructs the error response. The
  //   parameters of the Token Error Response are defined as in Section 5.2 of OAuth 2.0 [RFC6749]. The HTTP response
  //   body uses the application/json media type with HTTP response code of 400.

  // TODO: This is not implemented yet.
  return new Error(message);
}

function authenticateClientCredentials(clientId, clientSecret, cb) {
  if (!clientId || !clientSecret) { cb(null, false); }

  clients.findByClientId(clientId, (err, client) => {
    if (err) { return cb(err); }

    if (!client) { return cb(null, false); }
    // TODO: Test db that client.clientId === clientId
    // Authenticate the Client if it was issued Client Credentials [...].
    if (client.clientSecret !== clientSecret) { cb(null, false); }

    cb(null, true);
  });
}

function ensureAuthorizationCodeValid(code, clientId, redirectUri, cb) {
  authorizationCodes.find(code, (err, codeMetadata) => {
    if (err) { return cb(err); }

    // Verify that the Authorization Code is valid.
    if (!codeMetadata) { return cb(null, false); }
    // TODO: Test db that codeMetadata.code === code
    // Ensure the Authorization Code was issued to the authenticated Client.
    if (codeMetadata.clientID !== clientId) { return cb(null, false); }
    // TODO: If possible, verify that the Authorization Code has not been previously used.
    // Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included
    //   in the initial Authorization Request. [...]
    if (codeMetadata.redirectURI !== redirectUri) { return cb(null, false); }
    // TODO: Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request
    //   (so that an ID Token will be returned from the Token Endpoint).

    cb(null, true);
  });
}

function createIdToken(issuer, userId, clientId, cb) {
  // Implements http://openid.net/specs/openid-connect-core-1_0.html#IDToken
  // OpenID Connect Core 1.0:  2.  ID Token

  // The primary extension that OpenID Connect makes to OAuth 2.0 to enable End-Users to be Authenticated
  // is the ID Token data structure. The ID Token is a security token that contains Claims about the
  // Authentication of an End-User by an Authorization Server when using a Client, and potentially other
  // requested Claims. The ID Token is represented as a JSON Web Token (JWT) [JWT].
  //
  // The following Claims are used within the ID Token for all OAuth 2.0 flows used by OpenID Connect:
  //
  //  - iss REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL
  //        using the https scheme that contains scheme, host, and optionally, port number and path components
  //        and no query or fragment components.
  //  - sub REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer
  //        for the End-User, which is intended to be consumed by the Client, e.g., 24400320 or
  //        AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII characters in length. The
  //        sub value is a case sensitive string.
  //  - aud REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 client_id
  //        of the Relying Party as an audience value. It MAY also contain identifiers for other audiences.
  //        In the general case, the aud value is an array of case sensitive strings. In the common special
  //       case when there is one audience, the aud value MAY be a single case sensitive string.
  //  - exp REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
  //        The processing of this parameter requires that the current date/time MUST be before the expiration
  //        date/time listed in the value. Implementers MAY provide for some small leeway, usually no more than
  //        a few minutes, to account for clock skew. Its value is a JSON number representing the number of
  //        seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. See RFC 3339 [RFC3339]
  //        for details regarding date/times in general and UTC in particular.
  //  - iat REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number
  //        of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
  //  - auth_time Time when the End-User authentication occurred. Its value is a JSON number representing
  //        the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time. When a
  //        max_age request is made or when auth_time is requested as an Essential Claim, then this Claim
  //        is REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim semantically corresponds
  //        to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time response parameter.)
  //  - nonce String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
  //        The value is passed through unmodified from the Authentication Request to the ID Token. If present
  //        in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce
  //        parameter sent in the Authentication Request. If present in the Authentication Request,
  //        Authorization Servers MUST include a nonce Claim in the ID Token with the Claim Value being the
  //        nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other
  //        processing on nonce values used. The nonce value is a case sensitive string.
  //  - acr OPTIONAL. Authentication Context Class Reference. String specifying an Authentication Context
  //        Class Reference value that identifies the Authentication Context Class that the authentication
  //        performed satisfied. The value "0" indicates the End-User authentication did not meet the
  //        requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a long-lived browser
  //        cookie, for instance, is one example where the use of "level 0" is appropriate. Authentications
  //        with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value.
  //        (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An absolute URI or
  //        an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value; registered names MUST NOT
  //        be used with a different meaning than that which is registered. Parties using this claim will
  //        need to agree upon the meanings of the values used, which may be context-specific. The acr value
  //        is a case sensitive string.
  //  - amr OPTIONAL. Authentication Methods References. JSON array of strings that are identifiers for
  //        authentication methods used in the authentication. For instance, values might indicate that
  //        both password and OTP authentication methods were used. The definition of particular values to
  //        be used in the amr Claim is beyond the scope of this specification. Parties using this claim
  //        will need to agree upon the meanings of the values used, which may be context-specific. The
  //        amr value is an array of case sensitive strings.
  //  - azp OPTIONAL. Authorized party - the party to which the ID Token was issued. If present, it MUST
  //        contain the OAuth 2.0 Client ID of this party. This Claim is only needed when the ID Token
  //        has a single audience value and that audience is different than the authorized party. It MAY
  //        be included even when the authorized party is the same as the sole audience. The azp value is a
  //        case sensitive string containing a StringOrURI value.
  //
  // ID Tokens MAY contain other Claims. Any Claims used that are not understood MUST be ignored.
  // See Sections 3.1.3.6, 3.3.2.11, 5.1, and 7.4 for additional Claims defined by this specification.
  //
  // ID Tokens MUST be signed using JWS [JWS] and optionally both signed and then encrypted using JWS
  // [JWS] and JWE [JWE] respectively, thereby providing authentication, integrity, non-repudiation, and
  // optionally, confidentiality, per Section 16.14. If the ID Token is encrypted, it MUST be signed then
  // encrypted, with the result being a Nested JWT, as defined in [JWT]. ID Tokens MUST NOT use none as
  // the alg value unless the Response Type used returns no ID Token from the Authorization Endpoint (such
  // as when using the Authorization Code Flow) and the Client explicitly requested the use of none at
  // Registration time.
  //
  // ID Tokens SHOULD NOT use the JWS or JWE x5u, x5c, jku, or jwk Header Parameter fields. Instead,
  // references to keys used are communicated in advance using Discovery and Registration parameters,
  // per Section 10.
}

function createTokenRespone(cb) {
  // Implements http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
  // OpenID Connect Core 1.0:  3.1.3.3.  Successful Token Response
  // ... the Authorization Server returns a successful response that includes an ID Token and an Access Token. The
  //   parameters in the successful response are defined in Section 4.1.4 of OAuth 2.0 [RFC6749].

  // In addition to the response parameters specified by OAuth 2.0, the following parameters MUST be included in the
  //   response: id_token - ID Token value associated with the authenticated session.
  const id_token = '';

  // Implements https://tools.ietf.org/html/rfc6749#section-4.1.4
  // OAuth 2.0:  4.1.4.  Access Token Response
  // If the access token request is valid and authorized, the
  // authorization server issues an access token and optional refresh
  // token as described in Section 5.1.  If the request client
  // authentication failed or is invalid, the authorization server returns
  // an error response as described in Section 5.2.

  // Implements https://tools.ietf.org/html/rfc6749#section-5.1
  // OAuth 2.0:  5.1.  Successful Response
  // The authorization server issues an access token and optional refresh
  // token, and constructs the response by adding the following parameters
  // to the entity-body of the HTTP response with a 200 (OK) status code:

  // REQUIRED.  The access token issued by the authorization server.
  const access_token = '';

  // RECOMMENDED.  The lifetime in seconds of the access token.  For
  // example, the value "3600" denotes that the access token will
  // expire in one hour from the time the response was generated.
  //   If omitted, the authorization server SHOULD provide the
  // expiration time via other means or document the default value.
  const expires_in = 3600;

  // REQUIRED. [...]
  // Implements http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
  // OpenID Connect Core 1.0:  3.1.3.3.  Successful Token Response
  //  The OAuth 2.0 token_type response parameter value MUST be Bearer, as specified in OAuth 2.0 Bearer Token Usage
  //  [RFC6750] [...]. Servers SHOULD support the Bearer Token Type; [...].
  const token_type = 'Bearer';

  // OPTIONAL.  The refresh token, which can be used to obtain new
  //   access tokens using the same authorization grant as described
  // in Section 6.
  // refresh_token

  // OPTIONAL, if identical to the scope requested by the client;
  // otherwise, REQUIRED.  The scope of the access token as
  // described by Section 3.3.
  // scope

  // TODO: [..] The authorization server SHOULD document the size of any value it issues.
}

export default (req, res, next) => {
  const { code, client_id, client_secret, redirect_uri, grant_type } = req.body;

  // Implements http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
  // OpenID Connect Core 1.0:  3.1.3.2.  Token Request Validation
  authenticateClientCredentials(client_id, client_secret, (clientCredentialsErr, clientCredentialsValid) => {
    if (clientCredentialsErr) { return next(clientCredentialsErr); }
    if (!clientCredentialsValid) { return next(generateError('Client credentials invalid')); }

    ensureAuthorizationCodeValid(code, client_id, redirect_uri, (authorizationCodeErr, authorizationCodeValid) => {
      if (authorizationCodeErr) { return next(authorizationCodeErr); }
      if (!authorizationCodeValid) { return next(generateError('Authorization Code invalid')); }

      // Implements http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
      // OpenID Connect Core 1.0:  3.1.3.3.  Successful Token Response
      // After receiving and validating a valid and authorized Token Request from the Client...
      createTokenRespone((err, tokenResponse) => {
        // Implements https://tools.ietf.org/html/rfc6749#section-5.1
        // OAuth 2.0:  5.1.  Successful Response
        // The authorization server issues an access token and optional refresh
        // token, and constructs the response by adding the following parameters
        // to the entity-body of the HTTP response with a 200 (OK) status code:
        res.statusCode = 200;

        // Implements https://tools.ietf.org/html/rfc6749#section-5.1
        // OAuth 2.0:  5.1.  Successful Response
        // The authorization server MUST include the HTTP "Cache-Control"
        // response header field [RFC2616] with a value of "no-store" in any
        // response containing tokens, credentials, or other sensitive
        // information, as well as the "Pragma" response header field [RFC2616]
        // with a value of "no-cache".
        //
        // Implements http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        // OpenID Connect Core 1.0:  3.1.3.3.  Successful Token Response
        // All Token Responses that contain tokens, secrets, or other sensitive information MUST include the following
        // HTTP response header fields and values: Cache-Control: no-store, Pragma: no-cache
        res.set({
          'Cache-Control': 'no-store',
          'Pragma': 'no-cache',
        });

        // Implements https://tools.ietf.org/html/rfc6749#section-5.1
        // OAuth 2.0:  5.1.  Successful Response
        // The parameters are included in the entity-body of the HTTP response
        // using the "application/json" media type as defined by [RFC4627].  The
        // parameters are serialized into a JavaScript Object Notation (JSON)
        // structure by adding each parameter at the highest structure level.
        // Parameter names and string values are included as JSON strings.
        // Numerical values are included as JSON numbers. The order of
        // parameters does not matter and can vary.
        //
        // Implements http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
        // OpenID Connect Core 1.0:  3.1.3.3.  Successful Token Response
        // The response uses the application/json media type.
        res.json(tokenResponse);
      });
    });
  });
};
