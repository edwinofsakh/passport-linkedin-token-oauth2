/**
 * Module dependencies.
 */
const util = require('util');
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
const InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `LinkedinTokenStrategy` constructor.
 *
 * The Linkedin authentication strategy authenticates requests by delegating to
 * Linkedin using the OAuth 2.0 protocol.
 *
 * And accepts only access_tokens. Specialy designed for client-side flow (implicit grant flow)
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Linkedin application's App ID
 *   - `clientSecret`  your Linkedin application's App Secret
 *
 * Examples:
 *
 *     passport.use(new LinkedinTokenStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function LinkedinTokenStrategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://www.linkedin.com';
  options.tokenURL = options.tokenURL || 'https://www.linkedin.com/uas/oauth2/accessToken';
  options.scopeSeparator = options.scopeSeparator || ',';

  this._passReqToCallback = options.passReqToCallback;

  OAuth2Strategy.call(this, options, verify);
  this.profileUrl = options.profileURL || 'https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))';
  this.emailUrl = options.emailURL || 'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))';
  this.name = 'linkedin-token';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(LinkedinTokenStrategy, OAuth2Strategy);

/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @param options
 * @api protected
 */
LinkedinTokenStrategy.prototype.authenticate = function (req, options) {
  options = options || {};
  let self = this;

  if (req.query && req.query.error) {
    return this.fail();
  }

  // req.body may not be present, but token may be present in querystring
  let accessToken, refreshToken;
  if (req.body) {
    accessToken = req.body.access_token;
    refreshToken = req.body.refresh_token;
  }

  accessToken = accessToken || req.query.access_token || req.headers.access_token;
  refreshToken = refreshToken || req.query.refresh_token || req.headers.refresh_token;

  if (!accessToken) {
    return this.fail();
  }

  self._loadUserProfile(accessToken, function (err, profile) {
    if (err) {
      return self.fail(err);
    }

    function verified(err, user, info) {
      if (err) {
        return self.error(err);
      } else if (!user) {
        return self.fail(info);
      } else {
        self.success(user, info);
      }
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

LinkedinTokenStrategy.prototype.authorizationParams = function (options) {

  let params = {};

  // LinkedIn requires state parameter. It will return an error if not set.
  if (options.state) {
    params['state'] = options.state;
  }
  return params;
};

/**
 * Retrieve user profile from Linkedin.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `Linkedin`
 *   - `id`               the user's Linkedin ID
 *   - `username`         the user's Linkedin username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *   - `name.middleName`  the user's middle name
 *   - `gender`           the user's gender: `male` or `female`
 *   - `profileUrl`       the URL of the profile for the user on Linkedin
 *   - `emails`           the proxied or contact email address granted by the user
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
LinkedinTokenStrategy.prototype.userProfile = function (accessToken, done) {

  let that = this;
  // LinkedIn uses a custom name for the access_token parameter
  that._oauth2.setAccessTokenName("oauth2_access_token");

  that._oauth2.get(that.profileUrl, accessToken, function (profileErr, profileBody, profileRes) {
    void(profileRes);
    if (profileErr) {
      return done(new InternalOAuthError('failed to fetch user profile', profileErr));
    }

    that._oauth2.get(that.emailUrl, accessToken, function (emailErr, emailBody, emailRes) {
      void(emailRes);
      if (emailErr) {
        return done(new InternalOAuthError('failed to fetch user email', emailErr));
      }

      try {
        /** @type {linkedinUserProfile} */
        let profileJson = JSON.parse(profileBody);
        /** @type {linkedinUserEmail} */
        let emailJson = JSON.parse(emailBody);

        let profile = {provider: 'linkedin'};

        profile.id = profileJson.id;

        profile.name = {
          familyName: getLocalizedName(profileJson.lastName),
          givenName: getLocalizedName(profileJson.firstName)
        };

        profile.displayName = profile.name.givenName + ' ' + profile.name.familyName;

        addEmails(profile, emailJson);
        addPhotos(profile, profileJson);

        profile._raw = profileBody;
        profile._json = profileJson;

        done(null, profile);
      } catch (e) {
        done(e);
      }
    });
  });
};

/**
 * @typedef {object} linkedinUserEmail
 * @property {string} handle
 * @property {object} handle~
 * @property {string} handle~.emailAddress
 */

/**
 * @typedef {object} linkedinUserProfile
 * @property {string} id
 * @property {linkedinLocalizedProperty} firstName
 * @property {linkedinLocalizedProperty} lastName
 * @property {object} profilePicture
 * @property {string} profilePicture.displayImage
 */

/**
 * @typedef {object} linkedinLocalizedProperty
 * @property {object} localized
 * @property {object} preferredLocale
 * @property {string} preferredLocale.language
 * @property {string} preferredLocale.country
 */

// let example = {
//   "id": "REDACTED",
//   "firstName": {
//     "localized": {
//       "en_US": "Tina"
//     },
//     "preferredLocale": {
//       "country": "US",
//       "language": "en"
//     }
//   },
//   "lastName": {
//     "localized": {
//       "en_US": "Belcher"
//     },
//     "preferredLocale": {
//       "country": "US",
//       "language": "en"
//     }
//   },
//   "profilePicture": {
//     "displayImage": "urn:li:digitalmediaAsset:B54328XZFfe2134zTyq"
//   }
// };

// let example = {
//   "handle": "urn:li:emailAddress:3775708763",
//   "handle~": {
//     "emailAddress": "hsimpson@linkedin.com"
//   }
// };

/**
 *
 * @param {linkedinLocalizedProperty}name
 * @return {string}
 */
function getLocalizedName(name) {
  return name.localized[name.preferredLocale.language + '_' + name.preferredLocale.country];
}

function addEmails(profile, emailJson) {
  if (emailJson.elements) {
    profile.emails = emailJson.elements.reduce(function (memo, el) {
      if (el['handle~'] && el['handle~'].emailAddress) {
        memo.push({value: el['handle~'].emailAddress});
      }

      return memo;
    }, []);
  }
}

function addPhotos(profile, profileJson) {
  if (
    profileJson.profilePicture &&
    profileJson.profilePicture['displayImage~'] &&
    profileJson.profilePicture['displayImage~'].elements &&
    profileJson.profilePicture['displayImage~'].elements.length > 0
  ) {
    profile.photos = profileJson.profilePicture['displayImage~'].elements.reduce(function (memo, el) {
      if (el && el.identifiers && el.identifiers.length > 0) {
        memo.push({value: el.identifiers[0].identifier}); // Keep the first pic for now
      }

      return memo;
    }, []);
  }
}

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
LinkedinTokenStrategy.prototype._loadUserProfile = function (accessToken, done) {
  let self = this;

  function loadIt() {
    return self.userProfile(accessToken, done);
  }

  function skipIt() {
    return done(null);
  }

  if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function (err, skip) {
      if (err) {
        return done(err);
      } else if (!skip) {
        return loadIt();
      } else {
        return skipIt();
      }
    });
  } else {
    let skip = (typeof this._skipUserProfile === 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) {
      return loadIt();
    } else {
      return skipIt();
    }
  }
};

/**
 * Expose `LinkedinTokenStrategy`.
 */
module.exports = LinkedinTokenStrategy;
