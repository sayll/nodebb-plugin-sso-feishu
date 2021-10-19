(function (module) {
  'use strict'
  
  var User = require.main.require('./src/user')
  var db = require.main.require('./src/database')
  var meta = require.main.require('./src/meta')
  var nconf = require.main.require('nconf')
  var async = require.main.require('async')
  var passport = require.main.require('passport')
  var FeishuStrategy = require('passport-feishu2').Strategy
  
  var winston = require.main.require('winston')
  
  var constants = Object.freeze({
    'name': 'FeiShu',
    'admin': {
      'icon': 'fa-telegram',
      'route': '/plugins/sso-feishu'
    }
  })
  
  var FeiShu = {}
  const domain = nconf.get('url')
  
  FeiShu.getStrategy = function (strategies, callback) {
    meta.settings.get('sso-feishu', function (err, settings) {
      FeiShu.settings = settings
      
      if (!err && settings.id && settings.secret) {
        passport.use(new FeishuStrategy({
            clientID: settings.id,
            clientSecret: settings.secret,
            callbackURL: domain + '/auth/feishu/callback',
            appType: 'web',
            appTicket: function () {
              return new Promise((resolve, reject) => {
                setTimeout(function () {
                  resolve('the-ticket-received-from-feishu-service')
                }, 1000)
              })
            }
          },
          function (token, tokenSecret, profile, done) {
            var email = profile.email
            var pictureUrl = profile.avatar.big || profile.avatar.icon
            var displayName = profile.name
            var userName = profile.name
            FeiShu.login(profile.id, displayName, userName, email, pictureUrl, function (err, user) {
              if (err) return done(err)
              done(null, user)
            })
          }
        ))
        
        strategies.push({
          name: 'feishu',
          url: '/auth/feishu',
          callbackURL: '/auth/feishu/callback',
          icon: constants.admin.icon,
          scope: 'user:email'
        })
      }
      
      callback(null, strategies)
    })
  }
  
  FeiShu.appendUserHashWhitelist = function (data, callback) {
    data.whitelist.push('feishuid')
    setImmediate(callback, null, data)
  }
  
  FeiShu.getAssociation = function (data, callback) {
    User.getUserField(data.uid, 'feishuid', function (err, feishuid) {
      if (err) {
        return callback(err, data)
      }
      
      if (feishuid) {
        data.associations.push({
          associated: true,
          name: constants.name,
          icon: constants.admin.icon,
          deauthUrl: domain + '/deauth/feishu',
        })
      } else {
        data.associations.push({
          associated: false,
          url: domain + '/auth/feishu',
          name: constants.name,
          icon: constants.admin.icon
        })
      }
      
      callback(null, data)
    })
  }
  
  FeiShu.login = function (feishuID, displayName, username, email, pictureUrl, callback) {
    if (!email) {
      email = username + '@users.noreply.feishu.com'
    }
  
    FeiShu.getUidByFeiShuID(feishuID, function (err, uid) {
      if (err) {
        return callback(err)
      }
      
      if (uid) {
        // Existing User
        callback(null, {
          uid: uid
        })
      } else {
        // New User
        var success = function (uid) {
          function checkEmail(next) {
            if (FeiShu.settings.needToVerifyEmail === 'on') {
              return next()
            }
            User.email.confirmByUid(uid, next)
          }
          
          function mergeUserData(next) {
            async.waterfall([
              async.apply(User.getUserFields, uid, ['picture', 'firstName', 'lastName', 'fullname']),
              function (info, next) {
                if (!info.picture && pictureUrl) { // set profile picture
                  User.setUserField(uid, 'uploadedpicture', pictureUrl)
                  User.setUserField(uid, 'picture', pictureUrl)
                }
                
                if (!info.fullname && displayName) {
                  User.setUserField(uid, 'fullname', displayName)
                }
                next()
              }
            ], next)
          }
          
          // trust the email.
          async.series([
            async.apply(User.setUserField, uid, 'feishuid', feishuID),
            async.apply(db.setObjectField, 'feishuid:uid', feishuID, uid),
            checkEmail,
            mergeUserData
          ], function (err) {
            callback(err, {
              uid: uid
            })
          })
        }
        
        User.getUidByEmail(email, function (err, uid) {
          if (!uid) {
            // Abort user creation if registration via SSO is restricted
            if (FeiShu.settings.disableRegistration === 'on') {
              return callback(new Error('[[error:sso-registration-disabled, FeiShu]]'))
            }
            
            User.create({ username: username, email: email }, function (err, uid) {
              if (err !== null) {
                callback(err)
              } else {
                success(uid)
              }
            })
          } else {
            success(uid) // Existing account -- merge
          }
        })
      }
    })
  }
  
  FeiShu.getUidByFeiShuID = function (feishuID, callback) {
    db.getObjectField('feishuid:uid', feishuID, function (err, uid) {
      if (err) {
        callback(err)
      } else {
        callback(null, uid)
      }
    })
  }
  
  FeiShu.addMenuItem = function (custom_header, callback) {
    custom_header.authentication.push({
      'route': constants.admin.route,
      'icon': constants.admin.icon,
      'name': constants.name
    })
    
    callback(null, custom_header)
  }
  
  FeiShu.init = function (data, callback) {
    var hostHelpers = require.main.require('./src/routes/helpers')
    
    function renderAdmin(req, res) {
      res.render('admin/plugins/sso-feishu', {
        callbackURL: domain + '/auth/feishu/callback'
      })
    }
    
    data.router.get('/admin/plugins/sso-feishu', data.middleware.admin.buildHeader, renderAdmin)
    data.router.get('/api/admin/plugins/sso-feishu', renderAdmin)
    
    hostHelpers.setupPageRoute(data.router, '/deauth/feishu', data.middleware, [data.middleware.requireUser], function (req, res) {
      res.render('plugins/sso-feishu/deauth', {
        service: 'FeiShu',
      })
    })
    data.router.post('/deauth/feishu', [data.middleware.requireUser, data.middleware.applyCSRF], function (req, res, next) {
      FeiShu.deleteUserData({
        uid: req.user.uid,
      }, function (err) {
        if (err) {
          return next(err)
        }
        
        res.redirect(nconf.get('relative_path') + '/me/edit')
      })
    })
    
    callback()
  }
  
  FeiShu.deleteUserData = function (data, callback) {
    var uid = data.uid
    
    async.waterfall([
      async.apply(User.getUserField, uid, 'feishuid'),
      function (oAuthIdToDelete, next) {
        db.deleteObjectField('feishuid:uid', oAuthIdToDelete, next)
      },
      async.apply(db.deleteObjectField, 'user:' + uid, 'feishuid'),
    ], function (err) {
      if (err) {
        winston.error('[sso-feishu] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err)
        return callback(err)
      }
      callback(null, uid)
    })
  }
  
  module.exports = FeiShu
}(module))
