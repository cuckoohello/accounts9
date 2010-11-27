/* vim: set sw=2 ts=2 nocin si: */

var userbase = require('./userbase-mongo');

exports.checkUser = function (username, callback) {
  userbase.checkUser(username, function (occupied) {
    callback({ username: username, occupied: occupied });
  });
};

exports.register = function (userinfo, callback) {
  // First make sure that the user doesn't exist.
  userbase.checkUser(userinfo.username, function (occupied) {
    if (occupied) {
      callback({ success: false, userinfo: userinfo, error: 'user-exists' });
      return;
    }

    // When everything looks good, insert the record.
    userbase.create(userinfo, function (success, userOrErr) {
      if (success) callback({ success: true, userinfo: userOrErr });
      else callback({ success: false, userinfo: userinfo, error: userOrErr });
    });
  });
};

exports.authenticate = function (userinfo, callback) {
  userbase.authenticate(userinfo, function (success, userOrErr) {
    if (success) callback({ success: true, userinfo: userOrErr });
    else callback({ success: false, userinfo: userinfo, error: userOrErr });
  });
};

exports.getApps = function (username, callback) {
  callback({ success: true, apps: [] });
};

exports.editInfo = function (newinfo, callback) {
  userbase.authenticate({
    username: newinfo.username,
    password: newinfo.oldpass
  }, function (success, err) {
    if (success) {
      userbase.update({
        username: newinfo.username,
        password: newinfo.newpass,
        bio:      newinfo.bio
      }, function (success, userOrErr) {
        if (success) callback({ success: true, userinfo: userOrErr });
        else callback({ success: false, error: userOrErr });
      });
    } else {
      callback({ success: false, error: 'wrong-old-pass' });
    }
  });
};

