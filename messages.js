/* vim: set sw=2 ts=2 nocin si: */

var messages = {
  'page-title': '$1 - net9 Auth',
  'index-page-title': 'net9 Auth',
  'reg-username-tips': 'Username must be between 0 to &infin; characters.',
  'reg-password-tips': 'Do not use silly passwords.',
  'error-user-exists': 'Sorry, but this username is already taken. Please choose another one.',
  'error-user-pass-no-match': 'The username and password you provided don\'t match.',
  'welcome': 'Welcome, $1!',
  'my-info': 'My information',
  'edit-my-info': 'Edit my infomation',
  'my-apps': 'My applications',
  'create-new-app': 'Create new application',
  'no-apps-yet': 'You haven\'t registered any apps yet.',
  'old-password': 'Old password',
  'new-password': 'New password',
  'error-wrong-old-pass': 'The old password you provided is wrong.'
};

// Cache the argument regexps for performance. I genuinely hope arguments number 6+ won't be used.
// If someone uses them, God help him/her split the message into smaller parts.
var args = [/\$0/g, /\$1/g, /\$2/g, /\$3/g, /\$4/g, /\$5/g, /\$6/g];

exports.get = function (id) {
  //console.log("getting message " + id + " with " + arguments[1]);
  var msg = messages[id.toLowerCase()];
  if (!msg) return id;  // Fallback to the message name
  for (var i = 1; i < arguments.length; i++) {
    msg = msg.replace(args[i], arguments[i]);
  }
  return msg;
};
    