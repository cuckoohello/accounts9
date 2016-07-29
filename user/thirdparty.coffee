'use continuation'
oauth = require('oauth')
mongoose = require('../lib/mongoose')
config = require('../config')
utils = require('../lib/utils')

mongoose.model "ThirdPartyUser", new mongoose.Schema(
  uid:
    type: Number
    index: true
    unique: true
)

ThirdPartyUser = module.exports = mongoose.model('ThirdPartyUser')

ThirdPartyUser.get = (uid, callback) ->
  ThirdPartyUser.findOne {uid: uid}, callback

ThirdPartyUser.getOrCreate = (uid, callback) ->
  try
    ThirdPartyUser.findOne {uid: uid}, obtain(user)
    if not user
      user = new ThirdPartyUser
      user.uid = uid
    callback null, user
  catch err
    callback err

