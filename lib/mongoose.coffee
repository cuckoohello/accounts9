config = require '../config'
module.exports = mongoose = require('mongoose')
mongoose.connected = false
mongoose.connection.on 'open', ->
  mongoose.connected = true

mongoose.connect config.db.url
