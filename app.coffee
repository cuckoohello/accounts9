#!/usr/bin/env coffee

# Module dependencies

messages = require "./messages" 
config = require "./config" 
express = require "express" 
MongoStore = (require "connect-mongo") express
fs = require "fs"
util = require "util"
path = require "path"

# Configuration

app = module.exports = express.createServer()

accessLogfile = fs.createWriteStream config.log.access, flags: "a"
errorLogfile = fs.createWriteStream config.log.error, flags: "a"

app.configure ->
  app.use express.logger(stream: accessLogfile)
  app.set "views", __dirname + "/views"
  app.set "view engine", "ejs"
  app.enable "jsonp callback"
  app.use express.bodyParser()
  app.use express.methodOverride()
  app.use express.cookieParser()
  app.use express.session(
    secret: config.cookieSecret
    store: new MongoStore(
      db: config.db.name
      host: config.db.host
      port: config.db.port
    )
  )
  app.use app.router
  require("./routes")(app)
  app.use express.router require("./oauth")
  app.use express.router require("./app/")
  app.use express.router require("./interface")
  app.use require('connect-assets')(
    src: path.join __dirname, 'assets'
    buildDir: 'public'
  )
  app.use express.static __dirname + "/public" 

app.configure "development", ->
  app.use express.errorHandler(
    dumpExceptions: true
    showStack: true
  )
  app.use express.logger()

app.configure "production", ->
  app.error (err, req, res, next) ->
    meta = "[" + new Date() + "] " + req.url + "\n"
    errorLogfile.write meta
    errorLogfile.write err.stack
    errorLogfile.write "\n"
    next()

# Helper functions for view rendering

app.helpers
  msg: messages.get.bind messages 
  pageTitle: (title) ->
    if title
      messages.get "page-title", title
    else
      messages.get "index-page-title"

  inspect: (obj) ->
    util.inspect obj
  
  displayDate: (timestamp) ->
    date = new Date(timestamp * 1000)
    date.getFullYear() + '-' + (date.getMonth() + 1) + '-' + date.getDate() + ' ' +
      date.getHours() + ':' + date.getMinutes() + ':' + date.getSeconds()

app.dynamicHelpers
  curUser: (req, res) ->
    req.session.user

  error: (req, res) ->
    err = req.flash "error" 
    if err.length
      messages.get err
    else
      null

  info: (req, res) ->
    succ = req.flash "info" 
    if succ.length
      messages.get succ
    else
      null

unless module.parent
  app.listen 3000, "127.0.0.1", ->
  	console.log "Express server listening on port %d", app.address().port
