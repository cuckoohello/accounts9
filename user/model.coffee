'use continuation'
Group = require("../group/model")
mongoose = require("../lib/mongoose")
utils = require("../lib/utils")
assert = require("assert")
crypto = require("crypto")

UserSchema = new mongoose.Schema(
  name:
    type: String
    index: true
    unique: true
  uid: Number
  password: String
  ntPassword: String
  nickname: String
  surname: String
  givenname: String
  fullname: String
  email:
    type: String
    index: true
    unique: true
  emails: [ String ]
  mobile: String
  website: String
  address: String
  bio: String
  birthdate: String
  groups: [ String ]
  regtime: Date
  department: String
  identity: [ Buffer ]
)

mongoose.model "User", UserSchema
module.exports = User = mongoose.model "User"

UserSchema.pre 'save', (next) ->
  @nickname ?= ''
  @surname ?= ''
  @givenname ?= ''
  @fullname ?= ''
  @email ?= ''
  @email = @email.toLowerCase()
  @emails ?= []
  @emails = (item.toLowerCase() for item in @emails)
  emailRegex = /^([a-z0-9_\.\-])+\@(([a-z0-9\-])+\.)+([a-z0-9]{2,4})+$/
  @emails = @emails.filter (item) -> emailRegex.exec(item)
  @mobile ?= ''
  @website ?= ''
  @address ?= ''
  @bio ?= ''
  @birthdate ?= ''
  @regtime ?= new Date()
  @groups ?= []
  @department ?= ''
  @identity ?= []

  next()

User.sync = (callback) ->
  User.find {}, (err, users) ->
    users.forEach (user) ->
      User.getByName user.name, (err, user) ->
        user.password = ''
        user.ntPassword = ''
        user.save null
    callback null

User.checkName = (name, callback) ->
  User.findOne name: name, (err, user) ->
    return callback(err) if err
    if user
      callback "username-occupied"
    else
      callback null

User.checkIdentity = (identity, callback) ->
	User.getByIdentity identity, (err, user) ->
		if err is 'no-such-user'
			callback null
		else if err
			callback err
		else
			callback 'identity-exist'

User.getByNameOrEmail = (name_or_email, callback) ->
  User.findOne {$or: [{name: name_or_email},{email: name_or_email}]}, (err, user) ->
    return callback(err) if err
    if not user
      callback 'no-such-user'
    else
      callback null, user


User.getByName = (name, callback) ->
  User.findOne name: name, (err, user) ->
    return callback(err) if err
    if not user
      callback 'no-such-user'
    else
      callback null, user

User.getByUid = (uid, callback) ->
  User.findOne uid: uid, (err, user) ->
    return callback(err) if err
    if not user
      callback 'no-such-user'
    else
      callback null, user

User.getByEmail = (email, callback) ->
  User.findOne email: email, (err, user) ->
    return callback(err) if err
    if not user
      callback 'no-such-user'
    else
      callback null, user

User.getByIdentity = (identity, callback) ->
	User.findOne identity: $elemMatch: $eq: identity, (err, user) ->
		return callback(err) if err
		if not user
		  callback 'no-such-user'
		else
			callback null, user

User.getByNames = (usernames, callback) ->
  users = []
  returned = false
  return callback(null, users)  if usernames.length is 0
  usernames.forEach (username) ->
    return if returned
    User.getByName username, (err, user) ->
      if err
        returned = true
        return callback(err)
      users.push user
      if users.length is usernames.length
        utils.sortBy users, "uid"
        callback null, users

User.validate = (user, cb) ->
  unless user.name and user.surname and user.givenname and user.email and user.department
    return cb("fields-required")
  cb null

User.fillFrom = (user, o) ->
  user.name = o.username
  user.nickname = o.nickname
  user.surname = o.surname
  user.givenname = o.givenname
  user.fullname = o.fullname
  user.email = o.email
  if o.emails
    user.emails = o.emails.split(/\r?\n/)
  user.mobile = o.mobile
  user.website = o.website
  user.address = o.address
  user.bio = o.bio
  user.birthdate = o.birthdate
  user.fullname = o.surname + o.givenname
  user.department = o.department
  if o.password
    user.password = o.password
  if o['password-repeat']
    user.passwordConfirm = o['password-repeat']
  user

# Create a new user
User.create = (user, callback) ->
  try
    # Check require fields and if passwords match
    User.validate user, obtain()
    unless user.password
      throw 'fields-required'
    if user.password isnt user.passwordConfirm
      throw 'password-mismatch'

    # Normalize username and email address to lower case
    user.name = user.name.toLowerCase()
    user.email = user.email.toLowerCase()

    # Validate username and email format
    usernameRegex = /^[a-z][a-z0-9_]{3,11}$/
    if not usernameRegex.exec(user.name)
      return callback("invalid-username")
    emailRegex = /^([a-z0-9_\.\-])+\@(([a-z0-9\-])+\.)+([a-z0-9]{2,4})+$/
    if not emailRegex.exec(user.email)
      return callback("invalid-email")

    # Generate password hash
    user.ntPassword = utils.genNtPassword user.password
    user.password = utils.genPassword user.password

    User.checkName user.name, obtain()
    User.findOne {email: user.email}, obtain(existance)
    if (existance)
      throw 'email-already-exists'
    user = new User(user)
    user.generateUid obtain()
    user.addToDefaultGroup obtain()
    callback null, user
  catch err
    callback err

User::__defineGetter__ "title", ->
  if @fullname
    @fullname
  else
    @name

User::checkPassword = (password) ->
  (@password is utils.genPassword password) or (@password is '')

User::addToGroup = (groupName, callback) ->
  @groups = @groups or []
  for key of @groups
    if @groups[key] is groupName
      return callback("already-in-this-group")
  @groups.push groupName
  @save callback

User::addIdentity = (identity, callback) ->
  @identity ?= []
  self = this
  try
    User.checkIdentity(identity, obtain())
    self.identity.push identity
    self.save callback
  catch err
  	callback err

User::removeIdentity = (identity, callback) ->
	i = 0
	while i < @identity.length
    if @identity[i].equals identity
      @identity = @identity.slice(0, i).concat(@identity.slice(i + 1))
      @save callback
      return
    i++
  callback "no-such-identity"

User::addToDefaultGroup = (callback) ->
  self = this
  Group.getByName "root", (err, root) ->
    unless err
      self.addToGroup root.name, (err) ->
        return callback(err)  if err
        root.addUser self.name, callback
    else if err is "no-such-group"
      Group.initialize self, (err, root, authorized) ->
        callback err
    else
      callback err

User::removeFromGroup = (groupName, callback) ->
  i = 0

  while i < @groups.length
    if @groups[i] is groupName
      @groups = @groups.slice(0, i).concat(@groups.slice(i + 1))
      @save callback
      return
    i++
  callback "not-in-this-group"

User::checkGroup = (groupname, options, callback) ->
  self = this
  if not callback
    callback = options
    options = {}
  if options.direct
    Group.getByName groupname, (err, group) ->
      return callback(err)  if err
      group.checkUser self.name,
        direct: true
      , callback

    return
  self.getAllGroups (err, groups) ->
    for i of groups
      return callback(null, true)  if groups[i].name is groupname
    callback null, false

User::getAllGroups = (callback) ->
  self = this
  done = 0
  if self.groups.length is 0
    return callback null, []

  groupsMap = {}
  try
    for groupName in self.groups
      Group.getByName groupName, obtain(group)
      groupsMap[group.name] = group
      group.getAncestors obtain(ancestors)
      for ancestorGroup in ancestors
        groupsMap[ancestorGroup.name] = ancestorGroup

    groups = []
    for key of groupsMap
      groups.push groupsMap[key]
    callback null, groups
  catch err
    callback err

# Get group objects that the user directly belongs to
User::getDirectGroups = (callback) ->
  self = this
  try
    Group.getByNames self.groups, obtain(self.directGroups)
    callback null, self.directGroups
  catch err
    callback err

# Get group objects that the user manages
User::getAdminGroups = (callback) ->
  self = this
  try
    Group.getAll obtain(groups)
    self.adminGroups = []
    groups.forEach (group) ->
      if utils.contains(group.admins, self.name)
        self.adminGroups.push group
    callback null, self.adminGroups
  catch err
    callback err

User::gravatar = (size) ->
  size = 100  unless size
  hash = crypto.createHash("md5")
  hash.update @email
  hash = hash.digest("hex")
  url = "https://secure.gravatar.com/avatar/" + hash + "?d=mm&r=x&s=" + size
  url

User::isAuthorized = (callback) ->
  self = this
  self.getAllGroups (err, groups) ->
    return callback(err) if err
    for i of groups
      return callback(null, true)  if groups[i].name is "authorized"
    callback null, false

User::generateUid = (callback) ->
  self = this
  User.find().sort('-uid').limit(1).exec (err, doc) ->
    return callback(err) if err
    doc = doc[0]
    if !doc
      self.uid = 1
    else
      self.uid = doc.uid + 1
    callback null, self.uid

User::delete = (callback) ->
  assert @groups.length is 0
  return callback("mongodb-not-connected")  unless mongoose.connected
  User.remove name: @name, callback
