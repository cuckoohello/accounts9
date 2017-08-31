ldap = require 'ldapjs'

User = require('../user/model')
Group = require('../group/model').model
config = require '../config'

server = module.exports = ldap.createServer()

SUFFIX = config.suffix
USERS_DN = 'ou=users, '+SUFFIX
GROUPS_DN = 'ou=groups, '+SUFFIX
AUTH_DN = 'cn=auth, '+SUFFIX

# ldap_debug = console.log
ldap_debug = () ->
  ;

authorize = (req, res, next)->
  if (!req.connection.ldap.bindDN.equals(AUTH_DN))
    res.end()
    return next(new ldap.InsufficientAccessRightsError());

  return next();

server.bind AUTH_DN, (req, res, next)->
  if (req.dn.toString() != AUTH_DN or req.credentials != config.interfaceSecret)
    return next(new ldap.InvalidCredentialsError());

  res.end()
  return next()

server.bind USERS_DN, (req, res, next)->
  uname = req.dn.rdns[0]
  if not uname or not uname['uid']
    return next(new ldap.InvalidCredentialsError());

  uname = uname['uid']
  ldap_debug '======bind user======'
  ldap_debug("user: "+uname)
  User.getByName uname, (err,user)->
    if not err and (user.checkPassword req.credentials)
      user.isAuthorized (err,authorized)->
        if not err and authorized
          res.end()
          ldap_debug 'passed'
          return next()
        else
          ldap_debug 'failed: not authorized'
          return next(new ldap.InvalidCredentialsError())
    else
      ldap_debug 'failed: wrong password'
      return next(new ldap.InvalidCredentialsError())

server.search USERS_DN, (req, res, next)->
  handle_err = (err) ->
    ldap_debug err
    next(new ldap.UnavailableError())

  ldap_debug '======search user======'
  ldap_debug req.dn
  ldap_debug req.filter.json
  if req.dn.equals(USERS_DN)
    if not req.connection.ldap.bindDN.equals(AUTH_DN)
      return next(new ldap.InsufficientAccessRightsError())
    query = filter2mongoquery(req.filter, 'user')
    # ldap_debug req.scope
    ldap_debug (JSON.stringify (query))
    queryNtPassword = false
    if query and query["$and"] and query["$and"][0] and query["$and"][0]["authtype"]
      type = query["$and"].shift()
      if type["authtype"] == "radius"
        queryNtPassword = true

    User.find query, (err, users) ->
      return handle_err(err) if err
      # ldap_debug(users)
      for user in users
        record = buildUserRecord(user)
        if queryNtPassword
          record["attributes"]["ntPassword"] = user.ntPassword
        ldap_debug record
        res.send(record)
      res.end()
      next()
  else
    uname = req.dn.rdns[0]
    if not req.connection.ldap.bindDN.equals(AUTH_DN)
      bindName = req.connection.ldap.bindDN.rdns[0]
      if not (uname and uname['uid'] and bindName and bindName['uid'] and uname['uid'] == bindName['uid'])
        return next(new ldap.InsufficientAccessRightsError())

    if uname and uname['uid']
      uname = uname['uid']
      ldap_debug("User Name: "+uname)
      User.find {'name': uname}, (err,users)->
        for user in users
          record = buildUserRecord(user)
          ldap_debug record
          res.send(record)
        res.end()
        next()
    else
      next(new ldap.UnavailableError())

server.search GROUPS_DN, authorize, (req, res, next)->
  if not req.connection.ldap.bindDN.equals(AUTH_DN)
    return next(new ldap.InsufficientAccessRightsError())

  handle_err = (err) ->
    ldap_debug err
    next(new ldap.UnavailableError())

  ldap_debug '======search group======'
  ldap_debug req.dn
  ldap_debug req.filter.json
  if req.dn.equals(GROUPS_DN)
    query = filter2mongoquery(req.filter, 'group')
    ldap_debug (JSON.stringify (query))

    Group.find query, (err, groups) ->
      return handle_err(err) if err
      # ldap_debug(groups)
      for group in groups
        record = buildGroupRecord(group)
        ldap_debug record
        res.send(record)
      res.end()
      next()
  else
    gname = req.dn.rdns[0]
    if gname and gname['cn']
      gname = gname['cn']
      ldap_debug("Group Name: "+gname)
      Group.find {'name': gname}, (err,groups)->
        for group in groups
          record = buildGroupRecord(group)
          ldap_debug record
          res.send(record)
        res.end()
        next()
    else
      next(new ldap.UnavailableError())

username2dn = (name)->
  'uid='+name+', '+USERS_DN

dn2username = (dn)->
  ldap.parseDN(dn).rdns[0]['uid']

dn2groupname = (dn)->
  ldap.parseDN(dn).rdns[0]['cn']

filter2mongoquery = (filter, type)->
  result = {}
  switch filter.attribute
    when 'cn'
      if type == 'user'
        filter.attribute = 'fullname'
      else
        filter.attribute = 'name'
    when 'uid'
      filter.attribute = 'name'
    when 'mail'
      filter.attribute = 'email'
    when 'displayname'
      filter.attribute = 'fullname'
    when 'sn'
      filter.attribute = 'surname'
    when 'ou'
      filter.attribute = 'department'
    when 'mobile'
      filter.attribute = 'mobile'
    when 'description'
      filter.attribute = 'desc'

  switch filter.type
    when 'or','and'
      a = for k,v of filter.filters
        filter2mongoquery(v, type)
      result['$'+filter.type] = a
    when 'not'
      result['$not'] = filter2mongoquery(filter.filter, type)
    when 'equal'
      if filter.attribute != 'objectclass'
        if filter.attribute == 'member'
          result['users'] = dn2username(filter.value)
        else if filter.attribute == 'memberof'
          result['groups'] = dn2groupname(filter.value)
        else
          result[filter.attribute] = filter.value
    when 'present'
      if filter.attribute != 'objectclass'
        result[filter.attribute] = {$exists: true}
    when 'ge'
      result[filter.attribute] = {$gte: filter.value}
    when 'le'
      result[filter.attribute] = {$lte: filter.value}
  return result

buildUserRecord = (user)->
  record =
    dn: username2dn(user.name)
    attributes:
      objectclass: 'inetOrgPerson'
      cn: user.fullname
      uid: user.name
      mail: user.email
      displayName: user.fullname
      givenName: user.givenname
      sn: user.surname
      ou: user.department
      mobile: user.mobile

buildGroupRecord = (group)->
  members = []
  for u in group.users
    members.push username2dn(u)
  record =
    dn: 'cn='+group.name+', '+GROUPS_DN
    attributes:
      objectclass: 'groupOfNames'
      cn: group.name
      description: group.desc
      title: group.title
      member: members
