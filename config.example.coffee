module.exports =
  cookieSecret: "accounts9"
  interfaceSecret: "Example"
  host: "https://accounts.net9.org"
  smtp:
    host: 'smtp.263.net'
    secure: false
    port: 25
    auth:
      user: 'example@example.com'
      pass: 'password'
  db:
    url: 'mongodb://localhost/accounts9'
  log:
    access: "access.log"
    error: "error.log"
