const sessions = require('client-sessions')
const OAuth2 = require('client-oauth2')
const { atob, btoa } = require('Base64')
const { parse } = require('qs')

function Handler (opts) {
  this.init(opts)
}

Handler.prototype.init = function init ({ req, res, next, options = { sessionName: 'nuxtSession' } } = {}) {
  this.req = req
  this.res = res
  this.next = next
  this.opts = options
  this.auth = this.createAuth()
}

const errorLog = e => process.env.NODE_ENV === 'development' && console.error(e)

Handler.prototype.createAuth = function createAuth () {
  const { oauthHost, oauthClientID, oauthClientSecret, scopes } = this.opts
  const protocol = this.req.headers['x-forwarded-proto'] || this.req.headers['X-Forwarded-Proto'] || 'http'

  return new OAuth2({
    authorizationUri: `${oauthHost}/authorize`,
    accessTokenUri: `${oauthHost}/token`,
    clientId: oauthClientID,
    clientSecret: oauthClientSecret,
    redirectUri: `${protocol}://${this.req.headers.host}/auth/callback`,
    scopes: scopes
  })
}

Handler.prototype.redirect = function redirect (path) {
  this.res.writeHead(302, { location: path })
  this.res.end()
}

Handler.prototype.createSession = function createSession () {
  if (this.req[this.opts.sessionName]) return Promise.resolve()
  const session = sessions({
    cookieName: this.opts.sessionName,
    secret: this.opts.secretKey,
    duration: 24 * 60 * 60 * 1000
  })
  return new Promise(resolve => session(this.req, this.res, resolve))
}

Handler.prototype.authenticateCallbackToken = async function authenticateCallbackToken () {
  let redirectUrl
  try {
    const { state, error } = parse(this.req.url.split('?')[1])
    if (error === undefined) {
      redirectUrl = JSON.parse(atob(state)).redirectUrl
    } else if (error == 'access_denied') {
      redirectUrl = '/'
      return this.redirect(redirectUrl)
    }
  } catch (e) {
    errorLog(e)
    redirectUrl = '/'
    return this.redirect(redirectUrl)
  }
  try {
    const token = await this.auth.code.getToken(this.req.url)
    const { accessToken, refreshToken, expires } = token
    await this.saveData({ accessToken, refreshToken, expires })
    return this.redirect(redirectUrl)
  } catch (e) {
    // errorLog(e)
    // var url_parts = url.parse(request.url, true);
    // var query = url_parts.query;
    // console.dir(e.prototype)
    //if (query.error=='access') {
    //  return this.redirect(redirectUrl)
    //}
    return this.redirectToOAuth(redirectUrl)
  }
}

Handler.prototype.saveData = async function saveData (token) {
  await this.createSession()
  if (!token) return this.req[this.opts.sessionName].reset()

  const { accessToken, refreshToken, expires } = token
  this.req[this.opts.sessionName].token = { accessToken, refreshToken, expires }
  this.req.accessToken = accessToken

  const user = this.req[this.opts.sessionName].user || await this.opts.fetchUser(accessToken)
  this.req[this.opts.sessionName].user = user
  this.req.user = user
  return true
}

Handler.prototype.updateToken = async function updateToken () {
  await this.createSession()
  let { token } = this.req[this.opts.sessionName]
  if (!token) return false

  try {
    const newToken = await this.auth.createToken(token.accessToken, token.refreshToken, 'bearer')
    newToken.expiresIn(new Date(token.expires))

    if (newToken.expired()) {
      const { accessToken, refreshToken } = await newToken.refresh()
      token.accessToken = accessToken
      token.refreshToken = refreshToken
    }
  } catch (e) {
    errorLog(e)
    token = null
  }
  this.saveData(token)
  return true
}

Handler.prototype.redirectToOAuth = async function redirectToOAuth (redirect) {
  const redirectUrl = redirect || this.req.url
  const state = JSON.stringify({ redirectUrl })
  const url = this.auth.code.getUri({
    state: btoa(state)
  })
  return this.redirect(url)
}

Handler.prototype.logout = async function logout () {
  await this.createSession()
  this.req[this.opts.sessionName].reset()
  this.req[this.opts.sessionName].setDuration(0)

  const redirectUrl = parse(this.req.url.split('?')[1])['redirect-url'] || '/'
  await this.opts.onLogout(this.req, this.res, redirectUrl)
  if (this.res.headersSent) return
  this.redirect(redirectUrl)
}

Handler.routes = {
  login: '/auth/login',
  callback: '/auth/callback',
  logout: '/auth/logout'
}

Handler.prototype.isRoute = function isRoute (route) {
  const path = this.constructor.routes[route]

  return this.req.url.startsWith(path)
}

module.exports = Handler
