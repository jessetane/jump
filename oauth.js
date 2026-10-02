import { createHash, timingSafeEqual, randomBytes } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as db from './db/index.js'
import { getUserInfo, revokeGoogleToken, baseScopes, allScopes, services, buildScopesFromSelection } from './providers/google.js'
import { getBody, sendMail } from './util.js'
import { validatePolicy } from './policy.js'

export {
	handleOauth,
	handleAuthorize,
	handleAuthorizeConsent,
	handleVerify,
	handleGoogleConnect,
	handleGoogleConsent,
	handleCallback,
	handleToken,
	handleRevoke,
	handleProtectedResourceMetadata,
	handleAuthServerMetadata,
	isAllowedRedirectUri
}

const dirname = path.dirname(fileURLToPath(import.meta.url))

const appUrl = process.env.APP_URL || 'http://localhost:8080'
const clientId = process.env.GOOGLE_CLIENT_ID
const clientSecret = process.env.GOOGLE_CLIENT_SECRET

function getClientIp (req) {
	return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || null
}

function verifyCodeChallenge (verifier, challenge, method) {
	if (typeof verifier !== 'string' || typeof challenge !== 'string') return false
	if (method === 'S256') {
		const hash = createHash('sha256').update(verifier).digest('base64url')
		const bufHash = Buffer.from(hash)
		const bufChallenge = Buffer.from(challenge)
		if (bufHash.byteLength !== bufChallenge.byteLength) return false
		return timingSafeEqual(bufHash, bufChallenge)
	}
	return false
}

function isAllowedRedirectUri (redirectUri) {
	if (!redirectUri) return false
	let url
	try {
		url = new URL(redirectUri)
	} catch {
		return false
	}
	const envDomains = process.env.ALLOWED_REDIRECT_DOMAINS || 'localhost,127.0.0.1'
	const allowedDomains = envDomains.split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
	const hostname = url.hostname.toLowerCase()
	return allowedDomains.some(domain => {
		if (domain.startsWith('*.')) {
			const root = domain.slice(2)
			return hostname === root || hostname.endsWith(`.${root}`)
		}
		return hostname === domain
	})
}

async function handleProtectedResourceMetadata (req, res) {
	const base = appUrl.replace(/\/$/, '')
	const meta = {
		resource: `${base}/mcp`,
		authorization_servers: [base]
	}
	res.statusCode = 200
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify(meta, null, '\t'))
}

async function handleAuthServerMetadata (req, res) {
	const base = appUrl.replace(/\/$/, '')
	const meta = {
		issuer: base,
		authorization_endpoint: `${base}/oauth/authorize`,
		token_endpoint: `${base}/oauth/token`,
		revocation_endpoint: `${base}/oauth/revoke`,
		response_types_supported: ['code'],
		grant_types_supported: ['authorization_code'],
		token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
		revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
		code_challenge_methods_supported: ['S256'],
		client_id_metadata_document_supported: true
	}
	res.statusCode = 200
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify(meta, null, '\t'))
}

function validateAuthorizeParams (query) {
	if (query.redirect_uri) {
		if (!isAllowedRedirectUri(query.redirect_uri)) {
			console.warn(`[oauth] Unauthorized redirect_uri: "${query.redirect_uri}". Add domain to ALLOWED_REDIRECT_DOMAINS to allow.`)
			const err = new Error(`redirect_uri is not allowed: ${query.redirect_uri}`)
			err.code = 'invalid_request'
			err.status = 400
			throw err
		}
		if (!query.code_challenge) {
			const err = new Error('code_challenge required when redirect_uri is provided')
			err.code = 'invalid_request'
			err.status = 400
			throw err
		}
	}
	if (query.code_challenge_method && !query.code_challenge) {
		const err = new Error('code_challenge_method provided without code_challenge')
		err.code = 'invalid_request'
		err.status = 400
		throw err
	}
	const codeChallenge = query.code_challenge || null
	const codeChallengeMethod = query.code_challenge_method || (codeChallenge ? 'S256' : null)
	if (codeChallengeMethod && codeChallengeMethod !== 'S256') {
		const err = new Error('unsupported code_challenge_method')
		err.code = 'invalid_request'
		err.status = 400
		throw err
	}
	return { codeChallenge, codeChallengeMethod }
}

async function handleAuthorize (req, res, query) {
	let validation
	try {
		validation = validateAuthorizeParams(query)
	} catch (err) {
		res.statusCode = err.status || 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: err.code || 'invalid_request', error_description: err.message }))
		return
	}
	const initData = {
		params: query
	}
	const authorizeHtml = await fs.readFile(path.join(dirname, 'public/authorize.html'), 'utf8')
	const html = authorizeHtml.replace('{{INIT_DATA}}', JSON.stringify(initData).replace(/</g, '\\u003c'))
	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(html)
}

async function handleAuthorizeConsent (req, res) {
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.end('Method Not Allowed')
		return
	}
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)

	const query = {}
	let email = null
	let sessionName = null
	let admin = 0
	let policy = null

	for (const [key, value] of params.entries()) {
		if (key === 'email') {
			email = value.trim().toLowerCase() || null
		} else if (key === 'session_name') {
			sessionName = value.trim() || null
		} else if (key === 'admin') {
			admin = value === 'true' || value === '1' || value === 'on' ? 1 : 0
		} else if (key === 'policy') {
			policy = value.trim() || null
		} else {
			query[key] = value
		}
	}

	if (!email || !email.includes('@')) {
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_request', error_description: 'Valid email address is required' }))
		return
	}

	if (policy) {
		const policyValidation = validatePolicy(policy)
		if (!policyValidation.valid) {
			res.statusCode = 400
			res.setHeader('content-type', 'application/json; charset=utf-8')
			res.end(JSON.stringify({ error: 'invalid_request', error_description: policyValidation.error }))
			return
		}
	}

	let validation
	try {
		validation = validateAuthorizeParams(query)
	} catch (err) {
		res.statusCode = err.status || 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: err.code || 'invalid_request', error_description: err.message }))
		return
	}
	const { codeChallenge, codeChallengeMethod } = validation

	const magicCode = randomBytes(24).toString('base64url')
	const magicExpiresAt = Date.now() + (15 * 60 * 1000)
	const ip = getClientIp(req)

	db.oauthStates.create({
		clientRedirectUri: query.redirect_uri || null,
		clientState: query.state || null,
		codeChallenge,
		codeChallengeMethod,
		sessionName,
		admin,
		policy,
		email,
		magicCode,
		magicExpiresAt,
		ip
	})

	const verifyUrl = `${appUrl.replace(/\/$/, '')}/oauth/verify?code=${magicCode}`
	await sendMail({
		to: email,
		subject: 'Sign in to google-mcp Gateway',
		text: `Click the link below to sign in and activate your MCP session token:\n\n${verifyUrl}\n\nThis link expires in 15 minutes.`,
		html: `<p>Click the link below to sign in and activate your MCP session token:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>This link expires in 15 minutes.</p>`
	})

	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(`<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:440px;margin:50px auto;padding:24px;border:1px solid #e2e8f0;border-radius:8px;text-align:center;"><h2>Check your email</h2><p>A magic sign-in link has been sent to <strong>${email}</strong>.</p><p>Click the link in your email to activate your MCP session token.</p></body></html>`)
}

async function handleVerify (req, res, query) {
	const code = query.code
	if (!code) {
		res.statusCode = 400
		res.setHeader('content-type', 'text/plain')
		res.end('Missing verification code.')
		return
	}
	const state = db.oauthStates.consumeMagicCode(code)
	if (!state) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Invalid or expired verification link.')
		return
	}
	const email = state.email || 'user@localhost'
	const user = db.users.upsert({ email })
	const ip = getClientIp(req)
	const ua = req.headers['user-agent'] || null
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		type: 'bearer',
		name: state.sessionName || (state.admin ? 'Admin Session' : 'Default Session'),
		admin: state.admin ? 1 : 0,
		ip: state.ip || ip,
		ua
	})

	if (state.clientRedirectUri) {
		const authCode = db.oauthCodes.create({
			sessionId: session.id,
			clientRedirectUri: state.clientRedirectUri,
			codeChallenge: state.codeChallenge,
			codeChallengeMethod: state.codeChallengeMethod
		})
		const target = new URL(state.clientRedirectUri)
		target.searchParams.set('code', authCode)
		if (state.clientState) target.searchParams.set('state', state.clientState)
		res.statusCode = 302
		res.setHeader('location', target.toString())
		res.end()
		return
	}

	res.statusCode = 200
	res.setHeader('content-type', 'text/plain; charset=utf-8')
	res.end(`user: ${email}\ntoken: ${session.token}\n\nheader:\nAuthorization: Bearer ${session.token}\n`)
}

async function handleGoogleConnect (req, res, query) {
	const initData = {
		params: query
	}
	const connectHtml = await fs.readFile(path.join(dirname, 'public/google-connect.html'), 'utf8')
	const html = connectHtml.replace('{{INIT_DATA}}', JSON.stringify(initData).replace(/</g, '\\u003c'))
	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(html)
}

async function handleGoogleConsent (req, res) {
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.end('Method Not Allowed')
		return
	}
	if (!clientId) {
		res.statusCode = 500
		res.setHeader('content-type', 'text/plain')
		res.end('GOOGLE_CLIENT_ID environment variable is missing')
		return
	}
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)

	const servicesList = params.getAll('services')
	const writeList = params.getAll('write')
	const sessionId = params.get('session_id') || null
	const reauthAppId = params.get('reauth_app_id') || null
	const rawAppName = params.get('app_name') || params.get('name') || ''
	const sessionName = rawAppName ? String(rawAppName).trim() : null

	const scopes = buildScopesFromSelection(servicesList, writeList)
	const callbackUrl = `${appUrl.replace(/\/$/, '')}/oauth/callback`
	const ip = getClientIp(req)

	const stateToken = db.oauthStates.create({
		sessionId,
		reauthAppId,
		sessionName,
		provider: 'google',
		ip
	})

	const u = new URL('https://accounts.google.com/o/oauth2/v2/auth')
	u.searchParams.set('client_id', clientId)
	u.searchParams.set('redirect_uri', callbackUrl)
	u.searchParams.set('response_type', 'code')
	u.searchParams.set('scope', scopes)
	u.searchParams.set('access_type', 'offline')
	u.searchParams.set('prompt', 'consent')
	u.searchParams.set('state', stateToken)
	res.statusCode = 302
	res.setHeader('location', u.toString())
	res.end()
}

async function handleCallback (req, res, query) {
	const code = query.code
	const rawState = query.state
	if (!code) {
		res.statusCode = 400
		res.setHeader('content-type', 'text/plain')
		res.end(`Google Auth Error: ${query.error || 'no code'}`)
		return
	}
	const oauthState = db.oauthStates.consume(rawState)
	if (!oauthState) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Invalid or expired OAuth state (CSRF verification failed). Please try connecting Google again.')
		return
	}
	const callbackUrl = `${appUrl.replace(/\/$/, '')}/oauth/callback`
	const params = new URLSearchParams({
		code,
		client_id: clientId,
		client_secret: clientSecret,
		redirect_uri: callbackUrl,
		grant_type: 'authorization_code'
	})
	const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: params.toString()
	})
	const tokenData = await tokenRes.json()
	if (!tokenRes.ok) {
		console.error('Google token exchange failed:', tokenData)
		res.statusCode = 502
		res.setHeader('content-type', 'text/plain')
		res.end('Failed to exchange authorization code with Google')
		return
	}
	const googleUser = await getUserInfo(tokenData.access_token)
	const email = (googleUser.email || '').toLowerCase()
	if (!email) {
		res.statusCode = 400
		res.setHeader('content-type', 'text/plain')
		res.end('Could not retrieve user email from Google account.')
		return
	}

	if (oauthState.reauthAppId) {
		const existingApp = db.tokens.get(oauthState.reauthAppId)
		if (existingApp) {
			const updatedCreds = {
				...existingApp.credentials,
				accessToken: tokenData.access_token,
				refreshToken: tokenData.refresh_token || existingApp.credentials?.refreshToken
			}
			db.tokens.updateCredentials(existingApp.id, {
				credentials: updatedCreds,
				expiresAt: Date.now() + ((tokenData.expires_in || 3600) * 1000),
				scopes: tokenData.scope || existingApp.scopes
			})
			res.statusCode = 200
			res.setHeader('content-type', 'text/html; charset=utf-8')
			res.end('<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:500px;margin:50px auto;text-align:center;"><h2>Google App Re-authenticated</h2><p>Google app credentials have been successfully updated in place. Linked agent sessions will resume automatically.</p></body></html>')
			return
		}
	}

	let targetUserId = null
	if (oauthState.sessionId) {
		const session = db.tokens.get(oauthState.sessionId)
		if (session) targetUserId = session.userId
	}
	if (!targetUserId) {
		const user = db.users.upsert({
			email,
			name: googleUser.name || null
		})
		targetUserId = user.id
	}

	const appName = oauthState.sessionName || `${googleUser.name || email} Google`
	const appToken = db.tokens.create({
		userId: targetUserId,
		provider: 'google',
		type: 'oauth',
		name: appName,
		credentials: {
			accessToken: tokenData.access_token,
			refreshToken: tokenData.refresh_token || null,
			email,
			account: email
		},
		expiresAt: Date.now() + ((tokenData.expires_in || 3600) * 1000),
		scopes: tokenData.scope || null
	})

	if (oauthState.sessionId) {
		db.links.create({
			sessionTokenId: oauthState.sessionId,
			appTokenId: appToken.id
		})
	}

	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(`<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:500px;margin:50px auto;padding:24px;border:1px solid #e2e8f0;border-radius:8px;text-align:center;"><h2>Google Account Connected!</h2><p>Connected Google account <strong>${email}</strong>.</p><p>You can close this window and return to your MCP agent.</p></body></html>`)
}

async function handleToken (req, res) {
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.end('Method Not Allowed')
		return
	}
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)
	const code = params.get('code')
	const redirectUri = params.get('redirect_uri')
	const codeVerifier = params.get('code_verifier')

	if (!code) {
		console.warn('[oauth] Token exchange failed: Missing code')
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_request', error_description: 'Missing code' }))
		return
	}
	const authCode = db.oauthCodes.consume(code)
	if (!authCode) {
		console.warn('[oauth] Token exchange failed: Invalid or expired authorization code')
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' }))
		return
	}
	if (authCode.clientRedirectUri && authCode.clientRedirectUri !== redirectUri) {
		console.warn(`[oauth] Token exchange failed: redirect_uri mismatch (expected "${authCode.clientRedirectUri}", got "${redirectUri}")`)
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }))
		return
	}
	if (authCode.codeChallenge) {
		if (!codeVerifier) {
			console.warn('[oauth] Token exchange failed: Missing code_verifier')
			res.statusCode = 400
			res.setHeader('content-type', 'application/json; charset=utf-8')
			res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Missing code_verifier' }))
			return
		}
		if (typeof codeVerifier !== 'string' || codeVerifier.length < 43 || codeVerifier.length > 128) {
			console.warn(`[oauth] Token exchange failed: code_verifier length invalid (${codeVerifier?.length})`)
			res.statusCode = 400
			res.setHeader('content-type', 'application/json; charset=utf-8')
			res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid code_verifier' }))
			return
		}
		if (!verifyCodeChallenge(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
			console.warn('[oauth] Token exchange failed: PKCE verification failed')
			res.statusCode = 400
			res.setHeader('content-type', 'application/json; charset=utf-8')
			res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid code_verifier' }))
			return
		}
	}
	const session = db.tokens.get(authCode.sessionId)
	if (!session) {
		console.warn('[oauth] Token exchange failed: Session not found')
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Session not found' }))
		return
	}
	res.statusCode = 200
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify({
		access_token: session.token,
		token_type: 'Bearer',
		expires_in: 30 * 24 * 60 * 60
	}))
}

async function handleRevoke (req, res) {
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'method_not_allowed' }))
		return
	}
	const rawBody = await getBody(req)
	let token = null
	try {
		const parsed = JSON.parse(rawBody)
		token = parsed?.token || null
	} catch {
		const params = new URLSearchParams(rawBody)
		token = params.get('token')
	}
	if (!token) {
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_request', error_description: 'Missing token parameter' }))
		return
	}
	const session = db.tokens.getByToken(token)
	if (session) {
		const links = db.links.listBySessionId(session.id)
		for (const link of links) {
			if (link.app?.provider === 'google') {
				const upstreamToken = link.app.credentials?.refreshToken || link.app.credentials?.accessToken
				if (upstreamToken) await revokeGoogleToken(upstreamToken)
			}
		}
		db.tokens.remove(session.id)
	}
	res.statusCode = 200
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify({ status: 'ok' }))
}

const routes = {
	'/.well-known/oauth-protected-resource': (req, res) => handleProtectedResourceMetadata(req, res),
	'/.well-known/oauth-authorization-server': (req, res) => handleAuthServerMetadata(req, res),
	'/oauth/authorize': (req, res, { query }) => handleAuthorize(req, res, query),
	'/oauth/authorize/consent': (req, res) => handleAuthorizeConsent(req, res),
	'/oauth/verify': (req, res, { query }) => handleVerify(req, res, query),
	'/oauth/callback': (req, res, { query }) => handleCallback(req, res, query),
	'/oauth/token': (req, res) => handleToken(req, res),
	'/oauth/revoke': (req, res) => handleRevoke(req, res),
	'/providers/google/connect': (req, res, { query }) => handleGoogleConnect(req, res, query),
	'/providers/google/consent': (req, res) => handleGoogleConsent(req, res),
	'/providers/google/callback': (req, res, { query }) => handleCallback(req, res, query)
}

async function handleOauth (req, res, { pathname, query }) {
	const handler = routes[pathname]
	if (!handler) {
		const err = new Error('not found')
		err.code = 404
		throw err
	}
	await handler(req, res, { query })
}
