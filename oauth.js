import { createHash, timingSafeEqual, randomUUID } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as db from './db/index.js'
import { getProvider, listAuthProviders, requireAuthProvider, parseGrantedServices, summarizeScopes } from './providers/index.js'
import { assertSsoLogin, assertSsoLink, shouldClaimUnscoped } from './sso.js'
import { getBody, sendJson } from './util.js'

export {
	handleOauth,
	handleAuthorize,
	handleAuthorizeConsent,
	isAllowedRedirectUri,
	deriveClientName,
	getBaseUrl
}

const dirname = path.dirname(fileURLToPath(import.meta.url))

const KNOWN_CLIENT_NAMES = {
	'antigravity.google': 'Google Antigravity',
	'claude.ai': 'Claude',
	'claude.com': 'Claude',
	'anthropic.com': 'Anthropic',
	'chatgpt.com': 'ChatGPT',
	'chat.openai.com': 'ChatGPT',
	'openai.com': 'OpenAI',
	'cursor.sh': 'Cursor',
	'cursor.com': 'Cursor',
	'windsurf.com': 'Windsurf',
	'codeium.com': 'Codeium',
	'vscode.dev': 'VS Code',
	'github.dev': 'GitHub'
}

const DISALLOWED_REDIRECT_SCHEMES = new Set([
	'javascript:',
	'data:',
	'vbscript:',
	'file:',
	'blob:',
	'about:'
])

function getBaseUrl (req) {
	if (req && req.headers && (req.headers['x-forwarded-host'] || req.headers.host)) {
		const rawHost = String(req.headers['x-forwarded-host'] || req.headers.host).split(',')[0].trim().toLowerCase()
		if (rawHost) {
			const isLocal = rawHost.startsWith('localhost') || rawHost.startsWith('127.0.0.1') || rawHost.startsWith('[::1]')
			const rawProto = String(req.headers['x-forwarded-proto'] || (isLocal ? 'http' : 'https')).split(',')[0].trim().toLowerCase()
			if (rawProto === 'http' || rawProto === 'https') {
				try {
					const candidate = `${rawProto}://${rawHost}`
					const parsed = new URL(candidate)
					if (!parsed.username && !parsed.password && (parsed.host === rawHost || parsed.origin === candidate)) {
						return parsed.origin
					}
				} catch {}
			}
		}
	}
	return 'http://localhost:8080'
}

function getClientIp (req) {
	return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || null
}

function enforceSso (res, fn) {
	try {
		fn()
		return true
	} catch (err) {
		if (err.status === 403) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end(`${err.message}.`)
			return false
		}
		throw err
	}
}

function escapeHtml (str) {
	return String(str || '')
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
}

function renderCardPage (title, subtitle, bodyHtml) {
	return `<!DOCTYPE html>
<html>
	<head>
		<meta charset=utf-8>
		<meta name="viewport" content="width=device-width,initial-scale=1">
		<title>${escapeHtml(title)}</title>
		<link rel="stylesheet" href="/style.css">
	</head>
	<body class=column>
		<div class="view column">
			<h1>jump</h1>
			<p class="subtitle">${subtitle}</p>
			${bodyHtml}
		</div>
	</body>
</html>`
}

function deriveClientName (clientId, explicitName) {
	if (explicitName && typeof explicitName === 'string' && explicitName.trim()) {
		return explicitName.trim()
	}
	if (!clientId || typeof clientId !== 'string') return null
	if (clientId.startsWith('https://')) {
		let parsed
		try {
			parsed = new URL(clientId)
		} catch {
			return null
		}
		const host = parsed.hostname.toLowerCase()
		for (const [domain, label] of Object.entries(KNOWN_CLIENT_NAMES)) {
			if (host === domain || host.endsWith(`.${domain}`)) {
				return label
			}
		}
		return host
	}
	if (clientId.startsWith('client_')) return null
	return clientId.trim() || null
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
	if (!redirectUri || typeof redirectUri !== 'string') return false
	let url
	try {
		url = new URL(redirectUri)
	} catch {
		return false
	}
	if (url.hash) return false
	const protocol = url.protocol.toLowerCase()
	if (DISALLOWED_REDIRECT_SCHEMES.has(protocol)) return false
	const hostname = url.hostname.toLowerCase()
	const isLoopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
	if (protocol === 'http:') {
		return isLoopback
	}
	if (protocol === 'https:' && isLoopback) {
		return true
	}
	const envDomains = process.env.ALLOWED_REDIRECT_DOMAINS || ''
	const allowedDomains = envDomains.split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
	if (protocol !== 'https:') {
		const scheme = protocol.replace(/:$/, '')
		return allowedDomains.includes(scheme) || allowedDomains.includes(`${scheme}:`)
	}
	return allowedDomains.some(domain => {
		if (domain.startsWith('*.')) {
			const root = domain.slice(2)
			return hostname === root || hostname.endsWith(`.${root}`)
		}
		return hostname === domain
	})
}

async function handleProtectedResourceMetadata (req, res, pathname = '') {
	const base = getBaseUrl(req)
	const prefix = '/.well-known/oauth-protected-resource'
	const suffix = pathname.startsWith(`${prefix}/`) ? pathname.slice(prefix.length) : '/mcp'
	sendJson(res, {
		resource: `${base}${suffix}`,
		authorization_servers: [base],
		bearer_methods_supported: ['header'],
		scopes_supported: ['mcp']
	})
}

async function handleAuthServerMetadata (req, res) {
	const base = getBaseUrl(req)
	sendJson(res, {
		issuer: base,
		authorization_endpoint: `${base}/oauth/authorize`,
		token_endpoint: `${base}/oauth/token`,
		registration_endpoint: `${base}/oauth/register`,
		revocation_endpoint: `${base}/oauth/revoke`,
		response_types_supported: ['code'],
		response_modes_supported: ['query'],
		grant_types_supported: ['authorization_code', 'refresh_token'],
		token_endpoint_auth_methods_supported: ['none'],
		revocation_endpoint_auth_methods_supported: ['none'],
		code_challenge_methods_supported: ['S256'],
		scopes_supported: ['mcp', 'offline_access', 'openid', 'profile', 'email'],
		client_id_metadata_document_supported: true
	})
}

async function handleRegister (req, res) {
	if (req.method !== 'POST') {
		sendJson(res, { error: 'method_not_allowed' }, 405)
		return
	}
	const rawBody = await getBody(req)
	let body = {}
	try {
		body = rawBody ? JSON.parse(rawBody) : {}
	} catch {
		sendJson(res, { error: 'invalid_client_metadata', error_description: 'Invalid JSON body' }, 400)
		return
	}
	const rawRedirects = body.redirect_uris
	const redirectUris = Array.isArray(rawRedirects) ? rawRedirects : (rawRedirects ? [rawRedirects] : [])
	if (redirectUris.length === 0) {
		sendJson(res, { error: 'invalid_client_metadata', error_description: 'redirect_uris is required' }, 400)
		return
	}
	for (const uri of redirectUris) {
		if (!isAllowedRedirectUri(uri)) {
			sendJson(res, { error: 'invalid_redirect_uri', error_description: `redirect_uri is not allowed: ${uri}` }, 400)
			return
		}
	}
	const grantTypes = (Array.isArray(body.grant_types) && body.grant_types.length > 0 && body.grant_types.every(x => typeof x === 'string'))
		? body.grant_types
		: ['authorization_code', 'refresh_token']
	const clientPrefix = grantTypes.includes('refresh_token') ? 'client_' : 'client_bearer_'
	const clientId = `${clientPrefix}${randomUUID()}`
	sendJson(res, {
		client_id: clientId,
		client_id_issued_at: Math.floor(Date.now() / 1000),
		client_name: body.client_name || 'MCP Client',
		redirect_uris: redirectUris,
		grant_types: grantTypes,
		response_types: body.response_types || ['code'],
		token_endpoint_auth_method: 'none'
	}, 201)
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

function resolveSetupState (setup, expectedMode, expectedProvider = null) {
	if (!setup || setup.mode !== expectedMode) return null
	if (expectedProvider && setup.provider && setup.provider !== expectedProvider) return null
	const session = setup.sessionId ? db.tokens.getActiveSession(setup.sessionId) : null
	if (!session || !session.admin) return null
	return session
}

async function handleAuthorize (req, res, query) {
	if (query.session_id !== undefined) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Access denied: invalid or expired setup code.')
		return
	}
	try {
		validateAuthorizeParams(query)
	} catch (err) {
		sendJson(res, { error: err.code || 'invalid_request', error_description: err.message }, err.status || 400)
		return
	}
	let linkMode = false
	let resolvedParams = query
	if (query.code !== undefined) {
		const setup = db.tokens.getState(query.code)
		const session = resolveSetupState(setup, 'setup_link')
		if (!session) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: invalid or expired setup code.')
			return
		}
		if (!enforceSso(res, () => assertSsoLink(db.logins.listByUserId(session.userId), setup.provider))) return
		linkMode = true
		resolvedParams = { ...query, ...(setup.provider && { provider: setup.provider }) }
	}
	const clientName = deriveClientName(query.client_id, query.client_name)
	const authProviders = listAuthProviders().map(p => ({ id: p.id, name: p.name }))
	const initData = {
		params: resolvedParams,
		providers: authProviders,
		localAuth: !linkMode && authProviders.length === 0,
		...(linkMode && { linkMode: true }),
		...(clientName && { clientName })
	}
	const authorizeHtml = await fs.readFile(path.join(dirname, 'public/authorize.html'), 'utf8')
	const html = authorizeHtml.replace('{{INIT_DATA}}', JSON.stringify(initData).replace(/</g, '\\u003c'))
	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(html)
}

function filterValidAppIds (userId, appIds = []) {
	const valid = []
	for (const appId of appIds) {
		const app = db.tokens.get(appId)
		if (app && app.userId === userId && db.tokens.isUpstreamApp(app, { allowShare: true })) {
			valid.push(app.id)
		}
	}
	return valid
}

function linkSessionApps (sessionId, userId, appIds = []) {
	for (const appId of filterValidAppIds(userId, appIds)) {
		db.links.create({
			sessionId,
			appId
		})
	}
}

function completeLogin (req, res, { user, clientId, clientRedirectUri, clientState, codeChallenge, codeChallengeMethod, sessionName, admin, ip, appIds = [] }) {
	const ua = req.headers['user-agent'] || null
	const name = sessionName || (admin ? 'Admin Session' : 'Default Session')
	const clientIp = ip || getClientIp(req)
	if (clientRedirectUri) {
		const authCode = db.tokens.createAuthCode({
			userId: user.id,
			sessionName: name,
			admin: admin ? 1 : 0,
			ip: clientIp,
			ua,
			appIds: filterValidAppIds(user.id, appIds),
			clientId,
			clientRedirectUri,
			codeChallenge,
			codeChallengeMethod
		})
		const target = new URL(clientRedirectUri)
		target.searchParams.set('code', authCode)
		if (clientState) target.searchParams.set('state', clientState)
		res.statusCode = 302
		res.setHeader('location', target.toString())
		res.end()
		return
	}
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		type: 'bearer',
		name,
		admin: admin ? 1 : 0,
		ip: clientIp,
		ua
	})
	linkSessionApps(session.id, user.id, appIds)
	res.statusCode = 200
	res.setHeader('content-type', 'text/plain; charset=utf-8')
	res.end(`user: ${db.logins.getAccountByUserId(user.id)}\ntoken: ${session.token}\n\nheader:\nAuthorization: Bearer ${session.token}\n`)
}

function redirectToVerifyOrComplete (req, res, base, opts) {
	const userApps = db.tokens.listByUserId(opts.user.id).filter(t => db.tokens.isUpstreamApp(t, { allowShare: true }))
	if (userApps.length === 0) {
		completeLogin(req, res, opts)
		return
	}
	const verifyCode = db.tokens.createState({
		mode: 'verify',
		userId: opts.user.id,
		provider: opts.provider || null,
		clientId: opts.clientId,
		clientRedirectUri: opts.clientRedirectUri,
		clientState: opts.clientState,
		codeChallenge: opts.codeChallenge,
		codeChallengeMethod: opts.codeChallengeMethod,
		sessionName: opts.sessionName,
		admin: opts.admin,
		ip: opts.ip
	})
	res.statusCode = 302
	res.setHeader('location', `${base}/oauth/verify?code=${verifyCode}`)
	res.end()
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
	let providerName = null
	let localToken = null
	let sessionName = null
	let setupCode = null
	let hasSessionId = false
	let admin = 0
	for (const [key, value] of params.entries()) {
		if (key === 'provider') {
			providerName = value.trim().toLowerCase() || null
		} else if (key === 'token') {
			localToken = value.trim() || null
		} else if (key === 'session_name') {
			sessionName = value.trim() || null
		} else if (key === 'code') {
			setupCode = value.trim() || null
		} else if (key === 'session_id') {
			hasSessionId = true
		} else if (key === 'admin') {
			admin = value === 'true' || value === '1' || value === 'on' ? 1 : 0
		} else {
			query[key] = value
		}
	}
	if (hasSessionId) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Access denied: invalid or expired setup code.')
		return
	}
	let validation
	try {
		validation = validateAuthorizeParams(query)
	} catch (err) {
		sendJson(res, { error: err.code || 'invalid_request', error_description: err.message }, err.status || 400)
		return
	}
	const { codeChallenge, codeChallengeMethod } = validation
	const clientId = query.client_id || null
	const clientRedirectUri = query.redirect_uri || null
	const clientState = query.state || null
	const derivedName = deriveClientName(query.client_id, query.client_name)
	const effectiveSessionName = sessionName || derivedName || null
	const ip = getClientIp(req)
	const base = getBaseUrl(req)
	if (!setupCode && localToken && !providerName) {
		if (listAuthProviders().length > 0) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: local token sign-in is disabled when OAuth providers are configured.')
			return
		}
		const adminSession = db.tokens.getByToken(localToken)
		const user = adminSession?.admin ? db.users.get(adminSession.userId) : null
		if (!user) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: valid admin bearer token required.')
			return
		}
		redirectToVerifyOrComplete(req, res, base, {
			user,
			clientId,
			clientRedirectUri,
			clientState,
			codeChallenge,
			codeChallengeMethod,
			sessionName: effectiveSessionName,
			admin,
			ip
		})
		return
	}
	let linkSession = null
	if (setupCode) {
		const setup = db.tokens.consumeState(setupCode)
		linkSession = resolveSetupState(setup, 'setup_link')
		if (!linkSession) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: invalid or expired setup code.')
			return
		}
		if (setup.provider) {
			if (providerName && providerName !== setup.provider) {
				res.statusCode = 403
				res.setHeader('content-type', 'text/plain')
				res.end('Access denied: provider mismatch for setup code.')
				return
			}
			providerName = setup.provider
		}
	}
	if (!providerName) {
		sendJson(res, { error: 'invalid_request', error_description: 'OAuth provider or admin token is required' }, 400)
		return
	}
	let provider
	try {
		provider = requireAuthProvider(providerName)
	} catch (err) {
		sendJson(res, { error: 'invalid_request', error_description: err.message }, err.status || 400)
		return
	}
	if (linkSession && !enforceSso(res, () => assertSsoLink(db.logins.listByUserId(linkSession.userId), provider.id))) return
	const callbackUrl = `${base}/oauth/callback`
	const stateToken = db.tokens.createState({
		mode: linkSession ? 'auth' : 'login',
		provider: provider.id,
		clientId,
		clientRedirectUri,
		clientState,
		codeChallenge,
		codeChallengeMethod,
		sessionName: effectiveSessionName,
		admin,
		sessionId: linkSession ? linkSession.id : null,
		ip
	})
	let authUrl
	try {
		authUrl = provider.buildAuthUrl({
			state: stateToken,
			callbackUrl,
			login: true
		})
	} catch (err) {
		res.statusCode = err.status || 500
		res.setHeader('content-type', 'text/plain')
		res.end(err.message)
		return
	}
	res.statusCode = 302
	res.setHeader('location', authUrl)
	res.end()
}

async function handleVerify (req, res, query) {
	if (req.method === 'GET') {
		const code = query.code
		if (!code || !/^[a-zA-Z0-9_-]+$/.test(code)) {
			res.statusCode = 400
			res.setHeader('content-type', 'text/plain')
			res.end('Invalid or expired verification code')
			return
		}
		const state = db.tokens.getState(code)
		const existingUser = state?.mode === 'verify' && state.userId ? db.users.get(state.userId) : null
		if (!existingUser) {
			res.statusCode = 400
			res.setHeader('content-type', 'text/plain')
			res.end('Invalid or expired verification code')
			return
		}
		const userApps = db.tokens.listByUserId(existingUser.id).filter(t => db.tokens.isUpstreamApp(t, { allowShare: true }))
		let appsHtml = ''
		if (userApps.length > 0) {
			const checkedAttr = state.admin ? ' checked' : ''
			const items = userApps.map(app => {
				const provider = getProvider(app.provider)
				const account = app.credentials?.account || ''
				const scopeSummary = summarizeScopes(app.scopes, provider?.services)
				const baseName = app.name || provider?.name || `${app.provider} app`
				const label = scopeSummary ? `${baseName} · ${scopeSummary}` : baseName
				return `<label class="app-item"><input type="checkbox" name="app_id" value="${escapeHtml(app.id)}"${checkedAttr}><span>${escapeHtml(label)}</span>${account ? `<span class="app-meta">${escapeHtml(account)}</span>` : ''}</label>`
			}).join('')
			appsHtml = `<div class="app-list"><div class="app-list-title">Link connected apps</div>${items}</div>`
		}
		const displayAccount = db.logins.getAccountByUserId(existingUser.id)
		res.statusCode = 200
		res.setHeader('content-type', 'text/html; charset=utf-8')
		res.end(renderCardPage(
			'jump verify',
			`Activate session for <strong>${escapeHtml(displayAccount)}</strong>`,
			`<form method="POST" action="/oauth/verify"><input type="hidden" name="code" value="${escapeHtml(code)}">${appsHtml}<button type="submit">Continue</button></form>`
		))
		return
	}
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.end('Method Not Allowed')
		return
	}
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)
	const code = params.get('code') || query.code
	if (!code) {
		res.statusCode = 400
		res.setHeader('content-type', 'text/plain')
		res.end('Missing verification code.')
		return
	}
	const state = db.tokens.consumeState(code)
	const user = state?.mode === 'verify' && state.userId ? db.users.get(state.userId) : null
	if (!user) {
		res.statusCode = 400
		res.setHeader('content-type', 'text/plain')
		res.end('Invalid or expired verification code')
		return
	}
	completeLogin(req, res, {
		user,
		clientId: state.clientId,
		clientRedirectUri: state.clientRedirectUri,
		clientState: state.clientState,
		codeChallenge: state.codeChallenge,
		codeChallengeMethod: state.codeChallengeMethod,
		sessionName: state.sessionName,
		admin: state.admin,
		ip: state.ip,
		appIds: params.getAll('app_id')
	})
}

function getOwnedOauthApp (session, appId, providerId) {
	if (!session?.admin || !appId) return null
	const app = db.tokens.get(appId)
	if (!app || app.userId !== session.userId || app.provider !== providerId || app.type !== 'oauth') return null
	return app
}

async function handleProviderConnect (req, res, query, providerName = 'google') {
	const provider = getProvider(providerName)
	if (!provider || provider.type !== 'oauth') {
		const err = new Error('not found')
		err.status = 404
		throw err
	}
	if (query.session_id !== undefined) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Access denied: invalid or expired setup code.')
		return
	}
	const resolvedParams = { ...query }
	delete resolvedParams.reauth_app_id
	if (query.code !== undefined) {
		const setup = db.tokens.getState(query.code)
		const session = resolveSetupState(setup, 'setup_connect', provider.id)
		if (!session) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: invalid or expired setup code.')
			return
		}
		if (setup.reauthAppId) {
			const existingApp = getOwnedOauthApp(session, setup.reauthAppId, provider.id)
			if (!existingApp) {
				res.statusCode = 403
				res.setHeader('content-type', 'text/plain')
				res.end('Access denied: unauthorized re-authentication request.')
				return
			}
			resolvedParams.reauth_app_id = setup.reauthAppId
			if (query.services === undefined && query.write === undefined && provider.services && existingApp.scopes) {
				const granted = parseGrantedServices(existingApp.scopes, provider.services)
				if (granted.length > 0) {
					resolvedParams.services = granted.map(g => g.id).join(',')
					const rwIds = granted.filter(g => g.mode === 'rw').map(g => g.id)
					if (rwIds.length > 0) resolvedParams.write = rwIds.join(',')
				}
			}
		} else if (setup.sessionName && !resolvedParams.name && !resolvedParams.app_name) {
			resolvedParams.name = setup.sessionName
		}
	}
	const initData = {
		params: resolvedParams,
		provider: { id: provider.id, name: provider.name },
		...(provider.services && {
			services: Object.values(provider.services).map(s => ({
				id: s.id,
				name: s.name,
				ro: Boolean(s.ro?.length),
				rw: Boolean(s.rw?.length) && JSON.stringify(s.rw) !== JSON.stringify(s.ro)
			}))
		})
	}
	const connectHtml = await fs.readFile(path.join(dirname, 'public/connect.html'), 'utf8')
	const html = connectHtml.replace('{{INIT_DATA}}', JSON.stringify(initData).replace(/</g, '\\u003c'))
	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(html)
}

async function handleProviderConsent (req, res, providerName = 'google') {
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.end('Method Not Allowed')
		return
	}
	const provider = getProvider(providerName)
	if (!provider || provider.type !== 'oauth' || !provider.buildAuthUrl) {
		const err = new Error('not found')
		err.status = 404
		throw err
	}
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)
	const servicesList = []
	for (const v of params.getAll('services')) {
		for (const s of v.split(',')) {
			const clean = s.trim().toLowerCase()
			if (clean) servicesList.push(clean)
		}
	}
	const writeList = []
	for (const v of params.getAll('write')) {
		for (const s of v.split(',')) {
			const clean = s.trim().toLowerCase()
			if (clean) writeList.push(clean)
		}
	}
	if (params.has('session_id')) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Access denied: admin session required.')
		return
	}
	const setupCode = params.get('code') || null
	const setup = db.tokens.consumeState(setupCode)
	const session = resolveSetupState(setup, 'setup_connect', provider.id)
	if (!session) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Access denied: admin session required.')
		return
	}
	const reauthAppId = setup.reauthAppId || null
	if (params.get('reauth_app_id') && params.get('reauth_app_id') !== reauthAppId) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Access denied: unauthorized re-authentication request.')
		return
	}
	let existingApp = null
	if (reauthAppId) {
		existingApp = getOwnedOauthApp(session, reauthAppId, provider.id)
		if (!existingApp) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: unauthorized re-authentication request.')
			return
		}
	}
	const rawAppName = params.get('app_name') || params.get('name') || setup.sessionName || ''
	const sessionName = rawAppName ? String(rawAppName).trim() : null
	const base = getBaseUrl(req)
	const callbackUrl = `${base}/oauth/callback`
	const ip = getClientIp(req)
	const stateToken = db.tokens.createState({
		mode: 'connect',
		sessionId: session.id,
		reauthAppId,
		sessionName,
		provider: provider.id,
		ip
	})
	let authUrl
	try {
		authUrl = provider.buildAuthUrl({
			state: stateToken,
			callbackUrl,
			services: servicesList,
			write: writeList,
			loginHint: existingApp?.credentials?.account || null
		})
	} catch (err) {
		res.statusCode = err.status || 500
		res.setHeader('content-type', 'text/plain')
		res.end(err.message)
		return
	}
	res.statusCode = 302
	res.setHeader('location', authUrl)
	res.end()
}

async function handleCallback (req, res, query) {
	const code = query.code
	const rawState = query.state
	if (!code) {
		res.statusCode = 400
		res.setHeader('content-type', 'text/plain')
		res.end(`OAuth Error: ${query.error || 'no code'}`)
		return
	}
	const oauthState = db.tokens.consumeState(rawState)
	if (!oauthState || (oauthState.mode !== null && oauthState.mode !== 'connect' && oauthState.mode !== 'auth' && oauthState.mode !== 'login')) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Invalid or expired OAuth state (CSRF verification failed). Please try connecting again.')
		return
	}
	const provider = getProvider(oauthState.provider || 'google')
	const base = getBaseUrl(req)
	const callbackUrl = `${base}/oauth/callback`
	let exchanged
	try {
		exchanged = await provider.exchangeCode({ code, callbackUrl })
	} catch (err) {
		console.error(`${provider.name} token exchange failed:`, err.data || err.message)
		res.statusCode = err.status || 502
		res.setHeader('content-type', 'text/plain')
		res.end(err.message)
		return
	}
	const { accessToken, refreshToken, expiresAt, scopes, account } = exchanged
	if (oauthState.mode === 'auth') {
		const session = oauthState.sessionId ? db.tokens.getActiveSession(oauthState.sessionId) : null
		if (!session || !session.admin) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: admin session required.')
			return
		}
		const cleanAccount = String(account).trim().toLowerCase()
		if (!enforceSso(res, () => assertSsoLink(db.logins.listByUserId(session.userId), provider.id, cleanAccount))) return
		const allowUnscoped = shouldClaimUnscoped(provider.id, cleanAccount, { verifiedEmail: provider.verifiedEmail })
		try {
			db.logins.upsert({
				userId: session.userId,
				provider: provider.id,
				account: cleanAccount,
				allowUnscoped
			})
		} catch (err) {
			if (err.status === 409) {
				res.statusCode = 409
				res.setHeader('content-type', 'text/plain')
				res.end(`${err.message}.`)
				return
			}
			throw err
		}
		res.statusCode = 200
		res.setHeader('content-type', 'text/html; charset=utf-8')
		res.end(renderCardPage(
			'Login Linked',
			`Linked <strong>${escapeHtml(cleanAccount)}</strong>`,
			`<p class="subtitle">You can close this window and return to your agent.</p>`
		))
		return
	}
	if (oauthState.mode === 'login') {
		const cleanAccount = String(account).trim().toLowerCase()
		if (!enforceSso(res, () => assertSsoLogin(provider.id, cleanAccount))) return
		const allowUnscoped = shouldClaimUnscoped(provider.id, cleanAccount, { verifiedEmail: provider.verifiedEmail })
		const user = db.logins.resolveUser(provider.id, cleanAccount, { allowUnscoped })
		redirectToVerifyOrComplete(req, res, base, {
			user,
			provider: provider.id,
			clientId: oauthState.clientId,
			clientRedirectUri: oauthState.clientRedirectUri,
			clientState: oauthState.clientState,
			codeChallenge: oauthState.codeChallenge,
			codeChallengeMethod: oauthState.codeChallengeMethod,
			sessionName: oauthState.sessionName,
			admin: oauthState.admin,
			ip: oauthState.ip
		})
		return
	}
	const session = oauthState.sessionId ? db.tokens.getActiveSession(oauthState.sessionId) : null
	if (!session || !session.admin) {
		res.statusCode = 403
		res.setHeader('content-type', 'text/plain')
		res.end('Access denied: admin session required.')
		return
	}
	if (oauthState.reauthAppId) {
		const existingApp = getOwnedOauthApp(session, oauthState.reauthAppId, provider.id)
		if (!existingApp) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: unauthorized re-authentication request.')
			return
		}
		const expectedAccount = existingApp.credentials?.account
		if (expectedAccount && String(account).trim().toLowerCase() !== String(expectedAccount).trim().toLowerCase()) {
			res.statusCode = 409
			res.setHeader('content-type', 'text/plain')
			res.end(`Re-authentication failed: expected account "${expectedAccount}", got "${account}".`)
			return
		}
		const updatedCreds = {
			...existingApp.credentials,
			accessToken,
			refreshToken: refreshToken || existingApp.credentials?.refreshToken || null,
			account
		}
		db.tokens.updateCredentials(existingApp.id, {
			credentials: updatedCreds,
			expiresAt,
			scopes: scopes || existingApp.scopes
		})
		res.statusCode = 200
		res.setHeader('content-type', 'text/html; charset=utf-8')
		res.end(renderCardPage(
			`${provider.name} Re-authenticated`,
			`${escapeHtml(provider.name)} credentials updated`,
			`<p class="subtitle">Linked sessions will resume automatically.</p>`
		))
		return
	}
	const appName = oauthState.sessionName || provider.name
	const appToken = db.tokens.create({
		userId: session.userId,
		provider: provider.id,
		type: 'oauth',
		name: appName,
		credentials: {
			accessToken,
			refreshToken: refreshToken || null,
			account
		},
		expiresAt,
		scopes: scopes || null
	})
	db.links.create({
		sessionId: session.id,
		appId: appToken.id
	})
	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(renderCardPage(
		`${provider.name} Connected`,
		`Connected <strong>${escapeHtml(account)}</strong>`,
		`<p class="subtitle">You can close this window and return to your agent.</p>`
	))
}

function parseTokenParams (rawBody, req) {
	if (!rawBody || !rawBody.trim()) return {}
	const contentType = String(req?.headers?.['content-type'] || '').split(';')[0].trim().toLowerCase()
	const trimmed = rawBody.trim()
	if (contentType === 'application/json' || contentType.endsWith('+json') || trimmed.startsWith('{')) {
		let parsed
		try {
			parsed = JSON.parse(trimmed)
		} catch {
			const err = new Error('Invalid JSON body')
			err.status = 400
			throw err
		}
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
			const err = new Error('Invalid JSON body')
			err.status = 400
			throw err
		}
		return parsed
	}
	return Object.fromEntries(new URLSearchParams(rawBody))
}

async function handleToken (req, res) {
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.end('Method Not Allowed')
		return
	}
	const rawBody = await getBody(req)
	let params
	try {
		params = parseTokenParams(rawBody, req)
	} catch (err) {
		sendJson(res, { error: 'invalid_request', error_description: err.message }, err.status || 400)
		return
	}
	const grantType = params.grant_type || 'authorization_code'
	if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
		sendJson(res, { error: 'unsupported_grant_type', error_description: `Unsupported grant_type: ${grantType}` }, 400)
		return
	}
	const noStoreHeaders = { 'cache-control': 'no-store', pragma: 'no-cache' }
	if (grantType === 'refresh_token') {
		const refreshToken = params.refresh_token
		if (!refreshToken) {
			console.warn('[oauth] Token refresh failed: Missing refresh_token')
			sendJson(res, { error: 'invalid_request', error_description: 'Missing refresh_token' }, 400)
			return
		}
		const session = db.tokens.refreshOauthSession(refreshToken)
		if (!session) {
			console.warn('[oauth] Token refresh failed: Invalid or expired refresh token')
			sendJson(res, { error: 'invalid_grant', error_description: 'Invalid or expired refresh token' }, 400)
			return
		}
		const expiresIn = session.expiresAt ? Math.max(1, Math.ceil((session.expiresAt - Date.now()) / 1000)) : 3600
		sendJson(res, {
			access_token: session.token,
			refresh_token: session.credentials?.refreshToken,
			token_type: 'Bearer',
			expires_in: expiresIn,
			scope: 'mcp'
		}, 200, noStoreHeaders)
		return
	}
	const code = params.code
	const redirectUri = params.redirect_uri
	const codeVerifier = params.code_verifier
	if (!code) {
		console.warn('[oauth] Token exchange failed: Missing code')
		sendJson(res, { error: 'invalid_request', error_description: 'Missing code' }, 400)
		return
	}
	const authCode = db.tokens.consumeAuthCode(code)
	if (!authCode) {
		console.warn('[oauth] Token exchange failed: Invalid or expired authorization code')
		sendJson(res, { error: 'invalid_grant', error_description: 'Invalid or expired authorization code' }, 400)
		return
	}
	if (authCode.clientRedirectUri && authCode.clientRedirectUri !== redirectUri) {
		console.warn(`[oauth] Token exchange failed: redirect_uri mismatch (expected "${authCode.clientRedirectUri}", got "${redirectUri}")`)
		sendJson(res, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400)
		return
	}
	if (authCode.clientId && params.client_id && authCode.clientId !== params.client_id) {
		console.warn(`[oauth] Token exchange failed: client_id mismatch (expected "${authCode.clientId}", got "${params.client_id}")`)
		sendJson(res, { error: 'invalid_grant', error_description: 'client_id mismatch' }, 400)
		return
	}
	if (authCode.codeChallenge) {
		if (!codeVerifier) {
			console.warn('[oauth] Token exchange failed: Missing code_verifier')
			sendJson(res, { error: 'invalid_grant', error_description: 'Missing code_verifier' }, 400)
			return
		}
		if (typeof codeVerifier !== 'string' || codeVerifier.length < 43 || codeVerifier.length > 128) {
			console.warn(`[oauth] Token exchange failed: code_verifier length invalid (${codeVerifier?.length})`)
			sendJson(res, { error: 'invalid_grant', error_description: 'Invalid code_verifier' }, 400)
			return
		}
		if (!verifyCodeChallenge(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)) {
			console.warn('[oauth] Token exchange failed: PKCE verification failed')
			sendJson(res, { error: 'invalid_grant', error_description: 'Invalid code_verifier' }, 400)
			return
		}
	}
	const user = authCode.userId ? db.users.get(authCode.userId) : null
	if (!user) {
		console.warn('[oauth] Token exchange failed: User not found')
		sendJson(res, { error: 'invalid_grant', error_description: 'User not found' }, 400)
		return
	}
	const withRefresh = !authCode.clientId?.startsWith('client_bearer_')
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		type: 'bearer',
		name: authCode.sessionName || (authCode.admin ? 'Admin Session' : 'Default Session'),
		credentials: withRefresh ? { refreshToken: randomUUID() } : null,
		expiresAt: withRefresh ? Date.now() + 3600 * 1000 : null,
		admin: authCode.admin ? 1 : 0,
		ip: authCode.ip || getClientIp(req),
		ua: req.headers['user-agent'] || authCode.ua || null
	})
	linkSessionApps(session.id, user.id, authCode.appIds)
	if (!withRefresh) {
		sendJson(res, {
			access_token: session.token,
			token_type: 'Bearer',
			scope: 'mcp'
		}, 200, noStoreHeaders)
		return
	}
	sendJson(res, {
		access_token: session.token,
		refresh_token: session.credentials?.refreshToken,
		token_type: 'Bearer',
		expires_in: 3600,
		scope: 'mcp'
	}, 200, noStoreHeaders)
}

async function handleRevoke (req, res) {
	if (req.method !== 'POST') {
		sendJson(res, { error: 'method_not_allowed' }, 405)
		return
	}
	const rawBody = await getBody(req)
	let params
	try {
		params = parseTokenParams(rawBody, req)
	} catch (err) {
		sendJson(res, { error: 'invalid_request', error_description: err.message }, err.status || 400)
		return
	}
	const token = typeof params.token === 'string' ? params.token.trim() : ''
	if (!token) {
		sendJson(res, { error: 'invalid_request', error_description: 'Missing token parameter' }, 400)
		return
	}
	const session = db.tokens.findRevocable(token)
	if (session) {
		db.tokens.remove(session.id)
	}
	sendJson(res, { status: 'ok' })
}

const routes = {
	'/oauth/register': (req, res) => handleRegister(req, res),
	'/oauth/authorize': (req, res, { query }) => handleAuthorize(req, res, query),
	'/oauth/authorize/consent': (req, res) => handleAuthorizeConsent(req, res),
	'/oauth/verify': (req, res, { query }) => handleVerify(req, res, query),
	'/oauth/callback': (req, res, { query }) => handleCallback(req, res, query),
	'/oauth/token': (req, res) => handleToken(req, res),
	'/oauth/revoke': (req, res) => handleRevoke(req, res)
}

async function handleOauth (req, res, { pathname, query }) {
	if (pathname === '/.well-known/oauth-protected-resource' || pathname.startsWith('/.well-known/oauth-protected-resource/')) {
		await handleProtectedResourceMetadata(req, res, pathname)
		return
	}
	if (
		pathname === '/.well-known/oauth-authorization-server' ||
		pathname.startsWith('/.well-known/oauth-authorization-server/') ||
		pathname === '/.well-known/openid-configuration' ||
		pathname.startsWith('/.well-known/openid-configuration/')
	) {
		await handleAuthServerMetadata(req, res)
		return
	}
	const handler = routes[pathname]
	if (handler) {
		await handler(req, res, { query })
		return
	}
	const providerMatch = pathname.match(/^\/providers\/([a-z0-9_-]+)\/(connect|consent)$/i)
	if (providerMatch) {
		const [, providerName, action] = providerMatch
		const id = providerName.toLowerCase()
		if (action === 'connect') {
			await handleProviderConnect(req, res, query, id)
			return
		}
		if (action === 'consent') {
			await handleProviderConsent(req, res, id)
			return
		}
	}
	const err = new Error('not found')
	err.status = 404
	throw err
}
