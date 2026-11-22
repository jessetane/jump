import { createHash, timingSafeEqual, randomUUID } from 'node:crypto'
import fs from 'node:fs'
import * as db from './db/index.js'
import { getProvider, listAuthProviders, requireAuthProvider, parseGrantedServices, summarizeScopes } from './providers/index.js'
import { assertSsoLogin, assertSsoLink, shouldClaimUnscoped } from './sso.js'
import { getBody, getBaseUrl, getClientIp, isPlainObject, sendJson, sendText, sendHtml, redirect, isLoopbackHost } from './util.js'

export {
	handleOauth,
	handleAuthorize,
	handleAuthorizeConsent,
	isAllowedRedirectUri,
	deriveClientName
}

const AUTHORIZE_HTML = fs.readFileSync(new URL('./public/authorize.html', import.meta.url), 'utf8')
const CONNECT_HTML = fs.readFileSync(new URL('./public/connect.html', import.meta.url), 'utf8')

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

function checkFormOrigin (req, res) {
	const origin = req.headers.origin
	if (!origin) return true
	if (origin === 'null' || origin.toLowerCase() !== getBaseUrl(req).toLowerCase()) {
		sendText(res, 'Forbidden: cross-origin form submission.', 403)
		return false
	}
	return true
}

function enforceSso (res, fn) {
	try {
		fn()
		return true
	} catch (err) {
		if (err.status === 403) {
			sendText(res, `${err.message}.`, 403)
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

function encodeClientLabel (name) {
	if (typeof name !== 'string') return ''
	const clean = name.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 64)
	if (!clean || clean === 'MCP Client') return ''
	return Buffer.from(clean, 'utf8').toString('base64url')
}

function decodeClientLabel (clientId) {
	const match = clientId.match(/^client_(?:bearer_)?[0-9a-f-]{36}_([A-Za-z0-9_-]{1,120})$/i)
	if (!match) return null
	try {
		const decoded = Buffer.from(match[1], 'base64url').toString('utf8').replace(/[\x00-\x1f\x7f]/g, '').trim()
		return decoded || null
	} catch {
		return null
	}
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
	if (clientId.startsWith('client_')) return decodeClientLabel(clientId)
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
	if (url.hash || url.username || url.password) return false
	const protocol = url.protocol.toLowerCase()
	if (DISALLOWED_REDIRECT_SCHEMES.has(protocol)) return false
	const hostname = url.hostname.toLowerCase()
	const isLoopback = isLoopbackHost(hostname)
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
	if (!isPlainObject(body)) {
		sendJson(res, { error: 'invalid_client_metadata', error_description: 'JSON body must be an object' }, 400)
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
	const encodedLabel = encodeClientLabel(body.client_name)
	const clientId = `${clientPrefix}${randomUUID()}${encodedLabel ? `_${encodedLabel}` : ''}`
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
	try {
		validateAuthorizeParams(query)
	} catch (err) {
		sendJson(res, { error: err.code || 'invalid_request', error_description: err.message }, err.status || 400)
		return
	}
	let linkMode = false
	let linkAccount = null
	let linkLogins = null
	let mergeMode = false
	let resolvedParams = query
	if (query.code !== undefined) {
		const setup = db.tokens.getState(query.code)
		const session = resolveSetupState(setup, 'setup_link')
		if (!session) {
			sendText(res, 'Access denied: invalid or expired setup code.', 403)
			return
		}
		linkLogins = db.logins.listByUserId(session.userId)
		if (setup.provider && !enforceSso(res, () => assertSsoLink(linkLogins, setup.provider))) return
		linkMode = true
		linkAccount = db.logins.getAccountByUserId(session.userId)
		mergeMode = Boolean(setup.merge)
		resolvedParams = { ...query, ...(setup.provider && { provider: setup.provider }) }
	}
	const clientName = deriveClientName(query.client_id, query.client_name)
	let authProviders = listAuthProviders().map(p => ({ id: p.id, name: p.name }))
	if (linkMode && !resolvedParams.provider && linkLogins) {
		authProviders = authProviders.filter(p => {
			try {
				assertSsoLink(linkLogins, p.id)
				return true
			} catch {
				return false
			}
		})
	}
	const initData = {
		params: resolvedParams,
		providers: authProviders,
		localAuth: !linkMode && authProviders.length === 0,
		...(linkMode && { linkMode: true, linkAccount, ...(mergeMode && { mergeMode: true }) }),
		...(clientName && { clientName })
	}
	sendHtml(res, AUTHORIZE_HTML.replace('{{INIT_DATA}}', () => JSON.stringify(initData).replace(/</g, '\\u003c')))
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

function completeLogin (req, res, { user, clientId, clientRedirectUri, clientState, codeChallenge, codeChallengeMethod, name: rawName, admin, ip, appIds = [] }) {
	const ua = req.headers['user-agent'] || null
	const name = rawName || (admin ? 'Admin Session' : 'Default Session')
	const clientIp = ip || getClientIp(req)
	if (clientRedirectUri) {
		const authCode = db.tokens.createAuthCode({
			userId: user.id,
			name,
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
		redirect(res, target.toString())
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
	res.setHeader('cache-control', 'no-store')
	sendText(res, `user: ${db.logins.getAccountByUserId(user.id)}\ntoken: ${session.token}\n\nheader:\nAuthorization: Bearer ${session.token}\n`)
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
		name: opts.name,
		admin: opts.admin,
		ip: opts.ip
	})
	redirect(res, `${base}/oauth/verify?code=${verifyCode}`)
}

async function handleAuthorizeConsent (req, res) {
	if (req.method !== 'POST') {
		sendText(res, 'Method Not Allowed', 405)
		return
	}
	if (!checkFormOrigin(req, res)) return
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)
	const query = {}
	let providerName = null
	let localToken = null
	let sessionName = null
	let setupCode = null
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
		} else if (key === 'admin') {
			admin = value === 'true' || value === '1' || value === 'on' ? 1 : 0
		} else {
			query[key] = value
		}
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
	const name = sessionName || derivedName || null
	const ip = getClientIp(req)
	const base = getBaseUrl(req)
	if (!setupCode && localToken && !providerName) {
		if (listAuthProviders().length > 0) {
			sendText(res, 'Access denied: local token sign-in is disabled when OAuth providers are configured.', 403)
			return
		}
		const adminSession = db.tokens.getByToken(localToken)
		const user = adminSession?.admin ? db.users.get(adminSession.userId) : null
		if (!user) {
			sendText(res, 'Access denied: valid admin bearer token required.', 403)
			return
		}
		redirectToVerifyOrComplete(req, res, base, {
			user,
			clientId,
			clientRedirectUri,
			clientState,
			codeChallenge,
			codeChallengeMethod,
			name,
			admin,
			ip
		})
		return
	}
	let linkSession = null
	let linkMerge = false
	if (setupCode) {
		const setup = db.tokens.getState(setupCode)
		linkSession = resolveSetupState(setup, 'setup_link')
		if (!linkSession) {
			sendText(res, 'Access denied: invalid or expired setup code.', 403)
			return
		}
		linkMerge = Boolean(setup.merge)
		if (setup.provider) {
			if (providerName && providerName !== setup.provider) {
				sendText(res, 'Access denied: provider mismatch for setup code.', 403)
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
	if (setupCode) {
		const consumed = db.tokens.consumeState(setupCode)
		linkSession = resolveSetupState(consumed, 'setup_link')
		if (!linkSession) {
			sendText(res, 'Access denied: invalid or expired setup code.', 403)
			return
		}
		linkMerge = Boolean(consumed.merge)
	}
	const callbackUrl = `${base}/oauth/callback`
	const stateToken = db.tokens.createState({
		mode: linkSession ? 'auth' : 'login',
		provider: provider.id,
		clientId,
		clientRedirectUri,
		clientState,
		codeChallenge,
		codeChallengeMethod,
		name,
		admin,
		merge: linkMerge,
		sessionId: linkSession ? linkSession.id : null,
		ip
	})
	const authUrl = provider.buildAuthUrl({
		state: stateToken,
		callbackUrl,
		login: true
	})
	redirect(res, authUrl)
}

function renderAuthResult (res, merged, account) {
	sendHtml(res, renderCardPage(
		merged ? 'Accounts Merged' : 'Login Linked',
		merged ? `Merged <strong>${escapeHtml(account)}</strong>` : `Linked <strong>${escapeHtml(account)}</strong>`,
		`<p class="subtitle">You can close this window and return to your agent.</p>`
	))
}

function appIdentityKey (app) {
	return app.type === 'share' ? `share:${app.credentials?.appId || app.id}` : `app:${app.id}`
}

async function handleVerify (req, res, query) {
	if (req.method === 'GET') {
		const code = query.code
		if (!code || !/^[a-zA-Z0-9_-]+$/.test(code)) {
			sendText(res, 'Invalid or expired verification code', 400)
			return
		}
		const state = db.tokens.getState(code)
		const existingUser = state?.mode === 'verify' && state.userId ? db.users.get(state.userId) : null
		const targetSession = state?.sessionId ? db.tokens.getActiveSession(state.sessionId) : null
		if (!existingUser || (state.sessionId && (!targetSession || targetSession.userId !== existingUser.id))) {
			sendText(res, 'Invalid or expired verification code', 400)
			return
		}
		const userApps = db.tokens.listByUserId(existingUser.id).filter(t => db.tokens.isUpstreamApp(t, { allowShare: true }))
		let appsHtml = ''
		if (userApps.length > 0) {
			const linkedIds = targetSession ? new Set(db.links.listBySessionId(targetSession.id).map(l => l.appId)) : null
			const newIds = targetSession ? new Set(state.newAppIds || []) : null
			const items = userApps.map(app => {
				const provider = getProvider(app.provider)
				const account = app.credentials?.account || ''
				const scopeSummary = summarizeScopes(app.scopes, provider?.services)
				const baseName = app.name || provider?.name || `${app.provider} app`
				const label = scopeSummary ? `${baseName} · ${scopeSummary}` : baseName
				const isChecked = targetSession
					? (linkedIds.has(app.id) || (Boolean(state.admin) && newIds.has(app.id)))
					: Boolean(state.admin)
				const checkedAttr = isChecked ? ' checked' : ''
				return `<label class="app-item"><input type="checkbox" name="app_id" value="${escapeHtml(app.id)}"${checkedAttr}><span>${escapeHtml(label)}</span>${account ? `<span class="app-meta">${escapeHtml(account)}</span>` : ''}</label>`
			}).join('')
			appsHtml = `<div class="app-list"><div class="app-list-title">Link connected apps</div>${items}</div>`
		}
		const displayAccount = db.logins.getAccountByUserId(existingUser.id)
		const actionVerb = targetSession ? 'Update' : 'Activate'
		sendHtml(res, renderCardPage(
			'jump verify',
			`${actionVerb} session for <strong>${escapeHtml(displayAccount)}</strong>`,
			`<form method="POST" action="/oauth/verify"><input type="hidden" name="code" value="${escapeHtml(code)}">${appsHtml}<button type="submit">Continue</button></form>`
		))
		return
	}
	if (req.method !== 'POST') {
		sendText(res, 'Method Not Allowed', 405)
		return
	}
	if (!checkFormOrigin(req, res)) return
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)
	const code = params.get('code') || query.code
	if (!code) {
		sendText(res, 'Missing verification code.', 400)
		return
	}
	const state = db.tokens.consumeState(code)
	const user = state?.mode === 'verify' && state.userId ? db.users.get(state.userId) : null
	if (!user) {
		sendText(res, 'Invalid or expired verification code', 400)
		return
	}
	if (state.sessionId) {
		const targetSession = db.tokens.getActiveSession(state.sessionId)
		if (!targetSession || targetSession.userId !== user.id) {
			sendText(res, 'Invalid or expired verification code', 400)
			return
		}
		const selectedIds = new Set(filterValidAppIds(user.id, params.getAll('app_id')))
		const existingLinkedIds = new Set(db.links.listBySessionId(targetSession.id).map(l => l.appId))
		for (const appId of selectedIds) {
			if (!existingLinkedIds.has(appId)) {
				db.links.create({ sessionId: targetSession.id, appId })
			}
		}
		for (const appId of existingLinkedIds) {
			if (!selectedIds.has(appId)) {
				db.links.remove(targetSession.id, appId)
			}
		}
		renderAuthResult(res, state.merge, state.name || db.logins.getAccountByUserId(user.id))
		return
	}
	completeLogin(req, res, {
		user,
		clientId: state.clientId,
		clientRedirectUri: state.clientRedirectUri,
		clientState: state.clientState,
		codeChallenge: state.codeChallenge,
		codeChallengeMethod: state.codeChallengeMethod,
		name: state.name,
		admin: state.admin,
		ip: state.ip,
		appIds: params.getAll('app_id')
	})
}

function requireProviderEnv (res, provider) {
	try {
		provider.requireEnv()
		return true
	} catch (err) {
		sendText(res, err.message, err.status || 500)
		return false
	}
}

function getOwnedOauthApp (session, appId, providerId) {
	if (!session?.admin || !appId) return null
	const app = db.tokens.get(appId)
	if (!app || app.userId !== session.userId || app.provider !== providerId || app.type !== 'oauth') return null
	return app
}

async function handleProviderConnect (req, res, query, providerName = 'google', url = null) {
	const provider = getProvider(providerName)
	if (!provider || provider.type !== 'oauth') {
		const err = new Error('not found')
		err.status = 404
		throw err
	}
	if (!requireProviderEnv(res, provider)) return
	const resolvedParams = { ...query }
	if (url?.searchParams) {
		for (const key of ['services', 'write']) {
			const all = url.searchParams.getAll(key)
			if (all.length > 1) resolvedParams[key] = all.join(',')
		}
	}
	delete resolvedParams.reauth_app_id
	if (query.code !== undefined) {
		const setup = db.tokens.getState(query.code)
		const session = resolveSetupState(setup, 'setup_connect', provider.id)
		if (!session) {
			sendText(res, 'Access denied: invalid or expired setup code.', 403)
			return
		}
		if (setup.reauthAppId) {
			const existingApp = getOwnedOauthApp(session, setup.reauthAppId, provider.id)
			if (!existingApp) {
				sendText(res, 'Access denied: unauthorized re-authentication request.', 403)
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
		} else if (setup.name && !resolvedParams.name && !resolvedParams.app_name) {
			resolvedParams.name = setup.name
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
	sendHtml(res, CONNECT_HTML.replace('{{INIT_DATA}}', () => JSON.stringify(initData).replace(/</g, '\\u003c')))
}

async function handleProviderConsent (req, res, providerName = 'google') {
	if (req.method !== 'POST') {
		sendText(res, 'Method Not Allowed', 405)
		return
	}
	if (!checkFormOrigin(req, res)) return
	const provider = getProvider(providerName)
	if (!provider || provider.type !== 'oauth' || !provider.buildAuthUrl) {
		const err = new Error('not found')
		err.status = 404
		throw err
	}
	if (!requireProviderEnv(res, provider)) return
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
	const setupCode = params.get('code') || null
	const setup = db.tokens.consumeState(setupCode)
	const session = resolveSetupState(setup, 'setup_connect', provider.id)
	if (!session) {
		sendText(res, 'Access denied: admin session required.', 403)
		return
	}
	const reauthAppId = setup.reauthAppId || null
	if (params.get('reauth_app_id') && params.get('reauth_app_id') !== reauthAppId) {
		sendText(res, 'Access denied: unauthorized re-authentication request.', 403)
		return
	}
	let existingApp = null
	if (reauthAppId) {
		existingApp = getOwnedOauthApp(session, reauthAppId, provider.id)
		if (!existingApp) {
			sendText(res, 'Access denied: unauthorized re-authentication request.', 403)
			return
		}
	}
	const rawAppName = params.get('app_name') || params.get('name') || setup.name || ''
	const name = rawAppName ? String(rawAppName).trim() : null
	const base = getBaseUrl(req)
	const callbackUrl = `${base}/oauth/callback`
	const ip = getClientIp(req)
	const stateToken = db.tokens.createState({
		mode: 'connect',
		sessionId: session.id,
		reauthAppId,
		name,
		provider: provider.id,
		ip
	})
	const authUrl = provider.buildAuthUrl({
		state: stateToken,
		callbackUrl,
		services: servicesList,
		write: writeList,
		loginHint: existingApp?.credentials?.account || null
	})
	redirect(res, authUrl)
}

async function handleCallback (req, res, query) {
	const code = query.code
	const rawState = query.state
	if (!code) {
		sendText(res, `OAuth Error: ${query.error || 'no code'}`, 400)
		return
	}
	const oauthState = db.tokens.consumeState(rawState)
	if (!oauthState || (oauthState.mode !== null && oauthState.mode !== 'connect' && oauthState.mode !== 'auth' && oauthState.mode !== 'login')) {
		sendText(res, 'Invalid or expired OAuth state (CSRF verification failed). Please try connecting again.', 403)
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
		sendText(res, err.message, err.status || 502)
		return
	}
	const { accessToken, refreshToken, expiresAt, scopes, account } = exchanged
	if (oauthState.mode === 'auth') {
		const session = oauthState.sessionId ? db.tokens.getActiveSession(oauthState.sessionId) : null
		if (!session || !session.admin) {
			sendText(res, 'Access denied: admin session required.', 403)
			return
		}
		const cleanAccount = String(account).trim().toLowerCase()
		const selfLogins = db.logins.listByUserId(session.userId)
		const existingOwner = db.logins.findUserByAccount(cleanAccount, provider.id)
		const willMerge = Boolean(existingOwner && existingOwner.id !== session.userId && oauthState.merge)
		if (!enforceSso(res, () => {
			assertSsoLink(selfLogins, provider.id, cleanAccount)
			if (willMerge) {
				const combined = [...selfLogins, ...db.logins.listByUserId(existingOwner.id)]
				for (let i = 0; i < combined.length; i++) {
					assertSsoLink(combined.filter((_, j) => j !== i), combined[i].provider, combined[i].account)
				}
			}
		})) return
		const allowUnscoped = shouldClaimUnscoped(provider.id, cleanAccount, { verifiedEmail: provider.verifiedEmail })
		const beforeAppKeys = new Set(
			db.tokens.listByUserId(session.userId)
				.filter(t => db.tokens.isUpstreamApp(t, { allowShare: true }))
				.map(appIdentityKey)
		)
		try {
			db.logins.upsert({
				userId: session.userId,
				provider: provider.id,
				account: cleanAccount,
				allowUnscoped,
				merge: oauthState.merge
			})
		} catch (err) {
			if (err.status === 409) {
				sendText(res, `${err.message}.`, 409)
				return
			}
			throw err
		}
		const updatedSession = db.tokens.getActiveSession(session.id)
		const afterApps = updatedSession
			? db.tokens.listByUserId(updatedSession.userId).filter(t => db.tokens.isUpstreamApp(t, { allowShare: true }))
			: []
		const newAppIds = afterApps.filter(a => !beforeAppKeys.has(appIdentityKey(a))).map(a => a.id)
		if (updatedSession && newAppIds.length > 0) {
			const verifyCode = db.tokens.createState({
				mode: 'verify',
				userId: updatedSession.userId,
				sessionId: updatedSession.id,
				provider: provider.id,
				name: cleanAccount,
				admin: updatedSession.admin ? 1 : 0,
				merge: willMerge,
				newAppIds,
				ip: oauthState.ip
			})
			redirect(res, `${base}/oauth/verify?code=${verifyCode}`)
			return
		}
		renderAuthResult(res, willMerge, cleanAccount)
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
			name: oauthState.name,
			admin: oauthState.admin,
			ip: oauthState.ip
		})
		return
	}
	const session = oauthState.sessionId ? db.tokens.getActiveSession(oauthState.sessionId) : null
	if (!session || !session.admin) {
		sendText(res, 'Access denied: admin session required.', 403)
		return
	}
	if (oauthState.reauthAppId) {
		const existingApp = getOwnedOauthApp(session, oauthState.reauthAppId, provider.id)
		if (!existingApp) {
			sendText(res, 'Access denied: unauthorized re-authentication request.', 403)
			return
		}
		const expectedAccount = existingApp.credentials?.account
		if (expectedAccount && String(account).trim().toLowerCase() !== String(expectedAccount).trim().toLowerCase()) {
			sendText(res, `Re-authentication failed: expected account "${expectedAccount}", got "${account}".`, 409)
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
		sendHtml(res, renderCardPage(
			`${provider.name} Re-authenticated`,
			`${escapeHtml(provider.name)} credentials updated`,
			`<p class="subtitle">Linked sessions will resume automatically.</p>`
		))
		return
	}
	const appName = oauthState.name || provider.name
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
	sendHtml(res, renderCardPage(
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
		if (!isPlainObject(parsed)) {
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
		sendText(res, 'Method Not Allowed', 405)
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
	if (authCode.clientId && authCode.clientId !== params.client_id) {
		console.warn(`[oauth] Token exchange failed: client_id mismatch (expected "${authCode.clientId}", got "${params.client_id || '(missing)'}")`)
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
		name: authCode.name || (authCode.admin ? 'Admin Session' : 'Default Session'),
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

async function handleOauth (req, res, { pathname, url, query }) {
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
			await handleProviderConnect(req, res, query, id, url)
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
