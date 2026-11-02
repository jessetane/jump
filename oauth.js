import { createHash, timingSafeEqual, randomBytes, randomUUID } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as db from './db/index.js'
import { getProvider } from './providers/index.js'
import { getBody, sendMail } from './util.js'

export {
	handleOauth,
	handleRegister,
	handleAuthorize,
	handleAuthorizeConsent,
	handleVerify,
	handleProviderConnect,
	handleProviderConsent,
	handleCallback,
	handleToken,
	handleRevoke,
	handleProtectedResourceMetadata,
	handleAuthServerMetadata,
	isAllowedRedirectUri,
	deriveClientName,
	getBaseUrl
}

const dirname = path.dirname(fileURLToPath(import.meta.url))

const KNOWN_CLIENT_NAMES = {
	'antigravity.google': 'Google Antigravity',
	'claude.ai': 'Claude',
	'anthropic.com': 'Anthropic',
	'chatgpt.com': 'ChatGPT',
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
		const rawHost = String(req.headers['x-forwarded-host'] || req.headers.host).split(',')[0].trim()
		if (rawHost) {
			const isLocal = rawHost.startsWith('localhost') || rawHost.startsWith('127.0.0.1') || rawHost.startsWith('[::1]')
			const proto = String(req.headers['x-forwarded-proto'] || (isLocal ? 'http' : 'https')).split(',')[0].trim()
			return `${proto}://${rawHost}`
		}
	}
	return 'http://localhost:8080'
}

function getClientIp (req) {
	return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || null
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
		<style>
			* {
				box-sizing: border-box;
			}

			html {
				height: 100%;
			}

			body {
				margin: 0;
				height: 100%;
				font-family: sans-serif;
			}

			.column {
				display: flex;
				flex-direction: column;
			}

			.view {
				margin: auto;
				width: 100%;
				padding: 24px;
			}

			@media (min-width: 520px) {
				.view {
					max-width: 480px;
				}
			}

			h1 {
				font-size: 1.5rem;
				text-align: center;
				margin-top: 0.85rem;
				margin-bottom: 0.85rem;
			}

			.subtitle {
				color: #555;
				font-size: 0.95rem;
				line-height: 1.4;
				text-align: center;
				margin: 0 0 1.25rem;
			}

			.app-list {
				margin-bottom: 1.5rem;
				text-align: left;
			}

			.app-list-title {
				font-size: 0.9rem;
				font-weight: bold;
				color: #333;
				margin-bottom: 0.5rem;
			}

			.app-item {
				display: flex;
				align-items: center;
				gap: 8px;
				padding: 8px 6px;
				border-bottom: 1px solid #eee;
				font-size: 0.9rem;
				cursor: pointer;
				color: #333;
			}

			.app-item:hover {
				background: #fafafa;
			}

			.app-meta {
				color: #777;
				font-size: 0.8rem;
				margin-left: auto;
			}

			button[type=submit] {
				width: 100%;
				padding: 11px 16px;
				background: #000;
				color: #fff;
				border: none;
				border-radius: 6px;
				font-size: 1rem;
				cursor: pointer;
				margin-bottom: 1.5rem;
			}

			button[type=submit]:hover {
				opacity: 0.85;
			}
		</style>
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
	if (explicitName) return explicitName
	if (!clientId || typeof clientId !== 'string' || !clientId.startsWith('https://')) return null
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
	if (protocol === 'http:') {
		return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
	}
	if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === 'antigravity.google' || hostname.endsWith('.antigravity.google')) {
		return true
	}
	const envDomains = process.env.ALLOWED_REDIRECT_DOMAINS || 'localhost,127.0.0.1,antigravity.google,claude.ai,anthropic.com,chatgpt.com,chat.openai.com,openai.com,cursor.sh,cursor.com,windsurf.com,codeium.com,vscode.dev,github.dev,antigravity,cursor,vscode'
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

async function handleProtectedResourceMetadata (req, res) {
	const base = getBaseUrl(req)
	const meta = {
		resource: `${base}/mcp`,
		authorization_servers: [base],
		bearer_methods_supported: ['header'],
		scopes_supported: ['mcp']
	}
	res.statusCode = 200
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify(meta, null, '\t'))
}

async function handleAuthServerMetadata (req, res) {
	const base = getBaseUrl(req)
	const meta = {
		issuer: base,
		authorization_endpoint: `${base}/oauth/authorize`,
		token_endpoint: `${base}/oauth/token`,
		registration_endpoint: `${base}/oauth/register`,
		revocation_endpoint: `${base}/oauth/revoke`,
		response_types_supported: ['code'],
		response_modes_supported: ['query'],
		grant_types_supported: ['authorization_code'],
		token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
		revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
		code_challenge_methods_supported: ['S256'],
		scopes_supported: ['mcp', 'offline_access', 'openid', 'profile', 'email'],
		client_id_metadata_document_supported: true
	}
	res.statusCode = 200
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify(meta, null, '\t'))
}

async function handleRegister (req, res) {
	if (req.method !== 'POST') {
		res.statusCode = 405
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'method_not_allowed' }))
		return
	}
	const rawBody = await getBody(req)
	let body = {}
	try {
		body = rawBody ? JSON.parse(rawBody) : {}
	} catch {
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_client_metadata', error_description: 'Invalid JSON body' }))
		return
	}
	const rawRedirects = body.redirect_uris
	const redirectUris = Array.isArray(rawRedirects) ? rawRedirects : (rawRedirects ? [rawRedirects] : [])
	if (redirectUris.length === 0) {
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' }))
		return
	}
	for (const uri of redirectUris) {
		if (!isAllowedRedirectUri(uri)) {
			res.statusCode = 400
			res.setHeader('content-type', 'application/json; charset=utf-8')
			res.end(JSON.stringify({ error: 'invalid_redirect_uri', error_description: `redirect_uri is not allowed: ${uri}` }))
			return
		}
	}
	const authMethod = body.token_endpoint_auth_method || 'none'
	const clientId = body.client_id || `client_${randomUUID()}`
	const needsSecret = authMethod === 'client_secret_basic' || authMethod === 'client_secret_post'
	const clientSecret = body.client_secret || (needsSecret ? `cs_${randomBytes(24).toString('hex')}` : null)
	const response = {
		client_id: clientId,
		client_id_issued_at: Math.floor(Date.now() / 1000),
		client_name: body.client_name || 'MCP Client',
		redirect_uris: redirectUris,
		grant_types: body.grant_types || ['authorization_code'],
		response_types: body.response_types || ['code'],
		token_endpoint_auth_method: authMethod
	}
	if (clientSecret) {
		response.client_secret = clientSecret
		response.client_secret_expires_at = 0
	}
	res.statusCode = 201
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify(response))
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
	try {
		validateAuthorizeParams(query)
	} catch (err) {
		res.statusCode = err.status || 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: err.code || 'invalid_request', error_description: err.message }))
		return
	}
	const clientName = deriveClientName(query.client_id, query.client_name)
	const initData = {
		params: query,
		...(clientName && { clientName })
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
	for (const [key, value] of params.entries()) {
		if (key === 'email') {
			email = value.trim().toLowerCase() || null
		} else if (key === 'session_name') {
			sessionName = value.trim() || null
		} else if (key === 'admin') {
			admin = value === 'true' || value === '1' || value === 'on' ? 1 : 0
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
	const clientRedirectUri = query.redirect_uri || null
	const clientState = query.state || null
	const derivedName = deriveClientName(query.client_id, query.client_name)
	const effectiveSessionName = sessionName || derivedName || null
	const magicCode = randomBytes(24).toString('base64url')
	const magicExpiresAt = Date.now() + (15 * 60 * 1000)
	const ip = getClientIp(req)
	db.tokens.createState({
		clientRedirectUri,
		clientState,
		codeChallenge,
		codeChallengeMethod,
		sessionName: effectiveSessionName,
		admin,
		email,
		magicCode,
		magicExpiresAt,
		ip
	})
	const base = getBaseUrl(req)
	const verifyUrl = `${base}/oauth/verify?code=${magicCode}`
	await sendMail({
		to: email,
		subject: 'Sign in to jump',
		text: `Click the link below to sign in and activate your MCP session token:\n\n${verifyUrl}\n\nThis link expires in 15 minutes.`,
		html: `<p>Click the link below to sign in and activate your MCP session token:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>This link expires in 15 minutes.</p>`
	})
	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(renderCardPage(
		'jump sign in',
		'Check your email',
		`<p class="subtitle">A sign-in link has been sent to <strong>${escapeHtml(email)}</strong>.</p>`
	))
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
		const state = db.tokens.findStateByMagicCode(code)
		if (!state) {
			res.statusCode = 400
			res.setHeader('content-type', 'text/plain')
			res.end('Invalid or expired verification code')
			return
		}
		const existingUser = state.email ? db.users.getByEmail(state.email) : null
		const userApps = existingUser
			? db.tokens.listByUserId(existingUser.id).filter(t => t.provider !== 'self')
			: []
		let appsHtml = ''
		if (userApps.length > 0) {
			const checkedAttr = state.admin ? ' checked' : ''
			const items = userApps.map(app => {
				const account = app.credentials?.account || app.credentials?.email || ''
				const label = app.name || `${app.provider} app`
				return `<label class="app-item"><input type="checkbox" name="app_id" value="${escapeHtml(app.id)}"${checkedAttr}><span>${escapeHtml(label)}</span>${account ? `<span class="app-meta">${escapeHtml(account)}</span>` : ''}</label>`
			}).join('')
			appsHtml = `<div class="app-list"><div class="app-list-title">Link connected apps</div>${items}</div>`
		}
		const autoSubmitScript = userApps.length === 0 ? '<script>document.forms[0].submit()</script>' : ''
		res.statusCode = 200
		res.setHeader('content-type', 'text/html; charset=utf-8')
		res.end(renderCardPage(
			'jump verify',
			`Activate session for <strong>${escapeHtml(state.email || 'user')}</strong>`,
			`<form method="POST" action="/oauth/verify"><input type="hidden" name="code" value="${escapeHtml(code)}">${appsHtml}<button type="submit">Continue</button></form>${autoSubmitScript}`
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
	const state = db.tokens.consumeMagicCode(code)
	if (!state) {
		res.statusCode = 400
		res.setHeader('content-type', 'text/plain')
		res.end('Invalid or expired verification code')
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
	const selectedAppIds = params.getAll('app_id')
	for (const appId of selectedAppIds) {
		const app = db.tokens.get(appId)
		if (app && app.userId === user.id && app.provider !== 'self') {
			db.links.create({
				sessionId: session.id,
				appId: app.id
			})
		}
	}
	if (state.clientRedirectUri) {
		const authCode = db.tokens.createAuthCode({
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

async function handleProviderConnect (req, res, query, providerName = 'google') {
	const provider = getProvider(providerName)
	if (!provider || provider.type !== 'oauth') {
		const err = new Error('not found')
		err.code = 404
		throw err
	}
	const initData = {
		params: query,
		provider: { id: provider.id, name: provider.name },
		...(provider.services && {
			services: Object.values(provider.services).map(s => ({
				id: s.id,
				name: s.name,
				...(s.enterprise && { enterprise: true })
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
		err.code = 404
		throw err
	}
	const rawBody = await getBody(req)
	const params = new URLSearchParams(rawBody)
	const servicesList = []
	for (const v of params.getAll('services')) {
		for (const s of v.split(',')) {
			if (s.trim()) servicesList.push(s.trim())
		}
	}
	const writeList = []
	for (const v of params.getAll('write')) {
		for (const s of v.split(',')) {
			if (s.trim()) writeList.push(s.trim())
		}
	}
	const sessionId = params.get('session_id') || null
	const reauthAppId = params.get('reauth_app_id') || null
	if (reauthAppId) {
		const session = sessionId ? db.tokens.get(sessionId) : null
		const existingApp = db.tokens.get(reauthAppId)
		if (!session || session.provider !== 'self' || !existingApp || existingApp.userId !== session.userId || existingApp.provider !== provider.id) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: unauthorized re-authentication request.')
			return
		}
	}
	const rawAppName = params.get('app_name') || params.get('name') || ''
	const sessionName = rawAppName ? String(rawAppName).trim() : null
	const base = getBaseUrl(req)
	const callbackUrl = `${base}/oauth/callback`
	const ip = getClientIp(req)
	const stateToken = db.tokens.createState({
		sessionId,
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
			write: writeList
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
	if (!oauthState) {
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
	const { accessToken, refreshToken, expiresAt, scopes, email, account, userName } = exchanged
	if (oauthState.reauthAppId) {
		const session = oauthState.sessionId ? db.tokens.get(oauthState.sessionId) : null
		const existingApp = db.tokens.get(oauthState.reauthAppId)
		if (!session || session.provider !== 'self' || !existingApp || existingApp.userId !== session.userId || existingApp.provider !== provider.id) {
			res.statusCode = 403
			res.setHeader('content-type', 'text/plain')
			res.end('Access denied: unauthorized re-authentication request.')
			return
		}
		const updatedCreds = {
			...existingApp.credentials,
			accessToken,
			refreshToken: refreshToken || existingApp.credentials?.refreshToken,
			email,
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
	let targetUserId = null
	if (oauthState.sessionId) {
		const session = db.tokens.get(oauthState.sessionId)
		if (session) targetUserId = session.userId
	}
	if (!targetUserId) {
		const user = db.users.upsert({
			email,
			name: userName || null
		})
		targetUserId = user.id
	}
	const appName = oauthState.sessionName || `${userName || email} ${provider.name}`
	const appToken = db.tokens.create({
		userId: targetUserId,
		provider: provider.id,
		type: 'oauth',
		name: appName,
		credentials: {
			accessToken,
			refreshToken: refreshToken || null,
			email,
			account
		},
		expiresAt,
		scopes: scopes || null
	})
	if (oauthState.sessionId) {
		db.links.create({
			sessionId: oauthState.sessionId,
			appId: appToken.id
		})
	}
	res.statusCode = 200
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.end(renderCardPage(
		`${provider.name} Connected`,
		`Connected <strong>${escapeHtml(email)}</strong>`,
		`<p class="subtitle">You can close this window and return to your agent.</p>`
	))
}

function parseTokenParams (rawBody) {
	if (!rawBody) return {}
	const trimmed = rawBody.trim()
	if (trimmed.startsWith('{')) {
		try {
			return JSON.parse(trimmed)
		} catch {
			return {}
		}
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
	const params = parseTokenParams(rawBody)
	const code = params.code
	const redirectUri = params.redirect_uri
	const codeVerifier = params.code_verifier
	if (!code) {
		console.warn('[oauth] Token exchange failed: Missing code')
		res.statusCode = 400
		res.setHeader('content-type', 'application/json; charset=utf-8')
		res.end(JSON.stringify({ error: 'invalid_request', error_description: 'Missing code' }))
		return
	}
	const authCode = db.tokens.consumeAuthCode(code)
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
	res.setHeader('cache-control', 'no-store')
	res.setHeader('pragma', 'no-cache')
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify({
		access_token: session.token,
		token_type: 'Bearer',
		expires_in: 30 * 24 * 60 * 60,
		scope: 'mcp'
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
			const provider = getProvider(link.app?.provider)
			if (provider?.revokeToken) {
				await provider.revokeToken(link.app)
			}
		}
		db.tokens.remove(session.id)
	}
	res.statusCode = 200
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(JSON.stringify({ status: 'ok' }))
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
		await handleProtectedResourceMetadata(req, res)
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
	const providerMatch = pathname.match(/^\/providers\/([a-z0-9_-]+)\/(connect|consent|callback)$/i)
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
		if (action === 'callback') {
			await handleCallback(req, res, query)
			return
		}
	}
	const err = new Error('not found')
	err.code = 404
	throw err
}
