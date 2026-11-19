import * as db from '../db/index.js'
import { getProvider, listAuthProviders, requireAuthProvider } from '../providers/index.js'
import { assertSsoLink, resolveShareProvider } from '../sso.js'
import { parsePolicy, validatePolicy } from '../policy.js'
import { validateBaseUrl, parseAccountSpec, isPlainObject, requireBoolean } from '../util.js'

export {
	whoami,
	listSessions,
	getSession,
	createSession,
	updateSession,
	revokeSession,
	listApps,
	connectApp,
	disconnectApp,
	updateApp,
	shareApp,
	unshareApp,
	linkApp,
	unlinkApp,
	linkLogin,
	unlinkLogin,
	listLogs
}

function formatLogin (login) {
	return {
		id: login.id,
		provider: login.provider,
		account: login.account
	}
}

function formatApp (app, { sharesByAppId } = {}) {
	const item = {
		id: app.id,
		provider: app.provider,
		type: app.type,
		name: app.name,
		account: app.credentials?.account || null,
		...(app.credentials?.baseUrl ? { baseUrl: app.credentials.baseUrl } : {}),
		scopes: app.scopes,
		expiresAt: app.expiresAt,
		created: app.created,
		updated: app.updated
	}
	if (app.type === 'share') {
		item.sharedBy = app.sharedBy || null
		item.policy = parsePolicy(app.credentials?.policy)
	} else if (sharesByAppId) {
		const shares = sharesByAppId.get(app.id)
		if (shares) item.shares = shares
	}
	return item
}

function formatSession (s, currentSessionId) {
	const links = db.links.listBySessionId(s.id)
	return {
		id: s.id,
		userId: s.userId,
		name: s.name,
		admin: Boolean(s.admin),
		expiresAt: s.expiresAt,
		ip: s.ip,
		ua: s.ua,
		created: s.created,
		updated: s.updated,
		...(currentSessionId !== undefined ? { isCurrent: s.id === currentSessionId } : {}),
		apps: links.filter(l => l.app).map(l => ({
			...formatApp(l.app),
			policy: parsePolicy(l.policy)
		}))
	}
}

function resolveSession (auth) {
	if (!auth) return null
	if (typeof auth === 'object') return auth
	return db.tokens.getByToken(auth)
}

async function whoami (token, opts = {}) {
	const appUrl = (opts.appUrl || 'http://localhost:8080').replace(/\/$/, '')
	const session = resolveSession(token)
	if (!session) {
		return {
			authenticated: false,
			signInUrl: `${appUrl}/oauth/authorize`,
			message: 'Missing or expired Bearer token.'
		}
	}
	const logins = db.logins.listByUserId(session.userId)
	return {
		authenticated: true,
		user: {
			id: session.userId,
			account: session.account,
			logins: logins.map(formatLogin)
		},
		session: formatSession(session)
	}
}

function requireSession (token, opts = {}) {
	const appUrl = (opts.appUrl || 'http://localhost:8080').replace(/\/$/, '')
	const session = resolveSession(token)
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl}/oauth/authorize`)
		error.status = 401
		throw error
	}
	return { session, appUrl }
}

function requireAdmin (token, opts = {}, message = 'Access denied: app administration requires admin privileges') {
	const { session, appUrl } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error(message)
		error.status = 403
		throw error
	}
	return { session, appUrl }
}

function requireApp (userId, appId, { allowShare = true, requireId = false } = {}) {
	if (requireId && appId === undefined) {
		const error = new Error('appId is required')
		error.status = 400
		throw error
	}
	if (appId !== undefined) {
		appId = requireNonEmptyString(appId, 'appId')
	}
	const targetApp = db.tokens.get(appId)
	if (!targetApp || targetApp.userId !== userId || !db.tokens.isUpstreamApp(targetApp, { allowShare })) {
		const error = new Error(`App not found: ${appId}`)
		error.status = 404
		throw error
	}
	return targetApp
}

function requireTargetSession (userId, sessionId) {
	const targetSession = db.tokens.get(sessionId)
	if (!db.tokens.isSession(targetSession) || targetSession.userId !== userId) {
		const error = new Error(`Session not found: ${sessionId}`)
		error.status = 404
		throw error
	}
	return targetSession
}

function requireShareTarget (token, opts = {}) {
	const { appId, account, provider = null } = opts
	const { session } = requireAdmin(token, opts)
	if (!appId) {
		const error = new Error('appId is required')
		error.status = 400
		throw error
	}
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	if (!cleanAccount) {
		const error = new Error('Valid recipient account identifier is required')
		error.status = 400
		throw error
	}
	const targetApp = requireApp(session.userId, appId, { allowShare: false })
	return { session, targetApp, cleanAccount, cleanProvider }
}

async function listSessions (token, opts = {}) {
	const { session } = requireAdmin(token, opts, 'Access denied: session administration requires admin privileges')
	const rawSessions = db.tokens.listByUserId(session.userId, { provider: 'self' })
	return { sessions: rawSessions.map(s => formatSession(s, session.id)) }
}

async function getSession (token, sessionId, opts = {}) {
	const { session } = requireSession(token, opts)
	if (!session.admin && sessionId !== session.id) {
		const error = new Error('Access denied: session administration requires admin privileges')
		error.status = 403
		throw error
	}
	const targetSession = requireTargetSession(session.userId, sessionId)
	return { session: formatSession(targetSession, session.id) }
}

async function createSession (token, opts = {}) {
	const { name = 'New Session', admin, linkAppIds = [], policy = null } = opts
	const { session } = requireAdmin(token, opts, 'Access denied: session administration requires admin privileges')
	const isAdmin = requireBoolean(admin, 'admin', false)
	const policyCheck = validatePolicy(policy)
	if (!policyCheck.valid) {
		const error = new Error(policyCheck.error)
		error.status = 400
		throw error
	}
	const appsToLink = []
	for (const appId of (Array.isArray(linkAppIds) ? linkAppIds : [])) {
		appsToLink.push(requireApp(session.userId, appId))
	}
	const newSession = db.tokens.create({
		userId: session.userId,
		provider: 'self',
		type: 'bearer',
		name,
		admin: isAdmin ? 1 : 0
	})
	for (const app of appsToLink) {
		db.links.create({
			sessionId: newSession.id,
			appId: app.id,
			policy: policyCheck.policy
		})
	}
	return {
		created: true,
		session: {
			id: newSession.id,
			name: newSession.name,
			admin: Boolean(newSession.admin),
			expiresAt: newSession.expiresAt,
			token: newSession.token,
			created: newSession.created
		}
	}
}

async function revokeSession (token, { sessionId, allOthers } = {}) {
	const session = resolveSession(token)
	if (!session) {
		return {
			revoked: false,
			message: 'No active session found for the provided token.'
		}
	}
	const shouldRevokeAllOthers = requireBoolean(allOthers, 'allOthers', false)
	if (shouldRevokeAllOthers) {
		if (!session.admin) {
			const error = new Error('Access denied: revoking other sessions requires admin privileges')
			error.status = 403
			throw error
		}
		const userSessions = db.tokens.listByUserId(session.userId, { provider: 'self' })
		const others = userSessions.filter(s => s.id !== session.id)
		for (const s of others) {
			db.tokens.remove(s.id)
		}
		return {
			revoked: true,
			count: others.length,
			message: `Revoked ${others.length} other session(s).`
		}
	}
	if (sessionId && sessionId !== session.id) {
		if (!session.admin) {
			const error = new Error('Access denied: revoking other sessions requires admin privileges')
			error.status = 403
			throw error
		}
		const targetSession = db.tokens.get(sessionId)
		if (!db.tokens.isSession(targetSession) || targetSession.userId !== session.userId) {
			return {
				revoked: false,
				message: `Session not found: ${sessionId}`
			}
		}
		db.tokens.remove(targetSession.id)
		return {
			revoked: true,
			sessionId: targetSession.id,
			isCurrent: false,
			message: 'Session revoked.'
		}
	}
	db.tokens.remove(session.id)
	return {
		revoked: true,
		sessionId: session.id,
		isCurrent: true,
		message: 'Current session revoked.'
	}
}

async function listApps (token, opts = {}) {
	const { session } = requireAdmin(token, opts)
	const allTokens = db.tokens.listByUserId(session.userId)
	const ownedShares = db.tokens.listSharesByOwnerId(session.userId)
	const sharesByAppId = new Map()
	for (const s of ownedShares) {
		const targetAppId = s.credentials?.appId
		if (!targetAppId) continue
		if (!sharesByAppId.has(targetAppId)) sharesByAppId.set(targetAppId, [])
		sharesByAppId.get(targetAppId).push({
			userId: s.userId,
			account: s.account,
			...(s.credentials?.authProvider ? { provider: s.credentials.authProvider } : {}),
			policy: parsePolicy(s.credentials?.policy)
		})
	}
	const apps = allTokens.filter(t => t.provider !== 'self').map(a => formatApp(a, { sharesByAppId }))
	return { apps }
}

function optionalString (val, label) {
	if (val === undefined || val === null) return null
	if (typeof val !== 'string') {
		const error = new Error(`${label} must be a string`)
		error.status = 400
		throw error
	}
	return val.trim() || null
}

function requireNonEmptyString (val, label) {
	if (typeof val !== 'string' || !val.trim()) {
		const error = new Error(`${label} must be a non-empty string`)
		error.status = 400
		throw error
	}
	return val.trim()
}

function requireValidBaseUrl (rawBase) {
	const normalized = rawBase ? validateBaseUrl(rawBase) : null
	if (!normalized) {
		const error = new Error('Valid https:// baseUrl is required for api_key apps')
		error.status = 400
		throw error
	}
	return normalized
}

const ALLOWED_CREDENTIAL_KEYS = new Set(['bearer', 'basic', 'headers', 'query'])
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
const DISALLOWED_CREDENTIAL_HEADERS = new Set([
	'connection',
	'keep-alive',
	'transfer-encoding',
	'te',
	'trailer',
	'upgrade',
	'content-length',
	'host',
	'cookie',
	'__proto__'
])

function badRequest (message) {
	const error = new Error(message)
	error.status = 400
	return error
}

function isValidHeaderValue (val) {
	if (typeof val !== 'string' || !val.trim()) return false
	for (let i = 0; i < val.length; i++) {
		const c = val.charCodeAt(i)
		if ((c < 0x20 && c !== 0x09) || c === 0x7f || c > 0xff) return false
	}
	return true
}

function normalizeBearerToken (raw, label) {
	if (typeof raw !== 'string' || !raw.trim()) {
		throw badRequest(`${label} must be a non-empty string`)
	}
	if (!isValidHeaderValue(raw)) {
		throw badRequest(`${label} contains invalid HTTP header characters`)
	}
	const trimmed = raw.trim()
	if (/^Bearer(?:[ \t]+|$)/i.test(trimmed)) {
		const rest = trimmed.replace(/^Bearer/i, '').trim()
		if (!rest) throw badRequest(`${label} must contain a non-empty token`)
		return rest
	}
	return trimmed
}

function normalizeCredentials (raw) {
	if (typeof raw === 'string') {
		const token = normalizeBearerToken(raw, 'credentials')
		return { headers: { authorization: `Bearer ${token}` } }
	}
	if (!isPlainObject(raw)) {
		throw badRequest('credentials must be a non-empty string or object')
	}
	const keys = Object.keys(raw)
	for (const key of keys) {
		if (!ALLOWED_CREDENTIAL_KEYS.has(key)) {
			throw badRequest(`Unknown credentials field "${key}"`)
		}
	}
	const headers = Object.create(null)
	let authSource = null
	if (raw.bearer !== undefined) {
		const token = normalizeBearerToken(raw.bearer, 'credentials.bearer')
		headers.authorization = `Bearer ${token}`
		authSource = 'bearer'
	}
	if (raw.basic !== undefined) {
		if (typeof raw.basic !== 'string' || !raw.basic.trim()) {
			throw badRequest('credentials.basic must be a non-empty "user:pass" string')
		}
		if (/[\x00-\x1f\x7f]/.test(raw.basic)) {
			throw badRequest('credentials.basic must not contain control characters')
		}
		const cleanBasic = raw.basic.trim()
		if (!cleanBasic.includes(':') || cleanBasic === ':') {
			throw badRequest('credentials.basic must be in "user:pass" format')
		}
		if (authSource) {
			throw badRequest('Conflicting Authorization credentials: specify only one of bearer, basic, or headers.authorization')
		}
		headers.authorization = `Basic ${Buffer.from(cleanBasic).toString('base64')}`
		authSource = 'basic'
	}
	if (raw.headers !== undefined) {
		if (!isPlainObject(raw.headers) || Object.keys(raw.headers).length === 0) {
			throw badRequest('credentials.headers must be a non-empty object of header names to string values')
		}
		for (const [rawName, val] of Object.entries(raw.headers)) {
			const name = rawName.toLowerCase()
			if (!HEADER_NAME_RE.test(name)) {
				throw badRequest(`Invalid HTTP header name in credentials.headers: "${rawName}"`)
			}
			if (DISALLOWED_CREDENTIAL_HEADERS.has(name)) {
				throw badRequest(`Forbidden header in credentials.headers: "${name}"`)
			}
			if (!isValidHeaderValue(val)) {
				throw badRequest(`credentials.headers["${rawName}"] must be a valid non-empty HTTP header value`)
			}
			if (Object.hasOwn(headers, name)) {
				if (name === 'authorization' && authSource !== 'headers.authorization') {
					throw badRequest('Conflicting Authorization credentials: specify only one of bearer, basic, or headers.authorization')
				}
				throw badRequest(`Duplicate header in credentials.headers: "${name}"`)
			}
			if (name === 'authorization') {
				authSource = 'headers.authorization'
			}
			headers[name] = val.trim()
		}
	}
	const query = Object.create(null)
	if (raw.query !== undefined) {
		if (!isPlainObject(raw.query) || Object.keys(raw.query).length === 0) {
			throw badRequest('credentials.query must be a non-empty object of parameter names to string values')
		}
		const seenLower = new Set()
		for (const [rawParam, val] of Object.entries(raw.query)) {
			if (/[\x00-\x1f\x7f]/.test(rawParam)) {
				throw badRequest('credentials.query parameter names must not contain control characters')
			}
			const param = rawParam.trim()
			if (!param) {
				throw badRequest('credentials.query parameter names must be non-empty strings')
			}
			const lower = param.toLowerCase()
			if (seenLower.has(lower)) {
				throw badRequest(`Duplicate query parameter in credentials.query: "${param}"`)
			}
			seenLower.add(lower)
			if (typeof val !== 'string' || /[\x00-\x1f\x7f]/.test(val)) {
				throw badRequest(`credentials.query["${rawParam}"] must be a valid string`)
			}
			query[param] = val
		}
	}
	const hasHeaders = Object.keys(headers).length > 0
	const hasQuery = Object.keys(query).length > 0
	if (!hasHeaders && !hasQuery) {
		throw badRequest('credentials must specify at least one of bearer, basic, headers, or query')
	}
	return {
		...(hasHeaders && { headers: { ...headers } }),
		...(hasQuery && { query: { ...query } })
	}
}

async function connectApp (token, opts = {}) {
	let { provider, name, credentials, account, baseUrl, appId } = opts
	const { session, appUrl } = requireAdmin(token, opts)
	if (provider === undefined || provider === null) {
		provider = null
	} else {
		provider = requireNonEmptyString(provider, 'provider').toLowerCase()
	}
	const cleanName = optionalString(name, 'name')
	const cleanAccount = optionalString(account, 'account')
	if (appId !== undefined) {
		const existing = requireApp(session.userId, appId, { allowShare: false, requireId: true })
		appId = existing.id
		if (provider && provider !== existing.provider) {
			const error = new Error(`App ${appId} belongs to provider "${existing.provider}", not "${provider}"`)
			error.status = 400
			throw error
		}
		if (existing.type !== 'oauth') {
			const error = new Error(`Cannot re-authenticate ${existing.type} app via connect_app; use update_app instead`)
			error.status = 400
			throw error
		}
		if (credentials !== undefined || account !== undefined || baseUrl !== undefined) {
			const error = new Error('Cannot pass credentials, account, or baseUrl with appId in connect_app; use update_app instead')
			error.status = 400
			throw error
		}
		provider = existing.provider
	}
	const normalizedAuth = credentials !== undefined ? normalizeCredentials(credentials) : null
	provider = provider || 'google'
	if (provider === 'self') {
		const error = new Error('provider cannot be "self"')
		error.status = 400
		throw error
	}
	const providerDef = getProvider(provider)
	if (providerDef?.type === 'oauth' && !normalizedAuth) {
		requireAuthProvider(providerDef.id)
		const setupCode = db.tokens.createState({
			mode: 'setup_connect',
			sessionId: session.id,
			provider: providerDef.id,
			reauthAppId: appId || null,
			name: cleanName,
			ttl: 10 * 60 * 1000
		})
		return {
			actionRequired: 'oauth_flow',
			connectUrl: `${appUrl}/providers/${providerDef.id}/connect?code=${encodeURIComponent(setupCode)}`
		}
	}
	if (!normalizedAuth) {
		const error = new Error('credentials is required for api_key apps')
		error.status = 400
		throw error
	}
	const rawBase = baseUrl !== undefined ? baseUrl : (providerDef?.baseUrl || null)
	const normalizedBaseUrl = requireValidBaseUrl(rawBase)
	const creds = {
		...normalizedAuth,
		baseUrl: normalizedBaseUrl,
		...(cleanAccount && { account: cleanAccount })
	}
	const app = db.tokens.create({
		userId: session.userId,
		provider,
		type: 'api_key',
		name: cleanName || providerDef.name,
		credentials: creds
	})
	return {
		connected: true,
		app: formatApp(app)
	}
}

async function disconnectApp (token, opts = {}) {
	const { appId, revoke } = opts
	const { session } = requireAdmin(token, opts)
	const targetApp = requireApp(session.userId, appId)
	const shouldRevoke = requireBoolean(revoke, 'revoke', true)
	if (shouldRevoke) {
		const providerDef = getProvider(targetApp.provider)
		if (providerDef?.revokeToken) {
			await providerDef.revokeToken(targetApp)
		}
	}
	db.tokens.remove(targetApp.id)
	return {
		disconnected: true,
		appId: targetApp.id
	}
}

async function linkApp (token, opts = {}) {
	const { sessionId, appId, policy = null } = opts
	const { session } = requireAdmin(token, opts, 'Access denied: link administration requires admin privileges')
	const policyCheck = validatePolicy(policy)
	if (!policyCheck.valid) {
		const error = new Error(policyCheck.error)
		error.status = 400
		throw error
	}
	const targetSession = requireTargetSession(session.userId, sessionId)
	const targetApp = requireApp(session.userId, appId)
	const link = db.links.create({
		sessionId: targetSession.id,
		appId: targetApp.id,
		policy: policyCheck.policy
	})
	return {
		linked: true,
		sessionId: link.sessionId,
		appId: link.appId,
		policy: parsePolicy(link.policy)
	}
}

async function unlinkApp (token, opts = {}) {
	const { sessionId, appId } = opts
	const { session } = requireAdmin(token, opts, 'Access denied: link administration requires admin privileges')
	const targetSession = requireTargetSession(session.userId, sessionId)
	const targetApp = requireApp(session.userId, appId)
	const removed = db.links.remove(targetSession.id, targetApp.id)
	return {
		unlinked: removed,
		sessionId: targetSession.id,
		appId: targetApp.id
	}
}

async function linkLogin (token, opts = {}) {
	const { session, appUrl } = requireAdmin(token, opts, 'Access denied: login administration requires admin privileges')
	const { provider, merge } = opts
	const cleanProvider = optionalString(provider, 'provider')
	const shouldMerge = requireBoolean(merge, 'merge', false)
	const existingLogins = db.logins.listByUserId(session.userId)
	let resolvedProvider = null
	if (cleanProvider) {
		const providerDef = requireAuthProvider(cleanProvider)
		assertSsoLink(existingLogins, providerDef.id)
		resolvedProvider = providerDef.id
	} else if (listAuthProviders().length === 0) {
		const error = new Error('No OAuth sign-in providers are configured')
		error.status = 400
		throw error
	}
	const setupCode = db.tokens.createState({
		mode: 'setup_link',
		sessionId: session.id,
		provider: resolvedProvider,
		merge: shouldMerge,
		ttl: 10 * 60 * 1000
	})
	return {
		actionRequired: 'oauth_flow',
		connectUrl: `${appUrl}/oauth/authorize?code=${encodeURIComponent(setupCode)}`
	}
}

async function unlinkLogin (token, opts = {}) {
	const { session } = requireAdmin(token, opts, 'Access denied: login administration requires admin privileges')
	const { loginId = null, provider = null, account = null } = opts
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	if (!loginId && !cleanProvider && !cleanAccount) {
		const error = new Error('loginId, provider, or account is required to unlink a login key')
		error.status = 400
		throw error
	}
	const removed = db.logins.remove(session.userId, {
		loginId,
		provider: cleanProvider,
		account: cleanAccount
	})
	const remaining = db.logins.listByUserId(session.userId)
	return {
		unlinked: true,
		login: formatLogin(removed),
		logins: remaining.map(formatLogin)
	}
}

async function updateApp (token, opts = {}) {
	const { appId, name, account, baseUrl, credentials } = opts
	const { session } = requireAdmin(token, opts)
	const targetApp = requireApp(session.userId, appId, { allowShare: false, requireId: true })
	if ((account !== undefined || baseUrl !== undefined || credentials !== undefined) && targetApp.type !== 'api_key') {
		const error = new Error('account, baseUrl, and credentials can only be updated on api_key apps')
		error.status = 400
		throw error
	}
	const cleanName = name !== undefined ? optionalString(name, 'name') : undefined
	const cleanAccount = account !== undefined ? optionalString(account, 'account') : undefined
	const normalizedAuth = credentials !== undefined ? normalizeCredentials(credentials) : undefined
	const normalizedBaseUrl = baseUrl !== undefined ? requireValidBaseUrl(baseUrl) : undefined
	let updated = targetApp
	if (cleanName !== undefined || cleanAccount !== undefined || normalizedBaseUrl !== undefined || normalizedAuth !== undefined) {
		const hasCredChanges = cleanAccount !== undefined || normalizedBaseUrl !== undefined || normalizedAuth !== undefined
		let updatedCreds = undefined
		if (hasCredChanges) {
			const existingCreds = targetApp.credentials || {}
			const { headers: _h, query: _q, ...metaCreds } = existingCreds
			updatedCreds = {
				...metaCreds,
				...(normalizedAuth !== undefined
					? normalizedAuth
					: {
						...(existingCreds.headers ? { headers: existingCreds.headers } : {}),
						...(existingCreds.query ? { query: existingCreds.query } : {})
					}),
				...(normalizedBaseUrl !== undefined ? { baseUrl: normalizedBaseUrl } : {})
			}
			if (cleanAccount !== undefined) {
				if (cleanAccount) updatedCreds.account = cleanAccount
				else delete updatedCreds.account
			}
		}
		updated = db.tokens.updateCredentials(targetApp.id, {
			...(cleanName !== undefined ? { name: cleanName } : {}),
			...(updatedCreds !== undefined ? { credentials: updatedCreds } : {})
		})
	}
	return {
		updated: true,
		app: formatApp(updated)
	}
}

async function shareApp (token, opts = {}) {
	const { policy = null } = opts
	const { session, targetApp, cleanAccount, cleanProvider } = requireShareTarget(token, opts)
	const selfLogins = db.logins.listByUserId(session.userId)
	const isSelf = selfLogins.some(l => {
		const acc = (l.account || '').toLowerCase()
		return cleanProvider ? (l.provider === cleanProvider && acc === cleanAccount) : acc === cleanAccount
	}) || (!selfLogins.length && !cleanProvider && cleanAccount === (session.account || '').toLowerCase())
	if (isSelf) {
		const error = new Error('Cannot share an app with yourself')
		error.status = 400
		throw error
	}
	const policyCheck = validatePolicy(policy)
	if (!policyCheck.valid) {
		const error = new Error(policyCheck.error)
		error.status = 400
		throw error
	}
	const effectiveProvider = resolveShareProvider(selfLogins, cleanAccount, cleanProvider)
	if (effectiveProvider) {
		requireAuthProvider(effectiveProvider)
	}
	const recipient = db.logins.findUserByAccount(cleanAccount, effectiveProvider)
	if (recipient && recipient.id === session.userId) {
		const error = new Error('Cannot share an app with yourself')
		error.status = 400
		throw error
	}
	if (!recipient && !effectiveProvider && !cleanAccount.includes('@')) {
		const error = new Error(`Provider is required when sharing with bare account handle "${cleanAccount}" (e.g. provider: "github" or "github:${cleanAccount}")`)
		error.status = 400
		throw error
	}
	const userId = recipient ? recipient.id : null
	const share = db.tokens.upsertShare({
		userId,
		account: cleanAccount,
		authProvider: effectiveProvider,
		appId: targetApp.id,
		provider: targetApp.provider,
		policy: policyCheck.policy
	})
	const resolvedProvider = share.credentials?.authProvider || effectiveProvider
	return {
		shared: true,
		shareId: share.id,
		appId: targetApp.id,
		userId,
		account: cleanAccount,
		...(resolvedProvider ? { provider: resolvedProvider } : {}),
		policy: policyCheck.policy
	}
}

async function unshareApp (token, opts = {}) {
	const { targetApp, cleanAccount, cleanProvider } = requireShareTarget(token, opts)
	const unshared = db.tokens.removeShare({
		appId: targetApp.id,
		account: cleanAccount,
		provider: cleanProvider
	})
	return {
		unshared,
		appId: targetApp.id,
		account: cleanAccount
	}
}

async function updateSession (token, opts = {}) {
	const { sessionId, name, admin, rotateToken } = opts
	const { session } = requireSession(token, opts)
	const targetId = sessionId || session.id
	if (!session.admin && targetId !== session.id) {
		const error = new Error('Access denied: session administration requires admin privileges')
		error.status = 403
		throw error
	}
	if (admin !== undefined && !session.admin) {
		const error = new Error('Access denied: changing admin privileges requires admin privileges')
		error.status = 403
		throw error
	}
	const parsedAdmin = requireBoolean(admin, 'admin')
	const shouldRotate = requireBoolean(rotateToken, 'rotateToken', false)
	requireTargetSession(session.userId, targetId)
	const updated = db.tokens.updateSession(targetId, {
		name,
		admin: parsedAdmin,
		rotateToken: shouldRotate
	})
	return {
		updated: true,
		session: {
			...formatSession(updated, session.id),
			...(shouldRotate && updated?.token ? { token: updated.token } : {})
		}
	}
}

async function listLogs (token, opts = {}) {
	const { sessionId, appId, provider, allowed, limit } = opts
	const { session } = requireSession(token, opts)
	if (!session.admin && sessionId && sessionId !== session.id) {
		const error = new Error('Access denied: log administration requires admin privileges')
		error.status = 403
		throw error
	}
	const effectiveSessionId = session.admin ? sessionId : session.id
	const logs = db.logs.listByUserId(session.userId, {
		sessionId: effectiveSessionId,
		appId,
		provider,
		allowed,
		limit
	})
	return { logs }
}
