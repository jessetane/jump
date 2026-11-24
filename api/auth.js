import * as db from '../db/index.js'
import { RESERVED_PROVIDERS, isValidProviderId, getProvider, listOauthProviders, requireOauthProvider, normalizeServiceSelections } from '../providers/index.js'
import { assertSsoLink, resolveShareProvider } from '../sso.js'
import { parsePolicy, validatePolicy } from '../policy.js'
import { HOP_BY_HOP_HEADERS, assertKeys, getBaseUrl, httpError, validateBaseUrl, parseAccountSpec, isPlainObject, requireBoolean, optionalString } from '../util.js'

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

function resolveOrigin (appUrl) {
	return appUrl ? appUrl.replace(/\/+$/, '') : getBaseUrl()
}

async function whoami (token, opts = {}, appUrl) {
	assertKeys(opts, [])
	const session = db.tokens.resolveSession(token)
	if (!session) {
		return {
			authenticated: false,
			signInUrl: `${resolveOrigin(appUrl)}/oauth/authorize`,
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

function requireSession (token) {
	const session = db.tokens.resolveSession(token)
	if (!session) {
		throw httpError(401, 'Authentication required')
	}
	return session
}

function requireAdmin (token, message = 'Access denied: app administration requires admin privileges') {
	const session = requireSession(token)
	if (!session.admin) {
		throw httpError(403, message)
	}
	return session
}

function requireApp (userId, appId, { allowShare = true } = {}) {
	appId = requireNonEmptyString(appId, 'appId')
	const targetApp = db.tokens.get(appId)
	if (!targetApp || targetApp.userId !== userId || !db.tokens.isUpstreamApp(targetApp, { allowShare })) {
		throw httpError(404, `App not found: ${appId}`)
	}
	return targetApp
}

function requireTargetSession (userId, sessionId) {
	sessionId = requireNonEmptyString(sessionId, 'sessionId')
	const targetSession = db.tokens.get(sessionId)
	if (!db.tokens.isSession(targetSession) || targetSession.userId !== userId) {
		throw httpError(404, `Session not found: ${sessionId}`)
	}
	return targetSession
}

function requireShareTarget (token, opts = {}, allowedKeys = ['appId', 'account', 'provider']) {
	const session = requireAdmin(token)
	assertKeys(opts, allowedKeys)
	const { appId, account, provider = null } = opts
	if (!appId) {
		throw httpError(400, 'appId is required')
	}
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	if (!cleanAccount) {
		throw httpError(400, 'Valid recipient account identifier is required')
	}
	const targetApp = requireApp(session.userId, appId, { allowShare: false })
	return { session, targetApp, cleanAccount, cleanProvider }
}

async function listSessions (token, opts = {}) {
	const session = requireAdmin(token, 'Access denied: session administration requires admin privileges')
	assertKeys(opts, [])
	const rawSessions = db.tokens.listByUserId(session.userId, { provider: 'self' })
	return { sessions: rawSessions.map(s => formatSession(s, session.id)) }
}

async function getSession (token, opts = {}) {
	const session = requireSession(token)
	assertKeys(opts, ['sessionId'])
	const sessionId = requireNonEmptyString(opts.sessionId, 'sessionId')
	if (!session.admin && sessionId !== session.id) {
		throw httpError(403, 'Access denied: session administration requires admin privileges')
	}
	const targetSession = requireTargetSession(session.userId, sessionId)
	return { session: formatSession(targetSession, session.id) }
}

async function createSession (token, opts = {}) {
	const session = requireAdmin(token, 'Access denied: session administration requires admin privileges')
	assertKeys(opts, ['name', 'admin', 'linkAppIds', 'policy'])
	const { name, admin, linkAppIds = [], policy = null } = opts
	const cleanName = optionalString(name, 'name')
	const isAdmin = requireBoolean(admin, 'admin', false)
	if (!Array.isArray(linkAppIds)) {
		throw httpError(400, 'linkAppIds must be an array')
	}
	const policyCheck = validatePolicy(policy)
	if (!policyCheck.valid) {
		throw httpError(400, policyCheck.error)
	}
	if (policyCheck.policy !== null && linkAppIds.length === 0) {
		throw httpError(400, 'policy requires at least one appId in linkAppIds')
	}
	const appsToLink = []
	for (const appId of linkAppIds) {
		appsToLink.push(requireApp(session.userId, appId))
	}
	const newSession = db.tokens.create({
		userId: session.userId,
		provider: 'self',
		type: 'bearer',
		name: cleanName,
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

async function revokeSession (token, opts = {}) {
	assertKeys(opts, ['sessionId', 'allOthers'])
	const { sessionId, allOthers } = opts || {}
	const session = requireSession(token)
	if (sessionId !== undefined) requireNonEmptyString(sessionId, 'sessionId')
	const shouldRevokeAllOthers = requireBoolean(allOthers, 'allOthers', false)
	if (shouldRevokeAllOthers) {
		if (!session.admin) {
			throw httpError(403, 'Access denied: revoking other sessions requires admin privileges')
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
			throw httpError(403, 'Access denied: revoking other sessions requires admin privileges')
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
	const session = requireAdmin(token)
	assertKeys(opts, [])
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

function requireNonEmptyString (val, label) {
	if (typeof val !== 'string' || !val.trim()) {
		throw httpError(400, `${label} must be a non-empty string`)
	}
	return val.trim()
}

function requireValidBaseUrl (rawBase) {
	const normalized = rawBase ? validateBaseUrl(rawBase) : null
	if (!normalized) {
		throw httpError(400, 'Valid https:// baseUrl is required for static apps')
	}
	return normalized
}

const ALLOWED_CREDENTIAL_KEYS = new Set(['bearer', 'basic', 'headers', 'query'])
const DISALLOWED_CREDENTIAL_HEADERS = new Set([
	...HOP_BY_HOP_HEADERS,
	'content-length',
	'host',
	'cookie'
])

function assertHeaderValue (val, label) {
	if (typeof val !== 'string' || !val.trim() || /[\r\n]/.test(val)) {
		throw httpError(400, `${label} must be a valid non-empty HTTP header value`)
	}
	try {
		new Headers().set('x-check', val)
	} catch {
		throw httpError(400, `${label} contains invalid HTTP header characters`)
	}
}

function normalizeBearerToken (raw, label) {
	if (typeof raw !== 'string' || !raw.trim()) {
		throw httpError(400, `${label} must be a non-empty string`)
	}
	assertHeaderValue(raw, label)
	const trimmed = raw.trim()
	if (/^Bearer(?:[ \t]+|$)/i.test(trimmed)) {
		const rest = trimmed.replace(/^Bearer/i, '').trim()
		if (!rest) throw httpError(400, `${label} must contain a non-empty token`)
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
		throw httpError(400, 'credentials must be a non-empty string or object')
	}
	for (const key of Object.keys(raw)) {
		if (!ALLOWED_CREDENTIAL_KEYS.has(key)) {
			throw httpError(400, `Unknown credentials field "${key}"`)
		}
	}
	const headers = new Headers()
	let authSource = null
	if (raw.bearer !== undefined) {
		const token = normalizeBearerToken(raw.bearer, 'credentials.bearer')
		headers.set('authorization', `Bearer ${token}`)
		authSource = 'bearer'
	}
	if (raw.basic !== undefined) {
		if (typeof raw.basic !== 'string' || !raw.basic.trim()) {
			throw httpError(400, 'credentials.basic must be a non-empty "user:pass" string')
		}
		if (/[\x00-\x1f\x7f]/.test(raw.basic)) {
			throw httpError(400, 'credentials.basic must not contain control characters')
		}
		const cleanBasic = raw.basic.trim()
		if (!cleanBasic.includes(':') || cleanBasic === ':') {
			throw httpError(400, 'credentials.basic must be in "user:pass" format')
		}
		if (authSource) {
			throw httpError(400, 'Conflicting Authorization credentials: specify only one of bearer, basic, or headers.authorization')
		}
		headers.set('authorization', `Basic ${Buffer.from(cleanBasic).toString('base64')}`)
		authSource = 'basic'
	}
	if (raw.headers !== undefined) {
		if (!isPlainObject(raw.headers) || Object.keys(raw.headers).length === 0) {
			throw httpError(400, 'credentials.headers must be a non-empty object of header names to string values')
		}
		for (const [rawName, val] of Object.entries(raw.headers)) {
			const name = rawName.toLowerCase()
			if (DISALLOWED_CREDENTIAL_HEADERS.has(name)) {
				throw httpError(400, `Forbidden header in credentials.headers: "${name}"`)
			}
			assertHeaderValue(val, `credentials.headers["${rawName}"]`)
			let alreadySet = false
			try {
				alreadySet = headers.has(rawName)
				if (!alreadySet) headers.set(rawName, val)
			} catch {
				throw httpError(400, `Invalid HTTP header name in credentials.headers: "${rawName}"`)
			}
			if (alreadySet) {
				if (name === 'authorization' && authSource !== 'headers.authorization') {
					throw httpError(400, 'Conflicting Authorization credentials: specify only one of bearer, basic, or headers.authorization')
				}
				throw httpError(400, `Duplicate header in credentials.headers: "${name}"`)
			}
			if (name === 'authorization') {
				authSource = 'headers.authorization'
			}
		}
	}
	const query = Object.create(null)
	if (raw.query !== undefined) {
		if (!isPlainObject(raw.query) || Object.keys(raw.query).length === 0) {
			throw httpError(400, 'credentials.query must be a non-empty object of parameter names to string values')
		}
		const seenLower = new Set()
		for (const [rawParam, val] of Object.entries(raw.query)) {
			if (/[\x00-\x1f\x7f]/.test(rawParam)) {
				throw httpError(400, 'credentials.query parameter names must not contain control characters')
			}
			const param = rawParam.trim()
			if (!param) {
				throw httpError(400, 'credentials.query parameter names must be non-empty strings')
			}
			const lower = param.toLowerCase()
			if (seenLower.has(lower)) {
				throw httpError(400, `Duplicate query parameter in credentials.query: "${param}"`)
			}
			seenLower.add(lower)
			if (typeof val !== 'string' || /[\x00-\x1f\x7f]/.test(val)) {
				throw httpError(400, `credentials.query["${rawParam}"] must be a valid string`)
			}
			query[param] = val
		}
	}
	const headerMap = Object.assign(Object.create(null), Object.fromEntries(headers))
	const hasHeaders = Object.keys(headerMap).length > 0
	const hasQuery = Object.keys(query).length > 0
	if (!hasHeaders && !hasQuery) {
		throw httpError(400, 'credentials must specify at least one of bearer, basic, headers, or query')
	}
	return {
		...(hasHeaders && { headers: headerMap }),
		...(hasQuery && { query })
	}
}

async function connectApp (token, opts = {}, appUrl) {
	const session = requireAdmin(token)
	assertKeys(opts, ['provider', 'name', 'credentials', 'account', 'baseUrl', 'appId', 'services'])
	let { provider, name, credentials, account, baseUrl, appId, services } = opts || {}
	if (provider === undefined || provider === null) {
		provider = null
	} else {
		provider = requireNonEmptyString(provider, 'provider').toLowerCase()
	}
	const cleanName = optionalString(name, 'name')
	const cleanAccount = optionalString(account, 'account')
	if (appId !== undefined) {
		const existing = requireApp(session.userId, appId, { allowShare: false })
		appId = existing.id
		if (provider && provider !== existing.provider) {
			throw httpError(400, `App ${appId} belongs to provider "${existing.provider}", not "${provider}"`)
		}
		if (existing.type !== 'oauth') {
			throw httpError(400, `Cannot re-authenticate ${existing.type} app via connect_app; use update_app instead`)
		}
		if (name !== undefined || credentials !== undefined || account !== undefined || baseUrl !== undefined) {
			throw httpError(400, 'Cannot pass name, credentials, account, or baseUrl with appId in connect_app; use update_app instead')
		}
		provider = existing.provider
	}
	const normalizedAuth = credentials !== undefined ? normalizeCredentials(credentials) : null
	provider = provider || 'google'
	if (!isValidProviderId(provider)) {
		const msg = RESERVED_PROVIDERS.has(provider)
			? `provider cannot be "${provider}"`
			: 'provider must contain only letters, digits, underscores, or hyphens'
		throw httpError(400, msg)
	}
	const providerDef = getProvider(provider)
	if (providerDef?.type === 'oauth' && !normalizedAuth) {
		requireOauthProvider(providerDef.id, 'app')
		let resolvedServices = null
		if (services !== undefined) {
			if (!providerDef.services) {
				throw httpError(400, `Provider "${providerDef.id}" does not support service permissions`)
			}
			resolvedServices = normalizeServiceSelections(providerDef.services, services, { strict: true, providerId: providerDef.id })
			if (resolvedServices.length === 0) {
				throw httpError(400, 'services must contain at least one service')
			}
		}
		const setupCode = db.tokens.createState({
			mode: 'setup_connect',
			sessionId: session.id,
			provider: providerDef.id,
			reauthAppId: appId || null,
			name: cleanName,
			services: resolvedServices,
			ttl: 10 * 60 * 1000
		})
		return {
			actionRequired: 'oauth_flow',
			connectUrl: `${resolveOrigin(appUrl)}/providers/${providerDef.id}/connect?code=${encodeURIComponent(setupCode)}`
		}
	}
	if (services !== undefined) {
		throw httpError(400, 'services is only supported for OAuth apps')
	}
	if (!normalizedAuth) {
		throw httpError(400, 'credentials is required for static apps')
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
		type: 'static',
		name: cleanName || providerDef.name,
		credentials: creds
	})
	return {
		connected: true,
		app: formatApp(app)
	}
}

async function disconnectApp (token, opts = {}) {
	const session = requireAdmin(token)
	assertKeys(opts, ['appId', 'revoke'])
	const { appId, revoke } = opts || {}
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
	const session = requireAdmin(token, 'Access denied: link administration requires admin privileges')
	assertKeys(opts, ['sessionId', 'appId', 'policy'])
	const { sessionId, appId, policy = null } = opts || {}
	const policyCheck = validatePolicy(policy)
	if (!policyCheck.valid) {
		throw httpError(400, policyCheck.error)
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
	const session = requireAdmin(token, 'Access denied: link administration requires admin privileges')
	assertKeys(opts, ['sessionId', 'appId'])
	const { sessionId, appId } = opts || {}
	const targetSession = requireTargetSession(session.userId, sessionId)
	const targetApp = requireApp(session.userId, appId)
	const removed = db.links.remove(targetSession.id, targetApp.id)
	return {
		unlinked: removed,
		sessionId: targetSession.id,
		appId: targetApp.id
	}
}

async function linkLogin (token, opts = {}, appUrl) {
	const session = requireAdmin(token, 'Access denied: login administration requires admin privileges')
	assertKeys(opts, ['provider', 'merge'])
	const { provider, merge } = opts || {}
	const cleanProvider = optionalString(provider, 'provider')
	const shouldMerge = requireBoolean(merge, 'merge', false)
	const existingLogins = db.logins.listByUserId(session.userId)
	let resolvedProvider = null
	if (cleanProvider) {
		const providerDef = requireOauthProvider(cleanProvider, 'auth')
		assertSsoLink(existingLogins, providerDef.id)
		resolvedProvider = providerDef.id
	} else if (listOauthProviders('auth').length === 0) {
		throw httpError(400, 'No OAuth sign-in providers are configured')
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
		connectUrl: `${resolveOrigin(appUrl)}/oauth/authorize?code=${encodeURIComponent(setupCode)}`
	}
}

async function unlinkLogin (token, opts = {}) {
	const session = requireAdmin(token, 'Access denied: login administration requires admin privileges')
	assertKeys(opts, ['loginId', 'provider', 'account'])
	const { loginId = null, provider = null, account = null } = opts || {}
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	if (!loginId && !cleanProvider && !cleanAccount) {
		throw httpError(400, 'loginId, provider, or account is required to unlink a login key')
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
	const session = requireAdmin(token)
	assertKeys(opts, ['appId', 'name', 'account', 'baseUrl', 'credentials'])
	const { appId, name, account, baseUrl, credentials } = opts || {}
	const targetApp = requireApp(session.userId, appId, { allowShare: false })
	if (name === undefined && account === undefined && baseUrl === undefined && credentials === undefined) {
		throw httpError(400, 'At least one of name, account, baseUrl, or credentials is required')
	}
	if ((account !== undefined || baseUrl !== undefined || credentials !== undefined) && targetApp.type !== 'static') {
		throw httpError(400, 'account, baseUrl, and credentials can only be updated on static apps')
	}
	const cleanName = name !== undefined ? optionalString(name, 'name') : undefined
	const cleanAccount = account !== undefined ? optionalString(account, 'account') : undefined
	const normalizedAuth = credentials !== undefined ? normalizeCredentials(credentials) : undefined
	const normalizedBaseUrl = baseUrl !== undefined ? requireValidBaseUrl(baseUrl) : undefined
	const hasCredChanges = cleanAccount !== undefined || normalizedBaseUrl !== undefined || normalizedAuth !== undefined
	let updatedCreds = undefined
	if (hasCredChanges) {
		const existingCreds = targetApp.credentials || {}
		const { headers: _h, query: _q, ...metaCreds } = existingCreds
		updatedCreds = {
			...(normalizedAuth !== undefined ? { ...metaCreds, ...normalizedAuth } : existingCreds),
			...(normalizedBaseUrl !== undefined && { baseUrl: normalizedBaseUrl })
		}
		if (cleanAccount !== undefined) {
			if (cleanAccount) updatedCreds.account = cleanAccount
			else delete updatedCreds.account
		}
	}
	const updated = db.tokens.updateCredentials(targetApp.id, {
		...(cleanName !== undefined ? { name: cleanName } : {}),
		...(updatedCreds !== undefined ? { credentials: updatedCreds } : {})
	})
	return {
		updated: true,
		app: formatApp(updated)
	}
}

async function shareApp (token, opts = {}) {
	const { session, targetApp, cleanAccount, cleanProvider } = requireShareTarget(token, opts, ['appId', 'account', 'provider', 'policy'])
	const { policy = null } = opts || {}
	const selfLogins = db.logins.listByUserId(session.userId)
	const isSelf = selfLogins.some(l => {
		const acc = (l.account || '').toLowerCase()
		return cleanProvider ? (l.provider === cleanProvider && acc === cleanAccount) : acc === cleanAccount
	}) || (!selfLogins.length && !cleanProvider && cleanAccount === (session.account || '').toLowerCase())
	if (isSelf) {
		throw httpError(400, 'Cannot share an app with yourself')
	}
	const policyCheck = validatePolicy(policy)
	if (!policyCheck.valid) {
		throw httpError(400, policyCheck.error)
	}
	const effectiveProvider = resolveShareProvider(selfLogins, cleanAccount, cleanProvider)
	if (effectiveProvider) {
		requireOauthProvider(effectiveProvider, 'auth')
	}
	const recipient = db.logins.findUserByAccount(cleanAccount, effectiveProvider)
	if (recipient && recipient.id === session.userId) {
		throw httpError(400, 'Cannot share an app with yourself')
	}
	if (!recipient && !effectiveProvider && !cleanAccount.includes('@')) {
		throw httpError(400, `Provider is required when sharing with bare account handle "${cleanAccount}" (e.g. provider: "github" or "github:${cleanAccount}")`)
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
	const session = requireSession(token)
	assertKeys(opts, ['sessionId', 'name', 'admin', 'rotateToken'])
	const { sessionId, name, admin, rotateToken } = opts || {}
	if (sessionId !== undefined) requireNonEmptyString(sessionId, 'sessionId')
	const targetId = sessionId || session.id
	if (!session.admin && targetId !== session.id) {
		throw httpError(403, 'Access denied: session administration requires admin privileges')
	}
	if (admin !== undefined && !session.admin) {
		throw httpError(403, 'Access denied: changing admin privileges requires admin privileges')
	}
	if (name === undefined && admin === undefined && rotateToken === undefined) {
		throw httpError(400, 'At least one of name, admin, or rotateToken is required')
	}
	const cleanName = name !== undefined ? optionalString(name, 'name') : undefined
	const parsedAdmin = requireBoolean(admin, 'admin')
	const shouldRotate = requireBoolean(rotateToken, 'rotateToken', false)
	requireTargetSession(session.userId, targetId)
	const updated = db.tokens.updateSession(targetId, {
		name: cleanName,
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
	const session = requireSession(token)
	assertKeys(opts, ['sessionId', 'appId', 'provider', 'allowed', 'limit'])
	const { sessionId, appId, provider, allowed, limit } = opts || {}
	const cleanSessionId = optionalString(sessionId, 'sessionId')
	if (!session.admin && cleanSessionId && cleanSessionId !== session.id) {
		throw httpError(403, 'Access denied: log administration requires admin privileges')
	}
	const effectiveSessionId = session.admin ? cleanSessionId : session.id
	const logs = db.logs.listByUserId(session.userId, {
		sessionId: effectiveSessionId,
		appId,
		provider,
		allowed,
		limit
	})
	return { logs }
}
