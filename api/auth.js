import * as db from '../db/index.js'
import { getProvider, requireAuthProvider, hasSsoLock } from '../providers/index.js'
import { parsePolicy, validatePolicy } from '../policy.js'
import { validateBaseUrl, parseAccountSpec } from '../util.js'

export {
	whoami,
	list,
	get,
	createSession,
	updateSession,
	revoke,
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
	listLogs,
	validateBaseUrl
}

function formatLogin (login) {
	return {
		id: login.id,
		provider: login.provider,
		account: login.account
	}
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
		apps: links.map(l => ({
			id: l.app?.id,
			provider: l.app?.provider,
			type: l.app?.type,
			name: l.app?.name,
			account: l.app?.credentials?.account || null,
			scopes: l.app?.scopes,
			expiresAt: l.app?.expiresAt,
			...(l.app?.sharedBy ? { sharedBy: l.app.sharedBy } : {}),
			policy: parsePolicy(l.policy)
		}))
	}
}

async function whoami (token, opts = {}) {
	const appUrl = (opts.appUrl || 'http://localhost:8080').replace(/\/$/, '')
	const session = token ? db.tokens.getByToken(token) : null
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
	const session = token ? db.tokens.getByToken(token) : null
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
	if (requireId && !appId) {
		const error = new Error('appId is required')
		error.status = 400
		throw error
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

async function list (token, opts = {}) {
	const { session } = requireAdmin(token, opts, 'Access denied: session administration requires admin privileges')
	const rawSessions = db.tokens.listByUserId(session.userId, { provider: 'self' })
	return { sessions: rawSessions.map(s => formatSession(s, session.id)) }
}

async function get (token, sessionId, opts = {}) {
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
	const { name = 'New Session', admin = false, linkAppIds = [], policy = null } = opts
	const { session } = requireAdmin(token, opts, 'Access denied: session administration requires admin privileges')
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
		admin: admin ? 1 : 0
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

async function revoke (token, { sessionId, allOthers } = {}) {
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		return {
			revoked: false,
			message: 'No active session found for the provided token.'
		}
	}
	if (allOthers) {
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
	const apps = allTokens.filter(t => t.provider !== 'self').map(a => {
		const item = {
			id: a.id,
			provider: a.provider,
			type: a.type,
			name: a.name,
			account: a.credentials?.account || null,
			...(a.credentials?.baseUrl ? { baseUrl: a.credentials.baseUrl } : {}),
			scopes: a.scopes,
			expiresAt: a.expiresAt,
			created: a.created,
			updated: a.updated
		}
		if (a.type === 'share') {
			item.sharedBy = a.sharedBy || null
			item.policy = parsePolicy(a.credentials?.policy)
		} else {
			const shares = sharesByAppId.get(a.id)
			if (shares) item.shares = shares
		}
		return item
	})
	return { apps }
}

async function connectApp (token, opts = {}) {
	let { provider, name, apiKey, account, baseUrl, credentials, appId } = opts
	apiKey = typeof apiKey === 'string' ? apiKey.trim() : apiKey
	const { session, appUrl } = requireAdmin(token, opts)
	if (appId) {
		const existing = requireApp(session.userId, appId, { allowShare: false })
		if (!provider) provider = existing.provider
	}
	provider = (provider || 'google').toLowerCase()
	const providerDef = getProvider(provider)
	if (providerDef?.type === 'oauth' && !apiKey && !credentials) {
		const reauthParam = appId ? `&reauth_app_id=${encodeURIComponent(appId)}` : ''
		return {
			actionRequired: 'oauth_flow',
			connectUrl: `${appUrl}/providers/${providerDef.id}/connect?session_id=${session.id}${reauthParam}`
		}
	}
	const rawBase = baseUrl || credentials?.baseUrl || providerDef?.baseUrl || null
	const normalizedBaseUrl = rawBase ? validateBaseUrl(rawBase) : null
	if ((apiKey || providerDef?.type === 'api_key') && !normalizedBaseUrl) {
		const error = new Error('Valid https:// baseUrl is required for api_key apps')
		error.status = 400
		throw error
	}
	if (baseUrl !== undefined && !normalizedBaseUrl) {
		const error = new Error('Valid https:// baseUrl is required for api_key apps')
		error.status = 400
		throw error
	}
	let creds = credentials ? { ...credentials } : null
	if (creds && normalizedBaseUrl) {
		creds.baseUrl = normalizedBaseUrl
	}
	if (!creds && (apiKey || account || normalizedBaseUrl)) {
		creds = {
			...(apiKey && { apiKey }),
			...(account && { account: String(account).trim() }),
			...(normalizedBaseUrl && { baseUrl: normalizedBaseUrl })
		}
	}
	const app = db.tokens.create({
		userId: session.userId,
		provider,
		type: apiKey ? 'api_key' : 'oauth',
		name: name || providerDef.name,
		credentials: creds
	})
	return {
		connected: true,
		app: {
			id: app.id,
			provider: app.provider,
			type: app.type,
			name: app.name,
			account: app.credentials?.account || null,
			...(app.credentials?.baseUrl ? { baseUrl: app.credentials.baseUrl } : {})
		}
	}
}

async function disconnectApp (token, opts = {}) {
	const { appId, revoke = true } = opts
	const { session } = requireAdmin(token, opts)
	const targetApp = requireApp(session.userId, appId)
	const shouldRevoke = revoke !== false && revoke !== 'false' && revoke !== 0
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
	const { provider } = opts
	if (!provider || typeof provider !== 'string' || !provider.trim()) {
		const error = new Error('OAuth provider is required')
		error.status = 400
		throw error
	}
	const providerDef = requireAuthProvider(provider)
	if (hasSsoLock(session.userId, providerDef)) {
		const error = new Error('Access denied: SSO-only provider restriction prevents linking multiple sign-in providers')
		error.status = 403
		throw error
	}
	return {
		actionRequired: 'oauth_flow',
		connectUrl: `${appUrl}/oauth/authorize?session_id=${encodeURIComponent(session.id)}&provider=${encodeURIComponent(providerDef.id)}`
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
	const { appId, name, account, baseUrl, apiKey } = opts
	const { session } = requireAdmin(token, opts)
	const targetApp = requireApp(session.userId, appId, { allowShare: false, requireId: true })
	if ((account !== undefined || baseUrl !== undefined || apiKey !== undefined) && targetApp.type !== 'api_key') {
		const error = new Error('account, baseUrl, and apiKey can only be updated on api_key apps')
		error.status = 400
		throw error
	}
	let normalizedBaseUrl
	if (baseUrl !== undefined) {
		normalizedBaseUrl = validateBaseUrl(baseUrl)
		if (!normalizedBaseUrl) {
			const error = new Error('Valid https:// baseUrl is required for api_key apps')
			error.status = 400
			throw error
		}
	}
	if (name !== undefined) {
		db.tokens.updateName(appId, name)
	}
	if (account !== undefined || baseUrl !== undefined || apiKey !== undefined) {
		const updatedCreds = {
			...(targetApp.credentials || {}),
			...(account !== undefined ? { account: account ? String(account).trim() : null } : {}),
			...(baseUrl !== undefined ? { baseUrl: normalizedBaseUrl } : {}),
			...(apiKey !== undefined ? { apiKey: apiKey ? String(apiKey).trim() : null } : {})
		}
		db.tokens.updateCredentials(appId, { credentials: updatedCreds })
	}
	const updated = db.tokens.get(appId)
	return {
		updated: true,
		app: {
			id: updated.id,
			provider: updated.provider,
			type: updated.type,
			name: updated.name,
			account: updated.credentials?.account || null,
			...(updated.credentials?.baseUrl ? { baseUrl: updated.credentials.baseUrl } : {}),
			scopes: updated.scopes,
			expiresAt: updated.expiresAt,
			created: updated.created,
			updated: updated.updated
		}
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
	const sharerSsoLogin = selfLogins.find(l => getProvider(l.provider)?.ssoOnly)
	if (sharerSsoLogin && cleanProvider && cleanProvider !== sharerSsoLogin.provider) {
		const error = new Error(`Access denied: SSO-only provider restriction requires sharing within "${sharerSsoLogin.provider}"`)
		error.status = 403
		throw error
	}
	const effectiveProvider = cleanProvider || sharerSsoLogin?.provider || null
	if (effectiveProvider) {
		requireAuthProvider(effectiveProvider)
	}
	const recipient = db.logins.findUserByAccount(cleanAccount, effectiveProvider)
	if (recipient) {
		if (recipient.id === session.userId) {
			const error = new Error('Cannot share an app with yourself')
			error.status = 400
			throw error
		}
		const share = db.tokens.upsertShare({
			userId: recipient.id,
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
			userId: recipient.id,
			account: cleanAccount,
			...(resolvedProvider ? { provider: resolvedProvider } : {}),
			policy: policyCheck.policy
		}
	}
	if (!effectiveProvider && !cleanAccount.includes('@')) {
		const error = new Error(`Provider is required when sharing with bare account handle "${cleanAccount}" (e.g. provider: "github" or "github:${cleanAccount}")`)
		error.status = 400
		throw error
	}
	const share = db.tokens.upsertShare({
		userId: null,
		account: cleanAccount,
		authProvider: effectiveProvider,
		appId: targetApp.id,
		provider: targetApp.provider,
		policy: policyCheck.policy
	})
	return {
		shared: true,
		shareId: share.id,
		appId: targetApp.id,
		userId: null,
		account: cleanAccount,
		...(effectiveProvider ? { provider: effectiveProvider } : {}),
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
	requireTargetSession(session.userId, targetId)
	if (name !== undefined) {
		db.tokens.updateName(targetId, name)
	}
	if (admin !== undefined) {
		db.tokens.setAdmin(targetId, Boolean(admin))
	}
	let newToken = null
	if (rotateToken) {
		const rotated = db.tokens.rotateToken(targetId)
		newToken = rotated?.token || null
	}
	const updated = db.tokens.get(targetId)
	return {
		updated: true,
		session: {
			...formatSession(updated, session.id),
			...(newToken ? { token: newToken } : {})
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
