import * as db from '../db/index.js'
import { getProvider } from '../providers/index.js'
import { parsePolicy } from '../policy.js'
import { validateBaseUrl } from '../util.js'

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
	linkApp,
	unlinkApp,
	updateEmail,
	updateUser,
	listLogs,
	validateBaseUrl
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
			account: l.app?.credentials?.account || l.app?.credentials?.email || null,
			scopes: l.app?.scopes,
			expiresAt: l.app?.expiresAt,
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
	return {
		authenticated: true,
		user: {
			id: session.userId,
			email: session.email,
			name: session.userName
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

async function list (token, opts = {}) {
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: session administration requires admin privileges')
		error.status = 403
		throw error
	}
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
	const targetSession = db.tokens.get(sessionId)
	if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self' || !targetSession.token) {
		const error = new Error(`Session not found: ${sessionId}`)
		error.status = 404
		throw error
	}
	return { session: formatSession(targetSession, session.id) }
}

async function createSession (token, opts = {}) {
	const { name = 'New Session', admin = false, linkAppIds = [], policy = null } = opts
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: session administration requires admin privileges')
		error.status = 403
		throw error
	}
	const newSession = db.tokens.create({
		userId: session.userId,
		provider: 'self',
		type: 'bearer',
		name,
		admin: admin ? 1 : 0
	})
	for (const appId of (Array.isArray(linkAppIds) ? linkAppIds : [])) {
		const app = db.tokens.get(appId)
		if (app && app.userId === session.userId) {
			db.links.create({
				sessionId: newSession.id,
				appId: app.id,
				policy
			})
		}
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
		if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self') {
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
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: app administration requires admin privileges')
		error.status = 403
		throw error
	}
	const allTokens = db.tokens.listByUserId(session.userId)
	const apps = allTokens.filter(t => t.provider !== 'self').map(a => ({
		id: a.id,
		provider: a.provider,
		type: a.type,
		name: a.name,
		account: a.credentials?.account || a.credentials?.email || null,
		scopes: a.scopes,
		expiresAt: a.expiresAt,
		created: a.created,
		updated: a.updated
	}))
	return { apps }
}

async function connectApp (token, opts = {}) {
	let { provider, name, apiKey, account, baseUrl, credentials, appId } = opts
	const { session, appUrl } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: app administration requires admin privileges')
		error.status = 403
		throw error
	}
	if (appId && !provider) {
		const existing = db.tokens.get(appId)
		if (existing) provider = existing.provider
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
		name: name || `${provider} app`,
		credentials: creds
	})
	return {
		connected: true,
		app: {
			id: app.id,
			provider: app.provider,
			type: app.type,
			name: app.name,
			account: app.credentials?.account || app.credentials?.email || null,
			...(app.credentials?.baseUrl ? { baseUrl: app.credentials.baseUrl } : {})
		}
	}
}

async function disconnectApp (token, opts = {}) {
	const { appId, revoke = true } = opts
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: app administration requires admin privileges')
		error.status = 403
		throw error
	}
	const targetApp = db.tokens.get(appId)
	if (!targetApp || targetApp.userId !== session.userId || targetApp.provider === 'self') {
		const error = new Error(`App not found: ${appId}`)
		error.status = 404
		throw error
	}
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
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: link administration requires admin privileges')
		error.status = 403
		throw error
	}
	const targetSession = db.tokens.get(sessionId)
	if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self' || !targetSession.token) {
		const error = new Error(`Session not found: ${sessionId}`)
		error.status = 404
		throw error
	}
	const targetApp = db.tokens.get(appId)
	if (!targetApp || targetApp.userId !== session.userId || targetApp.provider === 'self') {
		const error = new Error(`App not found: ${appId}`)
		error.status = 404
		throw error
	}
	const link = db.links.create({
		sessionId: targetSession.id,
		appId: targetApp.id,
		policy
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
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: link administration requires admin privileges')
		error.status = 403
		throw error
	}
	const targetSession = db.tokens.get(sessionId)
	if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self' || !targetSession.token) {
		const error = new Error(`Session not found: ${sessionId}`)
		error.status = 404
		throw error
	}
	const targetApp = db.tokens.get(appId)
	if (!targetApp || targetApp.userId !== session.userId || targetApp.provider === 'self') {
		const error = new Error(`App not found: ${appId}`)
		error.status = 404
		throw error
	}
	const removed = db.links.remove(targetSession.id, targetApp.id)
	return {
		unlinked: removed,
		sessionId: targetSession.id,
		appId: targetApp.id
	}
}

async function updateEmail (token, opts = {}) {
	const newEmail = opts.email || opts.newEmail
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: updating account email requires admin privileges')
		error.status = 403
		throw error
	}
	if (!newEmail || typeof newEmail !== 'string' || !newEmail.includes('@')) {
		const error = new Error('Valid new email address is required')
		error.status = 400
		throw error
	}
	const normalizedEmail = newEmail.trim().toLowerCase()
	const existing = db.users.getByEmail(normalizedEmail)
	if (existing && existing.id !== session.userId) {
		const error = new Error(`Email already registered to another account: ${normalizedEmail}`)
		error.status = 409
		throw error
	}
	const user = db.users.updateEmail(session.userId, normalizedEmail)
	return {
		updated: true,
		user: {
			id: user.id,
			email: user.email,
			name: user.name
		}
	}
}

async function updateUser (token, opts = {}) {
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: updating user profile requires admin privileges')
		error.status = 403
		throw error
	}
	const { id, email, appUrl, ...updates } = opts
	const user = db.users.updateUser(session.userId, updates)
	return {
		updated: true,
		user: {
			id: user.id,
			email: user.email,
			name: user.name
		}
	}
}

async function updateApp (token, opts = {}) {
	const { appId, name, account, baseUrl } = opts
	const { session } = requireSession(token, opts)
	if (!session.admin) {
		const error = new Error('Access denied: app administration requires admin privileges')
		error.status = 403
		throw error
	}
	if (!appId) {
		const error = new Error('appId is required')
		error.status = 400
		throw error
	}
	const targetApp = db.tokens.get(appId)
	if (!targetApp || targetApp.userId !== session.userId || targetApp.provider === 'self') {
		const error = new Error(`App not found: ${appId}`)
		error.status = 404
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
	if (account !== undefined || baseUrl !== undefined) {
		const updatedCreds = {
			...(targetApp.credentials || {}),
			...(account !== undefined ? { account: account ? String(account).trim() : null } : {}),
			...(baseUrl !== undefined ? { baseUrl: normalizedBaseUrl } : {})
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
			account: updated.credentials?.account || updated.credentials?.email || null,
			...(updated.credentials?.baseUrl ? { baseUrl: updated.credentials.baseUrl } : {}),
			scopes: updated.scopes,
			expiresAt: updated.expiresAt,
			created: updated.created,
			updated: updated.updated
		}
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
	const targetSession = db.tokens.get(targetId)
	if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self' || !targetSession.token) {
		const error = new Error(`Session not found: ${targetId}`)
		error.status = 404
		throw error
	}
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
