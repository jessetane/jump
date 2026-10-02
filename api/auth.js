import * as db from '../db/index.js'
import { revokeGoogleToken } from '../providers/google.js'
import { parsePolicy } from '../policy.js'

export {
	whoami,
	status,
	list,
	listSessions,
	get,
	createSession,
	updateSession,
	revoke,
	revokeSession,
	listApps,
	connectApp,
	disconnectApp,
	updateApp,
	linkApp,
	unlinkApp,
	updateEmail,
	updateUser
}

const status = whoami
const listSessions = list
const revokeSession = revoke

async function whoami (token) {
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		return {
			authenticated: false,
			signInUrl: `${appUrl.replace(/\/$/, '')}/oauth/authorize`,
			message: 'Missing or expired Bearer token.'
		}
	}
	const links = db.links.listBySessionId(session.id)
	const apps = links.map(l => ({
		id: l.app?.id,
		provider: l.app?.provider,
		type: l.app?.type,
		name: l.app?.name,
		account: l.app?.credentials?.account || l.app?.credentials?.email || null,
		scopes: l.app?.scopes,
		expiresAt: l.app?.expiresAt,
		policy: parsePolicy(l.policy)
	}))
	return {
		authenticated: true,
		user: {
			id: session.userId,
			email: session.email,
			name: session.userName
		},
		session: {
			id: session.id,
			name: session.name,
			admin: Boolean(session.admin),
			ip: session.ip,
			ua: session.ua,
			created: session.created,
			updated: session.updated,
			apps
		}
	}
}

async function list (token) {
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
	if (!session.admin) {
		const error = new Error('Access denied: session administration requires admin privileges')
		error.status = 403
		throw error
	}
	const rawSessions = db.tokens.listByUserId(session.userId, { provider: 'self' })
	const sessions = rawSessions.map(s => {
		const links = db.links.listBySessionId(s.id)
		return {
			id: s.id,
			userId: s.userId,
			name: s.name,
			admin: Boolean(s.admin),
			ip: s.ip,
			ua: s.ua,
			created: s.created,
			updated: s.updated,
			isCurrent: s.id === session.id,
			apps: links.map(l => ({
				id: l.app?.id,
				provider: l.app?.provider,
				name: l.app?.name,
				account: l.app?.credentials?.account || l.app?.credentials?.email || null,
				policy: parsePolicy(l.policy)
			}))
		}
	})
	return { sessions }
}

async function get (token, sessionId) {
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
	if (!session.admin && sessionId !== session.id) {
		const error = new Error('Access denied: session administration requires admin privileges')
		error.status = 403
		throw error
	}
	const targetSession = db.tokens.get(sessionId)
	if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self') {
		const error = new Error(`Session not found: ${sessionId}`)
		error.status = 404
		throw error
	}
	const links = db.links.listBySessionId(targetSession.id)
	return {
		session: {
			id: targetSession.id,
			userId: targetSession.userId,
			name: targetSession.name,
			admin: Boolean(targetSession.admin),
			ip: targetSession.ip,
			ua: targetSession.ua,
			created: targetSession.created,
			updated: targetSession.updated,
			isCurrent: targetSession.id === session.id,
			apps: links.map(l => ({
				id: l.app?.id,
				provider: l.app?.provider,
				name: l.app?.name,
				account: l.app?.credentials?.account || l.app?.credentials?.email || null,
				policy: parsePolicy(l.policy)
			}))
		}
	}
}

async function createSession (token, opts = {}) {
	const { name = 'New Session', admin = false, linkAppIds = [], policy = null } = opts
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
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
				sessionTokenId: newSession.id,
				appTokenId: app.id,
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
		if (!targetSession || targetSession.userId !== session.userId) {
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

async function listApps (token) {
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
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
	let { provider, name, apiKey, account, credentials, appId } = opts
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
	if (!session.admin) {
		const error = new Error('Access denied: app administration requires admin privileges')
		error.status = 403
		throw error
	}
	if (appId && !provider) {
		const existing = db.tokens.get(appId)
		if (existing) provider = existing.provider
	}
	provider = provider || 'google'
	if (provider === 'google' && !apiKey && !credentials) {
		const reauthParam = appId ? `&reauth_app_id=${encodeURIComponent(appId)}` : ''
		return {
			actionRequired: 'oauth_flow',
			connectUrl: `${appUrl.replace(/\/$/, '')}/providers/google/connect?session_id=${session.id}${reauthParam}`
		}
	}
	let creds = credentials
	if (!creds && apiKey) {
		creds = { apiKey, ...(account && { account: String(account).trim() }) }
	} else if (!creds && account) {
		creds = { account: String(account).trim() }
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
			account: app.credentials?.account || app.credentials?.email || null
		}
	}
}

async function disconnectApp (token, opts = {}) {
	const { appId, revoke = true } = opts
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
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
	if (shouldRevoke && targetApp.provider === 'google') {
		const upstream = targetApp.credentials?.refreshToken || targetApp.credentials?.accessToken
		if (upstream) await revokeGoogleToken(upstream)
	}
	db.tokens.remove(targetApp.id)
	return {
		disconnected: true,
		appId: targetApp.id
	}
}

async function linkApp (token, { sessionId, appId, policy = null } = {}) {
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
	if (!session.admin) {
		const error = new Error('Access denied: link administration requires admin privileges')
		error.status = 403
		throw error
	}
	const targetSession = db.tokens.get(sessionId)
	if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self') {
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
		sessionTokenId: targetSession.id,
		appTokenId: targetApp.id,
		policy
	})
	return {
		linked: true,
		sessionTokenId: link.sessionTokenId,
		appTokenId: link.appTokenId,
		policy: parsePolicy(link.policy)
	}
}

async function unlinkApp (token, { sessionId, appId } = {}) {
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
	if (!session.admin) {
		const error = new Error('Access denied: link administration requires admin privileges')
		error.status = 403
		throw error
	}
	const removed = db.links.remove(sessionId, appId)
	return {
		unlinked: removed,
		sessionId,
		appId
	}
}

async function updateEmail (token, opts = {}) {
	const newEmail = opts.email || opts.newEmail
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
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
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
	if (!session.admin) {
		const error = new Error('Access denied: updating user profile requires admin privileges')
		error.status = 403
		throw error
	}
	const { id, email, ...updates } = opts
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
	const { appId, name, account } = opts
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
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
	if (name !== undefined) {
		db.tokens.updateName(appId, name)
	}
	if (account !== undefined) {
		const updatedCreds = {
			...(targetApp.credentials || {}),
			account: account ? String(account).trim() : null
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
			scopes: updated.scopes,
			expiresAt: updated.expiresAt,
			created: updated.created,
			updated: updated.updated
		}
	}
}

async function updateSession (token, opts = {}) {
	const { sessionId, name, admin, rotateToken } = opts
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const error = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		error.status = 401
		throw error
	}
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
	if (!targetSession || targetSession.userId !== session.userId || targetSession.provider !== 'self') {
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
			id: updated.id,
			userId: updated.userId,
			name: updated.name,
			admin: Boolean(updated.admin),
			...(newToken ? { token: newToken } : {}),
			ip: updated.ip,
			ua: updated.ua,
			created: updated.created,
			updated: updated.updated,
			isCurrent: updated.id === session.id
		}
	}
}
