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
	revoke,
	revokeSession,
	listApps,
	connectApp,
	disconnectApp,
	linkApp,
	unlinkApp
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
	const linkedApps = links.map(l => ({
		id: l.app?.id,
		provider: l.app?.provider,
		type: l.app?.type,
		name: l.app?.name,
		scopes: l.app?.scopes,
		expiresAt: l.app?.expiresAt,
		policy: parsePolicy(l.policy)
	}))
	return {
		authenticated: true,
		email: session.email,
		admin: Boolean(session.admin),
		currentSession: {
			id: session.id,
			name: session.name,
			admin: Boolean(session.admin),
			ip: session.ip,
			ua: session.ua,
			created: session.created,
			updated: session.updated
		},
		linkedApps
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
			linkedApps: links.map(l => ({
				id: l.app?.id,
				provider: l.app?.provider,
				name: l.app?.name,
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
			linkedApps: links.map(l => ({
				id: l.app?.id,
				provider: l.app?.provider,
				name: l.app?.name,
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
		scopes: a.scopes,
		expiresAt: a.expiresAt,
		created: a.created,
		updated: a.updated
	}))
	return { apps }
}

async function connectApp (token, opts = {}) {
	const { provider = 'google', name, apiKey, credentials } = opts
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
	if (provider === 'google' && !apiKey && !credentials) {
		return {
			actionRequired: 'oauth_flow',
			connectUrl: `${appUrl.replace(/\/$/, '')}/oauth/authorize?action=connect_app`
		}
	}
	const app = db.tokens.create({
		userId: session.userId,
		provider,
		type: apiKey ? 'api_key' : 'oauth',
		name: name || `${provider} app`,
		credentials: credentials || (apiKey ? { apiKey } : null)
	})
	return {
		connected: true,
		app: {
			id: app.id,
			provider: app.provider,
			type: app.type,
			name: app.name
		}
	}
}

async function disconnectApp (token, { appId } = {}) {
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
	if (targetApp.provider === 'google') {
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
