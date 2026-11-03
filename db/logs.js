import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	create,
	listByUserId,
	prune,
	format
}

let lastPruned = 0

function init () {
	sqlite.exec(`
		CREATE TABLE IF NOT EXISTS logs (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			session_id TEXT,
			app_id TEXT,
			provider TEXT NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			allowed INTEGER NOT NULL,
			status INTEGER,
			duration INTEGER,
			error TEXT,
			created TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created);
		CREATE INDEX IF NOT EXISTS idx_logs_user_created ON logs(user_id, created DESC);
		CREATE INDEX IF NOT EXISTS idx_logs_session_created ON logs(session_id, created DESC);
	`)
}

function format (row) {
	if (!row) return null
	return {
		id: row.id,
		userId: row.user_id,
		sessionId: row.session_id,
		appId: row.app_id,
		provider: row.provider,
		method: row.method,
		url: row.url,
		allowed: Boolean(row.allowed),
		status: row.status,
		duration: row.duration,
		error: row.error,
		created: row.created
	}
}

function normalizeAllowed (allowed) {
	if (allowed === true || allowed === 'true' || allowed === 1 || allowed === '1') return 1
	if (allowed === false || allowed === 'false' || allowed === 0 || allowed === '0') return 0
	return undefined
}

function prune (maxAgeMs = 30 * 24 * 60 * 60 * 1000) {
	lastPruned = Date.now()
	const minDate = new Date(lastPruned - maxAgeMs).toISOString()
	sqlite.prepare('DELETE FROM logs WHERE created < ?').run(minDate)
}

function pruneIfNeeded () {
	if (Date.now() - lastPruned > 60000) {
		prune()
	}
}

function create (opts = {}) {
	const {
		id = randomUUID(),
		userId,
		sessionId = null,
		appId = null,
		provider,
		method,
		url,
		allowed,
		status = null,
		duration = null,
		error = null
	} = opts
	pruneIfNeeded()
	const created = new Date().toISOString()
	const allowedInt = allowed ? 1 : 0
	sqlite.prepare(`
		INSERT INTO logs (id, user_id, session_id, app_id, provider, method, url, allowed, status, duration, error, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(id, userId, sessionId, appId, provider, method, url, allowedInt, status, duration, error, created)
	return format({
		id,
		user_id: userId,
		session_id: sessionId,
		app_id: appId,
		provider,
		method,
		url,
		allowed: allowedInt,
		status,
		duration,
		error,
		created
	})
}

function listByUserId (userId, opts = {}) {
	if (!userId) return []
	pruneIfNeeded()
	const { sessionId, appId, provider, allowed, limit = 100 } = opts
	let query = 'SELECT * FROM logs WHERE user_id = ?'
	const params = [userId]
	if (sessionId) {
		query += ' AND session_id = ?'
		params.push(sessionId)
	}
	if (appId) {
		query += ' AND app_id = ?'
		params.push(appId)
	}
	if (provider) {
		query += ' AND provider = ?'
		params.push(provider)
	}
	const normalizedAllowed = normalizeAllowed(allowed)
	if (normalizedAllowed !== undefined) {
		query += ' AND allowed = ?'
		params.push(normalizedAllowed)
	}
	const clampedLimit = Math.max(1, Math.min(Number(limit) || 100, 1000))
	query += ' ORDER BY created DESC, rowid DESC LIMIT ?'
	params.push(clampedLimit)
	const rows = sqlite.prepare(query).all(...params)
	return rows.map(format)
}
