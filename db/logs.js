import { sqlite } from './index.js'
import { userAccountSql } from './logins.js'
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
		...(row.account ? { account: row.account } : {}),
		sessionId: row.session_id,
		appId: row.resolved_app_id !== undefined ? row.resolved_app_id : row.app_id,
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
	let query = `
		SELECT logs.*,
			CASE
				WHEN logs.user_id = ? THEN ${userAccountSql('logs.user_id')}
				ELSE (
					SELECT rs.name
					FROM tokens AS rs
					WHERE rs.user_id = logs.user_id
						AND rs.type = 'share'
						AND json_extract(rs.credentials, '$.appId') = logs.app_id
					LIMIT 1
				)
			END AS account,
			COALESCE(owned.id, share.id) AS resolved_app_id
		FROM logs
		JOIN users ON logs.user_id = users.id
		LEFT JOIN tokens AS owned ON owned.id = logs.app_id AND owned.user_id = ? AND owned.type != 'share'
		LEFT JOIN tokens AS share ON share.user_id = ? AND share.type = 'share' AND json_extract(share.credentials, '$.appId') = logs.app_id
		WHERE (logs.user_id = ? OR owned.id IS NOT NULL)
	`
	const params = [userId, userId, userId, userId]
	if (sessionId) {
		query += ' AND logs.session_id = ?'
		params.push(sessionId)
	}
	if (appId) {
		query += ' AND COALESCE(owned.id, share.id) = ?'
		params.push(appId)
	}
	if (provider) {
		query += ' AND logs.provider = ?'
		params.push(provider)
	}
	const normalizedAllowed = normalizeAllowed(allowed)
	if (normalizedAllowed !== undefined) {
		query += ' AND logs.allowed = ?'
		params.push(normalizedAllowed)
	}
	const clampedLimit = Math.max(1, Math.min(Number(limit) || 100, 1000))
	query += ' ORDER BY logs.created DESC, logs.rowid DESC LIMIT ?'
	params.push(clampedLimit)
	const rows = sqlite.prepare(query).all(...params)
	return rows.map(format)
}
