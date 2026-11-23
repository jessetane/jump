import { sqlite } from './index.js'
import { userAccountSql } from './users.js'
import { httpError, requireBoolean, optionalString } from '../util.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	create,
	listByUserId,
	prune
}

const RETENTION_MS = 30 * 24 * 60 * 60 * 1000
const MAX_URL_LEN = 2048
const MAX_ERROR_LEN = 2048

function parseLimit (limit) {
	if (limit === undefined) return 100
	if (typeof limit === 'string' && !limit.trim()) {
		throw httpError(400, 'limit must be an integer between 1 and 1000')
	}
	const n = typeof limit === 'number' || typeof limit === 'string' ? Number(limit) : NaN
	if (!Number.isInteger(n) || n < 1 || n > 1000) {
		throw httpError(400, 'limit must be an integer between 1 and 1000')
	}
	return n
}

function truncate (str, maxLen) {
	if (typeof str !== 'string') return null
	return str.length > maxLen ? `${str.slice(0, maxLen)}…` : str
}

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

function prune (maxAgeMs = RETENTION_MS) {
	const minDate = new Date(Date.now() - maxAgeMs).toISOString()
	sqlite.prepare('DELETE FROM logs WHERE created < ?').run(minDate)
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
	const created = new Date().toISOString()
	const allowedInt = allowed ? 1 : 0
	const safeUrl = truncate(String(url || ''), MAX_URL_LEN)
	const safeError = error ? truncate(String(error), MAX_ERROR_LEN) : null
	sqlite.prepare(`
		INSERT INTO logs (id, user_id, session_id, app_id, provider, method, url, allowed, status, duration, error, created)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(id, userId, sessionId, appId, provider, method, safeUrl, allowedInt, status, duration, safeError, created)
	return format({
		id,
		user_id: userId,
		session_id: sessionId,
		app_id: appId,
		provider,
		method,
		url: safeUrl,
		allowed: allowedInt,
		status,
		duration,
		error: safeError,
		created
	})
}

function listByUserId (userId, opts = {}) {
	if (!userId) return []
	const { sessionId, appId, provider, allowed, limit = 100 } = opts
	const minDate = new Date(Date.now() - RETENTION_MS).toISOString()
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
			AND logs.created >= ?
	`
	const params = [userId, userId, userId, userId, minDate]
	const cleanSessionId = optionalString(sessionId, 'sessionId')
	if (cleanSessionId) {
		query += ' AND logs.session_id = ?'
		params.push(cleanSessionId)
	}
	const cleanAppId = optionalString(appId, 'appId')
	if (cleanAppId) {
		query += ' AND COALESCE(owned.id, share.id) = ?'
		params.push(cleanAppId)
	}
	const cleanProvider = optionalString(provider, 'provider')
	if (cleanProvider) {
		query += ' AND logs.provider = ?'
		params.push(cleanProvider)
	}
	const parsedAllowed = requireBoolean(allowed, 'allowed')
	if (parsedAllowed !== undefined) {
		query += ' AND logs.allowed = ?'
		params.push(parsedAllowed ? 1 : 0)
	}
	const parsedLimit = parseLimit(limit)
	query += ' ORDER BY logs.created DESC, logs.rowid DESC LIMIT ?'
	params.push(parsedLimit)
	const rows = sqlite.prepare(query).all(...params)
	return rows.map(format)
}
