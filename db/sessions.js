import { randomUUID } from 'node:crypto'
import { sqlite } from './index.js'
import { userAccountSql } from './users.js'
import { hashSecret } from '../crypto.js'

export {
	init,
	create,
	get,
	getActive,
	hasActiveAdmin,
	getByToken,
	resolve,
	findRevocable,
	refresh,
	listByUserId,
	update,
	remove,
	prune
}

const CREATE_SESSIONS_SQL = `
	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT,
		token_hash TEXT UNIQUE NOT NULL,
		refresh_hash TEXT,
		expires_at INTEGER,
		admin INTEGER NOT NULL DEFAULT 0,
		ip TEXT,
		ua TEXT,
		created TEXT NOT NULL,
		updated TEXT NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_refresh ON sessions(refresh_hash);
	CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated);
`

const DORMANT_MS = 30 * 24 * 60 * 60 * 1000
const REFRESH_DEDUP_MS = 60 * 1000
const recentRefreshes = new Map()
const SESSION_ACCOUNT_SQL = userAccountSql('sessions.user_id')

function staleSessionSql (prefix = '') {
	return `(${prefix}expires_at IS NOT NULL AND (${prefix}updated < ? OR (${prefix}expires_at <= ? AND ${prefix}refresh_hash IS NULL)))`
}

function pruneRecentRefreshes (now = Date.now()) {
	for (const [sid, entry] of recentRefreshes) {
		if (entry.dedupUntil <= now) recentRefreshes.delete(sid)
	}
}

function format (row) {
	if (!row) return null
	return {
		id: row.id,
		userId: row.user_id,
		name: row.name,
		token: null,
		hasRefresh: Boolean(row.refresh_hash),
		expiresAt: row.expires_at ?? null,
		admin: Boolean(row.admin),
		ip: row.ip || null,
		ua: row.ua || null,
		created: row.created,
		updated: row.updated,
		account: row.account || null
	}
}

function init () {
	sqlite.exec(CREATE_SESSIONS_SQL)
}

function create (opts = {}) {
	const {
		id = randomUUID(),
		userId,
		name = null,
		refreshToken = null,
		expiresAt = null,
		admin = 0,
		ip = null,
		ua = null
	} = opts
	const rawToken = opts.token || randomUUID()
	const tokenHash = hashSecret(rawToken)
	const refreshHash = refreshToken ? hashSecret(refreshToken) : null
	const now = new Date().toISOString()
	sqlite.prepare(`
		INSERT INTO sessions (id, user_id, name, token_hash, refresh_hash, expires_at, admin, ip, ua, created, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(id, userId, name, tokenHash, refreshHash, expiresAt, admin ? 1 : 0, ip, ua, now, now)
	const created = get(id)
	if (!created) return null
	return {
		...created,
		token: rawToken,
		...(refreshToken ? { refreshToken } : {})
	}
}

function get (id) {
	if (!id) return null
	const row = sqlite.prepare(`
		SELECT sessions.*, ${SESSION_ACCOUNT_SQL} AS account
		FROM sessions
		WHERE sessions.id = ?
	`).get(id)
	return format(row)
}

function getActive (id) {
	if (!id) return null
	const session = get(id)
	if (!session) return null
	const now = Date.now()
	if (session.expiresAt) {
		if (session.updated < new Date(now - DORMANT_MS).toISOString()) return null
		if (session.expiresAt <= now && !session.hasRefresh) return null
	}
	return session
}

function hasActiveAdmin () {
	const now = Date.now()
	const minUpdated = new Date(now - DORMANT_MS).toISOString()
	const row = sqlite.prepare(`
		SELECT 1
		FROM sessions
		WHERE admin = 1
			AND (expires_at IS NULL OR (expires_at > ? AND updated >= ?))
		LIMIT 1
	`).get(now, minUpdated)
	return Boolean(row)
}

function touch (id) {
	if (!id) return false
	const now = new Date().toISOString()
	const cutoff = new Date(Date.now() - 60000).toISOString()
	const res = sqlite.prepare('UPDATE sessions SET updated = ? WHERE id = ? AND updated < ?').run(now, id, cutoff)
	return res.changes > 0
}

function getByToken (token) {
	const tokenHash = hashSecret(token)
	if (!tokenHash) return null
	const now = Date.now()
	const minUpdated = new Date(now - DORMANT_MS).toISOString()
	const row = sqlite.prepare(`
		SELECT sessions.*, ${SESSION_ACCOUNT_SQL} AS account
		FROM sessions
		WHERE sessions.token_hash = ?
			AND (sessions.expires_at IS NULL OR (sessions.expires_at > ? AND sessions.updated >= ?))
	`).get(tokenHash, now, minUpdated)
	if (!row) return null
	if (touch(row.id)) {
		row.updated = new Date().toISOString()
	}
	return format(row)
}

function resolve (auth) {
	if (!auth) return null
	return typeof auth === 'object' ? auth : getByToken(auth)
}

function findRevocable (token) {
	const tokenHash = hashSecret(token)
	if (!tokenHash) return null
	const row = sqlite.prepare(`
		SELECT sessions.*, ${SESSION_ACCOUNT_SQL} AS account
		FROM sessions
		WHERE token_hash = ? OR refresh_hash = ?
	`).get(tokenHash, tokenHash)
	return format(row)
}

function refresh (refreshToken) {
	const refreshHash = hashSecret(refreshToken)
	if (!refreshHash) return null
	const now = Date.now()
	pruneRecentRefreshes(now)
	const minUpdated = new Date(now - DORMANT_MS).toISOString()
	const row = sqlite.prepare(`
		SELECT sessions.*, ${SESSION_ACCOUNT_SQL} AS account
		FROM sessions
		WHERE sessions.refresh_hash = ?
			AND (sessions.expires_at IS NULL OR sessions.updated >= ?)
	`).get(refreshHash, minUpdated)
	const session = format(row)
	if (!session) return null
	const cached = recentRefreshes.get(session.id)
	const isFresh = Boolean(cached && cached.dedupUntil > now && cached.tokenHash === row.token_hash && cached.expiresAt === session.expiresAt)
	let accessToken
	if (isFresh) {
		accessToken = cached.token
		touch(session.id)
	} else {
		accessToken = randomUUID()
		const tokenHash = hashSecret(accessToken)
		const expiresAt = now + 3600 * 1000
		const nowIso = new Date(now).toISOString()
		sqlite.prepare(`
			UPDATE sessions
			SET token_hash = ?, expires_at = ?, updated = ?
			WHERE id = ?
		`).run(tokenHash, expiresAt, nowIso, session.id)
		recentRefreshes.set(session.id, {
			token: accessToken,
			tokenHash,
			expiresAt,
			dedupUntil: now + REFRESH_DEDUP_MS
		})
	}
	const updated = get(session.id)
	if (!updated) return null
	return {
		...updated,
		token: accessToken,
		refreshToken
	}
}

function listByUserId (userId) {
	if (!userId) return []
	const now = Date.now()
	const minUpdated = new Date(now - DORMANT_MS).toISOString()
	const rows = sqlite.prepare(`
		SELECT sessions.*, ${SESSION_ACCOUNT_SQL} AS account
		FROM sessions
		WHERE sessions.user_id = ?
			AND NOT ${staleSessionSql('sessions.')}
		ORDER BY sessions.created DESC, sessions.rowid DESC
	`).all(userId, minUpdated, now)
	return rows.map(format)
}

function update (id, { name, admin, rotateToken = false } = {}) {
	if (!id) return null
	const nowMs = Date.now()
	const now = new Date(nowMs).toISOString()
	const sets = []
	const params = []
	let rotatedToken = null
	if (name !== undefined) {
		sets.push('name = ?')
		params.push(name ? String(name).trim() : null)
	}
	if (admin !== undefined) {
		sets.push('admin = ?')
		params.push(admin ? 1 : 0)
	}
	if (rotateToken) {
		rotatedToken = randomUUID()
		recentRefreshes.delete(id)
		sets.push('token_hash = ?')
		params.push(hashSecret(rotatedToken))
		sets.push('expires_at = CASE WHEN expires_at IS NOT NULL AND refresh_hash IS NOT NULL THEN ? ELSE expires_at END')
		params.push(nowMs + 3600 * 1000)
	}
	if (sets.length > 0) {
		sets.push('updated = ?')
		params.push(now, id)
		sqlite.prepare(`UPDATE sessions SET ${sets.join(', ')} WHERE id = ?`).run(...params)
	}
	const updated = get(id)
	if (!updated || !rotatedToken) return updated
	return { ...updated, token: rotatedToken }
}

function remove (id) {
	if (!id) return false
	recentRefreshes.delete(id)
	const res = sqlite.prepare('DELETE FROM sessions WHERE id = ?').run(id)
	return res.changes > 0
}

function prune (maxAgeMs = DORMANT_MS) {
	const now = Date.now()
	pruneRecentRefreshes(now)
	const minDate = new Date(now - maxAgeMs).toISOString()
	sqlite.prepare(`DELETE FROM sessions WHERE ${staleSessionSql()}`).run(minDate, now)
}
