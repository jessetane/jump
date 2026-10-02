import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	create,
	get,
	getByToken,
	listByUserId,
	updateCredentials,
	updateName,
	setAdmin,
	touch,
	touchByToken,
	remove,
	pruneDormant,
	formatToken
}

function init () {
	sqlite.exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			type TEXT NOT NULL,
			name TEXT,
			token TEXT UNIQUE,
			credentials TEXT,
			expires_at INTEGER,
			scopes TEXT,
			admin INTEGER DEFAULT 0,
			ip TEXT,
			ua TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
		CREATE INDEX IF NOT EXISTS idx_tokens_user_provider ON tokens(user_id, provider);
		CREATE INDEX IF NOT EXISTS idx_tokens_updated ON tokens(updated);
	`)
}

function formatToken (row) {
	if (!row) return null
	let credentials = null
	if (row.credentials) {
		try {
			credentials = JSON.parse(row.credentials)
		} catch {
			credentials = row.credentials
		}
	}
	return {
		id: row.id,
		userId: row.user_id,
		provider: row.provider,
		type: row.type,
		name: row.name,
		token: row.token,
		credentials,
		expiresAt: row.expires_at,
		scopes: row.scopes,
		admin: Boolean(row.admin),
		ip: row.ip,
		ua: row.ua,
		created: row.created,
		updated: row.updated,
		email: row.email,
		userName: row.user_name
	}
}

function create (opts = {}) {
	const {
		id = randomUUID(),
		userId,
		provider = 'self',
		type = 'bearer',
		name = null,
		token = provider === 'self' ? randomUUID() : null,
		credentials = null,
		expiresAt = null,
		scopes = null,
		admin = 0,
		ip = null,
		ua = null
	} = opts
	pruneDormant()
	const now = new Date().toISOString()
	const credsJson = credentials && typeof credentials === 'object' ? JSON.stringify(credentials) : credentials
	sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, expires_at, scopes, admin, ip, ua, created, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(id, userId, provider, type, name, token, credsJson, expiresAt, scopes, admin ? 1 : 0, ip, ua, now, now)
	return get(id)
}

function get (id) {
	if (!id) return null
	const row = sqlite.prepare(`
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.id = ?
	`).get(id)
	return formatToken(row)
}

function getByToken (token) {
	if (!token) return null
	const row = sqlite.prepare(`
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.token = ?
	`).get(token)
	return formatToken(row)
}

function touch (id) {
	if (!id) return false
	const now = new Date().toISOString()
	const res = sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(now, id)
	return res.changes > 0
}

function touchByToken (token) {
	if (!token) return false
	const now = new Date().toISOString()
	const res = sqlite.prepare('UPDATE tokens SET updated = ? WHERE token = ?').run(now, token)
	return res.changes > 0
}

function listByUserId (userId, opts = {}) {
	if (!userId) return []
	pruneDormant()
	let query = `
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.user_id = ?
	`
	const params = [userId]
	if (opts.provider) {
		query += ' AND tokens.provider = ?'
		params.push(opts.provider)
	}
	query += ' ORDER BY tokens.created DESC'
	const rows = sqlite.prepare(query).all(...params)
	return rows.map(formatToken)
}

function updateCredentials (id, opts = {}) {
	const { credentials, expiresAt, scopes = null, name = null } = opts
	const now = new Date().toISOString()
	const credsJson = credentials && typeof credentials === 'object' ? JSON.stringify(credentials) : credentials
	sqlite.prepare(`
		UPDATE tokens
		SET credentials = COALESCE(?, credentials),
			expires_at = COALESCE(?, expires_at),
			scopes = COALESCE(?, scopes),
			name = COALESCE(?, name),
			updated = ?
		WHERE id = ?
	`).run(credsJson, expiresAt, scopes, name, now, id)
	return get(id)
}

function updateName (id, name) {
	if (!id) return null
	const now = new Date().toISOString()
	sqlite.prepare('UPDATE tokens SET name = ?, updated = ? WHERE id = ?').run(name ? String(name).trim() : null, now, id)
	return get(id)
}

function setAdmin (id, admin = true) {
	const now = new Date().toISOString()
	sqlite.prepare('UPDATE tokens SET admin = ?, updated = ? WHERE id = ?').run(admin ? 1 : 0, now, id)
	return get(id)
}

function remove (id) {
	if (!id) return false
	const res = sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(id)
	return res.changes > 0
}

function pruneDormant (maxAgeMs = 30 * 24 * 60 * 60 * 1000) {
	const minDate = new Date(Date.now() - maxAgeMs).toISOString()
	sqlite.prepare("DELETE FROM tokens WHERE provider = 'self' AND updated < ?").run(minDate)
}
