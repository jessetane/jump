import { sqlite } from './index.js'
import { randomUUID, randomBytes } from 'node:crypto'

export {
	init,
	create,
	get,
	getByToken,
	listByUserId,
	updateCredentials,
	updateName,
	setAdmin,
	rotateToken,
	touch,
	touchByToken,
	remove,
	pruneDormant,
	pruneExpired,
	createState,
	getState,
	consumeState,
	findStateByMagicCode,
	consumeMagicCode,
	createAuthCode,
	consumeAuthCode,
	formatToken
}

function init () {
	sqlite.exec(`
		DROP TABLE IF EXISTS oauth_codes;
		DROP TABLE IF EXISTS oauth_states;
		CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT,
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
	const cols = sqlite.prepare('PRAGMA table_info(tokens)').all()
	const userIdCol = cols.find(c => c.name === 'user_id')
	if (userIdCol && userIdCol.notnull === 1) {
		sqlite.exec(`
			PRAGMA foreign_keys = OFF;
			BEGIN;
			CREATE TABLE tokens_new (
				id TEXT PRIMARY KEY,
				user_id TEXT,
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
			INSERT INTO tokens_new SELECT id, user_id, provider, type, name, token, credentials, expires_at, scopes, admin, ip, ua, created, updated FROM tokens;
			DROP TABLE tokens;
			ALTER TABLE tokens_new RENAME TO tokens;
			CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
			CREATE INDEX IF NOT EXISTS idx_tokens_user_provider ON tokens(user_id, provider);
			CREATE INDEX IF NOT EXISTS idx_tokens_updated ON tokens(updated);
			COMMIT;
			PRAGMA foreign_keys = ON;
		`)
	}
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
		userId = null,
		provider = 'self',
		type = 'bearer',
		name = null,
		token = (provider === 'self' && type === 'bearer') ? randomUUID() : null,
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
		LEFT JOIN users ON tokens.user_id = users.id
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
		WHERE tokens.token = ? AND tokens.provider = 'self' AND tokens.type = 'bearer'
	`).get(token)
	return formatToken(row)
}

function touch (id) {
	if (!id) return false
	const now = new Date().toISOString()
	const cutoff = new Date(Date.now() - 60000).toISOString()
	const res = sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ? AND updated < ?').run(now, id, cutoff)
	return res.changes > 0
}

function touchByToken (token) {
	if (!token) return false
	const now = new Date().toISOString()
	const cutoff = new Date(Date.now() - 60000).toISOString()
	const res = sqlite.prepare("UPDATE tokens SET updated = ? WHERE token = ? AND provider = 'self' AND type = 'bearer' AND updated < ?").run(now, token, cutoff)
	return res.changes > 0
}

function listByUserId (userId, opts = {}) {
	if (!userId) return []
	pruneDormant()
	let query = `
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.user_id = ? AND tokens.type NOT IN ('oauth_state', 'oauth_code')
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

function rotateToken (id, newToken = randomUUID()) {
	if (!id) return null
	const now = new Date().toISOString()
	sqlite.prepare('UPDATE tokens SET token = ?, updated = ? WHERE id = ?').run(newToken, now, id)
	return get(id)
}

function remove (id) {
	if (!id) return false
	const res = sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(id)
	return res.changes > 0
}

function pruneExpired () {
	const now = Date.now()
	sqlite.prepare("DELETE FROM tokens WHERE type IN ('oauth_state', 'oauth_code') AND expires_at IS NOT NULL AND expires_at < ?").run(now)
}

function pruneDormant (maxAgeMs = 30 * 24 * 60 * 60 * 1000) {
	pruneExpired()
	const minDate = new Date(Date.now() - maxAgeMs).toISOString()
	sqlite.prepare("DELETE FROM tokens WHERE provider = 'self' AND type = 'bearer' AND updated < ?").run(minDate)
}

function formatState (row) {
	if (!row) return null
	const tok = formatToken(row)
	const meta = tok.credentials || {}
	return {
		state: tok.id,
		userId: tok.userId,
		clientRedirectUri: meta.clientRedirectUri || null,
		clientState: meta.clientState || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		sessionName: tok.name,
		admin: tok.admin,
		reauthAppId: meta.reauthAppId || null,
		magicCode: tok.token,
		magicExpiresAt: tok.expiresAt,
		email: meta.email || null,
		sessionId: meta.sessionId || null,
		provider: tok.provider === 'self' ? null : tok.provider,
		ip: tok.ip,
		createdAt: new Date(tok.created).getTime()
	}
}

function createState (opts = {}) {
	const {
		userId = null,
		clientRedirectUri = null,
		clientState = null,
		codeChallenge = null,
		codeChallengeMethod = null,
		sessionName = null,
		admin = 0,
		reauthAppId = null,
		magicCode = null,
		magicExpiresAt = null,
		email = null,
		sessionId = null,
		provider = null,
		ip = null
	} = opts
	pruneExpired()
	const state = randomBytes(24).toString('base64url')
	const expiresAt = magicExpiresAt || (Date.now() + 15 * 60 * 1000)
	create({
		id: state,
		userId,
		provider: provider || 'self',
		type: 'oauth_state',
		name: sessionName,
		token: magicCode,
		credentials: {
			clientRedirectUri,
			clientState,
			codeChallenge,
			codeChallengeMethod,
			reauthAppId,
			email,
			sessionId
		},
		expiresAt,
		admin,
		ip
	})
	return state
}

function getState (state) {
	if (!state) return null
	pruneExpired()
	const row = sqlite.prepare("SELECT * FROM tokens WHERE id = ? AND type = 'oauth_state'").get(state)
	return formatState(row)
}

function consumeState (state) {
	if (!state) return null
	pruneExpired()
	const row = sqlite.prepare("SELECT * FROM tokens WHERE id = ? AND type = 'oauth_state'").get(state)
	if (!row) return null
	sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(state)
	return formatState(row)
}

function findStateByMagicCode (magicCode) {
	if (!magicCode) return null
	pruneExpired()
	const row = sqlite.prepare("SELECT * FROM tokens WHERE token = ? AND type = 'oauth_state'").get(magicCode)
	return formatState(row)
}

function consumeMagicCode (magicCode) {
	if (!magicCode) return null
	pruneExpired()
	const row = sqlite.prepare("SELECT * FROM tokens WHERE token = ? AND type = 'oauth_state'").get(magicCode)
	if (!row) return null
	sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(row.id)
	return formatState(row)
}

function createAuthCode (opts = {}) {
	const { sessionId, clientRedirectUri = null, codeChallenge = null, codeChallengeMethod = null } = opts
	pruneExpired()
	const code = randomBytes(24).toString('base64url')
	const session = get(sessionId)
	create({
		id: code,
		userId: session?.userId || null,
		provider: 'self',
		type: 'oauth_code',
		credentials: {
			sessionId,
			clientRedirectUri,
			codeChallenge,
			codeChallengeMethod
		},
		expiresAt: Date.now() + 10 * 60 * 1000
	})
	return code
}

function consumeAuthCode (code) {
	if (!code) return null
	pruneExpired()
	const row = sqlite.prepare("SELECT * FROM tokens WHERE id = ? AND type = 'oauth_code'").get(code)
	if (!row) return null
	sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(code)
	const tok = formatToken(row)
	const meta = tok.credentials || {}
	return {
		code: tok.id,
		sessionId: meta.sessionId,
		clientRedirectUri: meta.clientRedirectUri || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		createdAt: new Date(tok.created).getTime()
	}
}
