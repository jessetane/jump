import { sqlite } from './index.js'
import { randomUUID, randomBytes } from 'node:crypto'

export {
	init,
	create,
	get,
	getByToken,
	findRevocable,
	issueOauthTokens,
	refreshOauthSession,
	listByUserId,
	listSharesByOwnerId,
	upsertShare,
	removeShare,
	updateCredentials,
	updateName,
	setAdmin,
	rotateToken,
	touch,
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
	formatToken,
	UPSTREAM_SELECT,
	UPSTREAM_JOIN
}

const UPSTREAM_SELECT = `
	upstream.name AS upstream_name,
	upstream.scopes AS upstream_scopes,
	upstream.expires_at AS upstream_expires_at,
	json_extract(upstream.credentials, '$.account') AS upstream_account,
	json_extract(upstream.credentials, '$.baseUrl') AS upstream_base_url,
	owner.email AS shared_by_email
`

const UPSTREAM_JOIN = `
	LEFT JOIN tokens AS upstream ON tokens.type = 'share' AND upstream.id = json_extract(tokens.credentials, '$.appId')
	LEFT JOIN users AS owner ON upstream.user_id = owner.id
`

function init () {
	sqlite.exec(`
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
		CREATE INDEX IF NOT EXISTS idx_tokens_share_app ON tokens(json_extract(credentials, '$.appId')) WHERE type = 'share';
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
	const isShare = row.type === 'share'
	return {
		id: row.id,
		userId: row.user_id,
		provider: row.provider,
		type: row.type,
		name: isShare ? (row.upstream_name || null) : row.name,
		token: row.token,
		credentials: isShare && credentials ? {
			...credentials,
			...(row.upstream_account ? { account: row.upstream_account } : {}),
			...(row.upstream_base_url ? { baseUrl: row.upstream_base_url } : {})
		} : credentials,
		expiresAt: isShare ? (row.upstream_expires_at ?? null) : row.expires_at,
		scopes: isShare ? (row.upstream_scopes || null) : row.scopes,
		admin: Boolean(row.admin),
		ip: row.ip,
		ua: row.ua,
		created: row.created,
		updated: row.updated,
		email: row.email,
		userName: row.user_name,
		...(row.shared_by_email ? { sharedBy: row.shared_by_email } : {})
	}
}

function create (opts = {}) {
	const {
		id = randomUUID(),
		userId = null,
		provider = 'self',
		type = 'bearer',
		name = null,
		token = opts.token !== undefined ? opts.token : ((provider === 'self' && type === 'bearer') ? randomUUID() : null),
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
		SELECT tokens.*, users.email, users.name AS user_name, ${UPSTREAM_SELECT}
		FROM tokens
		LEFT JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE tokens.id = ?
	`).get(id)
	return formatToken(row)
}

function getByToken (token) {
	if (!token) return null
	const now = Date.now()
	const row = sqlite.prepare(`
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.token = ? AND tokens.provider = 'self' AND tokens.type = 'bearer'
			AND (tokens.expires_at IS NULL OR tokens.expires_at > ?)
	`).get(token, now)
	if (!row) return null
	if (touch(row.id)) {
		row.updated = new Date().toISOString()
	}
	return formatToken(row)
}

function findRevocable (token) {
	if (!token || typeof token !== 'string') return null
	pruneDormant()
	const row = sqlite.prepare(`
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.provider = 'self' AND tokens.type = 'bearer'
			AND (tokens.token = ? OR json_extract(tokens.credentials, '$.refreshToken') = ?)
	`).get(token, token)
	return formatToken(row)
}

function issueOauthTokens (id, { refresh = true } = {}) {
	if (!id) return null
	const session = get(id)
	if (!session || session.provider !== 'self' || session.type !== 'bearer') return null
	const now = Date.now()
	const token = session.token || randomUUID()
	let expiresAt = null
	let credentials = null
	if (refresh) {
		expiresAt = now + 3600 * 1000
		const refreshToken = session.credentials?.refreshToken || randomUUID()
		credentials = JSON.stringify({
			...(session.credentials || {}),
			refreshToken
		})
	} else if (session.credentials) {
		const { refreshToken, ...rest } = session.credentials
		if (Object.keys(rest).length > 0) {
			credentials = JSON.stringify(rest)
		}
	}
	const nowIso = new Date(now).toISOString()
	sqlite.prepare(`
		UPDATE tokens
		SET token = ?, credentials = ?, expires_at = ?, updated = ?
		WHERE id = ?
	`).run(token, credentials, expiresAt, nowIso, id)
	return get(id)
}

function refreshOauthSession (refreshToken) {
	if (!refreshToken) return null
	pruneDormant()
	const row = sqlite.prepare(`
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.provider = 'self' AND tokens.type = 'bearer'
			AND json_extract(tokens.credentials, '$.refreshToken') = ?
	`).get(refreshToken)
	const session = formatToken(row)
	if (!session) return null
	const now = Date.now()
	const nowIso = new Date(now).toISOString()
	const isFresh = Boolean(session.token && session.expiresAt && (session.expiresAt - now > (3600 - 60) * 1000))
	const accessToken = isFresh ? session.token : randomUUID()
	const expiresAt = isFresh ? session.expiresAt : now + 3600 * 1000
	sqlite.prepare(`
		UPDATE tokens
		SET token = ?, expires_at = ?, updated = ?
		WHERE id = ?
	`).run(accessToken, expiresAt, nowIso, session.id)
	return get(session.id)
}

function touch (id) {
	if (!id) return false
	const now = new Date().toISOString()
	const cutoff = new Date(Date.now() - 60000).toISOString()
	const res = sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ? AND updated < ?').run(now, id, cutoff)
	return res.changes > 0
}

function listByUserId (userId, opts = {}) {
	if (!userId) return []
	pruneDormant()
	let query = `
		SELECT tokens.*, users.email, users.name AS user_name, ${UPSTREAM_SELECT}
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE tokens.user_id = ? AND tokens.type NOT IN ('oauth_state', 'oauth_code')
			AND NOT (tokens.provider = 'self' AND tokens.type = 'bearer' AND tokens.token IS NULL)
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

function listSharesByOwnerId (ownerUserId) {
	if (!ownerUserId) return []
	const rows = sqlite.prepare(`
		SELECT tokens.*, users.email, users.name AS user_name
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		JOIN tokens AS upstream ON tokens.type = 'share' AND upstream.id = json_extract(tokens.credentials, '$.appId')
		WHERE upstream.user_id = ?
		ORDER BY tokens.created ASC
	`).all(ownerUserId)
	return rows.map(formatToken)
}

function upsertShare ({ userId, appId, provider, policy = null }) {
	const existing = sqlite.prepare(`
		SELECT id FROM tokens
		WHERE user_id = ? AND type = 'share' AND json_extract(credentials, '$.appId') = ?
	`).get(userId, appId)
	if (existing) {
		return updateCredentials(existing.id, {
			credentials: { appId, policy }
		})
	}
	return create({
		userId,
		provider,
		type: 'share',
		credentials: { appId, policy }
	})
}

function removeShare (userId, appId) {
	if (!userId || !appId) return false
	const res = sqlite.prepare(`
		DELETE FROM tokens
		WHERE user_id = ? AND type = 'share' AND json_extract(credentials, '$.appId') = ?
	`).run(userId, appId)
	return res.changes > 0
}

function updateCredentials (id, opts = {}) {
	const { credentials, expiresAt = null, scopes = null, name = null } = opts
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
	const nowMs = Date.now()
	const now = new Date(nowMs).toISOString()
	sqlite.prepare(`
		UPDATE tokens
		SET token = ?,
			expires_at = CASE WHEN expires_at IS NOT NULL THEN ? ELSE NULL END,
			updated = ?
		WHERE id = ? AND provider = 'self' AND type = 'bearer'
	`).run(newToken, nowMs + 3600 * 1000, now, id)
	return get(id)
}

function remove (id) {
	if (!id) return false
	sqlite.prepare(`
		DELETE FROM tokens
		WHERE type = 'share' AND json_extract(credentials, '$.appId') = ?
	`).run(id)
	const res = sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(id)
	return res.changes > 0
}

function pruneExpired () {
	const now = Date.now()
	sqlite.prepare("DELETE FROM tokens WHERE (type IN ('oauth_state', 'oauth_code') OR (provider = 'self' AND type = 'bearer' AND token IS NULL)) AND expires_at IS NOT NULL AND expires_at < ?").run(now)
}

function pruneDormant (maxAgeMs = 30 * 24 * 60 * 60 * 1000) {
	pruneExpired()
	const minDate = new Date(Date.now() - maxAgeMs).toISOString()
	sqlite.prepare("DELETE FROM tokens WHERE provider = 'self' AND type = 'bearer' AND expires_at IS NOT NULL AND updated < ?").run(minDate)
}

function formatState (row) {
	if (!row) return null
	const tok = formatToken(row)
	const meta = tok.credentials || {}
	return {
		state: tok.id,
		userId: tok.userId,
		clientId: meta.clientId || null,
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
		clientId = null,
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
			clientId,
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
	const { sessionId, clientId = null, clientRedirectUri = null, codeChallenge = null, codeChallengeMethod = null } = opts
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
			clientId,
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
		clientId: meta.clientId || null,
		clientRedirectUri: meta.clientRedirectUri || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		createdAt: new Date(tok.created).getTime()
	}
}
