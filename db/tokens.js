import { sqlite } from './index.js'
import * as users from './users.js'
import { randomUUID, randomBytes } from 'node:crypto'

export {
	init,
	create,
	get,
	getActiveSession,
	getByToken,
	findRevocable,
	issueOauthTokens,
	refreshOauthSession,
	listByUserId,
	listAuthByUserId,
	hasAuthTokens,
	findUserByAccount,
	claimStubUser,
	upsertAuth,
	resolveUserByAuth,
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
	owner.account AS shared_by_account
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
	if (users.consumeLegacyEmailMigration()) {
		const missingAuthUsers = sqlite.prepare(`
			SELECT users.* FROM users
			WHERE NOT EXISTS (
				SELECT 1 FROM tokens WHERE tokens.user_id = users.id AND tokens.type = 'auth'
			)
		`).all()
		for (const u of missingAuthUsers) {
			if (!u.account || !u.account.includes('@')) continue
			const cleanAccount = u.account.trim().toLowerCase()
			const authKey = `google:${cleanAccount}`
			const now = new Date().toISOString()
			sqlite.prepare(`
				INSERT OR IGNORE INTO tokens (id, user_id, provider, type, name, token, credentials, created, updated)
				VALUES (?, ?, 'google', 'auth', ?, ?, ?, ?, ?)
			`).run(randomUUID(), u.id, cleanAccount, authKey, JSON.stringify({ account: cleanAccount }), now, now)
		}
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
		account: row.account,
		userName: row.user_name,
		...(row.shared_by_account ? { sharedBy: row.shared_by_account } : {})
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
		SELECT tokens.*, users.account, users.name AS user_name, ${UPSTREAM_SELECT}
		FROM tokens
		LEFT JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE tokens.id = ?
	`).get(id)
	return formatToken(row)
}

function getActiveSession (id) {
	if (!id) return null
	const session = get(id)
	if (!session || session.provider !== 'self' || session.type !== 'bearer' || !session.token) return null
	if (session.expiresAt && session.expiresAt <= Date.now()) return null
	return session
}

function getByToken (token) {
	if (!token) return null
	const now = Date.now()
	const row = sqlite.prepare(`
		SELECT tokens.*, users.account, users.name AS user_name
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
		SELECT tokens.*, users.account, users.name AS user_name
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
		SELECT tokens.*, users.account, users.name AS user_name
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
		SELECT tokens.*, users.account, users.name AS user_name, ${UPSTREAM_SELECT}
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE tokens.user_id = ? AND tokens.type NOT IN ('oauth_state', 'oauth_code', 'auth')
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

function listAuthByUserId (userId) {
	if (!userId) return []
	const rows = sqlite.prepare(`
		SELECT tokens.*, users.account, users.name AS user_name, ${UPSTREAM_SELECT}
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE tokens.user_id = ? AND tokens.type = 'auth'
		ORDER BY tokens.created ASC
	`).all(userId)
	return rows.map(formatToken)
}

function hasAuthTokens (userId) {
	if (!userId) return false
	return Boolean(sqlite.prepare("SELECT 1 FROM tokens WHERE user_id = ? AND type = 'auth'").get(userId))
}

function findUserByAccount (account, provider = null) {
	if (!account) return null
	const cleanAccount = String(account).trim().toLowerCase()
	if (!cleanAccount) return null
	if (provider) {
		const cleanProvider = String(provider).trim().toLowerCase()
		const authKey = `${cleanProvider}:${cleanAccount}`
		const authRow = sqlite.prepare("SELECT user_id FROM tokens WHERE type = 'auth' AND token = ?").get(authKey)
		if (authRow) return users.get(authRow.user_id)
		return users.getByAccount(authKey) || users.getByAccount(cleanAccount)
	}
	const authRow = sqlite.prepare("SELECT user_id FROM tokens WHERE type = 'auth' AND (token = ? OR name = ?)").get(cleanAccount, cleanAccount)
	if (authRow) {
		return users.get(authRow.user_id)
	}
	return users.getByAccount(cleanAccount)
}

function claimStubUser (stubUserId, targetUserId) {
	if (!stubUserId || !targetUserId || stubUserId === targetUserId) return
	sqlite.prepare(`
		DELETE FROM tokens
		WHERE user_id = ? AND type = 'share'
			AND (
				json_extract(credentials, '$.appId') IN (
					SELECT json_extract(credentials, '$.appId') FROM tokens WHERE user_id = ? AND type = 'share'
				)
				OR json_extract(credentials, '$.appId') IN (
					SELECT id FROM tokens WHERE user_id = ?
				)
			)
	`).run(stubUserId, targetUserId, targetUserId)
	sqlite.prepare('UPDATE tokens SET user_id = ? WHERE user_id = ?').run(targetUserId, stubUserId)
	sqlite.prepare('DELETE FROM users WHERE id = ?').run(stubUserId)
}

function upsertAuth ({ userId, provider, account }) {
	const cleanProvider = String(provider).trim().toLowerCase()
	const cleanAccount = String(account).trim().toLowerCase()
	const authKey = `${cleanProvider}:${cleanAccount}`
	const existing = sqlite.prepare("SELECT * FROM tokens WHERE type = 'auth' AND token = ?").get(authKey)
	if (existing) {
		if (existing.user_id !== userId) {
			const err = new Error(`Account ${cleanAccount} is already bound to another user`)
			err.status = 409
			throw err
		}
		return get(existing.id)
	}
	return create({
		userId,
		provider: cleanProvider,
		type: 'auth',
		name: cleanAccount,
		token: authKey,
		credentials: { account: cleanAccount }
	})
}

function resolveUserByAuth (provider, account, { createIfMissing = true } = {}) {
	if (!provider || !account) return null
	const cleanProvider = String(provider).trim().toLowerCase()
	const cleanAccount = String(account).trim().toLowerCase()
	const authKey = `${cleanProvider}:${cleanAccount}`
	const row = sqlite.prepare("SELECT user_id FROM tokens WHERE type = 'auth' AND token = ?").get(authKey)
	if (row) {
		return users.get(row.user_id)
	}
	if (!createIfMissing) return null
	const existing = users.getByAccount(cleanAccount)
	if (existing && !hasAuthTokens(existing.id)) {
		upsertAuth({ userId: existing.id, provider: cleanProvider, account: cleanAccount })
		return existing
	}
	const targetAccount = existing ? `${cleanProvider}:${cleanAccount}` : cleanAccount
	const user = users.upsert({ account: targetAccount })
	upsertAuth({ userId: user.id, provider: cleanProvider, account: cleanAccount })
	return user
}

function listSharesByOwnerId (ownerUserId) {
	if (!ownerUserId) return []
	const rows = sqlite.prepare(`
		SELECT tokens.*, users.account, users.name AS user_name
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
		mode: meta.mode || null,
		clientId: meta.clientId || null,
		clientRedirectUri: meta.clientRedirectUri || null,
		clientState: meta.clientState || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		sessionName: tok.name,
		admin: tok.admin,
		reauthAppId: meta.reauthAppId || null,
		account: meta.account || null,
		sessionId: meta.sessionId || null,
		provider: tok.provider === 'self' ? null : tok.provider,
		ip: tok.ip,
		createdAt: new Date(tok.created).getTime()
	}
}

function createState (opts = {}) {
	const {
		userId = null,
		mode = null,
		clientId = null,
		clientRedirectUri = null,
		clientState = null,
		codeChallenge = null,
		codeChallengeMethod = null,
		sessionName = null,
		admin = 0,
		reauthAppId = null,
		account = null,
		sessionId = null,
		provider = null,
		ip = null
	} = opts
	pruneExpired()
	const state = randomBytes(24).toString('base64url')
	const expiresAt = Date.now() + 15 * 60 * 1000
	create({
		id: state,
		userId,
		provider: provider || 'self',
		type: 'oauth_state',
		name: sessionName,
		credentials: {
			mode,
			clientId,
			clientRedirectUri,
			clientState,
			codeChallenge,
			codeChallengeMethod,
			reauthAppId,
			account: account || null,
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
