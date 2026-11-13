import { sqlite } from './index.js'
import { userAccountSql } from './logins.js'
import { parseAccountSpec } from '../util.js'
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
	claimPendingShares,
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
	isUpstreamApp,
	USER_ACCOUNT_SQL,
	UPSTREAM_SELECT,
	UPSTREAM_JOIN,
	CREATE_TOKENS_SQL
}

const CREATE_TOKENS_SQL = `
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
`

const USER_ACCOUNT_SQL = userAccountSql('tokens.user_id')

const UPSTREAM_SELECT = `
	upstream.name AS upstream_name,
	upstream.scopes AS upstream_scopes,
	upstream.expires_at AS upstream_expires_at,
	json_extract(upstream.credentials, '$.account') AS upstream_account,
	json_extract(upstream.credentials, '$.baseUrl') AS upstream_base_url,
	CASE WHEN upstream.user_id IS NOT NULL THEN ${userAccountSql('upstream.user_id')} ELSE NULL END AS shared_by_account
`

const UPSTREAM_JOIN = `
	LEFT JOIN tokens AS upstream ON tokens.type = 'share' AND upstream.id = json_extract(tokens.credentials, '$.appId')
`

function init () {
	sqlite.exec(CREATE_TOKENS_SQL)
}

function isUpstreamApp (tok, { allowShare = false } = {}) {
	if (!tok || tok.provider === 'self') return false
	if (tok.type === 'oauth' || tok.type === 'api_key') return true
	return Boolean(allowShare && tok.type === 'share')
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
	const resolvedAccount = row.user_id ? (row.account || null) : (isShare ? row.name : null)
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
		account: resolvedAccount,
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
		SELECT tokens.*,
			CASE WHEN tokens.user_id IS NOT NULL THEN ${USER_ACCOUNT_SQL} ELSE NULL END AS account,
			${UPSTREAM_SELECT}
		FROM tokens
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
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account
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
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account
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
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account
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
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account, ${UPSTREAM_SELECT}
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE tokens.user_id = ? AND tokens.type IN ('bearer', 'oauth', 'api_key', 'share')
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

function claimPendingShares ({ userId, provider, account, allowUnscoped = false }) {
	const cleanProvider = String(provider).trim().toLowerCase()
	const cleanAccount = String(account).trim().toLowerCase()
	const pendingRows = allowUnscoped
		? sqlite.prepare(`
			SELECT id, credentials, updated FROM tokens
			WHERE user_id IS NULL AND type = 'share' AND name = ?
				AND (json_extract(credentials, '$.authProvider') IS NULL OR json_extract(credentials, '$.authProvider') = ?)
			ORDER BY
				CASE WHEN json_extract(credentials, '$.authProvider') = ? THEN 0 ELSE 1 END ASC,
				updated DESC,
				rowid DESC
		`).all(cleanAccount, cleanProvider, cleanProvider)
		: sqlite.prepare(`
			SELECT id, credentials, updated FROM tokens
			WHERE user_id IS NULL AND type = 'share' AND name = ?
				AND json_extract(credentials, '$.authProvider') = ?
			ORDER BY updated DESC, rowid DESC
		`).all(cleanAccount, cleanProvider)
	for (const row of pendingRows) {
		const creds = row.credentials ? JSON.parse(row.credentials) : {}
		const appId = creds.appId
		if (!appId) continue
		const ownsApp = sqlite.prepare('SELECT 1 FROM tokens WHERE id = ? AND user_id = ?').get(appId, userId)
		if (ownsApp) {
			sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(row.id)
			continue
		}
		const resolvedCreds = {
			...creds,
			authProvider: creds.authProvider || cleanProvider
		}
		const existingShare = sqlite.prepare(`
			SELECT id, name, updated FROM tokens
			WHERE user_id = ? AND type = 'share' AND json_extract(credentials, '$.appId') = ?
		`).get(userId, appId)
		if (existingShare) {
			if (creds.authProvider === cleanProvider && existingShare.name === cleanAccount && row.updated >= existingShare.updated) {
				sqlite.prepare(`
					UPDATE tokens
					SET name = ?, credentials = ?, updated = ?
					WHERE id = ?
				`).run(cleanAccount, JSON.stringify(resolvedCreds), row.updated, existingShare.id)
			}
			sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(row.id)
			continue
		}
		sqlite.prepare(`
			UPDATE tokens
			SET user_id = ?, name = ?, credentials = ?
			WHERE id = ?
		`).run(userId, cleanAccount, JSON.stringify(resolvedCreds), row.id)
	}
}

function listSharesByOwnerId (ownerUserId) {
	if (!ownerUserId) return []
	const rows = sqlite.prepare(`
		SELECT tokens.*,
			CASE WHEN tokens.user_id IS NOT NULL THEN COALESCE(tokens.name, ${USER_ACCOUNT_SQL}) ELSE tokens.name END AS account
		FROM tokens
		JOIN tokens AS upstream ON tokens.type = 'share' AND upstream.id = json_extract(tokens.credentials, '$.appId')
		WHERE upstream.user_id = ?
		ORDER BY tokens.created ASC, tokens.rowid ASC
	`).all(ownerUserId)
	return rows.map(formatToken)
}

function upsertShare ({ userId = null, account = null, authProvider = null, appId, provider, policy = null }) {
	const cleanAccount = account ? String(account).trim().toLowerCase() : null
	const cleanAuthProvider = authProvider ? String(authProvider).trim().toLowerCase() : null
	if (userId) {
		const existing = sqlite.prepare(`
			SELECT id, name, credentials FROM tokens
			WHERE user_id = ? AND type = 'share' AND json_extract(credentials, '$.appId') = ?
		`).get(userId, appId)
		const existingCreds = existing?.credentials ? JSON.parse(existing.credentials) : null
		let resolvedAuthProvider = cleanAuthProvider
		if (!resolvedAuthProvider) {
			if (existingCreds?.authProvider && (!cleanAccount || existing.name === cleanAccount)) {
				resolvedAuthProvider = existingCreds.authProvider
			} else if (cleanAccount) {
				const matchedLogin = sqlite.prepare(`
					SELECT provider FROM logins
					WHERE user_id = ? AND account = ?
					ORDER BY created ASC, rowid ASC
					LIMIT 1
				`).get(userId, cleanAccount)
				resolvedAuthProvider = matchedLogin?.provider || existingCreds?.authProvider || null
			}
		}
		const claimedCreds = {
			appId,
			policy,
			...(resolvedAuthProvider ? { authProvider: resolvedAuthProvider } : {})
		}
		if (existing) {
			return updateCredentials(existing.id, { credentials: claimedCreds, ...(cleanAccount ? { name: cleanAccount } : {}) })
		}
		return create({
			userId,
			provider,
			type: 'share',
			name: cleanAccount,
			credentials: claimedCreds
		})
	}
	const creds = {
		appId,
		policy,
		...(cleanAuthProvider ? { authProvider: cleanAuthProvider } : {})
	}
	const existingPending = cleanAuthProvider
		? sqlite.prepare(`
			SELECT id FROM tokens
			WHERE user_id IS NULL AND type = 'share' AND name = ?
				AND json_extract(credentials, '$.appId') = ?
				AND json_extract(credentials, '$.authProvider') = ?
		`).get(cleanAccount, appId, cleanAuthProvider)
		: sqlite.prepare(`
			SELECT id FROM tokens
			WHERE user_id IS NULL AND type = 'share' AND name = ?
				AND json_extract(credentials, '$.appId') = ?
				AND json_extract(credentials, '$.authProvider') IS NULL
		`).get(cleanAccount, appId)
	if (existingPending) {
		return updateCredentials(existingPending.id, { credentials: creds })
	}
	return create({
		userId: null,
		provider,
		type: 'share',
		name: cleanAccount,
		credentials: creds
	})
}

function removeShare ({ account = null, provider = null, appId }) {
	if (!appId) return false
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	if (!cleanAccount) return false
	if (cleanProvider) {
		let matchingShares = sqlite.prepare(`
			SELECT id FROM tokens
			WHERE type = 'share' AND name = ?
				AND json_extract(credentials, '$.appId') = ?
				AND json_extract(credentials, '$.authProvider') = ?
		`).all(cleanAccount, appId, cleanProvider)
		if (matchingShares.length === 0) {
			const hasScopedForAccount = sqlite.prepare(`
				SELECT 1 FROM tokens
				WHERE type = 'share' AND name = ?
					AND json_extract(credentials, '$.appId') = ?
					AND json_extract(credentials, '$.authProvider') IS NOT NULL
				LIMIT 1
			`).get(cleanAccount, appId)
			if (!hasScopedForAccount) {
				matchingShares = sqlite.prepare(`
					SELECT id FROM tokens
					WHERE user_id IS NULL AND type = 'share' AND name = ?
						AND json_extract(credentials, '$.appId') = ?
						AND json_extract(credentials, '$.authProvider') IS NULL
				`).all(cleanAccount, appId)
			}
		}
		if (matchingShares.length === 0) return false
		const stmt = sqlite.prepare('DELETE FROM tokens WHERE id = ?')
		for (const s of matchingShares) {
			stmt.run(s.id)
		}
		return true
	}
	const matchingShares = sqlite.prepare(`
		SELECT id FROM tokens
		WHERE type = 'share' AND name = ?
			AND json_extract(credentials, '$.appId') = ?
	`).all(cleanAccount, appId)
	if (matchingShares.length === 0) return false
	if (matchingShares.length > 1) {
		const err = new Error(`Ambiguous account "${cleanAccount}" matches multiple shared recipients on this app; specify provider`)
		err.status = 400
		throw err
	}
	sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(matchingShares[0].id)
	return true
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
