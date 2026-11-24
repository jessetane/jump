import { sqlite } from './index.js'
import { userAccountSql } from './users.js'
import { parseAccountSpec, isPlainObject, httpError } from '../util.js'
import { loadKeys, secretContext, encryptSecret, openSecret, decryptSecret } from '../crypto.js'
import { createHash, randomUUID } from 'node:crypto'

export {
	init,
	initKeys,
	hashSecret,
	create,
	get,
	getActiveSession,
	hasActiveAdmin,
	getByToken,
	resolveSession,
	findRevocable,
	refreshOauthSession,
	listByUserId,
	claimPendingShares,
	listSharesByOwnerId,
	upsertShare,
	removeShare,
	updateCredentials,
	updateSession,
	remove,
	prune,
	createState,
	getState,
	consumeState,
	createAuthCode,
	consumeAuthCode,
	formatToken,
	isSession,
	isUpstreamApp,
	USER_ACCOUNT_SQL,
	UPSTREAM_SELECT,
	UPSTREAM_JOIN
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
	CREATE TRIGGER IF NOT EXISTS trg_tokens_cascade_shares
	AFTER DELETE ON tokens
	WHEN OLD.type IN ('oauth', 'static')
	BEGIN
		DELETE FROM tokens WHERE type = 'share' AND json_extract(credentials, '$.appId') = OLD.id;
	END;
`

const DORMANT_MS = 30 * 24 * 60 * 60 * 1000
const REFRESH_DEDUP_MS = 60 * 1000
const recentRefreshes = new Map()

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

function hashSecret (secret) {
	if (!secret || typeof secret !== 'string') return null
	return createHash('sha256').update(secret).digest('hex')
}

function isHashedToken (provider, type) {
	return (provider === 'self' && type === 'bearer') || type === 'oauth_state' || type === 'oauth_code'
}

function isEncryptedTokenRow (provider, type) {
	return provider !== 'self' && (type === 'oauth' || type === 'static')
}

function encryptUpstreamCredentials (creds, { id, provider, type }, keys) {
	if (!isPlainObject(creds) || !isEncryptedTokenRow(provider, type)) return creds
	const { account, baseUrl, ...secrets } = creds
	return {
		...(account !== undefined && { account }),
		...(baseUrl !== undefined && { baseUrl }),
		...(Object.keys(secrets).length > 0 && {
			secret: encryptSecret(JSON.stringify(secrets), secretContext(id, provider, type), keys)
		})
	}
}

function decryptUpstreamCredentials (creds, { id, provider, type }) {
	if (!isPlainObject(creds) || !isEncryptedTokenRow(provider, type)) return creds
	const { secret, ...meta } = creds
	if (!secret) return meta
	return { ...meta, ...JSON.parse(decryptSecret(secret, secretContext(id, provider, type))) }
}

function serializeCredentials (credentials, meta) {
	if (!credentials || typeof credentials !== 'object') {
		return { credsJson: credentials, rawRefreshToken: null }
	}
	if (!meta) {
		return { credsJson: JSON.stringify(credentials), rawRefreshToken: null }
	}
	if (meta.provider === 'self' && meta.type === 'bearer' && typeof credentials.refreshToken === 'string') {
		const rawRefreshToken = credentials.refreshToken
		return {
			credsJson: JSON.stringify({ ...credentials, refreshToken: hashSecret(rawRefreshToken) }),
			rawRefreshToken
		}
	}
	return {
		credsJson: JSON.stringify(encryptUpstreamCredentials(credentials, meta)),
		rawRefreshToken: null
	}
}

function pruneRecentRefreshes (now = Date.now()) {
	for (const [sid, entry] of recentRefreshes) {
		if (entry.dedupUntil <= now) recentRefreshes.delete(sid)
	}
}

function vacuumDatabase (targetDb) {
	if (targetDb.isTransaction) return
	const prevUmask = process.umask(0o077)
	try {
		targetDb.exec('VACUUM;')
		targetDb.exec('PRAGMA wal_checkpoint(TRUNCATE);')
	} finally {
		process.umask(prevUmask)
	}
}

function initKeys (targetDb = sqlite) {
	const dbList = targetDb.prepare('PRAGMA database_list').get()
	const dbPath = dbList && 'file' in dbList ? (dbList.file || ':memory:') : (process.env.DB_PATH || './data.db')
	const rows = targetDb.prepare(`
		SELECT id, provider, type, credentials
		FROM tokens
		WHERE provider != 'self' AND type IN ('oauth', 'static') AND credentials IS NOT NULL
	`).all()
	const encrypted = rows.some(r => Boolean(JSON.parse(r.credentials)?.secret))
	const keys = loadKeys({ dbPath, encrypted })
	const updates = []
	for (const row of rows) {
		const creds = JSON.parse(row.credentials)
		if (!creds?.secret) continue
		const context = secretContext(row.id, row.provider, row.type)
		const { plaintext, keyIndex } = openSecret(creds.secret, context, keys)
		if (keyIndex > 0) {
			creds.secret = encryptSecret(plaintext, context, keys)
			updates.push({ id: row.id, credentials: JSON.stringify(creds) })
		}
	}
	if (updates.length === 0) return
	targetDb.exec('BEGIN IMMEDIATE;')
	try {
		const stmt = targetDb.prepare('UPDATE tokens SET credentials = ? WHERE id = ?')
		for (const u of updates) {
			stmt.run(u.credentials, u.id)
		}
		targetDb.exec('COMMIT;')
	} catch (err) {
		targetDb.exec('ROLLBACK;')
		throw err
	}
	vacuumDatabase(targetDb)
}

function init () {
	sqlite.exec(CREATE_TOKENS_SQL)
	initKeys(sqlite)
}

function isSession (tok) {
	return Boolean(tok && tok.provider === 'self' && tok.type === 'bearer')
}

function isUpstreamApp (tok, { allowShare = false } = {}) {
	if (!tok || tok.provider === 'self') return false
	if (tok.type === 'oauth' || tok.type === 'static') return true
	return Boolean(allowShare && tok.type === 'share')
}

function formatToken (row) {
	if (!row) return null
	const rawCreds = row.credentials ? JSON.parse(row.credentials) : null
	const isSelf = row.provider === 'self'
	let credentials = rawCreds
	if (isSelf && rawCreds && typeof rawCreds === 'object' && 'refreshToken' in rawCreds) {
		const { refreshToken: _rt, ...rest } = rawCreds
		credentials = Object.keys(rest).length > 0 ? rest : null
	} else if (isEncryptedTokenRow(row.provider, row.type) && rawCreds) {
		credentials = decryptUpstreamCredentials(rawCreds, row)
	}
	const isShare = row.type === 'share'
	const resolvedAccount = isShare ? (row.name || row.account || null) : (row.user_id ? (row.account || null) : null)
	return {
		id: row.id,
		userId: row.user_id,
		provider: row.provider,
		type: row.type,
		name: isShare ? (row.upstream_name || null) : row.name,
		token: isHashedToken(row.provider, row.type) ? null : row.token,
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
		credentials = null,
		expiresAt = null,
		scopes = null,
		admin = 0,
		ip = null,
		ua = null
	} = opts
	const hashedToken = isHashedToken(provider, type)
	const rawToken = hashedToken ? (opts.token || randomUUID()) : (opts.token || null)
	const storedToken = hashedToken ? hashSecret(rawToken) : rawToken
	const { credsJson, rawRefreshToken } = serializeCredentials(credentials, { id, provider, type })
	const now = new Date().toISOString()
	sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, expires_at, scopes, admin, ip, ua, created, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(id, userId, provider, type, name, storedToken, credsJson, expiresAt, scopes, admin ? 1 : 0, ip, ua, now, now)
	const created = get(id)
	if (!hashedToken || !created) return created
	return {
		...created,
		token: rawToken,
		...(rawRefreshToken ? { credentials: { ...(created.credentials || {}), refreshToken: rawRefreshToken } } : {})
	}
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
	if (!isSession(session)) return null
	const now = Date.now()
	if (session.expiresAt) {
		if (session.updated < new Date(now - DORMANT_MS).toISOString()) return null
		if (session.expiresAt <= now) {
			const refreshable = sqlite.prepare(`
				SELECT 1 FROM tokens
				WHERE id = ? AND json_extract(credentials, '$.refreshToken') IS NOT NULL
			`).get(id)
			if (!refreshable) return null
		}
	}
	return session
}

function hasActiveAdmin () {
	const now = Date.now()
	const minUpdated = new Date(now - DORMANT_MS).toISOString()
	const row = sqlite.prepare(`
		SELECT 1
		FROM tokens
		WHERE provider = 'self' AND type = 'bearer' AND admin = 1
			AND (expires_at IS NULL OR (expires_at > ? AND updated >= ?))
		LIMIT 1
	`).get(now, minUpdated)
	return Boolean(row)
}

function getByToken (token) {
	const tokenHash = hashSecret(token)
	if (!tokenHash) return null
	const now = Date.now()
	const minUpdated = new Date(now - DORMANT_MS).toISOString()
	const row = sqlite.prepare(`
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.token = ? AND tokens.provider = 'self' AND tokens.type = 'bearer'
			AND (tokens.expires_at IS NULL OR (tokens.expires_at > ? AND tokens.updated >= ?))
	`).get(tokenHash, now, minUpdated)
	if (!row) return null
	if (touch(row.id)) {
		row.updated = new Date().toISOString()
	}
	return formatToken(row)
}

function resolveSession (auth) {
	if (!auth) return null
	return typeof auth === 'object' ? auth : getByToken(auth)
}

function findRevocable (token) {
	const tokenHash = hashSecret(token)
	if (!tokenHash) return null
	const row = sqlite.prepare(`
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.provider = 'self' AND tokens.type = 'bearer'
			AND (tokens.token = ? OR json_extract(tokens.credentials, '$.refreshToken') = ?)
	`).get(tokenHash, tokenHash)
	return formatToken(row)
}

function refreshOauthSession (refreshToken) {
	const refreshHash = hashSecret(refreshToken)
	if (!refreshHash) return null
	const now = Date.now()
	pruneRecentRefreshes(now)
	const minUpdated = new Date(now - DORMANT_MS).toISOString()
	const row = sqlite.prepare(`
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		WHERE tokens.provider = 'self' AND tokens.type = 'bearer'
			AND json_extract(tokens.credentials, '$.refreshToken') = ?
			AND (tokens.expires_at IS NULL OR tokens.updated >= ?)
	`).get(refreshHash, minUpdated)
	const session = formatToken(row)
	if (!session) return null
	const cached = recentRefreshes.get(session.id)
	const isFresh = Boolean(cached && cached.dedupUntil > now && cached.tokenHash === row.token && cached.expiresAt === session.expiresAt)
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
			UPDATE tokens
			SET token = ?, expires_at = ?, updated = ?
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
		credentials: { ...(updated.credentials || {}), refreshToken }
	}
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
	const minUpdated = new Date(Date.now() - DORMANT_MS).toISOString()
	let query = `
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account, ${UPSTREAM_SELECT}
		FROM tokens
		JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE tokens.user_id = ? AND tokens.type IN ('bearer', 'oauth', 'static', 'share')
			AND NOT (tokens.provider = 'self' AND tokens.type = 'bearer' AND tokens.expires_at IS NOT NULL AND tokens.updated < ?)
	`
	const params = [userId, minUpdated]
	if (opts.provider) {
		query += ' AND tokens.provider = ?'
		params.push(opts.provider)
	}
	query += ' ORDER BY tokens.created DESC, tokens.rowid DESC'
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
			CASE WHEN tokens.user_id IS NOT NULL THEN ${USER_ACCOUNT_SQL} ELSE NULL END AS account
		FROM tokens
		JOIN tokens AS upstream ON tokens.type = 'share' AND upstream.id = json_extract(tokens.credentials, '$.appId')
		WHERE upstream.user_id = ?
		ORDER BY tokens.created ASC, tokens.rowid ASC
	`).all(ownerUserId)
	return rows.map(formatToken)
}

function buildShareCreds (appId, policy, authProvider) {
	return {
		appId,
		policy,
		...(authProvider ? { authProvider } : {})
	}
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
		const claimedCreds = buildShareCreds(appId, policy, resolvedAuthProvider)
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
	const creds = buildShareCreds(appId, policy, cleanAuthProvider)
	const existingPending = sqlite.prepare(`
		SELECT id FROM tokens
		WHERE user_id IS NULL AND type = 'share' AND name = ?
			AND json_extract(credentials, '$.appId') = ?
			AND json_extract(credentials, '$.authProvider') IS ?
	`).get(cleanAccount, appId, cleanAuthProvider)
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
		throw httpError(400, `Ambiguous account "${cleanAccount}" matches multiple shared recipients on this app; specify provider`)
	}
	sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(matchingShares[0].id)
	return true
}

function updateCredentials (id, opts = {}) {
	const sets = []
	const params = []
	let rawSelfRefresh = null
	if (opts.credentials !== undefined) {
		const meta = opts.credentials && typeof opts.credentials === 'object'
			? sqlite.prepare('SELECT provider, type FROM tokens WHERE id = ?').get(id)
			: null
		const serialized = serializeCredentials(opts.credentials, meta ? { id, provider: meta.provider, type: meta.type } : null)
		rawSelfRefresh = serialized.rawRefreshToken
		sets.push('credentials = ?')
		params.push(serialized.credsJson)
	}
	if (opts.expiresAt !== undefined) {
		sets.push('expires_at = ?')
		params.push(opts.expiresAt)
	}
	if (opts.scopes !== undefined) {
		sets.push('scopes = ?')
		params.push(opts.scopes)
	}
	if (opts.name !== undefined) {
		sets.push('name = ?')
		params.push(opts.name)
	}
	const now = new Date().toISOString()
	sets.push('updated = ?')
	params.push(now, id)
	sqlite.prepare(`UPDATE tokens SET ${sets.join(', ')} WHERE id = ?`).run(...params)
	const updated = get(id)
	if (!rawSelfRefresh || !updated) return updated
	return {
		...updated,
		credentials: { ...(updated.credentials || {}), refreshToken: rawSelfRefresh }
	}
}

function updateSession (id, { name, admin, rotateToken = false } = {}) {
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
		sets.push('token = ?')
		params.push(hashSecret(rotatedToken))
		sets.push('expires_at = CASE WHEN expires_at IS NOT NULL THEN ? ELSE NULL END')
		params.push(nowMs + 3600 * 1000)
	}
	if (sets.length > 0) {
		sets.push('updated = ?')
		params.push(now, id)
		sqlite.prepare(`UPDATE tokens SET ${sets.join(', ')} WHERE id = ? AND provider = 'self' AND type = 'bearer'`).run(...params)
	}
	const updated = get(id)
	if (!updated || !rotatedToken) return updated
	return { ...updated, token: rotatedToken }
}

function remove (id) {
	if (!id) return false
	recentRefreshes.delete(id)
	const res = sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(id)
	return res.changes > 0
}

function prune (maxAgeMs = DORMANT_MS) {
	const now = Date.now()
	pruneRecentRefreshes(now)
	const minDate = new Date(now - maxAgeMs).toISOString()
	sqlite.prepare("DELETE FROM tokens WHERE type IN ('oauth_state', 'oauth_code') AND expires_at IS NOT NULL AND expires_at <= ?").run(now)
	sqlite.prepare("DELETE FROM tokens WHERE provider = 'self' AND type = 'bearer' AND expires_at IS NOT NULL AND updated < ?").run(minDate)
}

function formatState (row, rawState = null) {
	if (!row) return null
	const tok = formatToken(row)
	const meta = tok.credentials || {}
	return {
		id: tok.id,
		state: rawState,
		userId: tok.userId,
		mode: meta.mode || null,
		clientId: meta.clientId || null,
		clientRedirectUri: meta.clientRedirectUri || null,
		clientState: meta.clientState || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		name: tok.name,
		admin: tok.admin,
		merge: Boolean(meta.merge),
		newAppIds: Array.isArray(meta.newAppIds) ? meta.newAppIds : null,
		reauthAppId: meta.reauthAppId || null,
		services: Array.isArray(meta.services) ? meta.services : null,
		baseUrl: meta.baseUrl || null,
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
		name = null,
		admin = 0,
		merge = false,
		newAppIds = null,
		reauthAppId = null,
		services = null,
		baseUrl = null,
		account = null,
		sessionId = null,
		provider = null,
		ip = null,
		ttl = 15 * 60 * 1000
	} = opts
	const expiresAt = Date.now() + ttl
	const created = create({
		userId,
		provider: provider || 'self',
		type: 'oauth_state',
		name,
		credentials: {
			mode,
			clientId,
			clientRedirectUri,
			clientState,
			codeChallenge,
			codeChallengeMethod,
			...(merge && { merge: true }),
			...(Array.isArray(newAppIds) && { newAppIds }),
			reauthAppId,
			...(Array.isArray(services) && { services }),
			...(baseUrl && { baseUrl }),
			...(account && { account }),
			sessionId
		},
		expiresAt,
		admin,
		ip
	})
	return created.token
}

function getState (state) {
	const tokenHash = hashSecret(state)
	if (!tokenHash) return null
	const row = sqlite.prepare("SELECT * FROM tokens WHERE token = ? AND type = 'oauth_state' AND (expires_at IS NULL OR expires_at > ?)").get(tokenHash, Date.now())
	return formatState(row, state)
}

function consumeState (state) {
	const tokenHash = hashSecret(state)
	if (!tokenHash) return null
	const row = sqlite.prepare("DELETE FROM tokens WHERE token = ? AND type = 'oauth_state' AND (expires_at IS NULL OR expires_at > ?) RETURNING *").get(tokenHash, Date.now())
	return formatState(row, state)
}

function createAuthCode (opts = {}) {
	const {
		userId,
		name = null,
		admin = 0,
		ip = null,
		ua = null,
		appIds = [],
		clientId = null,
		clientRedirectUri = null,
		codeChallenge = null,
		codeChallengeMethod = null
	} = opts
	const created = create({
		userId,
		provider: 'self',
		type: 'oauth_code',
		name,
		credentials: {
			appIds,
			clientId,
			clientRedirectUri,
			codeChallenge,
			codeChallengeMethod
		},
		expiresAt: Date.now() + 10 * 60 * 1000,
		admin: admin ? 1 : 0,
		ip,
		ua
	})
	return created.token
}

function consumeAuthCode (code) {
	const tokenHash = hashSecret(code)
	if (!tokenHash) return null
	const row = sqlite.prepare("DELETE FROM tokens WHERE token = ? AND type = 'oauth_code' AND (expires_at IS NULL OR expires_at > ?) RETURNING *").get(tokenHash, Date.now())
	if (!row) return null
	const tok = formatToken(row)
	const meta = tok.credentials || {}
	return {
		id: tok.id,
		code,
		userId: tok.userId,
		name: tok.name,
		admin: tok.admin,
		ip: tok.ip,
		ua: tok.ua,
		appIds: Array.isArray(meta.appIds) ? meta.appIds : [],
		clientId: meta.clientId || null,
		clientRedirectUri: meta.clientRedirectUri || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		createdAt: new Date(tok.created).getTime()
	}
}
