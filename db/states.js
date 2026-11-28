import { randomUUID } from 'node:crypto'
import { sqlite, transaction } from './index.js'
import { hashSecret } from '../crypto.js'

export {
	init,
	createState,
	getState,
	consumeState,
	consumeStateById,
	createAuthCode,
	consumeAuthCode,
	prune
}

const CREATE_STATES_SQL = `
	CREATE TABLE IF NOT EXISTS states (
		id TEXT PRIMARY KEY,
		token_hash TEXT UNIQUE NOT NULL,
		type TEXT NOT NULL,
		user_id TEXT,
		payload TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		created TEXT NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_states_expires ON states(expires_at);
`

function formatState (row, rawState = null) {
	if (!row) return null
	const meta = row.payload ? JSON.parse(row.payload) : {}
	return {
		id: row.id,
		state: rawState,
		userId: row.user_id || null,
		mode: meta.mode || null,
		clientId: meta.clientId || null,
		clientRedirectUri: meta.clientRedirectUri || null,
		clientState: meta.clientState || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		name: meta.name || null,
		admin: Boolean(meta.admin),
		merge: Boolean(meta.merge),
		newAppIds: Array.isArray(meta.newAppIds) ? meta.newAppIds : null,
		reauthAppId: meta.reauthAppId || null,
		setupStateId: meta.setupStateId || null,
		services: Array.isArray(meta.services) ? meta.services : null,
		baseUrl: meta.baseUrl || null,
		policy: meta.policy !== undefined ? meta.policy : null,
		sessionId: meta.sessionId || null,
		provider: meta.provider || null,
		ip: meta.ip || null,
		createdAt: new Date(row.created).getTime()
	}
}

function formatAuthCode (row, code) {
	if (!row) return null
	const meta = row.payload ? JSON.parse(row.payload) : {}
	return {
		id: row.id,
		code,
		userId: row.user_id || null,
		name: meta.name || null,
		admin: Boolean(meta.admin),
		ip: meta.ip || null,
		ua: meta.ua || null,
		appIds: Array.isArray(meta.appIds) ? meta.appIds : [],
		clientId: meta.clientId || null,
		clientRedirectUri: meta.clientRedirectUri || null,
		codeChallenge: meta.codeChallenge || null,
		codeChallengeMethod: meta.codeChallengeMethod || null,
		createdAt: new Date(row.created).getTime()
	}
}

function insertTokenRow ({ type, userId = null, payload, ttl }) {
	const id = randomUUID()
	const raw = randomUUID()
	const tokenHash = hashSecret(raw)
	const now = new Date().toISOString()
	const expiresAt = Date.now() + ttl
	sqlite.prepare(`
		INSERT INTO states (id, token_hash, type, user_id, payload, expires_at, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`).run(id, tokenHash, type, userId, JSON.stringify(payload), expiresAt, now)
	return raw
}

function init () {
	sqlite.exec(CREATE_STATES_SQL)
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
		setupStateId = null,
		services = null,
		baseUrl = null,
		policy = null,
		sessionId = null,
		provider = null,
		ip = null,
		ttl = 15 * 60 * 1000
	} = opts
	return insertTokenRow({
		type: 'state',
		userId,
		ttl,
		payload: {
			mode,
			clientId,
			clientRedirectUri,
			clientState,
			codeChallenge,
			codeChallengeMethod,
			name,
			admin: Boolean(admin),
			...(merge && { merge: true }),
			...(Array.isArray(newAppIds) && { newAppIds }),
			reauthAppId,
			...(setupStateId && { setupStateId }),
			...(Array.isArray(services) && { services }),
			...(baseUrl && { baseUrl }),
			...(policy !== null && { policy }),
			sessionId,
			provider: provider && provider !== 'self' ? provider : null,
			ip
		}
	})
}

function getState (state) {
	const tokenHash = hashSecret(state)
	if (!tokenHash) return null
	const row = sqlite.prepare("SELECT * FROM states WHERE token_hash = ? AND type = 'state' AND expires_at > ?").get(tokenHash, Date.now())
	return formatState(row, state)
}

function consumeState (state, validate = null) {
	const tokenHash = hashSecret(state)
	if (!tokenHash) return null
	if (!validate) {
		const row = sqlite.prepare("DELETE FROM states WHERE token_hash = ? AND type = 'state' AND expires_at > ? RETURNING *").get(tokenHash, Date.now())
		return formatState(row, state)
	}
	return transaction(() => {
		const found = getState(state)
		if (!found) return null
		const result = validate(found)
		if (!result) return null
		sqlite.prepare("DELETE FROM states WHERE token_hash = ? AND type = 'state'").run(tokenHash)
		return result === true ? found : result
	})
}

function consumeStateById (id) {
	if (!id) return null
	const row = sqlite.prepare("DELETE FROM states WHERE id = ? AND type = 'state' AND expires_at > ? RETURNING *").get(id, Date.now())
	return formatState(row)
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
	return insertTokenRow({
		type: 'code',
		userId,
		ttl: 10 * 60 * 1000,
		payload: {
			name,
			admin: Boolean(admin),
			ip,
			ua,
			appIds,
			clientId,
			clientRedirectUri,
			codeChallenge,
			codeChallengeMethod
		}
	})
}

function consumeAuthCode (code) {
	const tokenHash = hashSecret(code)
	if (!tokenHash) return null
	const row = sqlite.prepare("DELETE FROM states WHERE token_hash = ? AND type = 'code' AND expires_at > ? RETURNING *").get(tokenHash, Date.now())
	return formatAuthCode(row, code)
}

function prune () {
	sqlite.prepare('DELETE FROM states WHERE expires_at <= ?').run(Date.now())
}
