import { sqlite } from './index.js'
import { randomBytes } from 'node:crypto'

export {
	init,
	create,
	get,
	consume,
	setMagicCode,
	findByMagicCode,
	consumeMagicCode,
	pruneExpired
}

function init () {
	sqlite.exec(`
		CREATE TABLE IF NOT EXISTS oauth_states (
			state TEXT PRIMARY KEY,
			user_id TEXT,
			client_redirect_uri TEXT,
			client_state TEXT,
			code_challenge TEXT,
			code_challenge_method TEXT,
			session_name TEXT,
			admin INTEGER DEFAULT 0,
			policy TEXT,
			reauth_app_id TEXT,
			magic_code TEXT,
			magic_expires_at INTEGER,
			ip TEXT,
			created_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_oauth_states_created ON oauth_states(created_at);
		CREATE INDEX IF NOT EXISTS idx_oauth_states_magic_code ON oauth_states(magic_code);
	`)
	const columns = sqlite.prepare('PRAGMA table_info(oauth_states)').all().map(c => c.name)
	if (!columns.includes('user_id')) sqlite.exec('ALTER TABLE oauth_states ADD COLUMN user_id TEXT;')
	if (!columns.includes('session_name')) sqlite.exec('ALTER TABLE oauth_states ADD COLUMN session_name TEXT;')
	if (!columns.includes('reauth_app_id')) sqlite.exec('ALTER TABLE oauth_states ADD COLUMN reauth_app_id TEXT;')
	if (!columns.includes('magic_code')) sqlite.exec('ALTER TABLE oauth_states ADD COLUMN magic_code TEXT;')
	if (!columns.includes('magic_expires_at')) sqlite.exec('ALTER TABLE oauth_states ADD COLUMN magic_expires_at INTEGER;')
}

function formatOauthState (row) {
	if (!row) return null
	return {
		state: row.state,
		userId: row.user_id,
		clientRedirectUri: row.client_redirect_uri,
		clientState: row.client_state,
		codeChallenge: row.code_challenge,
		codeChallengeMethod: row.code_challenge_method,
		sessionName: row.session_name,
		admin: Boolean(row.admin),
		policy: row.policy,
		reauthAppId: row.reauth_app_id,
		magicCode: row.magic_code,
		magicExpiresAt: row.magic_expires_at,
		ip: row.ip,
		createdAt: row.created_at
	}
}

function create (opts = {}) {
	const {
		userId = null,
		clientRedirectUri = null,
		clientState = null,
		codeChallenge = null,
		codeChallengeMethod = null,
		sessionName = null,
		admin = 0,
		policy = null,
		reauthAppId = null,
		magicCode = null,
		magicExpiresAt = null,
		ip = null
	} = opts
	pruneExpired()
	const state = randomBytes(24).toString('base64url')
	const now = Date.now()
	sqlite.prepare(`
		INSERT INTO oauth_states (state, user_id, client_redirect_uri, client_state, code_challenge, code_challenge_method, session_name, admin, policy, reauth_app_id, magic_code, magic_expires_at, ip, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(state, userId, clientRedirectUri, clientState, codeChallenge, codeChallengeMethod, sessionName, admin ? 1 : 0, policy, reauthAppId, magicCode, magicExpiresAt, ip, now)
	return state
}

function get (state) {
	if (!state) return null
	pruneExpired()
	const row = sqlite.prepare('SELECT * FROM oauth_states WHERE state = ?').get(state)
	return formatOauthState(row)
}

function consume (state) {
	if (!state) return null
	pruneExpired()
	const row = sqlite.prepare('SELECT * FROM oauth_states WHERE state = ?').get(state)
	if (!row) return null
	sqlite.prepare('DELETE FROM oauth_states WHERE state = ?').run(state)
	return formatOauthState(row)
}

function setMagicCode (state, magicCode, magicExpiresAt, userId = null) {
	const res = sqlite.prepare(`
		UPDATE oauth_states
		SET magic_code = ?, magic_expires_at = ?, user_id = COALESCE(?, user_id)
		WHERE state = ?
	`).run(magicCode, magicExpiresAt, userId, state)
	return res.changes > 0 ? get(state) : null
}

function findByMagicCode (magicCode) {
	if (!magicCode) return null
	pruneExpired()
	const row = sqlite.prepare('SELECT * FROM oauth_states WHERE magic_code = ?').get(magicCode)
	if (!row) return null
	if (row.magic_expires_at && Date.now() > row.magic_expires_at) return null
	return formatOauthState(row)
}

function consumeMagicCode (magicCode) {
	if (!magicCode) return null
	pruneExpired()
	const row = sqlite.prepare('SELECT * FROM oauth_states WHERE magic_code = ?').get(magicCode)
	if (!row) return null
	if (row.magic_expires_at && Date.now() > row.magic_expires_at) return null
	sqlite.prepare('DELETE FROM oauth_states WHERE magic_code = ?').run(magicCode)
	return formatOauthState(row)
}

function pruneExpired (maxAgeMs = 15 * 60 * 1000) {
	const minTime = Date.now() - maxAgeMs
	sqlite.prepare('DELETE FROM oauth_states WHERE created_at < ?').run(minTime)
}
