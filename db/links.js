import { sqlite } from './index.js'
import { formatToken } from './tokens.js'

export {
	init,
	create,
	get,
	listBySessionId,
	listByAppId,
	updatePolicy,
	remove,
	formatLink
}

function init () {
	sqlite.exec(`
		CREATE TABLE IF NOT EXISTS token_links (
			session_token_id TEXT NOT NULL,
			app_token_id TEXT NOT NULL,
			policy TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL,
			PRIMARY KEY (session_token_id, app_token_id),
			FOREIGN KEY(session_token_id) REFERENCES tokens(id) ON DELETE CASCADE,
			FOREIGN KEY(app_token_id) REFERENCES tokens(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_token_links_app ON token_links(app_token_id);
	`)
}

function formatLink (row) {
	if (!row) return null
	return {
		sessionTokenId: row.session_token_id,
		appTokenId: row.app_token_id,
		policy: row.policy,
		created: row.link_created || row.created,
		updated: row.link_updated || row.updated,
		app: row.app_id ? formatToken({
			id: row.app_id,
			user_id: row.app_user_id,
			provider: row.app_provider,
			type: row.app_type,
			name: row.app_name,
			token: row.app_token,
			credentials: row.app_credentials,
			expires_at: row.app_expires_at,
			scopes: row.app_scopes,
			admin: row.app_admin,
			created: row.app_created,
			updated: row.app_updated,
			email: row.email,
			user_name: row.user_name
		}) : undefined
	}
}

function create (opts = {}) {
	const { sessionTokenId, appTokenId, policy = null } = opts
	const now = new Date().toISOString()
	const policyStr = policy && typeof policy === 'object' ? JSON.stringify(policy) : policy
	sqlite.prepare(`
		INSERT INTO token_links (session_token_id, app_token_id, policy, created, updated)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(session_token_id, app_token_id) DO UPDATE SET
			policy = excluded.policy,
			updated = excluded.updated
	`).run(sessionTokenId, appTokenId, policyStr, now, now)
	return get(sessionTokenId, appTokenId)
}

function get (sessionTokenId, appTokenId) {
	if (!sessionTokenId || !appTokenId) return null
	const row = sqlite.prepare(`
		SELECT token_links.*,
			tokens.id AS app_id, tokens.user_id AS app_user_id, tokens.provider AS app_provider,
			tokens.type AS app_type, tokens.name AS app_name, tokens.token AS app_token,
			tokens.credentials AS app_credentials, tokens.expires_at AS app_expires_at,
			tokens.scopes AS app_scopes, tokens.admin AS app_admin,
			tokens.created AS app_created, tokens.updated AS app_updated,
			users.email, users.name AS user_name
		FROM token_links
		JOIN tokens ON token_links.app_token_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		WHERE token_links.session_token_id = ? AND token_links.app_token_id = ?
	`).get(sessionTokenId, appTokenId)
	return formatLink(row)
}

function listBySessionId (sessionTokenId) {
	if (!sessionTokenId) return []
	const rows = sqlite.prepare(`
		SELECT token_links.session_token_id, token_links.app_token_id, token_links.policy,
			token_links.created AS link_created, token_links.updated AS link_updated,
			tokens.id AS app_id, tokens.user_id AS app_user_id, tokens.provider AS app_provider,
			tokens.type AS app_type, tokens.name AS app_name, tokens.token AS app_token,
			tokens.credentials AS app_credentials, tokens.expires_at AS app_expires_at,
			tokens.scopes AS app_scopes, tokens.admin AS app_admin,
			tokens.created AS app_created, tokens.updated AS app_updated,
			users.email, users.name AS user_name
		FROM token_links
		JOIN tokens ON token_links.app_token_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		WHERE token_links.session_token_id = ?
		ORDER BY token_links.created ASC
	`).all(sessionTokenId)
	return rows.map(formatLink)
}

function listByAppId (appTokenId) {
	if (!appTokenId) return []
	const rows = sqlite.prepare(`
		SELECT token_links.*,
			tokens.id AS session_id, tokens.user_id, tokens.provider, tokens.type,
			tokens.name, tokens.token, tokens.admin, tokens.ip, tokens.ua,
			tokens.created AS session_created, tokens.updated AS session_updated,
			users.email, users.name AS user_name
		FROM token_links
		JOIN tokens ON token_links.session_token_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		WHERE token_links.app_token_id = ?
		ORDER BY token_links.created ASC
	`).all(appTokenId)
	return rows.map(r => ({
		sessionTokenId: r.session_token_id,
		appTokenId: r.app_token_id,
		policy: r.policy,
		created: r.created,
		updated: r.updated,
		session: {
			id: r.session_id,
			userId: r.user_id,
			provider: r.provider,
			type: r.type,
			name: r.name,
			admin: Boolean(r.admin),
			ip: r.ip,
			ua: r.ua,
			created: r.session_created,
			updated: r.session_updated,
			email: r.email,
			userName: r.user_name
		}
	}))
}

function updatePolicy (sessionTokenId, appTokenId, policy) {
	const now = new Date().toISOString()
	const policyStr = policy && typeof policy === 'object' ? JSON.stringify(policy) : policy
	const res = sqlite.prepare(`
		UPDATE token_links
		SET policy = ?, updated = ?
		WHERE session_token_id = ? AND app_token_id = ?
	`).run(policyStr, now, sessionTokenId, appTokenId)
	return res.changes > 0 ? get(sessionTokenId, appTokenId) : null
}

function remove (sessionTokenId, appTokenId) {
	if (!sessionTokenId || !appTokenId) return false
	const res = sqlite.prepare(`
		DELETE FROM token_links
		WHERE session_token_id = ? AND app_token_id = ?
	`).run(sessionTokenId, appTokenId)
	return res.changes > 0
}
