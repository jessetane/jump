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
		CREATE TABLE IF NOT EXISTS links (
			session_id TEXT NOT NULL,
			app_id TEXT NOT NULL,
			policy TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL,
			PRIMARY KEY (session_id, app_id),
			FOREIGN KEY(session_id) REFERENCES tokens(id) ON DELETE CASCADE,
			FOREIGN KEY(app_id) REFERENCES tokens(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_links_app ON links(app_id);
	`)
}

function formatLink (row) {
	if (!row) return null
	return {
		sessionId: row.session_id,
		appId: row.app_id,
		policy: row.policy,
		created: row.link_created || row.created,
		updated: row.link_updated || row.updated,
		app: row.target_app_id ? formatToken({
			id: row.target_app_id,
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
	const { sessionId, appId, policy = null } = opts
	const now = new Date().toISOString()
	const policyStr = policy && typeof policy === 'object' ? JSON.stringify(policy) : policy
	sqlite.prepare(`
		INSERT INTO links (session_id, app_id, policy, created, updated)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(session_id, app_id) DO UPDATE SET
			policy = excluded.policy,
			updated = excluded.updated
	`).run(sessionId, appId, policyStr, now, now)
	return get(sessionId, appId)
}

function get (sessionId, appId) {
	if (!sessionId || !appId) return null
	const row = sqlite.prepare(`
		SELECT links.*,
			tokens.id AS target_app_id, tokens.user_id AS app_user_id, tokens.provider AS app_provider,
			tokens.type AS app_type, tokens.name AS app_name, tokens.token AS app_token,
			tokens.credentials AS app_credentials, tokens.expires_at AS app_expires_at,
			tokens.scopes AS app_scopes, tokens.admin AS app_admin,
			tokens.created AS app_created, tokens.updated AS app_updated,
			users.email, users.name AS user_name
		FROM links
		JOIN tokens ON links.app_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		WHERE links.session_id = ? AND links.app_id = ?
	`).get(sessionId, appId)
	return formatLink(row)
}

function listBySessionId (sessionId) {
	if (!sessionId) return []
	const rows = sqlite.prepare(`
		SELECT links.session_id, links.app_id, links.policy,
			links.created AS link_created, links.updated AS link_updated,
			tokens.id AS target_app_id, tokens.user_id AS app_user_id, tokens.provider AS app_provider,
			tokens.type AS app_type, tokens.name AS app_name, tokens.token AS app_token,
			tokens.credentials AS app_credentials, tokens.expires_at AS app_expires_at,
			tokens.scopes AS app_scopes, tokens.admin AS app_admin,
			tokens.created AS app_created, tokens.updated AS app_updated,
			users.email, users.name AS user_name
		FROM links
		JOIN tokens ON links.app_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		WHERE links.session_id = ?
		ORDER BY links.created ASC
	`).all(sessionId)
	return rows.map(formatLink)
}

function listByAppId (appId) {
	if (!appId) return []
	const rows = sqlite.prepare(`
		SELECT links.*,
			tokens.id AS target_session_id, tokens.user_id, tokens.provider, tokens.type,
			tokens.name, tokens.token, tokens.admin, tokens.ip, tokens.ua,
			tokens.created AS session_created, tokens.updated AS session_updated,
			users.email, users.name AS user_name
		FROM links
		JOIN tokens ON links.session_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		WHERE links.app_id = ?
		ORDER BY links.created ASC
	`).all(appId)
	return rows.map(r => ({
		sessionId: r.session_id,
		appId: r.app_id,
		policy: r.policy,
		created: r.created,
		updated: r.updated,
		session: {
			id: r.target_session_id,
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

function updatePolicy (sessionId, appId, policy) {
	const now = new Date().toISOString()
	const policyStr = policy && typeof policy === 'object' ? JSON.stringify(policy) : policy
	const res = sqlite.prepare(`
		UPDATE links
		SET policy = ?, updated = ?
		WHERE session_id = ? AND app_id = ?
	`).run(policyStr, now, sessionId, appId)
	return res.changes > 0 ? get(sessionId, appId) : null
}

function remove (sessionId, appId) {
	if (!sessionId || !appId) return false
	const res = sqlite.prepare(`
		DELETE FROM links
		WHERE session_id = ? AND app_id = ?
	`).run(sessionId, appId)
	return res.changes > 0
}
