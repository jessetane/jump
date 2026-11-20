import { sqlite } from './index.js'
import { formatToken, USER_ACCOUNT_SQL, UPSTREAM_SELECT, UPSTREAM_JOIN } from './tokens.js'

export {
	init,
	create,
	get,
	listBySessionId,
	remove
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
		created: row.link_created,
		updated: row.link_updated,
		app: row.id ? formatToken(row) : undefined
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
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account, ${UPSTREAM_SELECT},
			links.session_id, links.app_id, links.policy,
			links.created AS link_created, links.updated AS link_updated
		FROM links
		JOIN tokens ON links.app_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE links.session_id = ? AND links.app_id = ?
	`).get(sessionId, appId)
	return formatLink(row)
}

function listBySessionId (sessionId) {
	if (!sessionId) return []
	const rows = sqlite.prepare(`
		SELECT tokens.*, ${USER_ACCOUNT_SQL} AS account, ${UPSTREAM_SELECT},
			links.session_id, links.app_id, links.policy,
			links.created AS link_created, links.updated AS link_updated
		FROM links
		JOIN tokens ON links.app_id = tokens.id
		JOIN users ON tokens.user_id = users.id
		${UPSTREAM_JOIN}
		WHERE links.session_id = ?
		ORDER BY links.created ASC, links.rowid ASC
	`).all(sessionId)
	return rows.map(formatLink)
}

function remove (sessionId, appId) {
	if (!sessionId || !appId) return false
	const res = sqlite.prepare(`
		DELETE FROM links
		WHERE session_id = ? AND app_id = ?
	`).run(sessionId, appId)
	return res.changes > 0
}
