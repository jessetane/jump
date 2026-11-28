import { sqlite } from './index.js'
import { format as formatApp } from './apps.js'
import { userAccountSql } from './users.js'
import { serializePolicy } from '../policy.js'

export {
	init,
	create,
	get,
	listBySessionId,
	remove
}

const CREATE_LINKS_SQL = `
	CREATE TABLE IF NOT EXISTS links (
		session_id TEXT NOT NULL,
		app_id TEXT NOT NULL,
		share_id TEXT,
		policy TEXT,
		created TEXT NOT NULL,
		updated TEXT NOT NULL,
		PRIMARY KEY (session_id, app_id),
		FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
		FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE,
		FOREIGN KEY(share_id) REFERENCES shares(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_links_app ON links(app_id);
	CREATE INDEX IF NOT EXISTS idx_links_share ON links(share_id);
`

const LINK_SELECT = `
	SELECT
		links.session_id, links.app_id, links.share_id, links.policy,
		links.created AS link_created, links.updated AS link_updated,
		apps.user_id AS app_user_id, apps.provider AS app_provider, apps.type AS app_type,
		apps.name AS app_name, apps.account AS app_account, apps.base_url AS app_base_url,
		apps.credentials AS app_credentials, apps.scopes AS app_scopes,
		apps.expires_at AS app_expires_at, apps.policy AS app_policy,
		apps.created AS app_created, apps.updated AS app_updated,
		shares.user_id AS share_user_id, shares.account AS share_account,
		shares.auth_provider AS share_auth_provider, shares.policy AS share_policy,
		shares.created AS share_created, shares.updated AS share_updated,
		CASE WHEN shares.id IS NOT NULL THEN ${userAccountSql('apps.user_id')} ELSE NULL END AS shared_by_account
	FROM links
	JOIN apps ON links.app_id = apps.id
	LEFT JOIN shares ON links.share_id = shares.id
`

function formatLink (row) {
	if (!row) return null
	const app = formatApp({
		id: row.app_id,
		user_id: row.app_user_id,
		provider: row.app_provider,
		type: row.app_type,
		name: row.app_name,
		account: row.app_account,
		base_url: row.app_base_url,
		credentials: row.app_credentials,
		scopes: row.app_scopes,
		expires_at: row.app_expires_at,
		policy: row.app_policy,
		created: row.app_created,
		updated: row.app_updated
	})
	const share = row.share_id ? {
		id: row.share_id,
		appId: row.app_id,
		userId: row.share_user_id || null,
		account: row.share_account,
		authProvider: row.share_auth_provider || null,
		policy: row.share_policy ?? null,
		sharedBy: row.shared_by_account || null,
		created: row.share_created,
		updated: row.share_updated
	} : null
	return {
		sessionId: row.session_id,
		appId: row.app_id,
		shareId: row.share_id || null,
		targetId: row.share_id || row.app_id,
		policy: row.policy ?? null,
		created: row.link_created,
		updated: row.link_updated,
		app,
		share
	}
}

function init () {
	sqlite.exec(CREATE_LINKS_SQL)
}

function create (opts = {}) {
	const { sessionId, appId, shareId = null, policy = null } = opts
	const now = new Date().toISOString()
	const policyStr = serializePolicy(policy)
	sqlite.prepare(`
		INSERT INTO links (session_id, app_id, share_id, policy, created, updated)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id, app_id) DO UPDATE SET
			share_id = excluded.share_id,
			policy = excluded.policy,
			updated = excluded.updated
	`).run(sessionId, appId, shareId, policyStr, now, now)
	return get(sessionId, appId)
}

function get (sessionId, appId) {
	if (!sessionId || !appId) return null
	const row = sqlite.prepare(`
		${LINK_SELECT}
		WHERE links.session_id = ? AND links.app_id = ?
	`).get(sessionId, appId)
	return formatLink(row)
}

function listBySessionId (sessionId) {
	if (!sessionId) return []
	const rows = sqlite.prepare(`
		${LINK_SELECT}
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
