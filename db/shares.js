import { randomUUID } from 'node:crypto'
import { sqlite } from './index.js'
import { userAccountSql } from './users.js'
import { serializePolicy } from '../policy.js'
import { parseAccountSpec, httpError } from '../util.js'

export {
	init,
	get,
	listByUserId,
	listByOwnerId,
	claimPending,
	upsert,
	remove,
	removeByTarget
}

const CREATE_SHARES_SQL = `
	CREATE TABLE IF NOT EXISTS shares (
		id TEXT PRIMARY KEY,
		app_id TEXT NOT NULL,
		user_id TEXT,
		account TEXT NOT NULL,
		auth_provider TEXT,
		policy TEXT,
		created TEXT NOT NULL,
		updated TEXT NOT NULL,
		FOREIGN KEY(app_id) REFERENCES apps(id) ON DELETE CASCADE,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_shares_app ON shares(app_id);
	CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);
	CREATE INDEX IF NOT EXISTS idx_shares_pending ON shares(account, auth_provider) WHERE user_id IS NULL;
`

const SHARE_APP_SELECT = `
	shares.*,
	app.provider AS app_provider,
	app.type AS app_type,
	app.name AS app_name,
	app.account AS app_account,
	app.base_url AS app_base_url,
	app.scopes AS app_scopes,
	app.expires_at AS app_expires_at,
	app.policy AS app_policy,
	${userAccountSql('app.user_id')} AS shared_by_account
`

const SHARE_APP_JOIN = `
	JOIN apps AS app ON shares.app_id = app.id
`

function format (row) {
	if (!row) return null
	return {
		id: row.id,
		appId: row.app_id,
		userId: row.user_id || null,
		type: 'share',
		provider: row.app_provider,
		appType: row.app_type,
		name: row.app_name || null,
		appAccount: row.app_account || null,
		baseUrl: row.app_base_url || null,
		scopes: row.app_scopes || null,
		expiresAt: row.app_expires_at ?? null,
		appPolicy: row.app_policy ?? null,
		account: row.account,
		authProvider: row.auth_provider || null,
		policy: row.policy ?? null,
		sharedBy: row.shared_by_account || null,
		created: row.created,
		updated: row.updated
	}
}

function init () {
	sqlite.exec(CREATE_SHARES_SQL)
}

function get (id) {
	if (!id) return null
	const row = sqlite.prepare(`
		SELECT ${SHARE_APP_SELECT}
		FROM shares
		${SHARE_APP_JOIN}
		WHERE shares.id = ?
	`).get(id)
	return format(row)
}

function listByUserId (userId, opts = {}) {
	if (!userId) return []
	let query = `
		SELECT ${SHARE_APP_SELECT}
		FROM shares
		${SHARE_APP_JOIN}
		WHERE shares.user_id = ?
	`
	const params = [userId]
	if (opts.provider) {
		query += ' AND app.provider = ?'
		params.push(opts.provider)
	}
	query += ' ORDER BY shares.created DESC, shares.rowid DESC'
	return sqlite.prepare(query).all(...params).map(format)
}

function listByOwnerId (ownerUserId) {
	if (!ownerUserId) return []
	const rows = sqlite.prepare(`
		SELECT ${SHARE_APP_SELECT}
		FROM shares
		${SHARE_APP_JOIN}
		WHERE app.user_id = ?
		ORDER BY shares.created ASC, shares.rowid ASC
	`).all(ownerUserId)
	return rows.map(format)
}

function claimPending ({ userId, provider, account, allowUnscoped = false }) {
	const cleanProvider = String(provider).trim().toLowerCase()
	const cleanAccount = String(account).trim().toLowerCase()
	const pendingRows = allowUnscoped
		? sqlite.prepare(`
			SELECT id, app_id, auth_provider, updated
			FROM shares
			WHERE user_id IS NULL AND account = ?
				AND (auth_provider IS NULL OR auth_provider = ?)
			ORDER BY
				CASE WHEN auth_provider = ? THEN 0 ELSE 1 END ASC,
				updated DESC,
				rowid DESC
		`).all(cleanAccount, cleanProvider, cleanProvider)
		: sqlite.prepare(`
			SELECT id, app_id, auth_provider, updated
			FROM shares
			WHERE user_id IS NULL AND account = ? AND auth_provider = ?
			ORDER BY updated DESC, rowid DESC
		`).all(cleanAccount, cleanProvider)
	for (const row of pendingRows) {
		const ownsApp = sqlite.prepare('SELECT 1 FROM apps WHERE id = ? AND user_id = ?').get(row.app_id, userId)
		if (ownsApp) {
			sqlite.prepare('DELETE FROM shares WHERE id = ?').run(row.id)
			continue
		}
		const resolvedAuthProvider = row.auth_provider || cleanProvider
		const existingShare = sqlite.prepare('SELECT id, account, updated FROM shares WHERE user_id = ? AND app_id = ?').get(userId, row.app_id)
		if (existingShare) {
			if (row.auth_provider === cleanProvider && existingShare.account === cleanAccount && row.updated >= existingShare.updated) {
				sqlite.prepare(`
					UPDATE shares
					SET account = ?, auth_provider = ?, policy = (SELECT policy FROM shares WHERE id = ?), updated = ?
					WHERE id = ?
				`).run(cleanAccount, resolvedAuthProvider, row.id, row.updated, existingShare.id)
			}
			sqlite.prepare('DELETE FROM shares WHERE id = ?').run(row.id)
			continue
		}
		sqlite.prepare(`
			UPDATE shares
			SET user_id = ?, account = ?, auth_provider = ?
			WHERE id = ?
		`).run(userId, cleanAccount, resolvedAuthProvider, row.id)
	}
}

function upsert ({ userId = null, account = null, authProvider = null, appId, policy = null }) {
	const cleanAccount = account ? String(account).trim().toLowerCase() : null
	const cleanAuthProvider = authProvider ? String(authProvider).trim().toLowerCase() : null
	const policyStr = serializePolicy(policy)
	const now = new Date().toISOString()
	if (userId) {
		const existing = sqlite.prepare('SELECT id, account, auth_provider FROM shares WHERE user_id = ? AND app_id = ?').get(userId, appId)
		let resolvedAuthProvider = cleanAuthProvider
		if (!resolvedAuthProvider) {
			if (existing?.auth_provider && (!cleanAccount || existing.account === cleanAccount)) {
				resolvedAuthProvider = existing.auth_provider
			} else if (cleanAccount) {
				const matchedLogin = sqlite.prepare(`
					SELECT provider FROM logins
					WHERE user_id = ? AND account = ?
					ORDER BY created ASC, rowid ASC
					LIMIT 1
				`).get(userId, cleanAccount)
				resolvedAuthProvider = matchedLogin?.provider || existing?.auth_provider || null
			}
		}
		if (existing) {
			sqlite.prepare(`
				UPDATE shares
				SET policy = ?, auth_provider = ?, updated = ?${cleanAccount ? ', account = ?' : ''}
				WHERE id = ?
			`).run(policyStr, resolvedAuthProvider, now, ...(cleanAccount ? [cleanAccount] : []), existing.id)
			return get(existing.id)
		}
		const id = randomUUID()
		sqlite.prepare(`
			INSERT INTO shares (id, app_id, user_id, account, auth_provider, policy, created, updated)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`).run(id, appId, userId, cleanAccount, resolvedAuthProvider, policyStr, now, now)
		return get(id)
	}
	const existingPending = sqlite.prepare(`
		SELECT id FROM shares
		WHERE user_id IS NULL AND account = ? AND app_id = ? AND auth_provider IS ?
	`).get(cleanAccount, appId, cleanAuthProvider)
	if (existingPending) {
		sqlite.prepare('UPDATE shares SET policy = ?, updated = ? WHERE id = ?').run(policyStr, now, existingPending.id)
		return get(existingPending.id)
	}
	const id = randomUUID()
	sqlite.prepare(`
		INSERT INTO shares (id, app_id, user_id, account, auth_provider, policy, created, updated)
		VALUES (?, ?, NULL, ?, ?, ?, ?, ?)
	`).run(id, appId, cleanAccount, cleanAuthProvider, policyStr, now, now)
	return get(id)
}

function remove (id) {
	if (!id) return false
	const res = sqlite.prepare('DELETE FROM shares WHERE id = ?').run(id)
	return res.changes > 0
}

function removeByTarget ({ account = null, provider = null, appId }) {
	if (!appId) return false
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	if (!cleanAccount) return false
	if (cleanProvider) {
		let matches = sqlite.prepare(`
			SELECT id FROM shares
			WHERE account = ? AND app_id = ? AND auth_provider = ?
		`).all(cleanAccount, appId, cleanProvider)
		if (matches.length === 0) {
			const hasScopedForAccount = sqlite.prepare(`
				SELECT 1 FROM shares
				WHERE account = ? AND app_id = ? AND auth_provider IS NOT NULL
				LIMIT 1
			`).get(cleanAccount, appId)
			if (!hasScopedForAccount) {
				matches = sqlite.prepare(`
					SELECT id FROM shares
					WHERE user_id IS NULL AND account = ? AND app_id = ? AND auth_provider IS NULL
				`).all(cleanAccount, appId)
			}
		}
		if (matches.length === 0) return false
		const stmt = sqlite.prepare('DELETE FROM shares WHERE id = ?')
		for (const s of matches) {
			stmt.run(s.id)
		}
		return true
	}
	const matches = sqlite.prepare('SELECT id FROM shares WHERE account = ? AND app_id = ?').all(cleanAccount, appId)
	if (matches.length === 0) return false
	if (matches.length > 1) {
		throw httpError(400, `Ambiguous account "${cleanAccount}" matches multiple shared recipients on this app; specify provider`)
	}
	sqlite.prepare('DELETE FROM shares WHERE id = ?').run(matches[0].id)
	return true
}
