import { sqlite } from './index.js'
import * as users from './users.js'
import * as tokens from './tokens.js'
import { parseAccountSpec } from '../util.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	get,
	listByUserId,
	getAccountByUserId,
	findUserByAccount,
	upsert,
	remove,
	resolveUser
}

const CREATE_LOGINS_SQL = `
	CREATE TABLE IF NOT EXISTS logins (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		provider TEXT NOT NULL,
		account TEXT NOT NULL,
		created TEXT NOT NULL,
		UNIQUE(provider, account),
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_logins_user ON logins(user_id);
	CREATE INDEX IF NOT EXISTS idx_logins_account ON logins(account);
`

function formatLogin (row) {
	if (!row) return null
	return {
		id: row.id,
		userId: row.user_id,
		provider: row.provider,
		account: row.account,
		created: row.created
	}
}

function init () {
	sqlite.exec(CREATE_LOGINS_SQL)
}

function get (id) {
	if (!id) return null
	return formatLogin(sqlite.prepare('SELECT * FROM logins WHERE id = ?').get(id))
}

function listByUserId (userId) {
	if (!userId) return []
	const rows = sqlite.prepare(`
		SELECT * FROM logins
		WHERE user_id = ?
		ORDER BY created ASC, rowid ASC
	`).all(userId)
	return rows.map(formatLogin)
}

function getAccountByUserId (userId) {
	if (!userId) return null
	const row = sqlite.prepare(`
		SELECT account FROM logins
		WHERE user_id = ?
		ORDER BY created ASC, rowid ASC
		LIMIT 1
	`).get(userId)
	return row?.account || 'localhost'
}

function findUserByAccount (account, provider = null) {
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	if (!cleanAccount) return null
	if (cleanProvider) {
		const row = sqlite.prepare('SELECT user_id FROM logins WHERE provider = ? AND account = ?').get(cleanProvider, cleanAccount)
		return row ? users.get(row.user_id) : null
	}
	const rows = sqlite.prepare('SELECT DISTINCT user_id FROM logins WHERE account = ?').all(cleanAccount)
	if (rows.length > 1) {
		const err = new Error(`Ambiguous account "${cleanAccount}" matches multiple users across providers; specify provider`)
		err.status = 400
		throw err
	}
	return rows.length === 1 ? users.get(rows[0].user_id) : null
}

function runInTransaction (fn) {
	if (!sqlite.isTransaction) {
		sqlite.exec('BEGIN IMMEDIATE;')
		try {
			const result = fn()
			sqlite.exec('COMMIT;')
			return result
		} catch (err) {
			sqlite.exec('ROLLBACK;')
			throw err
		}
	}
	return fn()
}

function mergeUsers (userIdA, userIdB) {
	const uA = users.get(userIdA)
	const uB = users.get(userIdB)
	const [surviving, absorbed] = (uB && (!uA || uB.created < uA.created)) ? [uB, uA] : [uA, uB]
	sqlite.prepare('UPDATE logins SET user_id = ? WHERE user_id = ?').run(surviving.id, absorbed.id)
	sqlite.prepare('UPDATE tokens SET user_id = ? WHERE user_id = ?').run(surviving.id, absorbed.id)
	sqlite.prepare('UPDATE logs SET user_id = ? WHERE user_id = ?').run(surviving.id, absorbed.id)
	sqlite.prepare(`
		DELETE FROM tokens
		WHERE user_id = ? AND type = 'share'
			AND EXISTS (
				SELECT 1 FROM tokens AS owned
				WHERE owned.id = json_extract(tokens.credentials, '$.appId') AND owned.user_id = ?
			)
	`).run(surviving.id, surviving.id)
	const shares = sqlite.prepare(`
		SELECT id, json_extract(credentials, '$.appId') AS app_id
		FROM tokens
		WHERE user_id = ? AND type = 'share'
		ORDER BY created ASC, rowid ASC
	`).all(surviving.id)
	const seenApps = new Map()
	for (const s of shares) {
		if (!s.app_id) continue
		const keptId = seenApps.get(s.app_id)
		if (keptId) {
			sqlite.prepare('UPDATE links SET app_id = ? WHERE app_id = ? AND session_id NOT IN (SELECT session_id FROM links WHERE app_id = ?)').run(keptId, s.id, keptId)
			sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(s.id)
		} else {
			seenApps.set(s.app_id, s.id)
		}
	}
	sqlite.prepare('DELETE FROM users WHERE id = ?').run(absorbed.id)
	return surviving.id
}

function upsert ({ id = randomUUID(), userId, provider, account, allowUnscoped = false, merge = false }) {
	const cleanProvider = String(provider).trim().toLowerCase()
	const cleanAccount = String(account).trim().toLowerCase()
	return runInTransaction(() => {
		const existing = sqlite.prepare('SELECT * FROM logins WHERE provider = ? AND account = ?').get(cleanProvider, cleanAccount)
		if (existing) {
			if (existing.user_id !== userId) {
				if (!merge) {
					const err = new Error(`Account ${cleanAccount} is already registered to another user. Re-run link_login with merge: true to merge both accounts`)
					err.status = 409
					throw err
				}
				const survivingId = mergeUsers(userId, existing.user_id)
				tokens.claimPendingShares({ userId: survivingId, provider: cleanProvider, account: cleanAccount, allowUnscoped })
				return get(existing.id)
			}
			tokens.claimPendingShares({ userId, provider: cleanProvider, account: cleanAccount, allowUnscoped })
			return formatLogin(existing)
		}
		const now = new Date().toISOString()
		sqlite.prepare(`
			INSERT INTO logins (id, user_id, provider, account, created)
			VALUES (?, ?, ?, ?, ?)
		`).run(id, userId, cleanProvider, cleanAccount, now)
		tokens.claimPendingShares({ userId, provider: cleanProvider, account: cleanAccount, allowUnscoped })
		return get(id)
	})
}

function remove (userId, { loginId = null, provider = null, account = null } = {}) {
	if (!userId) return null
	const { account: cleanAccount, provider: cleanProvider } = parseAccountSpec(account, provider)
	return runInTransaction(() => {
		const allLogins = listByUserId(userId)
		let matches = allLogins
		if (loginId) {
			matches = matches.filter(l => l.id === loginId)
		}
		if (cleanProvider) {
			matches = matches.filter(l => l.provider === cleanProvider)
		}
		if (cleanAccount) {
			matches = matches.filter(l => l.account === cleanAccount)
		}
		if (matches.length === 0) {
			const err = new Error('Login key not found')
			err.status = 404
			throw err
		}
		if (matches.length > 1) {
			const err = new Error('Multiple login keys match; specify account')
			err.status = 400
			throw err
		}
		if (allLogins.length <= 1) {
			const err = new Error('Cannot unlink your only login key')
			err.status = 400
			throw err
		}
		const target = matches[0]
		sqlite.prepare('DELETE FROM logins WHERE id = ? AND user_id = ?').run(target.id, userId)
		return target
	})
}

function resolveUser (provider, account, { createIfMissing = true, allowUnscoped = false } = {}) {
	if (!provider || !account) return null
	const cleanProvider = String(provider).trim().toLowerCase()
	const cleanAccount = String(account).trim().toLowerCase()
	return runInTransaction(() => {
		const row = sqlite.prepare('SELECT user_id FROM logins WHERE provider = ? AND account = ?').get(cleanProvider, cleanAccount)
		if (row) {
			tokens.claimPendingShares({ userId: row.user_id, provider: cleanProvider, account: cleanAccount, allowUnscoped })
			return users.get(row.user_id)
		}
		if (!createIfMissing) return null
		const user = users.create()
		upsert({ userId: user.id, provider: cleanProvider, account: cleanAccount, allowUnscoped })
		return user
	})
}
