import { randomUUID } from 'node:crypto'
import * as users from './users.js'

export {
	migrate
}

const SCHEMA_VERSION = 1

function migrate (sqlite) {
	const version = sqlite.prepare('PRAGMA user_version').get()?.user_version || 0
	if (version >= SCHEMA_VERSION) return
	const userCols = sqlite.prepare('PRAGMA table_info(users)').all()
	const hasEmail = userCols.some(c => c.name === 'email')
	if (!hasEmail) {
		sqlite.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`)
		return
	}
	sqlite.exec('PRAGMA foreign_keys = OFF;')
	try {
		sqlite.exec('BEGIN IMMEDIATE;')
		try {
			const rows = sqlite.prepare('SELECT id, email, created FROM users ORDER BY created ASC, rowid ASC').all()
			const insertLogin = sqlite.prepare('INSERT INTO logins (id, user_id, provider, account, created) VALUES (?, ?, ?, ?, ?)')
			const findLogin = sqlite.prepare('SELECT user_id FROM logins WHERE provider = ? AND account = ?')
			const dropUserIds = []
			for (const r of rows) {
				const account = typeof r.email === 'string' ? r.email.trim().toLowerCase() : ''
				if (!account) continue
				const existing = findLogin.get('google', account)
				if (existing && existing.user_id !== r.id) {
					sqlite.prepare('UPDATE tokens SET user_id = ? WHERE user_id = ?').run(existing.user_id, r.id)
					sqlite.prepare('UPDATE logs SET user_id = ? WHERE user_id = ?').run(existing.user_id, r.id)
					dropUserIds.push(r.id)
					continue
				}
				if (!existing) {
					insertLogin.run(randomUUID(), r.id, 'google', account, r.created || new Date().toISOString())
				}
			}
			sqlite.exec(`
				CREATE TEMP TABLE users_backup AS SELECT id, created, updated FROM users;
				DROP TABLE users;
				${users.CREATE_USERS_SQL}
				INSERT INTO users (id, created, updated) SELECT id, created, updated FROM users_backup;
				DROP TABLE users_backup;
			`)
			for (const dropId of dropUserIds) {
				sqlite.prepare('DELETE FROM users WHERE id = ?').run(dropId)
			}
			sqlite.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`)
			sqlite.exec('COMMIT;')
		} catch (err) {
			sqlite.exec('ROLLBACK;')
			throw err
		}
	} finally {
		sqlite.exec('PRAGMA foreign_keys = ON;')
	}
}
