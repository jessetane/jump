import { DatabaseSync } from 'node:sqlite'
import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import * as users from './users.js'
import * as tokens from './tokens.js'
import * as links from './links.js'

const dbPath = process.env.DB_PATH || './data.db'

const prevUmask = process.umask(0o077)
const sqlite = new DatabaseSync(dbPath)
process.umask(prevUmask)

sqlite.exec('PRAGMA journal_mode = WAL;')
sqlite.exec('PRAGMA foreign_keys = ON;')
sqlite.exec('PRAGMA busy_timeout = 5000;')

for (const ext of ['', '-wal', '-shm']) {
	const file = `${dbPath}${ext}`
	if (fs.existsSync(file)) fs.chmodSync(file, 0o600)
}

function migrateLegacySessions () {
	const hasSessions = sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sessions'").get()
	if (!hasSessions) return
	const rows = sqlite.prepare(`
		SELECT sessions.*, users.email, users.name AS user_name
		FROM sessions
		JOIN users ON sessions.user_id = users.id
	`).all()
	sqlite.exec('BEGIN;')
	try {
		for (const row of rows) {
			sqlite.prepare(`
				INSERT OR IGNORE INTO tokens (id, user_id, provider, type, name, token, credentials, expires_at, scopes, admin, ip, ua, created, updated)
				VALUES (?, ?, 'self', 'bearer', NULL, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?)
			`).run(row.id, row.user_id, row.token, row.admin ? 1 : 0, row.ip || null, row.ua || null, row.created, row.updated)
			if (row.refresh_token || row.access_token) {
				const appId = randomUUID()
				const creds = JSON.stringify({
					accessToken: row.access_token || null,
					refreshToken: row.refresh_token || null,
					email: row.email,
					account: row.email
				})
				const appName = `${row.user_name || row.email} Google`
				sqlite.prepare(`
					INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, expires_at, scopes, admin, ip, ua, created, updated)
					VALUES (?, ?, 'google', 'oauth', ?, NULL, ?, ?, ?, 0, NULL, NULL, ?, ?)
				`).run(appId, row.user_id, appName, creds, row.expires_at || null, row.scope || null, row.created, row.updated)
				sqlite.prepare(`
					INSERT OR IGNORE INTO links (session_id, app_id, policy, created, updated)
					VALUES (?, ?, ?, ?, ?)
				`).run(row.id, appId, row.policy || null, row.created, row.updated)
			}
		}
		sqlite.exec('DROP TABLE sessions;')
		sqlite.exec('COMMIT;')
	} catch (err) {
		sqlite.exec('ROLLBACK;')
		throw err
	}
}

users.init()
tokens.init()
links.init()
migrateLegacySessions()
tokens.pruneDormant()

export {
	sqlite,
	users,
	tokens,
	links,
	migrateLegacySessions
}
