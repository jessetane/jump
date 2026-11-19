import { randomUUID } from 'node:crypto'
import * as users from './users.js'
import { hashSecret, encryptUpstreamCredentials, parseLegacyApiKey } from './tokens.js'
import { loadKeys, secretContext, encryptSecret, openSecret, decryptSecret } from '../crypto.js'

export {
	migrate
}

const SCHEMA_VERSION = 4
const ENCRYPTED_SCHEMA_VERSION = 3
const LEGACY_V3_SECRET_FIELDS = ['accessToken', 'refreshToken', 'apiKey']

function migrateUsersEmail (sqlite) {
	const userCols = sqlite.prepare('PRAGMA table_info(users)').all()
	const hasEmail = userCols.some(c => c.name === 'email')
	if (!hasEmail) return false
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
			sqlite.exec('COMMIT;')
			return true
		} catch (err) {
			sqlite.exec('ROLLBACK;')
			throw err
		}
	} finally {
		sqlite.exec('PRAGMA foreign_keys = ON;')
	}
}

function migrateSelfTokenHashes (sqlite) {
	sqlite.exec('BEGIN IMMEDIATE;')
	try {
		const rows = sqlite.prepare(`
			SELECT id, type, token, credentials
			FROM tokens
			WHERE provider = 'self' OR type IN ('oauth_state', 'oauth_code')
		`).all()
		const updateStmt = sqlite.prepare('UPDATE tokens SET id = ?, token = ?, credentials = ? WHERE id = ?')
		let changedCount = 0
		for (const row of rows) {
			let nextId = row.id
			let nextToken = row.token
			let changed = false
			if (typeof row.token === 'string' && row.token) {
				nextToken = hashSecret(row.token)
				changed = true
			} else if ((row.type === 'oauth_state' || row.type === 'oauth_code') && !row.token) {
				nextId = randomUUID()
				nextToken = hashSecret(row.id)
				changed = true
			}
			let nextCreds = row.credentials
			if (row.type === 'bearer' && row.credentials) {
				const parsed = JSON.parse(row.credentials)
				if (parsed && typeof parsed === 'object' && typeof parsed.refreshToken === 'string' && parsed.refreshToken) {
					parsed.refreshToken = hashSecret(parsed.refreshToken)
					nextCreds = JSON.stringify(parsed)
					changed = true
				}
			}
			if (changed) {
				updateStmt.run(nextId, nextToken, nextCreds, row.id)
				changedCount++
			}
		}
		sqlite.exec('PRAGMA user_version = 2;')
		sqlite.exec('COMMIT;')
		return changedCount > 0
	} catch (err) {
		sqlite.exec('ROLLBACK;')
		throw err
	}
}

function migrateUpstreamSecrets (sqlite, keys, fromVersion) {
	sqlite.exec('BEGIN IMMEDIATE;')
	try {
		const rows = sqlite.prepare(`
			SELECT id, provider, type, credentials
			FROM tokens
			WHERE provider != 'self' AND type IN ('oauth', 'api_key') AND credentials IS NOT NULL
		`).all()
		const stmt = sqlite.prepare('UPDATE tokens SET credentials = ? WHERE id = ?')
		let changedCount = 0
		for (const row of rows) {
			const rawCreds = JSON.parse(row.credentials)
			if (!rawCreds || typeof rawCreds !== 'object') continue
			const creds = { ...rawCreds }
			if (fromVersion === 3) {
				for (const field of LEGACY_V3_SECRET_FIELDS) {
					const val = creds[field]
					if (val !== undefined && val !== null && val !== '') {
						creds[field] = decryptSecret(val, JSON.stringify([row.id, row.provider, row.type, field]), keys)
					}
				}
			}
			if (row.type === 'api_key' && 'apiKey' in creds) {
				const rawApiKey = creds.apiKey
				delete creds.apiKey
				Object.assign(creds, parseLegacyApiKey(rawApiKey))
			}
			stmt.run(JSON.stringify(encryptUpstreamCredentials(creds, row, keys)), row.id)
			changedCount++
		}
		sqlite.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`)
		sqlite.exec('COMMIT;')
		return changedCount > 0
	} catch (err) {
		sqlite.exec('ROLLBACK;')
		throw err
	}
}

function verifyAndRotateUpstreamEncryption (sqlite, keys) {
	const rows = sqlite.prepare(`
		SELECT id, provider, type, credentials
		FROM tokens
		WHERE provider != 'self' AND type IN ('oauth', 'api_key') AND credentials IS NOT NULL
	`).all()
	const updates = []
	for (const row of rows) {
		const creds = JSON.parse(row.credentials)
		if (!creds?.secret) continue
		const context = secretContext(row.id, row.provider, row.type)
		const { plaintext, keyIndex } = openSecret(creds.secret, context, keys)
		if (keyIndex > 0) {
			creds.secret = encryptSecret(plaintext, context, keys)
			updates.push({ id: row.id, credentials: JSON.stringify(creds) })
		}
	}
	if (updates.length === 0) return false
	sqlite.exec('BEGIN IMMEDIATE;')
	try {
		const stmt = sqlite.prepare('UPDATE tokens SET credentials = ? WHERE id = ?')
		for (const u of updates) {
			stmt.run(u.credentials, u.id)
		}
		sqlite.exec('COMMIT;')
	} catch (err) {
		sqlite.exec('ROLLBACK;')
		throw err
	}
	return true
}

function vacuumDatabase (sqlite) {
	if (sqlite.isTransaction) return
	const prevUmask = process.umask(0o077)
	try {
		sqlite.exec('VACUUM;')
		sqlite.exec('PRAGMA wal_checkpoint(TRUNCATE);')
	} finally {
		process.umask(prevUmask)
	}
}

function migrate (sqlite) {
	const version = sqlite.prepare('PRAGMA user_version').get()?.user_version || 0
	const dbList = sqlite.prepare('PRAGMA database_list').get()
	const dbPath = dbList && 'file' in dbList ? (dbList.file || ':memory:') : (process.env.DB_PATH || './data.db')
	const keys = loadKeys({ dbPath, encrypted: version >= ENCRYPTED_SCHEMA_VERSION })
	let dirty = version > 0 && version < SCHEMA_VERSION
	if (version < 1 && migrateUsersEmail(sqlite)) {
		dirty = true
	}
	if (version < 2 && migrateSelfTokenHashes(sqlite)) {
		dirty = true
	}
	if (version < 4) {
		if (migrateUpstreamSecrets(sqlite, keys, version)) dirty = true
	} else if (verifyAndRotateUpstreamEncryption(sqlite, keys)) {
		dirty = true
	}
	if (dirty) {
		vacuumDatabase(sqlite)
	}
}
