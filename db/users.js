import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

let migratedLegacyEmail = false

export {
	init,
	consumeLegacyEmailMigration,
	upsert,
	get,
	getByAccount,
	updateAccount,
	updateUser
}

function consumeLegacyEmailMigration () {
	const val = migratedLegacyEmail
	migratedLegacyEmail = false
	return val
}

function init () {
	const cols = sqlite.prepare('PRAGMA table_info(users)').all()
	if (cols.some(c => c.name === 'email') && !cols.some(c => c.name === 'account')) {
		sqlite.exec(`
			DROP INDEX IF EXISTS idx_users_email;
			ALTER TABLE users RENAME COLUMN email TO account;
		`)
		migratedLegacyEmail = true
	}
	sqlite.exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			account TEXT UNIQUE NOT NULL,
			name TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_users_account ON users(account);
	`)
}

function get (id) {
	if (!id) return null
	return sqlite.prepare('SELECT * FROM users WHERE id = ?').get(id) || null
}

function getByAccount (account) {
	if (!account) return null
	const normalizedAccount = String(account).trim().toLowerCase()
	return sqlite.prepare('SELECT * FROM users WHERE account = ?').get(normalizedAccount) || null
}

function upsert (opts = {}) {
	const { id = randomUUID(), account, name = null } = opts
	const now = new Date().toISOString()
	const normalizedAccount = String(account).trim().toLowerCase()
	sqlite.prepare(`
		INSERT INTO users (id, account, name, created, updated)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(account) DO UPDATE SET
			name = COALESCE(excluded.name, users.name),
			updated = excluded.updated
	`).run(id, normalizedAccount, name, now, now)
	return sqlite.prepare('SELECT * FROM users WHERE account = ?').get(normalizedAccount)
}

function updateAccount (id, newAccount) {
	if (!id || !newAccount) return null
	const now = new Date().toISOString()
	const normalizedAccount = String(newAccount).trim().toLowerCase()
	sqlite.prepare('UPDATE users SET account = ?, updated = ? WHERE id = ?').run(normalizedAccount, now, id)
	return get(id)
}

function updateUser (id, updates = {}) {
	if (!id || typeof updates !== 'object') return null
	const allowed = ['name']
	const sets = []
	const params = []
	for (const key of allowed) {
		if (key in updates) {
			sets.push(`${key} = ?`)
			params.push(updates[key] ? String(updates[key]).trim() : null)
		}
	}
	if (sets.length === 0) return get(id)
	const now = new Date().toISOString()
	sets.push('updated = ?')
	params.push(now)
	params.push(id)
	sqlite.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...params)
	return get(id)
}
