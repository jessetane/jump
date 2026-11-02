import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	upsert,
	get,
	getByEmail,
	updateEmail,
	updateUser
}

function init () {
	sqlite.exec(`
		DROP TABLE IF EXISTS user_identities;
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			name TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	`)
}

function get (id) {
	if (!id) return null
	return sqlite.prepare('SELECT * FROM users WHERE id = ?').get(id) || null
}

function getByEmail (email) {
	if (!email) return null
	const normalizedEmail = email.trim().toLowerCase()
	return sqlite.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail) || null
}

function upsert (opts = {}) {
	const { id = randomUUID(), email, name = null } = opts
	const now = new Date().toISOString()
	const normalizedEmail = email.trim().toLowerCase()
	sqlite.prepare(`
		INSERT INTO users (id, email, name, created, updated)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET
			name = COALESCE(excluded.name, users.name),
			updated = excluded.updated
	`).run(id, normalizedEmail, name, now, now)
	return sqlite.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail)
}

function updateEmail (id, newEmail) {
	if (!id || !newEmail) return null
	const now = new Date().toISOString()
	const normalizedEmail = newEmail.trim().toLowerCase()
	sqlite.prepare('UPDATE users SET email = ?, updated = ? WHERE id = ?').run(normalizedEmail, now, id)
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
