import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	upsert,
	get,
	getByEmail,
	updateEmail,
	updateName
}

function init () {
	sqlite.exec(`
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
	return sqlite.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase()) || null
}

function upsert (opts = {}) {
	const { id = randomUUID(), email, name = null } = opts
	const now = new Date().toISOString()
	const normalizedEmail = email.toLowerCase()
	sqlite.prepare(`
		INSERT INTO users (id, email, name, created, updated)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET
			name = COALESCE(excluded.name, users.name),
			updated = excluded.updated
	`).run(id, normalizedEmail, name, now, now)
	return getByEmail(normalizedEmail)
}

function updateEmail (id, newEmail) {
	if (!id || !newEmail) return null
	const now = new Date().toISOString()
	const normalizedEmail = newEmail.trim().toLowerCase()
	sqlite.prepare('UPDATE users SET email = ?, updated = ? WHERE id = ?').run(normalizedEmail, now, id)
	return get(id)
}

function updateName (id, newName) {
	if (!id) return null
	const now = new Date().toISOString()
	sqlite.prepare('UPDATE users SET name = ?, updated = ? WHERE id = ?').run(newName, now, id)
	return get(id)
}
