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
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			name TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
		CREATE TABLE IF NOT EXISTS user_identities (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			identifier TEXT NOT NULL,
			verified_at TEXT NOT NULL,
			config TEXT DEFAULT '{}',
			created TEXT NOT NULL,
			UNIQUE(provider, identifier),
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_identities_provider_identifier ON user_identities(provider, identifier);
		INSERT OR IGNORE INTO user_identities (id, user_id, provider, identifier, verified_at, config, created)
		SELECT lower(hex(randomblob(16))), id, 'email', lower(email), created, '{}', created
		FROM users
		WHERE email IS NOT NULL AND trim(email) != '';
	`)
}

function get (id) {
	if (!id) return null
	return sqlite.prepare('SELECT * FROM users WHERE id = ?').get(id) || null
}

function getByEmail (email) {
	if (!email) return null
	const normalizedEmail = email.toLowerCase()
	const identity = sqlite.prepare("SELECT user_id FROM user_identities WHERE provider = 'email' AND identifier = ?").get(normalizedEmail)
	if (identity) {
		return get(identity.user_id)
	}
	return sqlite.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail) || null
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
	const user = sqlite.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail)
	if (user) {
		sqlite.prepare(`
			INSERT INTO user_identities (id, user_id, provider, identifier, verified_at, config, created)
			VALUES (?, ?, 'email', ?, ?, '{}', ?)
			ON CONFLICT(provider, identifier) DO UPDATE SET
				user_id = excluded.user_id,
				verified_at = excluded.verified_at
		`).run(randomUUID(), user.id, normalizedEmail, now, now)
	}
	return user
}

function updateEmail (id, newEmail) {
	if (!id || !newEmail) return null
	const now = new Date().toISOString()
	const normalizedEmail = newEmail.trim().toLowerCase()
	const oldUser = get(id)
	sqlite.prepare('UPDATE users SET email = ?, updated = ? WHERE id = ?').run(normalizedEmail, now, id)
	if (oldUser && oldUser.email) {
		sqlite.prepare("DELETE FROM user_identities WHERE user_id = ? AND provider = 'email' AND identifier = ?").run(id, oldUser.email.toLowerCase())
	}
	sqlite.prepare(`
		INSERT INTO user_identities (id, user_id, provider, identifier, verified_at, config, created)
		VALUES (?, ?, 'email', ?, ?, '{}', ?)
		ON CONFLICT(provider, identifier) DO UPDATE SET
			user_id = excluded.user_id,
			verified_at = excluded.verified_at
	`).run(randomUUID(), id, normalizedEmail, now, now)
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
