import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	create,
	get,
	getByIdentifier,
	listByUserId,
	remove,
	formatIdentity
}

function init () {
	sqlite.exec(`
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
	`)
}

function formatIdentity (row) {
	if (!row) return null
	let config = {}
	if (row.config) {
		try {
			config = JSON.parse(row.config)
		} catch {
			config = {}
		}
	}
	return {
		id: row.id,
		userId: row.user_id,
		provider: row.provider,
		identifier: row.identifier,
		verifiedAt: row.verified_at,
		config,
		created: row.created
	}
}

function create (opts = {}) {
	const {
		id = randomUUID(),
		userId,
		provider = 'email',
		identifier,
		verifiedAt = new Date().toISOString(),
		config = {}
	} = opts
	if (!userId || !identifier) return null
	const now = new Date().toISOString()
	const cleanIdentifier = provider === 'email' ? identifier.trim().toLowerCase() : identifier.trim()
	const configJson = typeof config === 'object' ? JSON.stringify(config) : config
	sqlite.prepare(`
		INSERT INTO user_identities (id, user_id, provider, identifier, verified_at, config, created)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, identifier) DO UPDATE SET
			user_id = excluded.user_id,
			verified_at = excluded.verified_at,
			config = excluded.config
	`).run(id, userId, provider, cleanIdentifier, verifiedAt, configJson, now)
	return get(id)
}

function get (id) {
	if (!id) return null
	const row = sqlite.prepare('SELECT * FROM user_identities WHERE id = ?').get(id)
	return formatIdentity(row)
}

function getByIdentifier (provider, identifier) {
	if (!provider || !identifier) return null
	const cleanIdentifier = provider === 'email' ? identifier.trim().toLowerCase() : identifier.trim()
	const row = sqlite.prepare('SELECT * FROM user_identities WHERE provider = ? AND identifier = ?').get(provider, cleanIdentifier)
	return formatIdentity(row)
}

function listByUserId (userId) {
	if (!userId) return []
	const rows = sqlite.prepare('SELECT * FROM user_identities WHERE user_id = ? ORDER BY created ASC').all(userId)
	return rows.map(formatIdentity)
}

function remove (id) {
	if (!id) return false
	const res = sqlite.prepare('DELETE FROM user_identities WHERE id = ?').run(id)
	return res.changes > 0
}
