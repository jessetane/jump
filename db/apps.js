import { randomUUID } from 'node:crypto'
import { sqlite, transaction } from './index.js'
import { loadKeys, secretContext, encryptSecret, openSecret, decryptSecret } from '../crypto.js'
import { serializePolicy } from '../policy.js'
import { isPlainObject } from '../util.js'

export {
	init,
	initKeys,
	format,
	create,
	get,
	listByUserId,
	update,
	remove
}

const CREATE_APPS_SQL = `
	CREATE TABLE IF NOT EXISTS apps (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		provider TEXT NOT NULL,
		type TEXT NOT NULL,
		name TEXT,
		account TEXT,
		base_url TEXT,
		credentials TEXT,
		scopes TEXT,
		expires_at INTEGER,
		policy TEXT,
		created TEXT NOT NULL,
		updated TEXT NOT NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_apps_user_provider ON apps(user_id, provider);
`

function serializeCredentials (credentials, { id, provider, type }) {
	if (!isPlainObject(credentials) || Object.keys(credentials).length === 0) return null
	return encryptSecret(JSON.stringify(credentials), secretContext(id, provider, type))
}

function decryptCredentials (secret, { id, provider, type }) {
	if (!secret) return null
	return JSON.parse(decryptSecret(secret, secretContext(id, provider, type)))
}

function format (row) {
	if (!row) return null
	return {
		id: row.id,
		userId: row.user_id,
		provider: row.provider,
		type: row.type,
		name: row.name,
		account: row.account || null,
		baseUrl: row.base_url || null,
		credentials: decryptCredentials(row.credentials, row),
		scopes: row.scopes || null,
		expiresAt: row.expires_at ?? null,
		policy: row.policy ?? null,
		created: row.created,
		updated: row.updated
	}
}

function vacuumDatabase (targetDb) {
	if (targetDb.isTransaction) return
	const prevUmask = process.umask(0o077)
	try {
		targetDb.exec('VACUUM;')
		targetDb.exec('PRAGMA wal_checkpoint(TRUNCATE);')
	} finally {
		process.umask(prevUmask)
	}
}

function initKeys (targetDb = sqlite) {
	const dbList = targetDb.prepare('PRAGMA database_list').get()
	const dbPath = dbList && 'file' in dbList ? (dbList.file || ':memory:') : (process.env.DB_PATH || './data.db')
	const rows = targetDb.prepare(`
		SELECT id, provider, type, credentials
		FROM apps
		WHERE credentials IS NOT NULL
	`).all()
	const keys = loadKeys({ dbPath, encrypted: rows.length > 0 })
	const updates = []
	for (const row of rows) {
		const context = secretContext(row.id, row.provider, row.type)
		const { plaintext, keyIndex } = openSecret(row.credentials, context, keys)
		if (keyIndex > 0) {
			updates.push({ id: row.id, credentials: encryptSecret(plaintext, context, keys) })
		}
	}
	if (updates.length === 0) return
	transaction(() => {
		const stmt = targetDb.prepare('UPDATE apps SET credentials = ? WHERE id = ?')
		for (const u of updates) {
			stmt.run(u.credentials, u.id)
		}
	}, targetDb)
	vacuumDatabase(targetDb)
}

function init () {
	sqlite.exec(CREATE_APPS_SQL)
	initKeys(sqlite)
}

function create (opts = {}) {
	const {
		id = randomUUID(),
		userId,
		provider,
		type,
		name = null,
		account = null,
		baseUrl = null,
		credentials = null,
		scopes = null,
		expiresAt = null,
		policy = null
	} = opts
	const encryptedCreds = serializeCredentials(credentials, { id, provider, type })
	const now = new Date().toISOString()
	sqlite.prepare(`
		INSERT INTO apps (id, user_id, provider, type, name, account, base_url, credentials, scopes, expires_at, policy, created, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`).run(id, userId, provider, type, name, account, baseUrl, encryptedCreds, scopes, expiresAt, serializePolicy(policy), now, now)
	return get(id)
}

function get (id) {
	if (!id) return null
	const row = sqlite.prepare('SELECT * FROM apps WHERE id = ?').get(id)
	return format(row)
}

function listByUserId (userId, opts = {}) {
	if (!userId) return []
	let query = 'SELECT * FROM apps WHERE user_id = ?'
	const params = [userId]
	if (opts.provider) {
		query += ' AND provider = ?'
		params.push(opts.provider)
	}
	query += ' ORDER BY created DESC, rowid DESC'
	return sqlite.prepare(query).all(...params).map(format)
}

function update (id, opts = {}) {
	const sets = []
	const params = []
	if (opts.credentials !== undefined) {
		const meta = opts.credentials ? sqlite.prepare('SELECT provider, type FROM apps WHERE id = ?').get(id) : null
		sets.push('credentials = ?')
		params.push(meta ? serializeCredentials(opts.credentials, { id, provider: meta.provider, type: meta.type }) : null)
	}
	if (opts.name !== undefined) {
		sets.push('name = ?')
		params.push(opts.name)
	}
	if (opts.account !== undefined) {
		sets.push('account = ?')
		params.push(opts.account)
	}
	if (opts.baseUrl !== undefined) {
		sets.push('base_url = ?')
		params.push(opts.baseUrl)
	}
	if (opts.expiresAt !== undefined) {
		sets.push('expires_at = ?')
		params.push(opts.expiresAt)
	}
	if (opts.scopes !== undefined) {
		sets.push('scopes = ?')
		params.push(opts.scopes)
	}
	if (opts.policy !== undefined) {
		sets.push('policy = ?')
		params.push(serializePolicy(opts.policy))
	}
	sets.push('updated = ?')
	params.push(new Date().toISOString(), id)
	sqlite.prepare(`UPDATE apps SET ${sets.join(', ')} WHERE id = ?`).run(...params)
	return get(id)
}

function remove (id) {
	if (!id) return false
	const res = sqlite.prepare('DELETE FROM apps WHERE id = ?').run(id)
	return res.changes > 0
}
