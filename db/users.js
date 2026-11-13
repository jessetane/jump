import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	create,
	get,
	CREATE_USERS_SQL
}

const CREATE_USERS_SQL = `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		created TEXT NOT NULL,
		updated TEXT NOT NULL
	);
`

function init () {
	sqlite.exec(CREATE_USERS_SQL)
}

function get (id) {
	if (!id) return null
	return sqlite.prepare('SELECT * FROM users WHERE id = ?').get(id) || null
}

function create (opts = {}) {
	const { id = randomUUID() } = opts
	const now = new Date().toISOString()
	sqlite.prepare(`
		INSERT INTO users (id, created, updated)
		VALUES (?, ?, ?)
	`).run(id, now, now)
	return get(id)
}
