import { sqlite } from './index.js'
import { randomUUID } from 'node:crypto'

export {
	init,
	create,
	get,
	userAccountSql
}

function userAccountSql (userIdExpr) {
	return `COALESCE((SELECT l.account FROM logins AS l WHERE l.user_id = ${userIdExpr} ORDER BY l.created ASC, l.rowid ASC LIMIT 1), 'localhost')`
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
