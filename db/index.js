import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import * as users from './users.js'
import * as logins from './logins.js'
import * as tokens from './tokens.js'
import * as links from './links.js'
import * as logs from './logs.js'
import { migrate as runMigrate } from './migrate.js'

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

function migrate () {
	runMigrate(sqlite)
}

function init () {
	users.init()
	logins.init()
	tokens.init()
	links.init()
	logs.init()
	migrate()
}

init()
tokens.pruneDormant()
logs.prune()

export {
	sqlite,
	init,
	migrate,
	users,
	logins,
	tokens,
	links,
	logs
}
