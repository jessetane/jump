import { DatabaseSync } from 'node:sqlite'
import { tightenFileMode } from '../util.js'
import * as users from './users.js'
import * as logins from './logins.js'
import * as tokens from './tokens.js'
import * as links from './links.js'
import * as logs from './logs.js'
import { migrate as runMigrate } from './migrate.js'

const dbPath = process.env.DB_PATH || './data.db'
const PRUNE_INTERVAL_MS = 15 * 60 * 1000

function migrate () {
	runMigrate(sqlite)
}

function prune () {
	tokens.prune()
	logs.prune()
}

function init () {
	users.init()
	logins.init()
	tokens.init()
	links.init()
	logs.init()
	migrate()
}

const prevUmask = process.umask(0o077)
let sqlite
try {
	if (dbPath !== ':memory:') tightenFileMode(dbPath)
	sqlite = new DatabaseSync(dbPath)
	sqlite.exec('PRAGMA journal_mode = WAL;')
	sqlite.exec('PRAGMA secure_delete = ON;')
	sqlite.exec('PRAGMA foreign_keys = ON;')
	sqlite.exec('PRAGMA recursive_triggers = ON;')
	sqlite.exec('PRAGMA busy_timeout = 5000;')
	init()
	if (dbPath !== ':memory:') {
		for (const ext of ['', '-wal', '-shm']) {
			tightenFileMode(`${dbPath}${ext}`)
		}
	}
} finally {
	process.umask(prevUmask)
}

prune()
setInterval(prune, PRUNE_INTERVAL_MS).unref()

export {
	sqlite,
	init,
	migrate,
	prune,
	users,
	logins,
	tokens,
	links,
	logs
}
