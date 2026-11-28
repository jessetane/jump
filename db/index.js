import { DatabaseSync } from 'node:sqlite'
import { tightenFileMode } from '../util.js'
import * as users from './users.js'
import * as logins from './logins.js'
import * as apps from './apps.js'
import * as sessions from './sessions.js'
import * as shares from './shares.js'
import * as links from './links.js'
import * as states from './states.js'
import * as logs from './logs.js'

const dbPath = process.env.DB_PATH || './data.db'
const PRUNE_INTERVAL_MS = 15 * 60 * 1000

function prune () {
	sessions.prune()
	states.prune()
	logs.prune()
}

function transaction (fn, targetDb = sqlite) {
	if (targetDb.isTransaction) return fn()
	targetDb.exec('BEGIN IMMEDIATE;')
	try {
		const result = fn()
		targetDb.exec('COMMIT;')
		return result
	} catch (err) {
		try {
			targetDb.exec('ROLLBACK;')
		} catch {}
		throw err
	}
}

function init () {
	users.init()
	logins.init()
	apps.init()
	sessions.init()
	shares.init()
	links.init()
	states.init()
	logs.init()
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
	prune,
	transaction,
	users,
	logins,
	apps,
	sessions,
	shares,
	links,
	states,
	logs
}
