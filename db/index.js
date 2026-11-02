import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import * as users from './users.js'
import * as tokens from './tokens.js'
import * as links from './links.js'

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

users.init()
tokens.init()
links.init()
tokens.pruneDormant()

export {
	sqlite,
	users,
	tokens,
	links
}
