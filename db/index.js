import { DatabaseSync } from 'node:sqlite'
import fs from 'node:fs'
import { randomUUID } from 'node:crypto'
import * as users from './users.js'
import * as tokens from './tokens.js'
import * as links from './links.js'
import * as logs from './logs.js'
import { parseAccountSpec } from '../util.js'

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

function parseLegacyIdentifier (raw) {
	if (!raw || typeof raw !== 'string') return { provider: null, account: null }
	const trimmed = raw.trim().toLowerCase()
	if (!trimmed) return { provider: null, account: null }
	try {
		return parseAccountSpec(trimmed)
	} catch {
		return { provider: null, account: trimmed }
	}
}

function deleteTokenCascade (tokenId, replacementAppId = null) {
	if (replacementAppId && replacementAppId !== tokenId) {
		sqlite.prepare('UPDATE OR IGNORE links SET app_id = ? WHERE app_id = ?').run(replacementAppId, tokenId)
	}
	sqlite.prepare('DELETE FROM links WHERE app_id = ? OR session_id = ?').run(tokenId, tokenId)
	sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(tokenId)
}

function mergeUserIntoSurvivor (dupUserId, survivorId, dropUserIds) {
	if (dupUserId === survivorId) return
	const dupShares = sqlite.prepare("SELECT id, credentials FROM tokens WHERE user_id = ? AND type = 'share'").all(dupUserId)
	for (const ds of dupShares) {
		const dCreds = ds.credentials ? JSON.parse(ds.credentials) : {}
		const dAppId = dCreds.appId
		const survivorToken = dAppId ? sqlite.prepare(`
			SELECT id FROM tokens
			WHERE user_id = ? AND (id = ? OR (type = 'share' AND json_extract(credentials, '$.appId') = ?))
			ORDER BY CASE WHEN id = ? THEN 0 ELSE 1 END ASC
			LIMIT 1
		`).get(survivorId, dAppId, dAppId, dAppId) : null
		if (survivorToken) {
			deleteTokenCascade(ds.id, survivorToken.id)
		} else {
			sqlite.prepare('UPDATE tokens SET user_id = ? WHERE id = ?').run(survivorId, ds.id)
		}
	}
	const dupAuths = sqlite.prepare("SELECT id, token FROM tokens WHERE user_id = ? AND type = 'auth'").all(dupUserId)
	for (const da of dupAuths) {
		if (!da.token) {
			deleteTokenCascade(da.id)
			continue
		}
		const existingOnSurvivor = sqlite.prepare("SELECT 1 FROM tokens WHERE user_id = ? AND type = 'auth' AND token = ?").get(survivorId, da.token)
		if (existingOnSurvivor) {
			deleteTokenCascade(da.id)
		} else {
			sqlite.prepare('UPDATE tokens SET user_id = ? WHERE id = ?').run(survivorId, da.id)
		}
	}
	sqlite.prepare("UPDATE tokens SET user_id = ? WHERE user_id = ? AND type NOT IN ('share', 'auth')").run(survivorId, dupUserId)
	sqlite.prepare('UPDATE logs SET user_id = ? WHERE user_id = ?').run(survivorId, dupUserId)
	dropUserIds.add(dupUserId)
}

function migrate () {
	const cols = sqlite.prepare('PRAGMA table_info(users)').all()
	const hasEmail = cols.some(c => c.name === 'email')
	const hasAccount = cols.some(c => c.name === 'account')
	const hasName = cols.some(c => c.name === 'name')
	const hasLegacyUsers = hasEmail || hasAccount || hasName
	const unnormalizedAuthIds = sqlite.prepare(`
		SELECT id FROM tokens
		WHERE type = 'auth' AND (
			user_id IS NULL
			OR credentials IS NOT NULL
			OR name IS NULL
			OR TRIM(name) = ''
			OR provider != LOWER(TRIM(provider))
			OR name != LOWER(TRIM(name))
			OR token IS NULL
			OR token != LOWER(TRIM(provider)) || ':' || LOWER(TRIM(name))
		)
		ORDER BY created ASC, rowid ASC
	`).all()
	const hasLegacyClaimedShares = Boolean(sqlite.prepare(`
		SELECT 1 FROM tokens
		WHERE type = 'share' AND user_id IS NOT NULL
			AND (name IS NULL OR TRIM(name) = '' OR json_extract(credentials, '$.authProvider') IS NULL)
			AND EXISTS (SELECT 1 FROM tokens AS a WHERE a.user_id = tokens.user_id AND a.type = 'auth')
		LIMIT 1
	`).get())
	const hasClaimablePending = Boolean(sqlite.prepare(`
		SELECT 1
		FROM tokens AS a
		JOIN tokens AS p ON p.user_id IS NULL AND p.type = 'share' AND p.name = a.name
			AND (json_extract(p.credentials, '$.authProvider') IS NULL OR json_extract(p.credentials, '$.authProvider') = a.provider)
		WHERE a.type = 'auth' AND a.user_id IS NOT NULL
		LIMIT 1
	`).get())
	if (!hasLegacyUsers && unnormalizedAuthIds.length === 0 && !hasLegacyClaimedShares && !hasClaimablePending) return
	const accountCol = hasEmail ? 'email' : (hasAccount ? 'account' : null)
	const selectCols = accountCol
		? `id, ${accountCol} AS legacy_account, created, updated`
		: 'id, NULL AS legacy_account, created, updated'
	sqlite.exec('PRAGMA foreign_keys = OFF;')
	try {
		sqlite.exec('BEGIN;')
		try {
			const dropUserIds = new Set()
			for (const { id } of unnormalizedAuthIds) {
				const a = sqlite.prepare('SELECT id, user_id, provider, name, token, credentials FROM tokens WHERE id = ?').get(id)
				if (!a) continue
				let creds = null
				if (a.credentials) {
					try {
						creds = JSON.parse(a.credentials)
					} catch {
						creds = null
					}
				}
				const cleanProvider = typeof a.provider === 'string' ? a.provider.trim().toLowerCase() : ''
				const rawAccount = typeof a.name === 'string' && a.name.trim() ? a.name : (typeof creds?.account === 'string' ? creds.account : '')
				const cleanAccount = rawAccount.trim().toLowerCase()
				const userExists = a.user_id ? Boolean(sqlite.prepare('SELECT 1 FROM users WHERE id = ?').get(a.user_id)) : false
				if (!userExists || !cleanProvider || !cleanAccount) {
					deleteTokenCascade(a.id)
					continue
				}
				const authKey = `${cleanProvider}:${cleanAccount}`
				const collider = sqlite.prepare('SELECT id, user_id, type FROM tokens WHERE token = ? AND id != ?').get(authKey, a.id)
				if (collider) {
					if (collider.type !== 'auth') {
						deleteTokenCascade(collider.id)
						sqlite.prepare('UPDATE tokens SET provider = ?, name = ?, token = ?, credentials = NULL WHERE id = ?').run(cleanProvider, cleanAccount, authKey, a.id)
					} else if (collider.user_id === a.user_id) {
						deleteTokenCascade(a.id)
					} else if (!dropUserIds.has(collider.user_id)) {
						deleteTokenCascade(a.id)
						mergeUserIntoSurvivor(a.user_id, collider.user_id, dropUserIds)
					} else {
						deleteTokenCascade(collider.id)
						sqlite.prepare('UPDATE tokens SET provider = ?, name = ?, token = ?, credentials = NULL WHERE id = ?').run(cleanProvider, cleanAccount, authKey, a.id)
					}
				} else {
					sqlite.prepare('UPDATE tokens SET provider = ?, name = ?, token = ?, credentials = NULL WHERE id = ?').run(cleanProvider, cleanAccount, authKey, a.id)
				}
			}
			if (hasLegacyUsers) {
				const rows = sqlite.prepare(`SELECT ${selectCols} FROM users ORDER BY created ASC, rowid ASC`).all()
				for (const r of rows) {
					if (dropUserIds.has(r.id)) continue
					const hasAuth = Boolean(sqlite.prepare("SELECT 1 FROM tokens WHERE user_id = ? AND type = 'auth'").get(r.id))
					const hasNonShare = Boolean(sqlite.prepare("SELECT 1 FROM tokens WHERE user_id = ? AND type NOT IN ('share', 'oauth_state', 'oauth_code')").get(r.id))
					const hasShare = Boolean(sqlite.prepare("SELECT 1 FROM tokens WHERE user_id = ? AND type = 'share'").get(r.id))
					const hasUserLogs = Boolean(sqlite.prepare('SELECT 1 FROM logs WHERE user_id = ?').get(r.id))
					const { provider: parsedProvider, account: parsedAccount } = parseLegacyIdentifier(r.legacy_account)
					if (hasShare && !hasAuth && !hasNonShare && !hasUserLogs) {
						const shareRows = sqlite.prepare("SELECT id, credentials FROM tokens WHERE user_id = ? AND type = 'share' ORDER BY created ASC, rowid ASC").all(r.id)
						for (const s of shareRows) {
							if (!parsedAccount) {
								deleteTokenCascade(s.id)
								continue
							}
							const creds = s.credentials ? JSON.parse(s.credentials) : {}
							const appId = creds.appId || null
							const defaultStubProvider = !parsedAccount.includes('@') ? 'github' : null
							const authProvider = creds.authProvider || parsedProvider || defaultStubProvider
							if (!appId) {
								deleteTokenCascade(s.id)
								continue
							}
							const dupPending = authProvider
								? sqlite.prepare(`
									SELECT id FROM tokens
									WHERE id != ? AND user_id IS NULL AND type = 'share' AND name = ?
										AND json_extract(credentials, '$.appId') = ?
										AND json_extract(credentials, '$.authProvider') = ?
								`).get(s.id, parsedAccount, appId, authProvider)
								: sqlite.prepare(`
									SELECT id FROM tokens
									WHERE id != ? AND user_id IS NULL AND type = 'share' AND name = ?
										AND json_extract(credentials, '$.appId') = ?
										AND json_extract(credentials, '$.authProvider') IS NULL
								`).get(s.id, parsedAccount, appId)
							if (dupPending) {
								deleteTokenCascade(s.id, dupPending.id)
								continue
							}
							const nextCreds = {
								...creds,
								...(authProvider ? { authProvider } : {})
							}
							sqlite.prepare('UPDATE tokens SET user_id = NULL, name = ?, credentials = ? WHERE id = ?').run(
								parsedAccount,
								JSON.stringify(nextCreds),
								s.id
							)
						}
						const ephemeralRows = sqlite.prepare('SELECT id FROM tokens WHERE user_id = ?').all(r.id)
						for (const ep of ephemeralRows) {
							deleteTokenCascade(ep.id)
						}
						dropUserIds.add(r.id)
						continue
					}
					const fallbackProvider = parsedProvider || (parsedAccount?.includes('@') ? 'google' : (hasAccount && parsedAccount && parsedAccount !== 'localhost' ? 'github' : null))
					if (!hasAuth && parsedAccount && fallbackProvider) {
						const authProvider = fallbackProvider
						const authKey = `${authProvider}:${parsedAccount}`
						const existingAuth = sqlite.prepare("SELECT user_id FROM tokens WHERE type = 'auth' AND token = ?").get(authKey)
						if (existingAuth && existingAuth.user_id !== r.id && !dropUserIds.has(existingAuth.user_id)) {
							mergeUserIntoSurvivor(r.id, existingAuth.user_id, dropUserIds)
							continue
						}
						const now = new Date().toISOString()
						sqlite.prepare(`
							INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, created, updated)
							VALUES (?, ?, ?, 'auth', ?, ?, NULL, ?, ?)
						`).run(randomUUID(), r.id, authProvider, parsedAccount, authKey, now, now)
					}
				}
				sqlite.exec(`
					CREATE TEMP TABLE users_backup AS SELECT id, created, updated FROM users;
					DROP TABLE users;
					${users.CREATE_USERS_SQL}
					INSERT INTO users (id, created, updated) SELECT id, created, updated FROM users_backup;
					DROP TABLE users_backup;
				`)
			}
			for (const dropId of dropUserIds) {
				sqlite.prepare('DELETE FROM users WHERE id = ?').run(dropId)
			}
			const legacyClaimedShares = sqlite.prepare(`
				SELECT id, user_id, name, credentials FROM tokens
				WHERE type = 'share' AND user_id IS NOT NULL
					AND (name IS NULL OR TRIM(name) = '' OR json_extract(credentials, '$.authProvider') IS NULL)
			`).all()
			for (const cs of legacyClaimedShares) {
				const primaryAuth = sqlite.prepare(`
					SELECT provider, name FROM tokens
					WHERE user_id = ? AND type = 'auth'
					ORDER BY created ASC, rowid ASC
					LIMIT 1
				`).get(cs.user_id)
				if (!primaryAuth) continue
				const creds = cs.credentials ? JSON.parse(cs.credentials) : {}
				const nextName = (typeof cs.name === 'string' && cs.name.trim()) ? cs.name.trim().toLowerCase() : primaryAuth.name
				const nextCreds = {
					...creds,
					authProvider: creds.authProvider || primaryAuth.provider
				}
				sqlite.prepare('UPDATE tokens SET name = ?, credentials = ? WHERE id = ?').run(nextName, JSON.stringify(nextCreds), cs.id)
			}
			sqlite.exec("DELETE FROM links WHERE app_id IN (SELECT id FROM tokens WHERE user_id IS NULL AND type = 'share')")
			const matchingAuths = sqlite.prepare(`
				SELECT DISTINCT a.user_id, a.provider, a.name
				FROM tokens AS a
				JOIN tokens AS p ON p.user_id IS NULL AND p.type = 'share' AND p.name = a.name
					AND (json_extract(p.credentials, '$.authProvider') IS NULL OR json_extract(p.credentials, '$.authProvider') = a.provider)
				WHERE a.type = 'auth' AND a.user_id IS NOT NULL
				ORDER BY a.created ASC, a.rowid ASC
			`).all()
			for (const a of matchingAuths) {
				tokens.claimPendingShares({ userId: a.user_id, provider: a.provider, account: a.name })
			}
			sqlite.exec('COMMIT;')
		} catch (err) {
			sqlite.exec('ROLLBACK;')
			throw err
		}
	} finally {
		sqlite.exec('PRAGMA foreign_keys = ON;')
	}
}

function init () {
	users.init()
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
	tokens,
	links,
	logs
}
