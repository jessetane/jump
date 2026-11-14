import { randomUUID } from 'node:crypto'
import * as users from './users.js'
import * as logins from './logins.js'
import * as tokens from './tokens.js'
import { getProvider } from '../providers/index.js'
import { parseAccountSpec } from '../util.js'

export {
	migrate
}

const SCHEMA_VERSION = 1

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

function deleteTokenCascade (sqlite, tokenId, replacementAppId = null) {
	if (replacementAppId && replacementAppId !== tokenId) {
		sqlite.prepare('UPDATE OR IGNORE links SET app_id = ? WHERE app_id = ?').run(replacementAppId, tokenId)
	}
	sqlite.prepare('DELETE FROM links WHERE app_id = ? OR session_id = ?').run(tokenId, tokenId)
	sqlite.prepare('DELETE FROM tokens WHERE id = ?').run(tokenId)
}

function mergeUserIntoSurvivor (sqlite, dupUserId, survivorId, dropUserIds) {
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
			deleteTokenCascade(sqlite, ds.id, survivorToken.id)
		} else {
			sqlite.prepare('UPDATE tokens SET user_id = ? WHERE id = ?').run(survivorId, ds.id)
		}
	}
	const dupLogins = sqlite.prepare('SELECT id, provider, account FROM logins WHERE user_id = ?').all(dupUserId)
	for (const dl of dupLogins) {
		const existingOnSurvivor = sqlite.prepare('SELECT 1 FROM logins WHERE user_id = ? AND provider = ? AND account = ?').get(survivorId, dl.provider, dl.account)
		if (existingOnSurvivor) {
			sqlite.prepare('DELETE FROM logins WHERE id = ?').run(dl.id)
		} else {
			sqlite.prepare('UPDATE logins SET user_id = ? WHERE id = ?').run(survivorId, dl.id)
		}
	}
	sqlite.prepare("UPDATE tokens SET user_id = ? WHERE user_id = ? AND type != 'share'").run(survivorId, dupUserId)
	sqlite.prepare('UPDATE logs SET user_id = ? WHERE user_id = ?').run(survivorId, dupUserId)
	dropUserIds.add(dupUserId)
}

function migrate (sqlite) {
	const version = sqlite.prepare('PRAGMA user_version').get()?.user_version || 0
	if (version >= SCHEMA_VERSION) return
	const userCols = sqlite.prepare('PRAGMA table_info(users)').all()
	const hasEmail = userCols.some(c => c.name === 'email')
	const hasAccount = userCols.some(c => c.name === 'account')
	const hasName = userCols.some(c => c.name === 'name')
	const hasLegacyUsers = hasEmail || hasAccount || hasName
	const tokenCols = sqlite.prepare('PRAGMA table_info(tokens)').all()
	const userIdNotNull = tokenCols.some(c => c.name === 'user_id' && c.notnull === 1)
	const legacyTables = new Set(
		sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('token_links', 'oauth_states', 'oauth_codes')").all().map(r => r.name)
	)
	const hasAuthTokens = Boolean(sqlite.prepare("SELECT 1 FROM tokens WHERE type = 'auth' LIMIT 1").get())
	const hasLegacyClaimedShares = Boolean(sqlite.prepare(`
		SELECT 1 FROM tokens
		WHERE type = 'share' AND user_id IS NOT NULL
			AND (name IS NULL OR TRIM(name) = '' OR json_extract(credentials, '$.authProvider') IS NULL)
		LIMIT 1
	`).get())
	if (!hasLegacyUsers && !userIdNotNull && legacyTables.size === 0 && !hasAuthTokens && !hasLegacyClaimedShares) {
		sqlite.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`)
		return
	}
	const accountCol = hasEmail ? 'email' : (hasAccount ? 'account' : null)
	const selectCols = accountCol
		? `id, ${accountCol} AS legacy_account, created, updated`
		: 'id, NULL AS legacy_account, created, updated'
	sqlite.exec('PRAGMA foreign_keys = OFF;')
	try {
		sqlite.exec('BEGIN IMMEDIATE;')
		try {
			if (legacyTables.has('token_links')) {
				sqlite.exec(`
					INSERT OR IGNORE INTO links (session_id, app_id, policy, created, updated)
					SELECT session_token_id, app_token_id, policy, created, updated
					FROM token_links
					WHERE EXISTS (SELECT 1 FROM tokens WHERE id = token_links.session_token_id)
						AND EXISTS (SELECT 1 FROM tokens WHERE id = token_links.app_token_id);
					DROP TABLE token_links;
				`)
			}
			if (legacyTables.has('oauth_states')) sqlite.exec('DROP TABLE oauth_states;')
			if (legacyTables.has('oauth_codes')) sqlite.exec('DROP TABLE oauth_codes;')
			if (userIdNotNull) {
				const cols = 'id, user_id, provider, type, name, token, credentials, expires_at, scopes, admin, ip, ua, created, updated'
				sqlite.exec(`
					CREATE TEMP TABLE tokens_backup AS SELECT ${cols} FROM tokens;
					DROP TABLE tokens;
					${tokens.CREATE_TOKENS_SQL}
					INSERT INTO tokens (${cols}) SELECT ${cols} FROM tokens_backup;
					DROP TABLE tokens_backup;
				`)
			}
			const dropUserIds = new Set()
			const legacyAuthRows = sqlite.prepare("SELECT id, user_id, provider, name, credentials, created FROM tokens WHERE type = 'auth' ORDER BY created ASC, rowid ASC").all()
			for (const a of legacyAuthRows) {
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
				deleteTokenCascade(sqlite, a.id)
				if (!userExists || !cleanProvider || !cleanAccount) continue
				const collider = sqlite.prepare('SELECT id, user_id FROM logins WHERE provider = ? AND account = ?').get(cleanProvider, cleanAccount)
				if (collider) {
					if (collider.user_id !== a.user_id && !dropUserIds.has(collider.user_id)) {
						mergeUserIntoSurvivor(sqlite, a.user_id, collider.user_id, dropUserIds)
					} else if (dropUserIds.has(collider.user_id)) {
						sqlite.prepare('UPDATE logins SET user_id = ? WHERE id = ?').run(a.user_id, collider.id)
					}
				} else {
					sqlite.prepare('INSERT INTO logins (id, user_id, provider, account, created) VALUES (?, ?, ?, ?, ?)').run(
						a.id,
						a.user_id,
						cleanProvider,
						cleanAccount,
						a.created || new Date().toISOString()
					)
				}
			}
			if (hasLegacyUsers) {
				const rows = sqlite.prepare(`SELECT ${selectCols} FROM users ORDER BY created ASC, rowid ASC`).all()
				for (const r of rows) {
					if (dropUserIds.has(r.id)) continue
					const hasLogin = Boolean(sqlite.prepare('SELECT 1 FROM logins WHERE user_id = ?').get(r.id))
					const hasNonShare = Boolean(sqlite.prepare("SELECT 1 FROM tokens WHERE user_id = ? AND type NOT IN ('share', 'oauth_state', 'oauth_code')").get(r.id))
					const hasShare = Boolean(sqlite.prepare("SELECT 1 FROM tokens WHERE user_id = ? AND type = 'share'").get(r.id))
					const hasUserLogs = Boolean(sqlite.prepare('SELECT 1 FROM logs WHERE user_id = ?').get(r.id))
					const { provider: parsedProvider, account: parsedAccount } = parseLegacyIdentifier(r.legacy_account)
					if (hasShare && !hasLogin && !hasNonShare && !hasUserLogs) {
						const shareRows = sqlite.prepare("SELECT id, credentials FROM tokens WHERE user_id = ? AND type = 'share' ORDER BY created ASC, rowid ASC").all(r.id)
						for (const s of shareRows) {
							if (!parsedAccount) {
								deleteTokenCascade(sqlite, s.id)
								continue
							}
							const creds = s.credentials ? JSON.parse(s.credentials) : {}
							const appId = creds.appId || null
							const defaultStubProvider = !parsedAccount.includes('@') ? 'github' : null
							const authProvider = creds.authProvider || parsedProvider || defaultStubProvider
							if (!appId) {
								deleteTokenCascade(sqlite, s.id)
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
								deleteTokenCascade(sqlite, s.id, dupPending.id)
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
							deleteTokenCascade(sqlite, ep.id)
						}
						dropUserIds.add(r.id)
						continue
					}
					const fallbackProvider = parsedProvider || (parsedAccount?.includes('@') ? 'google' : (hasAccount && parsedAccount && parsedAccount !== 'localhost' ? 'github' : null))
					if (!hasLogin && parsedAccount && fallbackProvider) {
						const existingLogin = sqlite.prepare('SELECT user_id FROM logins WHERE provider = ? AND account = ?').get(fallbackProvider, parsedAccount)
						if (existingLogin && existingLogin.user_id !== r.id && !dropUserIds.has(existingLogin.user_id)) {
							mergeUserIntoSurvivor(sqlite, r.id, existingLogin.user_id, dropUserIds)
							continue
						}
						sqlite.prepare('INSERT INTO logins (id, user_id, provider, account, created) VALUES (?, ?, ?, ?, ?)').run(
							randomUUID(),
							r.id,
							fallbackProvider,
							parsedAccount,
							r.created || new Date().toISOString()
						)
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
				const primaryLogin = sqlite.prepare(`
					SELECT provider, account FROM logins
					WHERE user_id = ?
					ORDER BY created ASC, rowid ASC
					LIMIT 1
				`).get(cs.user_id)
				if (!primaryLogin) continue
				const creds = cs.credentials ? JSON.parse(cs.credentials) : {}
				const nextName = (typeof cs.name === 'string' && cs.name.trim()) ? cs.name.trim().toLowerCase() : primaryLogin.account
				const nextCreds = {
					...creds,
					authProvider: creds.authProvider || primaryLogin.provider
				}
				sqlite.prepare('UPDATE tokens SET name = ?, credentials = ? WHERE id = ?').run(nextName, JSON.stringify(nextCreds), cs.id)
			}
			sqlite.exec("DELETE FROM links WHERE app_id IN (SELECT id FROM tokens WHERE user_id IS NULL AND type = 'share')")
			const matchingLogins = sqlite.prepare(`
				SELECT DISTINCT l.user_id, l.provider, l.account
				FROM logins AS l
				JOIN tokens AS p ON p.user_id IS NULL AND p.type = 'share' AND p.name = l.account
					AND (json_extract(p.credentials, '$.authProvider') IS NULL OR json_extract(p.credentials, '$.authProvider') = l.provider)
				ORDER BY l.created ASC, l.rowid ASC
			`).all()
			for (const l of matchingLogins) {
				const allowUnscoped = Boolean(getProvider(l.provider)?.verifiedEmail)
				tokens.claimPendingShares({ userId: l.user_id, provider: l.provider, account: l.account, allowUnscoped })
			}
			sqlite.exec(`PRAGMA user_version = ${SCHEMA_VERSION};`)
			sqlite.exec('COMMIT;')
		} catch (err) {
			sqlite.exec('ROLLBACK;')
			throw err
		}
	} finally {
		sqlite.exec('PRAGMA foreign_keys = ON;')
	}
}
