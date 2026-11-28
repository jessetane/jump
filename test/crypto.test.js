import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { Worker } from 'node:worker_threads'
import { useServer, testDbPath, createTestSession, withEnv, mcp, req, db, utilMod, cryptoMod } from './helpers.js'

useServer()

const TOKEN_DDL = `
	CREATE TABLE tokens (
		id TEXT PRIMARY KEY,
		user_id TEXT,
		provider TEXT NOT NULL,
		type TEXT NOT NULL,
		name TEXT,
		token TEXT UNIQUE,
		credentials TEXT,
		expires_at INTEGER,
		scopes TEXT,
		admin INTEGER DEFAULT 0,
		ip TEXT,
		ua TEXT,
		created TEXT NOT NULL,
		updated TEXT NOT NULL
	);
`

test('key validation rejects malformed, hex, padded, non-canonical, or duplicate keys', () => {
	assert.throws(() => cryptoMod.parseKey('short'), /43 chars/)
	assert.throws(() => cryptoMod.parseKey(randomBytes(32).toString('hex')), /43 chars/)
	assert.throws(() => cryptoMod.parseKey(randomBytes(32).toString('base64')), /43 chars/)
	assert.throws(() => cryptoMod.parseKey(`${'A'.repeat(42)}B`), /canonical 32-byte base64url/)
	const k1 = cryptoMod.generateKey()
	assert.throws(() => cryptoMod.parseKeyList(`${k1},`), /empty key entry/)
	assert.throws(() => cryptoMod.parseKeyList(`${k1},${k1}`), /duplicate encryption key/)
})

test('encryption at rest uses AES-256-GCM with per-write salt and strict AAD context binding', () => {
	assert.equal(db.sqlite.prepare('PRAGMA secure_delete').get().secure_delete, 1)
	assert.equal(fs.existsSync(`${testDbPath}.key`), true)
	assert.equal(fs.statSync(`${testDbPath}.key`).mode & 0o777, 0o600)
	const { user, session } = createTestSession({ account: 'crypto-owner@example.com', admin: true })
	const stripeApp = db.tokens.create({
		userId: user.id,
		provider: 'stripe',
		type: 'static',
		name: 'Canary Stripe',
		credentials: {
			headers: { authorization: 'Bearer sk_live_CANARY_112233' },
			query: { apiKey: 'qp_CANARY_998877' },
			baseUrl: 'https://api.stripe.com',
			account: 'acct_canary'
		}
	})
	const futureApp = db.tokens.create({
		userId: user.id,
		provider: 'future',
		type: 'oauth',
		credentials: { accessToken: 'tok_1', customSecret: 'fail_closed_canary', account: 'future@example.com' }
	})
	const rawStripe = JSON.parse(db.sqlite.prepare('SELECT credentials FROM tokens WHERE id = ?').get(stripeApp.id).credentials)
	assert.deepEqual(Object.keys(rawStripe).sort(), ['account', 'baseUrl', 'secret'])
	assert.match(rawStripe.secret, /^[A-Za-z0-9_-]{22}:[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{22}:[A-Za-z0-9_-]+$/)
	assert.equal(rawStripe.baseUrl, 'https://api.stripe.com')
	assert.equal(rawStripe.account, 'acct_canary')
	const rawFuture = JSON.parse(db.sqlite.prepare('SELECT credentials FROM tokens WHERE id = ?').get(futureApp.id).credentials)
	assert.deepEqual(Object.keys(rawFuture).sort(), ['account', 'secret'], 'Unlisted credential fields are encrypted inside secret envelope')
	assert.equal(db.tokens.get(futureApp.id).credentials.customSecret, 'fail_closed_canary')
	db.links.create({ sessionId: session.id, appId: stripeApp.id })
	assert.deepEqual(db.links.get(session.id, stripeApp.id).app.credentials.headers, { authorization: 'Bearer sk_live_CANARY_112233' })
	assert.deepEqual(db.links.get(session.id, stripeApp.id).app.credentials.query, { apiKey: 'qp_CANARY_998877' })
	db.sqlite.exec('PRAGMA wal_checkpoint(FULL);')
	const dbBytes = fs.readFileSync(testDbPath)
	assert.equal(dbBytes.includes('sk_live_CANARY_112233'), false)
	assert.equal(dbBytes.includes('qp_CANARY_998877'), false)
	assert.equal(dbBytes.includes('fail_closed_canary'), false)
	const dupApp = db.tokens.create({
		userId: user.id,
		provider: 'stripe',
		type: 'static',
		credentials: { headers: { authorization: 'Bearer sk_live_CANARY_112233' }, baseUrl: 'https://api.stripe.com' }
	})
	const ctA = rawStripe.secret
	const ctB = JSON.parse(db.sqlite.prepare('SELECT credentials FROM tokens WHERE id = ?').get(dupApp.id).credentials).secret
	assert.notEqual(ctA, ctB, 'Identical plaintext must produce distinct ciphertexts')
	assert.throws(() => cryptoMod.decryptSecret(ctA, cryptoMod.secretContext(dupApp.id, 'stripe', 'static')), /unable to authenticate/i)
	assert.throws(() => cryptoMod.decryptSecret(ctA, cryptoMod.secretContext(stripeApp.id, 'github', 'static')), /unable to authenticate/i)
	assert.throws(() => cryptoMod.decryptSecret(ctA, cryptoMod.secretContext(stripeApp.id, 'stripe', 'oauth')), /unable to authenticate/i)
	assert.notEqual(cryptoMod.secretContext('a:b', 'c', 'static'), cryptoMod.secretContext('a', 'b:c', 'static'))
	const parts = ctA.split(':')
	assert.throws(() => cryptoMod.decryptSecret(`${parts[0]}:${parts[1]}:${parts[2].slice(0, 8)}:${parts[3]}`, cryptoMod.secretContext(stripeApp.id, 'stripe', 'static')), /Malformed encrypted credential parameters/)
	assert.throws(() => cryptoMod.decryptSecret('bad-envelope', cryptoMod.secretContext(stripeApp.id, 'stripe', 'static')), /Malformed encrypted credential envelope/)
	assert.throws(() => cryptoMod.decryptSecret(`${parts[0]}:${parts[1]}:${parts[2]}:`, cryptoMod.secretContext(stripeApp.id, 'stripe', 'static')), /Malformed encrypted credential parameters/)
	assert.throws(() => cryptoMod.encryptSecret('', cryptoMod.secretContext('x', 'stripe', 'static')), /non-empty string plaintext/)
})

test('session tokens, refresh tokens, and ephemeral oauth codes/states are hashed at rest and masked on read', async () => {
	const { session, app } = createTestSession({ account: 'hash-check@example.com', admin: true })
	assert.match(db.tokens.hashSecret(session.token), /^[0-9a-f]{64}$/)
	const rawSession = db.sqlite.prepare('SELECT token FROM tokens WHERE id = ?').get(session.id)
	assert.equal(rawSession.token, db.tokens.hashSecret(session.token))
	assert.equal(db.tokens.get(session.id).token, null, 'Read back session must never expose token hash')
	assert.equal(db.tokens.getByToken(rawSession.token), null, 'Database hash stolen from SQLite must never authenticate')
	const selfWithRefresh = db.tokens.create({ userId: session.userId, provider: 'self', credentials: { refreshToken: 'rt-init' } })
	const updSelf = db.tokens.updateCredentials(selfWithRefresh.id, { credentials: { refreshToken: 'rt-rotated' } })
	assert.equal(updSelf.credentials.refreshToken, 'rt-rotated')
	const rawCreds = JSON.parse(db.sqlite.prepare('SELECT credentials FROM tokens WHERE id = ?').get(selfWithRefresh.id).credentials)
	assert.equal(rawCreds.refreshToken, db.tokens.hashSecret('rt-rotated'))
	assert.equal(db.tokens.refreshOauthSession(rawCreds.refreshToken), null, 'Refresh hash stolen from SQLite must never refresh')
	const state = db.tokens.createState({ mode: 'setup_connect', provider: 'google', sessionId: session.id })
	assert.equal(db.sqlite.prepare('SELECT 1 FROM tokens WHERE id = ? OR token = ?').get(state, state), undefined)
	const stateRow = db.sqlite.prepare('SELECT id FROM tokens WHERE token = ?').get(db.tokens.hashSecret(state))
	assert.equal(db.tokens.get(stateRow.id).token, null)
	const listed = JSON.parse((await mcp(session.token, 'admin', { action: 'list_apps' })).content[0].text).apps
	const whoami = JSON.parse((await mcp(session.token, 'admin', { action: 'whoami' })).content[0].text).session.apps
	for (const entry of [listed.find(a => a.id === app.id), whoami.find(a => a.id === app.id)]) {
		assert.equal(entry.headers, undefined)
		assert.equal(entry.query, undefined)
		assert.equal(entry.credentials, undefined)
	}
	const tamperApp = db.tokens.create({ userId: session.userId, provider: 'stripe', type: 'static', credentials: { bearer: 'sk_tamper' } })
	const rawSecret = JSON.parse(db.sqlite.prepare('SELECT credentials FROM tokens WHERE id = ?').get(tamperApp.id).credentials)
	const parts = rawSecret.secret.split(':')
	parts[3] = `${parts[3][0] === 'A' ? 'B' : 'A'}${parts[3].slice(1)}`
	db.sqlite.prepare('UPDATE tokens SET credentials = ? WHERE id = ?').run(JSON.stringify({ secret: parts.join(':') }), tamperApp.id)
	assert.throws(() => db.tokens.get(tamperApp.id), /unable to authenticate/i)
	db.tokens.remove(tamperApp.id)
})

test('encryption key sources, rotation across restarts, and VACUUM scrubbing of old ciphertext', async () => {
	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jump-crypto-rot-'))
	const k1 = cryptoMod.generateKey()
	const k2 = cryptoMod.generateKey()
	try {
		const diyPath = path.join(tmpDir, 'diy.db')
		const diyDb = new DatabaseSync(diyPath)
		try {
			diyDb.exec('PRAGMA journal_mode = WAL; PRAGMA secure_delete = ON;')
			diyDb.exec(TOKEN_DDL)
			await withEnv({ ENCRYPTION_KEY: '', CREDENTIALS_DIRECTORY: undefined }, () => {
				db.tokens.initKeys(diyDb)
				assert.equal(fs.existsSync(`${diyPath}.key`), true)
				fs.chmodSync(`${diyPath}.key`, 0o644)
				db.tokens.initKeys(diyDb)
				assert.equal(fs.statSync(`${diyPath}.key`).mode & 0o777, 0o600, 'initKeys tightens permissive .key permissions')
				const ctOld = cryptoMod.encryptSecret(JSON.stringify({ headers: { authorization: 'Bearer sk_diy_rot' } }), cryptoMod.secretContext('app-1', 'stripe', 'static'))
				const now = new Date().toISOString()
				diyDb.prepare("INSERT INTO tokens (id, provider, type, credentials, created, updated) VALUES ('app-1', 'stripe', 'static', ?, ?, ?)").run(JSON.stringify({ secret: ctOld }), now, now)
				diyDb.exec('PRAGMA wal_checkpoint(FULL);')
				assert.equal(fs.readFileSync(diyPath).includes(ctOld), true)
				fs.renameSync(`${diyPath}.key`, `${diyPath}.key.old`)
				fs.writeFileSync(`${diyPath}.key`, `${k2}\n`, { mode: 0o600 })
				db.tokens.initKeys(diyDb)
				diyDb.exec('PRAGMA wal_checkpoint(FULL);')
				for (const f of [diyPath, `${diyPath}-wal`].filter(p => fs.existsSync(p))) {
					assert.equal(fs.readFileSync(f).includes(ctOld), false, `VACUUM must scrub old ciphertext from ${f}`)
				}
			})
		} finally {
			diyDb.close()
		}
		const credDir = path.join(tmpDir, 'systemd-creds')
		fs.mkdirSync(credDir, { mode: 0o700 })
		const tpmDbPath = path.join(tmpDir, 'tpm.db')
		const tpmDb = new DatabaseSync(tpmDbPath)
		try {
			tpmDb.exec('PRAGMA journal_mode = WAL; PRAGMA secure_delete = ON;')
			tpmDb.exec(TOKEN_DDL)
			const credFile = `${utilMod.APP_NAME}.key`
			const oldCredFile = `${utilMod.APP_NAME}.key.old`
			await withEnv({ CREDENTIALS_DIRECTORY: credDir, ENCRYPTION_KEY: undefined }, () => {
				assert.throws(() => db.tokens.initKeys(tpmDb), /Missing systemd credential/)
				assert.equal(fs.existsSync(`${tpmDbPath}.key`), false)
				fs.writeFileSync(path.join(credDir, credFile), `${k1}\n`, { mode: 0o600 })
				db.tokens.initKeys(tpmDb)
				assert.equal(fs.existsSync(`${tpmDbPath}.key`), false)
				const ctx = cryptoMod.secretContext('tpm-1', 'stripe', 'static')
				const now = new Date().toISOString()
				tpmDb.prepare("INSERT INTO tokens (id, provider, type, credentials, created, updated) VALUES ('tpm-1', 'stripe', 'static', ?, ?, ?)").run(
					JSON.stringify({ secret: cryptoMod.encryptSecret(JSON.stringify({ headers: { authorization: 'Bearer sk_tpm' } }), ctx) }),
					now,
					now
				)
				fs.renameSync(path.join(credDir, credFile), path.join(credDir, oldCredFile))
				fs.writeFileSync(path.join(credDir, credFile), `${k2}\n`, { mode: 0o600 })
				db.tokens.initKeys(tpmDb)
				fs.rmSync(path.join(credDir, oldCredFile))
				db.tokens.initKeys(tpmDb)
				const ctNew = JSON.parse(tpmDb.prepare("SELECT credentials FROM tokens WHERE id = 'tpm-1'").get().credentials).secret
				assert.deepEqual(JSON.parse(cryptoMod.decryptSecret(ctNew, ctx)), { headers: { authorization: 'Bearer sk_tpm' } })
				fs.writeFileSync(path.join(credDir, credFile), `${k1}\n`, { mode: 0o600 })
				assert.throws(() => db.tokens.initKeys(tpmDb), /unable to authenticate/i)
			})
		} finally {
			tpmDb.close()
		}
		const memDb = new DatabaseSync(':memory:')
		try {
			memDb.exec(TOKEN_DDL)
			await withEnv({ CREDENTIALS_DIRECTORY: undefined, ENCRYPTION_KEY: undefined }, () => {
				db.tokens.initKeys(memDb)
				assert.equal(fs.existsSync(':memory:.key'), false)
				const now = new Date().toISOString()
				memDb.prepare("INSERT INTO tokens (id, provider, type, credentials, created, updated) VALUES ('m1', 'google', 'oauth', ?, ?, ?)").run(
					JSON.stringify({ secret: cryptoMod.encryptSecret(JSON.stringify({ accessToken: 'tok' }), cryptoMod.secretContext('m1', 'google', 'oauth')) }),
					now,
					now
				)
				assert.throws(() => db.tokens.initKeys(memDb), /Missing encryption key for encrypted in-memory database/)
			})
		} finally {
			memDb.close()
		}
		cryptoMod.loadKeys({ dbPath: testDbPath, encrypted: true })
		const { user } = createTestSession({ account: 'env-rot@example.com' })
		const envApp = db.tokens.create({
			userId: user.id,
			provider: 'stripe',
			type: 'static',
			credentials: { headers: { authorization: 'Bearer sk_env_rot_canary' }, baseUrl: 'https://api.stripe.com' }
		})
		const sharedKey = fs.readFileSync(`${testDbPath}.key`, 'utf8').trim()
		await withEnv({ CREDENTIALS_DIRECTORY: undefined, ENCRYPTION_KEY: `${k2},${sharedKey}` }, () => {
			db.init()
			process.env.ENCRYPTION_KEY = k2
			db.init()
			assert.deepEqual(db.tokens.get(envApp.id).credentials.headers, { authorization: 'Bearer sk_env_rot_canary' })
			process.env.ENCRYPTION_KEY = `${sharedKey},${k2}`
			db.init()
		})
	} finally {
		cryptoMod.loadKeys({ dbPath: testDbPath, encrypted: true })
		fs.rmSync(tmpDir, { recursive: true, force: true })
	}
})

test('stdout access and mcp logs omit query strings, credentials, and request bodies', async () => {
	const { session } = createTestSession({ account: 'log-redaction@example.com', admin: true })
	const origLog = console.log
	const lines = []
	console.log = (...args) => lines.push(args.map(String).join(' '))
	try {
		await req('GET', '/?secret=leak_me_123')
		await req('POST', '/mcp', {
			token: session.token,
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'admin', arguments: { action: 'whoami', credentials: 'sk_live_secret', body: 'private_email_body' } }
			}
		})
	} finally {
		console.log = origLog
	}
	const joined = lines.join('\n')
	assert.match(joined, /\[200\] GET \/ \(/)
	assert.match(joined, /\[mcp\] tools\/call: name=admin action=whoami/)
	assert.equal(joined.includes('leak_me_123'), false)
	assert.equal(joined.includes('sk_live_secret'), false)
	assert.equal(joined.includes('private_email_body'), false)
})

test('db.logins transactions use BEGIN IMMEDIATE to wait on WAL write locks without SQLITE_BUSY', async () => {
	const lockSignal = new Int32Array(new SharedArrayBuffer(4))
	const workerSrc = `
		import { DatabaseSync } from 'node:sqlite'
		import { workerData } from 'node:worker_threads'
		const conn = new DatabaseSync(workerData.dbPath)
		conn.exec('PRAGMA busy_timeout = 5000;')
		conn.exec('BEGIN IMMEDIATE;')
		Atomics.store(workerData.lockSignal, 0, 1)
		Atomics.notify(workerData.lockSignal, 0)
		Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 40)
		conn.exec('COMMIT;')
		conn.close()
	`
	const worker = new Worker(new URL(`data:text/javascript,${encodeURIComponent(workerSrc)}`), {
		workerData: { dbPath: testDbPath, lockSignal }
	})
	Atomics.wait(lockSignal, 0, 0, 2000)
	const resolved = db.logins.resolveUser('google', 'wal-contention@example.com')
	assert.ok(resolved?.id)
	await new Promise((resolve, reject) => {
		worker.once('exit', code => code === 0 ? resolve() : reject(new Error(`Worker exited with ${code}`)))
		worker.once('error', reject)
	})
})
