import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { useServer, baseUrl, createTestSession, withEnv, mcp, req, db, mcpMod, utilMod, server } from './helpers.js'

const dirname = path.dirname(fileURLToPath(import.meta.url))
useServer()

test('HTTP security headers, malformed URL 400, OPTIONS CORS, and 404 routing', async () => {
	const health = await req('HEAD', '/api/health')
	assert.equal(health.status, 200)
	assert.equal(health.headers.get('x-content-type-options'), 'nosniff')
	for (const p of ['/', '/oauth/authorize']) {
		const res = await req('GET', p)
		assert.equal(res.status, 200)
		assert.equal(res.headers.get('access-control-allow-origin'), null)
		assert.equal(res.headers.get('x-frame-options'), 'DENY')
		assert.equal(res.headers.get('referrer-policy'), 'same-origin')
		assert.equal(res.headers.get('cache-control'), 'no-store')
		assert.equal(res.headers.get('x-content-type-options'), 'nosniff')
		assert.equal(res.headers.get('content-security-policy'), "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
	}
	assert.equal((await req('PUT', '/')).status, 405)
	assert.equal((await req('OPTIONS', '/oauth/token')).status, 204)
	assert.equal((await req('GET', '/unknown-route')).status, 404)
	const badRawUrl = await new Promise((resolve, reject) => {
		const sock = net.createConnection({ host: '127.0.0.1', port: new URL(baseUrl()).port }, () => {
			sock.end('GET http://[bad]/foo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n')
		})
		const chunks = []
		sock.on('data', c => chunks.push(c))
		sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
		sock.on('error', reject)
	})
	assert.match(badRawUrl, /^HTTP\/1\.1 400 Bad Request/)
	const abortedStream = new Readable({ read () {} })
	const rawP = utilMod.getRawBody(abortedStream)
	abortedStream.push(Buffer.from('partial'))
	abortedStream.destroy()
	await assert.rejects(rawP, /Request stream closed prematurely/)
})

test('MCP JSON-RPC framing, method guards, and internal error masking', async () => {
	const { session } = createTestSession({ account: 'mcp-rpc@example.com', admin: true })
	assert.equal((await req('GET', '/mcp', { token: session.token })).status, 405)
	assert.equal((await req('POST', '/mcp', { token: session.token, headers: { 'content-type': 'application/json' }, body: '{"bad' })).data.error.code, -32700)
	for (const badRpc of ['null', '123', '"str"', '[]', '{"jsonrpc":"2.0","id":42}']) {
		const res = await req('POST', '/mcp', { token: session.token, headers: { 'content-type': 'application/json' }, body: badRpc })
		assert.equal(res.status, 200)
		assert.equal(res.data.error.code, -32600)
	}
	const zeroId = await req('POST', '/mcp', { token: session.token, body: { jsonrpc: '2.0', id: 0, method: '' } })
	assert.equal(zeroId.data.id, 0)
	assert.equal(zeroId.data.error.code, -32600)
	assert.equal((await req('POST', '/mcp', { token: session.token, body: { jsonrpc: '2.0', id: 1, method: 'toString', params: {} } })).data.error.code, -32601)
	assert.equal((await req('POST', '/mcp', { token: session.token, body: { jsonrpc: '2.0', method: 'notifications/initialized', params: {} } })).status, 202)
	const missingName = await req('POST', '/mcp', { token: session.token, body: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { arguments: {} } } })
	assert.equal(missingName.data.result.isError, true)
	const unknownTool = await req('POST', '/mcp', { token: session.token, body: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'missing', arguments: {} } } })
	assert.equal(unknownTool.data.result.isError, true)
	const origErr = console.error
	const logged = []
	console.error = (...args) => logged.push(args)
	try {
		const internal = mcpMod.formatError(new Error('SQLITE_ERROR: schema detail'), 'admin')
		assert.equal(internal.isError, true)
		assert.equal(internal.content[0].text, 'Internal Server Error')
		assert.equal(logged.length, 1)
		const op = mcpMod.formatError(Object.assign(new Error('App not found: x'), { status: 404 }), 'admin')
		assert.equal(op.content[0].text, 'App not found: x')
	} finally {
		console.error = origErr
	}
})

test('canonical REST contract rejects method/payload smuggling, trailing slashes, reserved subpaths, and bad encoding', async () => {
	const { session, app } = createTestSession({ account: 'rest-contract@example.com', admin: true })
	assert.equal((await req('GET', '/api/whoami')).data.authenticated, false)
	assert.equal((await req('GET', '/api/sessions')).status, 401)
	assert.equal((await req('DELETE', '/api/sessions?allOthers=true')).status, 401)
	const sess2 = db.tokens.create({ userId: session.userId, provider: 'self', admin: 0 })
	db.links.create({ sessionId: sess2.id, appId: app.id })
	assert.equal((await req('GET', `/api/sessions/${sess2.id}`, { token: session.token })).data.session.token, undefined)
	const rotated = await req('PATCH', `/api/sessions/${sess2.id}`, { token: session.token, body: { rotateToken: true } })
	assert.equal(rotated.status, 200)
	assert.equal(rotated.data.session.id, sess2.id)
	assert.equal((await req('GET', '/api/whoami', { token: sess2.token })).data.authenticated, false)
	assert.equal((await req('GET', '/api/whoami', { token: rotated.data.session.token })).data.authenticated, true)
	assert.equal(db.links.listBySessionId(sess2.id).length, 1, 'rotateToken preserves session links')
	assert.equal((await req('DELETE', `/api/sessions/${sess2.id}`, { token: session.token })).status, 200)
	assert.equal((await req('GET', '/api/whoami', { token: rotated.data.session.token })).data.authenticated, false)
	const sess3 = db.tokens.create({ userId: session.userId, provider: 'self', admin: 0 })
	assert.equal((await req('DELETE', '/api/sessions?allOthers=true', { token: session.token })).status, 200)
	assert.equal((await req('GET', '/api/whoami', { token: session.token })).data.authenticated, true)
	assert.equal((await req('GET', '/api/whoami', { token: sess3.token })).data.authenticated, false)
	assert.equal((await req('DELETE', '/api/sessions', { token: session.token })).status, 400, 'Bare DELETE /api/sessions requires allOthers=true')
	assert.equal((await req('DELETE', `/api/sessions?sessionId=${session.id}`, { token: session.token })).status, 400)
	assert.equal((await req('DELETE', '/api/sessions?all_others=true', { token: session.token })).status, 400)
	assert.equal((await req('DELETE', '/api/sessions', { token: session.token, body: { allOthers: true } })).status, 400)
	assert.equal((await req('DELETE', '/api/logins', { token: session.token })).status, 405)
	assert.equal((await req('PUT', `/api/sessions/${session.id}`, { token: session.token, body: { name: 'X' } })).status, 405)
	assert.equal((await req('PATCH', '/api/user', { token: session.token, body: { name: 'X' } })).status, 404)
	assert.equal((await req('GET', '/api/apps?provider=stripe', { token: session.token })).status, 400)
	assert.equal((await req('POST', '/api/apps', { token: session.token, body: '["arr"]', headers: { 'content-type': 'application/json' } })).status, 400)
	assert.equal((await req('PATCH', `/api/apps/${app.id}`, { token: session.token, body: { appId: app.id, name: 'X' } })).status, 400)
	for (const p of ['/api/sessions/', '/api/apps/', '/api/logins/', '/api/health/extra', '/api/whoami/extra', '/api/links/123', '/api/shares/123', '/api/logs/123']) {
		assert.equal((await req('GET', p, { token: session.token })).status, 404, `Reserved/trailing path must 404: ${p}`)
	}
	assert.equal((await req('DELETE', '/api/apps/%E0%A4%A', { token: session.token })).status, 400)
	const specialApp = db.tokens.create({ id: 'app:sp/id%1', userId: session.userId, provider: 'stripe', type: 'static', credentials: { headers: { authorization: 'Bearer sk' }, baseUrl: 'https://api.stripe.com' } })
	assert.equal((await req('PATCH', `/api/apps/${encodeURIComponent(specialApp.id)}`, { token: session.token, body: { name: 'Renamed' } })).status, 200)
	assert.equal((await req('DELETE', `/api/apps/${encodeURIComponent(specialApp.id)}?revoke=false`, { token: session.token })).status, 200)
	assert.equal((await req('GET', `/api/stripe/v1/customers?app=${app.id}&app=x`, { token: session.token })).status, 400, 'Duplicate query param app fails 400')
})

test('strict input validation parity, requireBoolean, invalid credential rejection, and log retention pruning', async () => {
	const { user, session, app } = createTestSession({ account: 'validation@example.com', admin: true })
	const target = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
	assert.equal((await req('PATCH', `/api/sessions/${target.id}`, { token: session.token, body: { admin: 'false' } })).data.session.admin, false)
	assert.equal((await req('PATCH', `/api/sessions/${target.id}`, { token: session.token, body: { admin: 'not-a-bool' } })).status, 400)
	assert.equal((await req('DELETE', '/api/sessions?allOthers=invalid', { token: session.token })).status, 400)
	assert.equal((await req('DELETE', `/api/apps/${app.id}?revoke=invalid`, { token: session.token })).status, 400)
	assert.equal((await req('GET', '/api/logs?allowed=invalid', { token: session.token })).status, 400)
	assert.throws(() => db.logs.listByUserId(user.id, { allowed: 'invalid' }), /allowed must be a boolean/)
	for (const bad of [
		{ action: 'update_app', appId: app.id },
		{ action: 'update_app', appId: app.id, name: 'X', apiKey: 'legacy' },
		{ action: 'connect_app', provider: 'google', appUrl: 'https://evil.com' },
		{ action: 'list_apps', provider: 'stripe' },
		{ action: 'update_session' },
		{ action: 'revoke_session', sessionId: '' },
		{ action: 'create_session', linkAppIds: ['missing'] }
	]) {
		assert.equal((await mcp(session.token, 'admin', bad)).isError, true)
	}
	for (const badProv of ['self', 'sessions', 'my.api']) {
		assert.equal((await mcp(session.token, 'admin', { action: 'connect_app', provider: badProv, credentials: 'sk', baseUrl: 'https://api.stripe.com' })).isError, true)
	}
	for (const badCreds of ['', '   ', 'tok\r\ninj: 1', {}, { bearer: 'a', basic: 'u:p' }, { basic: 'nocolon' }, { headers: { cookie: 'x=1' } }, { headers: { host: 'evil.com' } }, { query: { ApiKey: '1', apikey: '2' } }]) {
		assert.equal((await req('POST', '/api/apps', { token: session.token, body: { provider: 'stripe', credentials: badCreds, baseUrl: 'https://api.stripe.com' } })).status, 400)
	}
	await withEnv({ UPSTREAM_TIMEOUT_MS: undefined }, () => assert.equal(utilMod.positiveNumberEnv('UPSTREAM_TIMEOUT_MS', 60000), 60000))
	await withEnv({ UPSTREAM_TIMEOUT_MS: '  ' }, () => assert.equal(utilMod.positiveNumberEnv('UPSTREAM_TIMEOUT_MS', 60000), 60000))
	await withEnv({ UPSTREAM_TIMEOUT_MS: '25' }, () => assert.equal(utilMod.positiveNumberEnv('UPSTREAM_TIMEOUT_MS', 60000), 25))
	for (const badEnv of ['0', '-5', 'Infinity', '10mb']) {
		await withEnv({ UPSTREAM_TIMEOUT_MS: badEnv }, () => assert.throws(() => utilMod.positiveNumberEnv('UPSTREAM_TIMEOUT_MS', 60000), /Invalid UPSTREAM_TIMEOUT_MS/))
	}
	const upd = db.tokens.updateCredentials(app.id, { credentials: { accessToken: 'ya29.2', refreshToken: '1//r' }, expiresAt: null, scopes: null })
	assert.equal(upd.expiresAt, null)
	assert.equal(upd.scopes, null)
	const oldLog = db.logs.create({ userId: user.id, sessionId: session.id, appId: app.id, provider: 'stripe', method: 'GET', url: 'https://api.stripe.com/old', allowed: true, status: 200 })
	db.sqlite.prepare('UPDATE logs SET created = ? WHERE id = ?').run(new Date(Date.now() - 35 * 86400 * 1000).toISOString(), oldLog.id)
	assert.equal(db.logs.listByUserId(user.id).length, 0)
	db.logs.prune()
	assert.equal(db.sqlite.prepare('SELECT id FROM logs WHERE id = ?').get(oldLog.id), undefined)
})

test('getBaseUrl / getClientIp fail-closed proxy trust, OAuth rate limiting, and graceful SIGTERM shutdown', async () => {
	assert.equal(utilMod.getBaseUrl({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-host': 'jump.acme.com:443', 'x-forwarded-proto': 'https' } }), 'https://jump.acme.com')
	assert.equal(utilMod.getBaseUrl({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-host': 'evil.com"><script>' } }), 'http://localhost:8080')
	assert.equal(utilMod.getBaseUrl({ socket: { remoteAddress: '203.0.113.5' }, headers: { host: '127.0.0.1:8080', 'x-forwarded-host': 'evil.com', 'x-forwarded-proto': 'https' } }), 'http://127.0.0.1:8080')
	assert.equal(utilMod.getBaseUrl({ socket: {}, headers: { host: '127.0.0.1:8080', 'x-forwarded-host': 'evil.com' } }), 'http://127.0.0.1:8080')
	assert.equal(utilMod.getClientIp({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '203.0.113.9, 198.51.100.7' } }), '198.51.100.7')
	assert.equal(utilMod.getClientIp({ socket: {}, headers: { 'x-forwarded-for': '198.51.100.7' } }), null)
	assert.throws(() => utilMod.parseAppUrl('https://pinned.acme.com/sub'), /Invalid APP_URL/)
	await withEnv({ APP_URL: utilMod.parseAppUrl('https://pinned.acme.com:443///') }, () => {
		assert.equal(utilMod.getBaseUrl({ headers: { host: 'evil.com' } }), 'https://pinned.acme.com')
	})
	await withEnv({ OAUTH_RATE_LIMIT: '2' }, async () => {
		for (let i = 0; i < 2; i++) assert.equal((await req('GET', '/oauth/authorize', { headers: { 'x-forwarded-for': '198.51.100.88' } })).status, 200)
		assert.equal((await req('GET', '/oauth/authorize', { headers: { 'x-forwarded-for': '198.51.100.1, 198.51.100.88' } })).status, 429)
		assert.equal((await req('GET', '/api/health', { headers: { 'x-forwarded-for': '198.51.100.88' } })).status, 200)
	})
	assert.equal(server.headersTimeout, 15000)
	assert.equal(server.keepAliveTimeout, 125000)
	const probe = http.createServer()
	await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve))
	const freePort = probe.address().port
	await new Promise(resolve => probe.close(resolve))
	const subDbPath = path.join(os.tmpdir(), `jump-shutdown-${process.pid}.db`)
	const child = spawn(process.execPath, [path.join(dirname, '..', 'index.js')], {
		cwd: dirname,
		env: { ...process.env, NODE_ENV: 'production', HOST: '127.0.0.1', PORT: String(freePort), DB_PATH: subDbPath },
		stdio: ['ignore', 'pipe', 'pipe']
	})
	let inflight = null
	try {
		await new Promise((resolve, reject) => {
			let out = ''
			child.stdout.on('data', c => { out += c.toString('utf8'); if (out.includes('jump listening on')) resolve() })
			child.once('exit', code => reject(new Error(`Exited early: ${code}`)))
		})
		const body = JSON.stringify({ redirect_uris: ['http://127.0.0.1:9999/cb'] })
		inflight = net.connect(freePort, '127.0.0.1')
		inflight.on('error', () => {})
		await new Promise(resolve => inflight.once('connect', resolve))
		let rawReply = ''
		inflight.on('data', c => { rawReply += c.toString('utf8') })
		inflight.write(`POST /oauth/register HTTP/1.1\r\nHost: 127.0.0.1:${freePort}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n`)
		await new Promise(r => setTimeout(r, 20))
		const exitPromise = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })))
		child.kill('SIGTERM')
		await new Promise(r => setTimeout(r, 15))
		child.kill('SIGTERM')
		await new Promise(r => setTimeout(r, 25))
		if (!inflight.destroyed) inflight.write(body)
		await new Promise(resolve => inflight.destroyed ? resolve() : inflight.once('close', resolve))
		assert.match(rawReply, /^HTTP\/1\.1 201 /)
		const exitRes = await Promise.race([exitPromise, new Promise(r => setTimeout(() => r({ timedOut: true }), 1500).unref())])
		assert.equal(exitRes.code, 0)
	} finally {
		inflight?.destroy()
		if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
		for (const suffix of ['', '-wal', '-shm', '.key']) fs.rmSync(`${subDbPath}${suffix}`, { force: true })
	}
})
