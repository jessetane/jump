import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { Worker } from 'node:worker_threads'

const dirname = path.dirname(fileURLToPath(import.meta.url))
const testDbPath = path.join(dirname, 'test.db')
process.env.DB_PATH = testDbPath
process.env.NODE_ENV = 'test'
process.env.GOOGLE_CLIENT_ID = 'test-client-id'
process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret'
process.env.ALLOWED_REDIRECT_DOMAINS = 'chatgpt.com,*.antigravity.google,antigravity,cursor,vscode'

fs.rmSync(testDbPath, { force: true })
fs.rmSync(`${testDbPath}-wal`, { force: true })
fs.rmSync(`${testDbPath}-shm`, { force: true })

const { server, bootstrapLocalAdmin } = await import('../index.js')
const db = await import('../db/index.js')
const { google, github, createProvider, getProvider, listAuthProviders, requireAuthProvider, summarizeScopes } = await import('../providers/index.js')
const { isAllowedUrl: isGoogleAllowedUrl, services: googleServices } = google
const { isAllowedUrl: isGithubAllowedUrl, services: githubServices } = github
const { readResponseBody } = await import('../api/proxy.js')
const { executeTool, redactLogArgs } = await import('../mcp.js')
const { isAllowedRedirectUri, deriveClientName, getBaseUrl } = await import('../oauth.js')
const api = await import('../api/index.js')
const { evaluatePolicy, matchPattern, parsePolicy, validatePolicy } = await import('../policy.js')

function createTestSession (opts = {}) {
	const {
		account = 'user@example.com',
		provider = 'google',
		admin = false,
		accessToken = 'ya29.fake-token',
		refreshToken = '1//fake-refresh',
		expiresAt = Date.now() + 3600000,
		scopes = null,
		policy = null,
		ip = '127.0.0.1',
		ua = 'TestClient/1.0'
	} = opts
	const user = db.logins.resolveUser(provider, account)
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		type: 'bearer',
		name: 'Test Session',
		admin: admin ? 1 : 0,
		ip,
		ua
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Test Google App',
		credentials: {
			accessToken,
			refreshToken
		},
		expiresAt,
		scopes
	})
	db.links.create({
		sessionId: session.id,
		appId: app.id,
		policy
	})
	return { user, session, app }
}

test('setup server', (t, done) => {
	server.listen(0, '127.0.0.1', done)
})

test('health endpoint', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/api/health`)
	assert.equal(res.status, 200)
	const text = await res.text()
	assert.equal(text, 'ok\n')
})

test('root endpoint', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/`)
	assert.equal(res.status, 200)
	assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8')
	assert.equal(getBaseUrl({ headers: { 'x-forwarded-host': 'jump.acme.com', 'x-forwarded-proto': 'https' } }), 'https://jump.acme.com')
	assert.equal(getBaseUrl({ headers: { host: 'localhost:8080' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { 'x-forwarded-host': 'evil.com"><script>alert(1)</script>' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { 'x-forwarded-host': 'jump.acme.com', 'x-forwarded-proto': 'javascript' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { 'x-forwarded-host': 'user:pass@jump.acme.com' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { 'x-forwarded-host': 'jump.acme.com/path' } }), 'http://localhost:8080')
	const xssRootRes = await fetch(`http://127.0.0.1:${addr.port}/`, {
		headers: { 'x-forwarded-host': 'evil.com"><script>alert(1)</script>' }
	})
	assert.equal(xssRootRes.status, 200)
	const xssHtml = await xssRootRes.text()
	assert.equal(xssHtml.includes('<script>alert(1)</script>'), false)
	assert.match(xssHtml, /http:\/\/localhost:8080\/mcp/)
	const text = await res.text()
	assert.match(text, /jump/)
	assert.match(text, /\/mcp/)
	assert.match(text, /href="\/oauth\/authorize"/)
})

test('mcp initialize & tools/list and RFC 9728 401 WWW-Authenticate when unauthenticated', async () => {
	const addr = server.address()
	const unauthRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: { protocolVersion: '2025-03-26' }
		})
	})
	assert.equal(unauthRes.status, 401)
	const wwwAuth = unauthRes.headers.get('www-authenticate') || ''
	assert.match(wwwAuth, /Bearer/)
	assert.match(wwwAuth, /\/\.well-known\/oauth-protected-resource/)
	assert.match(wwwAuth, /\/oauth\/authorize/)
	const expose = unauthRes.headers.get('access-control-expose-headers') || ''
	assert.match(expose, /WWW-Authenticate/)
	const getUnauthRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'GET',
		headers: { accept: 'text/event-stream' }
	})
	assert.equal(getUnauthRes.status, 401)
	assert.match(getUnauthRes.headers.get('www-authenticate') || '', /\/\.well-known\/oauth-protected-resource/)
	const user = db.logins.resolveUser('google', 'mcp-init@example.com')
	const bareSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
	const authHeaders = {
		'content-type': 'application/json',
		authorization: `Bearer ${bareSession.token}`
	}
	const initRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: authHeaders,
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: { protocolVersion: '2025-03-26' }
		})
	})
	assert.equal(initRes.status, 200)
	const initData = await initRes.json()
	assert.equal(initData.result.serverInfo.name, 'jump')
	assert.equal(initData.result.protocolVersion, '2025-03-26')
	const rootInitRes = await fetch(`http://127.0.0.1:${addr.port}/`, {
		method: 'POST',
		headers: authHeaders,
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: {}
		})
	})
	assert.equal(rootInitRes.status, 200)
	const rootInitData = await rootInitRes.json()
	assert.equal(rootInitData.result.serverInfo.name, 'jump')
	assert.equal(rootInitData.result.protocolVersion, '2024-11-05')
	const notifRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: authHeaders,
		body: JSON.stringify({
			jsonrpc: '2.0',
			method: 'notifications/initialized',
			params: {}
		})
	})
	assert.equal(notifRes.status, 202)
	const listRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: authHeaders,
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 2,
			method: 'tools/list',
			params: {}
		})
	})
	assert.equal(listRes.status, 200)
	const listData = await listRes.json()
	const toolNames = listData.result.tools.map(t => t.name)
	assert.deepEqual(toolNames, [])
})

test('mcp admin tool without auth', async () => {
	const res = await executeTool('admin', { action: 'whoami' }, null)
	assert.equal(res.isError, undefined)
	const parsed = JSON.parse(res.content[0].text)
	assert.equal(parsed.authenticated, false)
})

test('mcp google_api tool requires auth', async () => {
	const res = await executeTool('google_api', { url: 'drive/v3/files' }, null)
	assert.equal(res.isError, true)
	assert.match(res.content[0].text, /Authentication required/)
})

test('mcp rejects tool call without name', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'missing-name@example.com' })
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${session.token}`
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 5,
			method: 'tools/call',
			params: {
				arguments: { action: 'whoami' }
			}
		})
	})
	assert.equal(res.status, 200)
	const data = await res.json()
	assert.equal(data.result.isError, true)
	assert.equal(data.result.content[0].text, 'Tool name is required')
})

test('mcp rejects unknown tool call', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'unknown-tool@example.com' })
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${session.token}`
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 6,
			method: 'tools/call',
			params: {
				name: 'non_existent_tool',
				arguments: {}
			}
		})
	})
	assert.equal(res.status, 200)
	const data = await res.json()
	assert.equal(data.result.isError, true)
	assert.equal(data.result.content[0].text, 'Unknown tool: non_existent_tool')
})

test('google.isAllowedUrl domain restrictions', () => {
	assert.equal(isGoogleAllowedUrl('https://www.googleapis.com/drive/v3/files').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://sheets.googleapis.com/v4/spreadsheets').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://docs.googleapis.com/v1/documents').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://calendar.googleapis.com/calendar/v3/events').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://googleapis.com/test').allowed, true)
	assert.equal(isGoogleAllowedUrl('http://www.googleapis.com/test').allowed, false)
	assert.equal(isGoogleAllowedUrl('https://evil.com').allowed, false)
	assert.equal(isGoogleAllowedUrl('https://evilgoogleapis.com').allowed, false)
	assert.equal(isGoogleAllowedUrl('https://localhost:8080').allowed, false)
	assert.equal(isGoogleAllowedUrl('not-a-url').allowed, false)
})

test('summarizeScopes formats provider service scope combinations concisely', () => {
	assert.equal(summarizeScopes(null, googleServices), '')
	assert.equal(summarizeScopes('https://www.googleapis.com/auth/userinfo.email', googleServices), '')
	assert.equal(
		summarizeScopes('https://www.googleapis.com/auth/calendar.readonly', googleServices),
		'calendar (ro)'
	)
	assert.equal(
		summarizeScopes('https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/spreadsheets.readonly', googleServices),
		'drive, sheets (ro)'
	)
	assert.equal(
		summarizeScopes('https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.readonly', googleServices),
		'drive (rw), gmail (ro)'
	)
	assert.equal(
		summarizeScopes(googleServices.photos.ro.join(' '), googleServices),
		'photos (ro)'
	)
	assert.equal(
		summarizeScopes(googleServices.photos.rw.join(' '), googleServices),
		'photos (rw)'
	)
	assert.equal(
		summarizeScopes(googleServices.admin.ro.join(' '), googleServices),
		'admin (ro)'
	)
	assert.equal(
		summarizeScopes(googleServices.admin.rw.join(' '), googleServices),
		'admin (rw)'
	)
	const fiveMixed = [
		...googleServices.drive.rw,
		...googleServices.docs.rw,
		...googleServices.sheets.ro,
		...googleServices.slides.ro,
		...googleServices.forms.ro
	].join(' ')
	assert.equal(summarizeScopes(fiveMixed, googleServices), '5 (2 rw, 3 ro)')
	const allRw = Object.values(googleServices).flatMap(s => s.rw).join(' ')
	assert.equal(summarizeScopes(allRw, googleServices), 'all (rw)')
})

test('rejects non-googleapis URLs in google_api tool', async () => {
	const { session } = createTestSession({ account: 'user@example.com' })
	const result = await executeTool('google_api', {
		url: 'https://evil.com/steal-token'
	}, session.token)
	assert.equal(result.isError, true)
	assert.match(result.content[0].text, /Target URL domain not allowed/)
})

test('mcp google_api tool ignores body on GET requests', async () => {
	const { session } = createTestSession({ account: 'getbody@example.com' })
	const result = await executeTool('google_api', {
		url: 'https://www.googleapis.com/drive/v3/files',
		method: 'GET',
		body: { unwanted: 'payload' }
	}, session.token)
	assert.ok(result)
})

test('oauth state flow', async () => {
	const state = db.tokens.createState({
		clientRedirectUri: 'https://example.com/oauth/return',
		clientState: 'random-state',
		ip: '127.0.0.1'
	})
	assert.ok(state)
	const consumed = db.tokens.consumeState(state)
	assert.equal(consumed.clientState, 'random-state')
	assert.equal(consumed.clientRedirectUri, 'https://example.com/oauth/return')
	assert.equal(db.tokens.consumeState(state), null)
})

test('oauth code exchange flow', async () => {
	const { session, app } = createTestSession({ account: 'test@example.com', name: 'Test User' })
	const code = db.tokens.createAuthCode({
		userId: session.userId,
		sessionName: 'Test OAuth Session',
		appIds: [app.id],
		clientRedirectUri: 'https://chatgpt.com/callback'
	})
	assert.ok(code)
	const addr = server.address()
	const mismatchRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code,
			redirect_uri: 'https://evil.com/callback',
			grant_type: 'authorization_code'
		}).toString()
	})
	assert.equal(mismatchRes.status, 400)
	const mismatchData = await mismatchRes.json()
	assert.equal(mismatchData.error, 'invalid_grant')
	const code2 = db.tokens.createAuthCode({
		userId: session.userId,
		sessionName: 'Test OAuth Session',
		appIds: [app.id],
		clientRedirectUri: 'https://chatgpt.com/callback'
	})
	const res = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: code2,
			redirect_uri: 'https://chatgpt.com/callback',
			grant_type: 'authorization_code'
		}).toString()
	})
	assert.equal(res.status, 200)
	const data = await res.json()
	assert.ok(data.access_token)
	assert.notEqual(data.access_token, session.token)
	assert.ok(data.refresh_token)
	assert.equal(data.token_type, 'Bearer')
	assert.equal(data.expires_in, 3600)
	assert.equal(data.scope, 'mcp')
	assert.equal(db.tokens.consumeAuthCode(code2), null)
	const issuedSession = db.tokens.getByToken(data.access_token)
	assert.ok(issuedSession)
	assert.equal(issuedSession.userId, session.userId)
	assert.equal(issuedSession.name, 'Test OAuth Session')
	assert.ok(issuedSession.expiresAt > Date.now())
	assert.equal(issuedSession.credentials.refreshToken, data.refresh_token)
	const issuedLinks = db.links.listBySessionId(issuedSession.id)
	assert.equal(issuedLinks.length, 1)
	assert.equal(issuedLinks[0].appId, app.id)
	const orphanCode = db.tokens.createAuthCode({
		userId: null,
		clientRedirectUri: 'https://chatgpt.com/callback'
	})
	const orphanRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: orphanCode,
			redirect_uri: 'https://chatgpt.com/callback',
			grant_type: 'authorization_code'
		}).toString()
	})
	assert.equal(orphanRes.status, 400, 'Code referencing deleted user must fail loud with 400 invalid_grant')
})

test('oauth refresh_token grant rotation, access_token expiration, and embedded session indefinite TTL', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'refresh-flow@example.com')
	const code = db.tokens.createAuthCode({
		userId: user.id,
		sessionName: 'Refresh User',
		admin: 1,
		clientRedirectUri: 'https://chatgpt.com/callback'
	})
	const tokenRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			code,
			redirect_uri: 'https://chatgpt.com/callback',
			grant_type: 'authorization_code'
		})
	})
	assert.equal(tokenRes.status, 200)
	const initialTokens = await tokenRes.json()
	const session = db.tokens.getByToken(initialTokens.access_token)
	assert.ok(session)
	assert.equal(session.admin, true)
	assert.equal(session.name, 'Refresh User')
	assert.ok(initialTokens.refresh_token)
	assert.equal(initialTokens.expires_in, 3600)
	const unsupportedRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ grant_type: 'client_credentials' })
	})
	assert.equal(unsupportedRes.status, 400)
	const unsupportedData = await unsupportedRes.json()
	assert.equal(unsupportedData.error, 'unsupported_grant_type')
	const missingRefreshRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ grant_type: 'refresh_token' })
	})
	assert.equal(missingRefreshRes.status, 400)
	const missingRefreshData = await missingRefreshRes.json()
	assert.equal(missingRefreshData.error, 'invalid_request')
	db.sqlite.prepare('UPDATE tokens SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, session.id)
	assert.equal(db.tokens.getByToken(initialTokens.access_token), null, 'Expired access_token must return null from getByToken')
	const expiredMcpRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${initialTokens.access_token}`
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: { protocolVersion: '2025-03-26' }
		})
	})
	assert.equal(expiredMcpRes.status, 401, 'Expired access_token must be rejected with 401 on /mcp')
	const expiredApiRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions`, {
		headers: { authorization: `Bearer ${initialTokens.access_token}` }
	})
	assert.equal(expiredApiRes.status, 401, 'Expired access_token must be rejected with 401 on REST API')
	const refreshRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: initialTokens.refresh_token
		}).toString()
	})
	assert.equal(refreshRes.status, 200)
	const rotatedTokens = await refreshRes.json()
	assert.ok(rotatedTokens.access_token)
	assert.ok(rotatedTokens.refresh_token)
	assert.notEqual(rotatedTokens.access_token, initialTokens.access_token, 'Access token must rotate when expired')
	assert.equal(rotatedTokens.refresh_token, initialTokens.refresh_token, 'Refresh token must remain stable across refreshes')
	assert.equal(rotatedTokens.token_type, 'Bearer')
	assert.equal(rotatedTokens.expires_in, 3600)
	assert.equal(rotatedTokens.scope, 'mcp')
	const concurrentRefreshRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			grant_type: 'refresh_token',
			refresh_token: initialTokens.refresh_token
		})
	})
	assert.equal(concurrentRefreshRes.status, 200, 'Concurrent refresh with stable refresh_token must succeed')
	const concurrentData = await concurrentRefreshRes.json()
	assert.equal(concurrentData.access_token, rotatedTokens.access_token, 'Concurrent refresh within 60s window must return the same access_token')
	assert.equal(concurrentData.refresh_token, initialTokens.refresh_token, 'Concurrent refresh must return the same refresh_token')
	assert.ok(concurrentData.expires_in > 3500 && concurrentData.expires_in <= 3600)
	db.sqlite.prepare('UPDATE tokens SET expires_at = ? WHERE id = ?').run(Date.now() + 9000, session.id)
	const proactiveRefreshRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			grant_type: 'refresh_token',
			refresh_token: initialTokens.refresh_token
		})
	})
	assert.equal(proactiveRefreshRes.status, 200, 'Proactive refresh 9s before expiry must succeed')
	const proactiveTokens = await proactiveRefreshRes.json()
	assert.notEqual(proactiveTokens.access_token, rotatedTokens.access_token, 'Proactive refresh past 60s dedup window must rotate access_token')
	assert.equal(proactiveTokens.refresh_token, initialTokens.refresh_token, 'Proactive refresh must keep refresh_token stable')
	assert.equal(proactiveTokens.expires_in, 3600, 'Proactive refresh must reset expires_in to 3600')
	const oldTouchTime = new Date(Date.now() - 120000).toISOString()
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(oldTouchTime, session.id)
	const validMcpRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${proactiveTokens.access_token}`
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 2,
			method: 'initialize',
			params: { protocolVersion: '2025-03-26' }
		})
	})
	assert.equal(validMcpRes.status, 200, 'Newly minted access_token must authenticate /mcp')
	assert.ok(db.tokens.get(session.id).updated > oldTouchTime, 'getByToken must touch updated timestamp on auth')
	const embeddedRes = await executeTool('admin', {
		action: 'create_session',
		name: 'Embedded Worker',
		admin: false
	}, proactiveTokens.access_token)
	assert.equal(embeddedRes.isError, undefined)
	const embeddedData = JSON.parse(embeddedRes.content[0].text)
	assert.equal(embeddedData.session.expiresAt, null)
	const embeddedRow = db.tokens.get(embeddedData.session.id)
	assert.equal(embeddedRow.expiresAt, null, 'Embedded session created via create_session must have expiresAt: null')
	assert.equal(embeddedRow.credentials, null, 'Embedded session must not have refresh token credentials')
	const whoamiRes = await executeTool('admin', { action: 'whoami' }, proactiveTokens.access_token)
	const whoamiData = JSON.parse(whoamiRes.content[0].text)
	assert.ok(typeof whoamiData.session.expiresAt === 'number', 'whoami must expose expiresAt for OAuth session')
	const dormantDate = new Date(Date.now() - 31 * 86400 * 1000).toISOString()
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(dormantDate, session.id)
	const expiredRefreshRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			grant_type: 'refresh_token',
			refresh_token: rotatedTokens.refresh_token
		})
	})
	assert.equal(expiredRefreshRes.status, 400, 'Dormant/expired refresh_token (>30d) must be rejected with 400')
	const expiredRefreshData = await expiredRefreshRes.json()
	assert.equal(expiredRefreshData.error, 'invalid_grant')
	assert.ok(!db.tokens.listByUserId(user.id, { provider: 'self' }).some(t => t.id === session.id), 'Dormant session is excluded at read time without inline DELETE')
	db.prune()
	assert.equal(db.tokens.get(session.id), null, 'Dormant session is physically deleted by db.prune()')
	assert.equal(deriveClientName('client_12345'), null, 'Generated DCR client_id must not become derived session name')
	assert.equal(deriveClientName('client_bearer_12345'), null, 'Generated DCR client_bearer_id must not become derived session name')
	assert.equal(deriveClientName('client_12345', 'Explicit Client'), 'Explicit Client')
	assert.equal(deriveClientName('custom_named_client'), 'custom_named_client')
	const bearerRegRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/register`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			client_name: 'Embedded MCP Client',
			redirect_uris: ['http://localhost:8080/cb'],
			grant_types: ['authorization_code'],
			response_types: ['code'],
			token_endpoint_auth_method: 'none'
		})
	})
	assert.equal(bearerRegRes.status, 201)
	const bearerRegData = await bearerRegRes.json()
	assert.ok(bearerRegData.client_id.startsWith('client_bearer_'), 'DCR without refresh_token grant must issue client_bearer_ prefix')
	assert.deepEqual(bearerRegData.grant_types, ['authorization_code'])
	const bearerChallenge = createHash('sha256').update('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk').digest('base64url')
	const bearerConsentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			provider: 'google',
			client_id: bearerRegData.client_id,
			redirect_uri: 'http://localhost:8080/cb',
			code_challenge: bearerChallenge,
			code_challenge_method: 'S256'
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(bearerConsentRes.status, 302)
	const bearerStateToken = new URL(bearerConsentRes.headers.get('location')).searchParams.get('state')
	const bearerState = db.tokens.getState(bearerStateToken)
	assert.equal(bearerState.clientId, bearerRegData.client_id)
	assert.equal(bearerState.sessionName, null, 'DCR client_id without explicit name must not pollute sessionName')
	const origFetch = globalThis.fetch
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.embedded_login', token_type: 'Bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: 'embedded-oauth@example.com' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	let redirectLoc
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=google-code&state=${bearerStateToken}`, { redirect: 'manual' })
		assert.equal(cbRes.status, 302)
		redirectLoc = cbRes.headers.get('location')
	} finally {
		globalThis.fetch = origFetch
	}
	const cbUrl = new URL(redirectLoc)
	assert.equal(cbUrl.origin, 'http://localhost:8080')
	assert.equal(cbUrl.pathname, '/cb')
	const bearerCode = cbUrl.searchParams.get('code')
	assert.ok(bearerCode)
	const bearerTokenRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: bearerRegData.client_id,
			code: bearerCode,
			redirect_uri: 'http://localhost:8080/cb',
			code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
		}).toString()
	})
	assert.equal(bearerTokenRes.status, 200)
	const bearerTokenData = await bearerTokenRes.json()
	assert.ok(bearerTokenData.access_token)
	assert.equal(bearerTokenData.refresh_token, undefined, 'Static bearer OAuth client must not receive refresh_token')
	assert.equal(bearerTokenData.expires_in, undefined, 'Static bearer OAuth client must not receive expires_in')
	assert.equal(bearerTokenData.token_type, 'Bearer')
	assert.equal(bearerTokenData.scope, 'mcp')
	const bearerSession = db.tokens.getByToken(bearerTokenData.access_token)
	assert.ok(bearerSession)
	assert.equal(bearerSession.expiresAt, null, 'Static bearer OAuth session must have expiresAt: null')
	assert.equal(bearerSession.credentials, null, 'Static bearer OAuth session must have credentials: null')
	assert.equal(bearerSession.name, 'Default Session')
	const boundCode = db.tokens.createAuthCode({
		userId: bearerSession.userId,
		clientId: 'client_refresh_bound',
		clientRedirectUri: 'http://localhost:8080/cb'
	})
	const mismatchClientRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			grant_type: 'authorization_code',
			client_id: 'client_bearer_spoofed',
			code: boundCode,
			redirect_uri: 'http://localhost:8080/cb'
		})
	})
	assert.equal(mismatchClientRes.status, 400, 'Mismatched client_id on /oauth/token must be rejected with 400')
	const mismatchClientData = await mismatchClientRes.json()
	assert.equal(mismatchClientData.error, 'invalid_grant')
	assert.equal(mismatchClientData.error_description, 'client_id mismatch')
	const unboundCode = db.tokens.createAuthCode({
		userId: bearerSession.userId,
		clientRedirectUri: 'http://localhost:8080/cb'
	})
	const spoofAttemptRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			grant_type: 'authorization_code',
			client_id: 'client_bearer_spoofed',
			code: unboundCode,
			redirect_uri: 'http://localhost:8080/cb'
		})
	})
	assert.equal(spoofAttemptRes.status, 200)
	const spoofAttemptData = await spoofAttemptRes.json()
	assert.ok(spoofAttemptData.refresh_token, 'Unauthenticated client_id=client_bearer_... body param must not downgrade an unbound code to static bearer')
	assert.equal(spoofAttemptData.expires_in, 3600)
})

test('well-known oauth discovery endpoints', async () => {
	const addr = server.address()
	const resResource = await fetch(`http://127.0.0.1:${addr.port}/.well-known/oauth-protected-resource`)
	assert.equal(resResource.status, 200)
	const resourceData = await resResource.json()
	assert.ok(Array.isArray(resourceData.authorization_servers))
	const resResourceMcp = await fetch(`http://127.0.0.1:${addr.port}/.well-known/oauth-protected-resource/mcp`)
	assert.equal(resResourceMcp.status, 200)
	assert.deepEqual(await resResourceMcp.json(), resourceData)
	const resResourceWork = await fetch(`http://127.0.0.1:${addr.port}/.well-known/oauth-protected-resource/mcp/work`)
	assert.equal(resResourceWork.status, 200)
	const resourceWorkData = await resResourceWork.json()
	assert.equal(resourceWorkData.resource, `http://127.0.0.1:${addr.port}/mcp/work`)
	const unauthSubRes = await fetch(`http://127.0.0.1:${addr.port}/mcp/work`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })
	})
	assert.equal(unauthSubRes.status, 401)
	assert.match(unauthSubRes.headers.get('www-authenticate') || '', /\/\.well-known\/oauth-protected-resource\/mcp\/work/)
	const resAuth = await fetch(`http://127.0.0.1:${addr.port}/.well-known/oauth-authorization-server`)
	assert.equal(resAuth.status, 200)
	const authData = await resAuth.json()
	assert.ok(authData.authorization_endpoint.endsWith('/oauth/authorize'))
	assert.ok(authData.token_endpoint.endsWith('/oauth/token'))
	assert.ok(authData.registration_endpoint.endsWith('/oauth/register'))
	assert.ok(authData.revocation_endpoint.endsWith('/oauth/revoke'))
	assert.deepEqual(authData.grant_types_supported, ['authorization_code', 'refresh_token'])
	assert.deepEqual(authData.token_endpoint_auth_methods_supported, ['none'])
	assert.deepEqual(authData.revocation_endpoint_auth_methods_supported, ['none'])
	assert.deepEqual(authData.code_challenge_methods_supported, ['S256'])
	assert.equal(authData.client_id_metadata_document_supported, true)
	const resAuthMcp = await fetch(`http://127.0.0.1:${addr.port}/.well-known/oauth-authorization-server/mcp`)
	assert.equal(resAuthMcp.status, 200)
	assert.deepEqual(await resAuthMcp.json(), authData)
	const resOidc = await fetch(`http://127.0.0.1:${addr.port}/.well-known/openid-configuration/mcp`)
	assert.equal(resOidc.status, 200)
	assert.deepEqual(await resOidc.json(), authData)
})

test('oauth pkce flow with S256', async () => {
	const { session } = createTestSession({ account: 'pkce@example.com', name: 'PKCE User' })
	const addr = server.address()
	const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
	const challenge = createHash('sha256').update(verifier).digest('base64url')
	const codeMissing = db.tokens.createAuthCode({
		userId: session.userId,
		clientRedirectUri: 'https://chatgpt.com/callback',
		codeChallenge: challenge,
		codeChallengeMethod: 'S256'
	})
	const missingVerifierRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: codeMissing,
			redirect_uri: 'https://chatgpt.com/callback',
			grant_type: 'authorization_code'
		}).toString()
	})
	assert.equal(missingVerifierRes.status, 400)
	const missingData = await missingVerifierRes.json()
	assert.equal(missingData.error_description, 'Missing code_verifier')
	const codeWrong = db.tokens.createAuthCode({
		userId: session.userId,
		clientRedirectUri: 'https://chatgpt.com/callback',
		codeChallenge: challenge,
		codeChallengeMethod: 'S256'
	})
	const wrongVerifierRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: codeWrong,
			redirect_uri: 'https://chatgpt.com/callback',
			code_verifier: 'wrong-verifier-length-must-be-at-least-43-chars-long'
		}).toString()
	})
	assert.equal(wrongVerifierRes.status, 400)
	const wrongData = await wrongVerifierRes.json()
	assert.equal(wrongData.error_description, 'Invalid code_verifier')
	const codeSuccess = db.tokens.createAuthCode({
		userId: session.userId,
		clientRedirectUri: 'https://chatgpt.com/callback',
		codeChallenge: challenge,
		codeChallengeMethod: 'S256'
	})
	const successRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: codeSuccess,
			redirect_uri: 'https://chatgpt.com/callback',
			code_verifier: verifier
		}).toString()
	})
	assert.equal(successRes.status, 200)
	const successData = await successRes.json()
	assert.ok(successData.access_token)
	assert.equal(db.tokens.getByToken(successData.access_token)?.userId, session.userId)
})

test('isAllowedRedirectUri exact and wildcard matching', () => {
	assert.equal(isAllowedRedirectUri('https://chatgpt.com/callback'), true)
	assert.equal(isAllowedRedirectUri('https://foo.chatgpt.com/callback'), false)
	assert.equal(isAllowedRedirectUri('http://localhost:3000/cb'), true)
	assert.equal(isAllowedRedirectUri('https://localhost:3000/cb'), true)
	assert.equal(isAllowedRedirectUri('http://127.0.0.1:8080/cb'), true)
	assert.equal(isAllowedRedirectUri('http://[::1]:8080/cb'), true)
	assert.equal(isAllowedRedirectUri('custom://localhost/cb'), false)
	assert.equal(isAllowedRedirectUri('https://antigravity.google/oauth-callback'), true)
	assert.equal(isAllowedRedirectUri('https://sub.antigravity.google/oauth-callback'), true)
	assert.equal(isAllowedRedirectUri('antigravity://auth-callback'), true)
	assert.equal(isAllowedRedirectUri('cursor://anyscheme/callback'), true)
	assert.equal(isAllowedRedirectUri('vscode://callback'), true)
	assert.equal(isAllowedRedirectUri('https://evil.com/callback'), false)
	assert.equal(isAllowedRedirectUri('malicious://callback'), false)
	assert.equal(isAllowedRedirectUri(''), false)
	assert.equal(isAllowedRedirectUri(null), false)
	const prev = process.env.ALLOWED_REDIRECT_DOMAINS
	delete process.env.ALLOWED_REDIRECT_DOMAINS
	try {
		assert.equal(isAllowedRedirectUri('http://127.0.0.1:4321/cb'), true)
		assert.equal(isAllowedRedirectUri('https://chatgpt.com/callback'), false)
		assert.equal(isAllowedRedirectUri('https://antigravity.google/oauth-callback'), false)
		assert.equal(isAllowedRedirectUri('antigravity://auth-callback'), false)
	} finally {
		process.env.ALLOWED_REDIRECT_DOMAINS = prev
	}
})

test('oauth pkce authorize endpoint validation and stateless rendering', async () => {
	const addr = server.address()
	const methodWithoutChallengeRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?code_challenge_method=S256`)
	assert.equal(methodWithoutChallengeRes.status, 400)
	const methodWithoutChallengeData = await methodWithoutChallengeRes.json()
	assert.equal(methodWithoutChallengeData.error, 'invalid_request')
	const unsupportedMethodRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?code_challenge=xyz&code_challenge_method=unsupported`)
	assert.equal(unsupportedMethodRes.status, 400)
	const unsupportedMethodData = await unsupportedMethodRes.json()
	assert.equal(unsupportedMethodData.error, 'invalid_request')
	const plainMethodRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?code_challenge=xyz&code_challenge_method=plain`)
	assert.equal(plainMethodRes.status, 400)
	const plainMethodData = await plainMethodRes.json()
	assert.equal(plainMethodData.error, 'invalid_request')
	const unauthorizedRedirectRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?redirect_uri=https://evil.com/callback&code_challenge=xyz`)
	assert.equal(unauthorizedRedirectRes.status, 400)
	const unauthorizedRedirectData = await unauthorizedRedirectRes.json()
	assert.equal(unauthorizedRedirectData.error, 'invalid_request')
	assert.match(unauthorizedRedirectData.error_description, /redirect_uri is not allowed/)
	const missingPkceRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?redirect_uri=https://chatgpt.com/callback`)
	assert.equal(missingPkceRes.status, 400)
	const missingPkceData = await missingPkceRes.json()
	assert.equal(missingPkceData.error, 'invalid_request')
	assert.match(missingPkceData.error_description, /code_challenge required/)
	const countBefore = db.sqlite.prepare("SELECT COUNT(*) AS count FROM tokens WHERE type = 'oauth_state'").get().count
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const authRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?redirect_uri=https://chatgpt.com/callback&state=test-state&code_challenge=${challenge}&code_challenge_method=S256`)
	assert.equal(authRes.status, 200)
	assert.equal(authRes.headers.get('content-type'), 'text/html; charset=utf-8')
	const countAfter = db.sqlite.prepare("SELECT COUNT(*) AS count FROM tokens WHERE type = 'oauth_state'").get().count
	assert.equal(countAfter, countBefore, 'GET /oauth/authorize must not write oauth_state rows')
	const authHtml = await authRes.text()
	assert.match(authHtml, /"redirect_uri":"https:\/\/chatgpt\.com\/callback"/)
	assert.match(authHtml, /"state":"test-state"/)
	assert.match(authHtml, /"code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"/)
	assert.match(authHtml, /"code_challenge_method":"S256"/)
	assert.doesNotMatch(authHtml, /consent_token/)
})

test('oauth consent html page, post consent, callback login, and scanner-safe two-step verify flow', async () => {
	const addr = server.address()
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const pageRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?redirect_uri=https://chatgpt.com/callback&state=client-state-123&code_challenge=${challenge}&code_challenge_method=S256`)
	assert.equal(pageRes.status, 200)
	assert.equal(pageRes.headers.get('content-type'), 'text/html; charset=utf-8')
	const html = await pageRes.text()
	assert.match(html, /Generate bearer token/)
	assert.match(html, /action="\/oauth\/authorize\/consent"/)
	assert.match(html, /"redirect_uri":"https:\/\/chatgpt\.com\/callback"/)
	assert.match(html, /"state":"client-state-123"/)
	const consentBody = new URLSearchParams({
		provider: 'google',
		redirect_uri: 'https://chatgpt.com/callback',
		state: 'client-state-123',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		session_name: 'Coding Agent'
	})
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 302)
	const googleAuthUrl = new URL(consentRes.headers.get('location'))
	assert.equal(googleAuthUrl.hostname, 'accounts.google.com')
	assert.equal(googleAuthUrl.searchParams.get('access_type'), null, 'Login redirect must not request offline refresh tokens')
	assert.equal(googleAuthUrl.searchParams.get('prompt'), null, 'Login redirect must not force consent prompt')
	const loginStateToken = googleAuthUrl.searchParams.get('state')
	assert.ok(loginStateToken)
	const stateObj = db.tokens.getState(loginStateToken)
	assert.equal(stateObj.mode, 'login')
	assert.equal(stateObj.clientRedirectUri, 'https://chatgpt.com/callback')
	assert.equal(stateObj.sessionName, 'Coding Agent')
	const origFetch = globalThis.fetch
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.login', token_type: 'Bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: 'agent@example.com' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	let directLocation
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=google-auth-code&state=${loginStateToken}`, { redirect: 'manual' })
		assert.equal(cbRes.status, 302)
		directLocation = cbRes.headers.get('location')
	} finally {
		globalThis.fetch = origFetch
	}
	const directUrl = new URL(directLocation)
	assert.equal(directUrl.hostname, 'chatgpt.com', 'User with 0 apps skips /oauth/verify and redirects directly to clientRedirectUri')
	assert.equal(directUrl.searchParams.get('state'), 'client-state-123')
	const code = directUrl.searchParams.get('code')
	assert.ok(code)
	const agentUser = db.logins.findUserByAccount('agent@example.com')
	const unexchangedSessions = db.tokens.listByUserId(agentUser.id, { provider: 'self' })
	assert.deepEqual(unexchangedSessions, [], 'No bearer session exists before /oauth/token exchange')
	assert.equal(db.sqlite.prepare("SELECT COUNT(*) AS count FROM tokens WHERE user_id = ? AND type = 'bearer'").get(agentUser.id).count, 0, 'Unexchanged OAuth flow must not create bearer row until /oauth/token')
	const codeRow = db.sqlite.prepare("SELECT * FROM tokens WHERE id = ? AND type = 'oauth_code'").get(code)
	assert.equal(codeRow.user_id, agentUser.id)
	assert.equal(codeRow.name, 'Coding Agent')
	assert.ok(codeRow.expires_at > Date.now(), 'oauth_code must have 10m expiresAt')
	const connectedApp = db.tokens.create({
		userId: agentUser.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Agent Stripe',
		credentials: { apiKey: 'sk_agent', baseUrl: 'https://api.stripe.com' }
	})
	const secondConsentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	const secondLoginState = new URL(secondConsentRes.headers.get('location')).searchParams.get('state')
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.login2', token_type: 'Bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: 'agent@example.com' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	let verifyLocation
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=google-auth-code&state=${secondLoginState}`, { redirect: 'manual' })
		assert.equal(cbRes.status, 302)
		verifyLocation = cbRes.headers.get('location')
	} finally {
		globalThis.fetch = origFetch
	}
	const verifyUrl = new URL(verifyLocation)
	assert.equal(verifyUrl.pathname, '/oauth/verify', 'User with connected apps redirects to /oauth/verify')
	const verifyCode = verifyUrl.searchParams.get('code')
	assert.ok(verifyCode)
	assert.equal(db.tokens.getState(verifyCode).mode, 'verify')
	const getVerifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${verifyCode}`, {
		redirect: 'manual'
	})
	assert.equal(getVerifyRes.status, 200)
	assert.equal(getVerifyRes.headers.get('content-type'), 'text/html; charset=utf-8')
	const getVerifyHtml = await getVerifyRes.text()
	assert.match(getVerifyHtml, /<form method="POST" action="\/oauth\/verify">/)
	assert.ok(db.tokens.getState(verifyCode), 'GET /oauth/verify must not consume verify state')
	const postVerifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: verifyCode, app_id: connectedApp.id }).toString(),
		redirect: 'manual'
	})
	assert.equal(postVerifyRes.status, 302)
	const targetUrl = new URL(postVerifyRes.headers.get('location'))
	assert.equal(targetUrl.hostname, 'chatgpt.com')
	assert.equal(targetUrl.searchParams.get('state'), 'client-state-123')
	assert.ok(targetUrl.searchParams.get('code'))
	assert.equal(db.tokens.getState(verifyCode), null, 'POST /oauth/verify must consume verify state')
	assert.deepEqual(db.links.listByAppId(connectedApp.id), [], 'App links must not be created until /oauth/token exchanges the auth code')
})

test('direct browser authorize without redirect_uri', async () => {
	const addr = server.address()
	const pageRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize`)
	assert.equal(pageRes.status, 200)
	assert.equal(pageRes.headers.get('content-type'), 'text/html; charset=utf-8')
	const html = await pageRes.text()
	assert.match(html, /Generate bearer token/)
	assert.match(html, /action="\/oauth\/authorize\/consent"/)
	const consentBody = new URLSearchParams({
		provider: 'google',
		session_name: 'Browser Session'
	})
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 302)
	const loginStateToken = new URL(consentRes.headers.get('location')).searchParams.get('state')
	const stateObj = db.tokens.getState(loginStateToken)
	assert.equal(stateObj.sessionName, 'Browser Session')
	const origFetch = globalThis.fetch
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.browser', token_type: 'Bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: 'browser@example.com' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	let verifyText
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=browser-code&state=${loginStateToken}`, { redirect: 'manual' })
		assert.equal(cbRes.status, 200, 'Direct browser login with 0 apps returns token directly without /oauth/verify hop')
		verifyText = await cbRes.text()
	} finally {
		globalThis.fetch = origFetch
	}
	assert.match(verifyText, /user: browser@example\.com/)
	assert.match(verifyText, /Authorization: Bearer/)
	const browserUser = db.logins.findUserByAccount('browser@example.com')
	const browserSessions = db.tokens.listByUserId(browserUser.id, { provider: 'self' })
	assert.equal(browserSessions.length, 1)
	assert.equal(browserSessions[0].expiresAt, null, 'Direct browser login without redirect_uri must have expiresAt: null')
})

test('google provider connect screen and consent flow', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'connect-flow@example.com', admin: true })
	const { session: workerSession, app: nonSelfToken } = createTestSession({ account: 'nonself-consent@example.com', admin: false })
	const connectRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/connect?session_id=${session.id}`)
	assert.equal(connectRes.status, 200)
	const connectHtml = await connectRes.text()
	assert.match(connectHtml, /Configure API services access/)
	assert.match(connectHtml, /Sign in with Google/)
	assert.match(connectHtml, /action="\/providers\/google\/consent"/)
	const invalidSessionConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ session_id: 'non-existent-session' }).toString(),
		redirect: 'manual'
	})
	assert.equal(invalidSessionConsentRes.status, 403)
	const nonSelfConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ session_id: nonSelfToken.id }).toString(),
		redirect: 'manual'
	})
	assert.equal(nonSelfConsentRes.status, 403)
	const nonAdminInitialConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ session_id: workerSession.id }).toString(),
		redirect: 'manual'
	})
	assert.equal(nonAdminInitialConsentRes.status, 403)
	const consentBody = new URLSearchParams({
		session_id: session.id,
		app_name: 'Custom Work Google'
	})
	consentBody.append('services', 'drive')
	consentBody.append('services', 'calendar')
	consentBody.append('write', 'calendar')
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 302)
	const location = consentRes.headers.get('location')
	const targetUrl = new URL(location)
	assert.equal(targetUrl.hostname, 'accounts.google.com')
	assert.match(targetUrl.searchParams.get('scope'), /drive\.readonly/)
	assert.match(targetUrl.searchParams.get('scope'), /calendar\b/)
	assert.doesNotMatch(targetUrl.searchParams.get('scope'), /gmail/)
	const stateParam = targetUrl.searchParams.get('state')
	assert.ok(stateParam)
	const stateRow = db.tokens.consumeState(stateParam)
	assert.equal(stateRow.sessionId, session.id)
	assert.equal(stateRow.sessionName, 'Custom Work Google')
	assert.equal(stateRow.provider, 'google')
})

test('provider connect page with repeated query parameters', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/providers/google/connect?services=drive&services=calendar&write=drive&write=calendar`)
	assert.equal(res.status, 200)
	const html = await res.text()
	assert.match(html, /"services":"drive,calendar"/)
	assert.match(html, /"write":"drive,calendar"/)
})

test('cors preflight options request', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'OPTIONS'
	})
	assert.equal(res.status, 204)
	assert.equal(res.headers.get('access-control-allow-origin'), '*')
	assert.match(res.headers.get('access-control-allow-methods'), /POST/)
})

test('not found returns 404 json', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/unknown-route`)
	assert.equal(res.status, 404)
	const data = await res.json()
	assert.equal(data.error, 'not found')
})

test('unknown rpc method returns -32601 error', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'unknown-rpc@example.com' })
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${session.token}`
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 99,
			method: 'nonexistent/method',
			params: {}
		})
	})
	assert.equal(res.status, 200)
	const data = await res.json()
	assert.ok(data.error, 'response should contain an error')
	assert.equal(data.error.code, -32601)
})

test('mcp invalid json returns jsonrpc parse error', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'invalid-json@example.com' })
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${session.token}`
		},
		body: '{"invalid_json'
	})
	const data = await res.json()
	assert.equal(data.jsonrpc, '2.0')
	assert.equal(data.error?.code, -32700)
})

test('mcp non-POST request returns 405 Method Not Allowed', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'non-post@example.com' })
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'GET',
		headers: { authorization: `Bearer ${session.token}` }
	})
	assert.equal(res.status, 405)
	const data = await res.json()
	assert.equal(data.error, 'Method Not Allowed')
})

test('readResponseBody enforces size limit on streams', async () => {
	const stream = new ReadableStream({
		start (controller) {
			controller.enqueue(new Uint8Array(500))
			controller.enqueue(new Uint8Array(600))
			controller.close()
		}
	})
	const response = new Response(stream)
	await assert.rejects(
		async () => {
			await readResponseBody(response, 1000)
		},
		err => {
			assert.equal(err.status, 413)
			assert.match(err.message, /File too large/)
			return true
		}
	)
	const smallStream = new ReadableStream({
		start (controller) {
			controller.enqueue(new TextEncoder().encode('hello world'))
			controller.close()
		}
	})
	const smallResponse = new Response(smallStream)
	const buf = await readResponseBody(smallResponse, 1000)
	assert.equal(buf.toString(), 'hello world')
})

test('rfc 7009 /oauth/revoke endpoint', async () => {
	const addr = server.address()
	const methodRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'GET'
	})
	assert.equal(methodRes.status, 405)
	const missingRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: ''
	})
	assert.equal(missingRes.status, 400)
	const missingData = await missingRes.json()
	assert.equal(missingData.error, 'invalid_request')
	const nonStringTokenRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ token: 123 })
	})
	assert.equal(nonStringTokenRes.status, 400, 'Non-string token parameter must return 400 invalid_request')
	const nonStringData = await nonStringTokenRes.json()
	assert.equal(nonStringData.error, 'invalid_request')
	const unknownRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: 'nonexistent-token' }).toString()
	})
	assert.equal(unknownRes.status, 200)
	const { session, app: sharedApp } = createTestSession({ account: 'revoke-endpoint@example.com' })
	assert.ok(db.tokens.get(session.id))
	assert.ok(db.tokens.get(sharedApp.id))
	const revokeRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: session.token }).toString()
	})
	assert.equal(revokeRes.status, 200)
	assert.equal(db.tokens.get(session.id), null)
	assert.ok(db.tokens.get(sharedApp.id), 'Revoking a session via /oauth/revoke must not delete shared upstream app credentials')
	const { session: sessionJson } = createTestSession({ account: 'revoke-json@example.com' })
	assert.ok(db.tokens.get(sessionJson.id))
	const revokeJsonRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ token: sessionJson.token })
	})
	assert.equal(revokeJsonRes.status, 200)
	assert.equal(db.tokens.get(sessionJson.id), null)
	const { session: baseRevokeSession, app: refreshSharedApp } = createTestSession({ account: 'revoke-refresh@example.com' })
	const sessionRefreshRevoke = db.tokens.create({
		userId: baseRevokeSession.userId,
		provider: 'self',
		credentials: { refreshToken: 'rt_revoke_expired_access' },
		expiresAt: Date.now() - 5000
	})
	db.links.create({ sessionId: sessionRefreshRevoke.id, appId: refreshSharedApp.id })
	const revokeByRefreshRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: sessionRefreshRevoke.credentials.refreshToken }).toString()
	})
	assert.equal(revokeByRefreshRes.status, 200)
	assert.equal(db.tokens.get(sessionRefreshRevoke.id), null, 'Revoking by refresh_token must delete the session even if access_token expired')
	assert.ok(db.tokens.get(refreshSharedApp.id), 'Revoking by refresh_token must preserve shared upstream app')
})

test('mcp auth whoami, list, and revoke', async () => {
	const user = db.logins.resolveUser('google', 'sessions-tool@example.com')
	const session1 = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1,
		ip: '192.168.1.10',
		ua: 'ClaudeDesktop/1.0'
	})
	const session2 = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 0,
		ip: '10.0.0.5',
		ua: 'ChatGPT/2.0'
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Google Drive',
		scopes: 'https://www.googleapis.com/auth/drive.readonly',
		expiresAt: Date.now() + 3600000
	})
	db.links.create({ sessionId: session1.id, appId: app.id })
	db.links.create({ sessionId: session2.id, appId: app.id })
	const listResult = await executeTool('admin', { action: 'list' }, session1.token)
	assert.equal(listResult.isError, undefined)
	const listParsed = JSON.parse(listResult.content[0].text)
	assert.equal(listParsed.sessions.length, 2)
	const current = listParsed.sessions.find(s => s.isCurrent)
	assert.equal(current.id, session1.id)
	assert.equal(current.ip, '192.168.1.10')
	assert.equal(current.ua, 'ClaudeDesktop/1.0')
	const other = listParsed.sessions.find(s => !s.isCurrent)
	assert.equal(other.id, session2.id)
	assert.equal(other.ip, '10.0.0.5')
	assert.equal(other.ua, 'ChatGPT/2.0')
	const revokeAppAsSessionResult = await api.auth.revoke(session1.token, { sessionId: app.id })
	assert.equal(revokeAppAsSessionResult.revoked, false, 'api.auth.revoke must reject non-self app IDs')
	assert.ok(db.tokens.get(app.id), 'api.auth.revoke must not delete upstream app token')
	const ephemeralCode = db.tokens.createAuthCode({ userId: user.id, clientRedirectUri: 'https://chatgpt.com/callback' })
	const revokeCodeAsSessionResult = await api.auth.revoke(session1.token, { sessionId: ephemeralCode })
	assert.equal(revokeCodeAsSessionResult.revoked, false, 'api.auth.revoke must reject non-bearer self rows (oauth_code / oauth_state)')
	assert.ok(db.tokens.get(ephemeralCode), 'api.auth.revoke must not delete oauth_code row')
	const revokeOtherResult = await executeTool('admin', { action: 'revoke', allOthers: true }, session1.token)
	assert.equal(revokeOtherResult.isError, undefined)
	const revokeOtherParsed = JSON.parse(revokeOtherResult.content[0].text)
	assert.equal(revokeOtherParsed.revoked, true)
	assert.equal(revokeOtherParsed.count, 1)
	assert.equal(db.tokens.get(session2.id), null)
	assert.ok(db.tokens.get(session1.id))
	const revokeCurrentResult = await executeTool('admin', { action: 'revoke' }, session1.token)
	assert.equal(revokeCurrentResult.isError, undefined)
	const revokeCurrentParsed = JSON.parse(revokeCurrentResult.content[0].text)
	assert.equal(revokeCurrentParsed.revoked, true)
	assert.equal(db.tokens.get(session1.id), null)
})

test('matchPattern matching logic', () => {
	assert.equal(matchPattern('*', 'anything'), true)
	assert.equal(matchPattern('**', '/nested/path/to/resource'), true)
	assert.equal(matchPattern('/calendar/v3/calendars/*/events', '/calendar/v3/calendars/work/events'), true)
	assert.equal(matchPattern('/calendar/v3/calendars/*/events', '/calendar/v3/calendars/work/other/events'), false)
	assert.equal(matchPattern('/calendar/v3/calendars/**/events', '/calendar/v3/calendars/work/sub/events'), true)
	assert.equal(matchPattern('/drive/v3/files/*', '/drive/v3/files/file123'), true)
	assert.equal(matchPattern('/drive/v3/files/*', '/drive/v3/files/file123/comments'), false)
	assert.equal(matchPattern('/drive/v3/files/**', '/drive/v3/files/file123/comments'), true)
	assert.equal(matchPattern('/drive/**/files', '/drive/files'), true)
	assert.equal(matchPattern('/drive/**/files', '/drive/v3/files'), true)
	assert.equal(matchPattern('/drive/**/files', '/drive/a/b/files'), true)
	assert.equal(matchPattern('/**/files', '/files'), true)
	assert.equal(matchPattern('/**/files', '/a/files'), true)
	assert.equal(matchPattern('/*/events', '/calendar/events'), true)
	assert.equal(matchPattern('/*/events', '/calendar/work/events'), false)
	assert.equal(matchPattern('/**/events', '/events'), true)
	assert.equal(matchPattern('/**/events', '/calendar/events'), true)
	assert.equal(matchPattern('/**/events', '/calendar/work/events'), true)
	assert.equal(matchPattern('/**/**/**/**/**/**/**/**/**/**/**/**/**/**/**/**/x', '/a/a/a/a/a/a/a/a/a/a/a/a/a'), false)
	assert.equal(matchPattern(null, 'test'), false)
	assert.equal(matchPattern('test', null), false)
	assert.equal(matchPattern('test', undefined), false)
})

test('parsePolicy helper parses valid JSON and returns null for invalid or empty policy', () => {
	const policy = [{ action: 'allow', path: '/**' }]
	assert.deepEqual(parsePolicy(JSON.stringify(policy)), policy)
	assert.deepEqual(parsePolicy(policy), policy)
	assert.equal(parsePolicy(null), null)
	assert.equal(parsePolicy(''), null)
	assert.equal(parsePolicy('invalid-json'), null)
	assert.equal(parsePolicy([{ invalid: 'rule' }]), null)
})

test('evaluatePolicy allows all when policy is null or empty, denies when empty array', () => {
	assert.equal(evaluatePolicy(null, { url: '/calendar/v3/calendars/primary/events', method: 'GET' }).allowed, true)
	assert.equal(evaluatePolicy('', { url: '/calendar/v3/calendars/primary/events', method: 'GET' }).allowed, true)
	assert.equal(evaluatePolicy('[]', { url: '/calendar/v3/calendars/primary/events', method: 'GET' }).allowed, false)
	assert.equal(evaluatePolicy([], { url: '/calendar/v3/calendars/primary/events', method: 'GET' }).allowed, false)
})

test('evaluatePolicy denylist mode with allow-all fallback', () => {
	const policy = [
		{
			action: 'deny',
			methods: ['DELETE']
		},
		{
			action: 'allow'
		}
	]
	assert.equal(evaluatePolicy(policy, { url: '/calendar/v3/calendars/primary/events', method: 'GET' }).allowed, true)
	assert.equal(evaluatePolicy(policy, { url: '/calendar/v3/calendars/primary/events', method: 'POST' }).allowed, true)
	assert.equal(evaluatePolicy(policy, { url: '/calendar/v3/calendars/primary/events/123', method: 'DELETE' }).allowed, false)
})

test('evaluatePolicy sequential evaluation for calendar allowlist (default deny)', () => {
	const policy = [
		{
			action: 'allow',
			methods: ['GET'],
			path: '/calendar/v3/calendars/team-schedule@group.calendar.google.com'
		},
		{
			action: 'allow',
			path: '/calendar/v3/calendars/team-schedule@group.calendar.google.com/events/**'
		}
	]
	const allowedGetCal = evaluatePolicy(policy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/team-schedule@group.calendar.google.com',
		method: 'GET'
	})
	assert.equal(allowedGetCal.allowed, true)
	const deniedDeleteCal = evaluatePolicy(policy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/team-schedule@group.calendar.google.com',
		method: 'DELETE'
	})
	assert.equal(deniedDeleteCal.allowed, false)
	const allowedGetEvents = evaluatePolicy(policy, {
		url: '/calendar/v3/calendars/team-schedule@group.calendar.google.com/events',
		method: 'GET'
	})
	assert.equal(allowedGetEvents.allowed, true)
	const allowedPostEvents = evaluatePolicy(policy, {
		url: '/calendar/v3/calendars/team-schedule@group.calendar.google.com/events',
		method: 'POST'
	})
	assert.equal(allowedPostEvents.allowed, true)
	const allowedDeleteEvents = evaluatePolicy(policy, {
		url: '/calendar/v3/calendars/team-schedule@group.calendar.google.com/events/evt123',
		method: 'DELETE'
	})
	assert.equal(allowedDeleteEvents.allowed, true)
	const deniedOtherCal = evaluatePolicy(policy, {
		url: '/calendar/v3/calendars/other-team@group.calendar.google.com/events',
		method: 'GET'
	})
	assert.equal(deniedOtherCal.allowed, false)
	const allowedEncodedEvents = evaluatePolicy(policy, {
		url: '/calendar/v3/calendars/team-schedule%40group.calendar.google.com/events',
		method: 'GET'
	})
	assert.equal(allowedEncodedEvents.allowed, true)
	const deniedEncodedOtherCal = evaluatePolicy(policy, {
		url: '/calendar/v3/calendars/other-team%40group.calendar.google.com/events',
		method: 'GET'
	})
	assert.equal(deniedEncodedOtherCal.allowed, false)
})

test('evaluatePolicy matches relative paths and origin-scoped rules without google default', () => {
	const relPolicy = [
		{ action: 'allow', path: 'calendar/**' }
	]
	assert.equal(evaluatePolicy(relPolicy, { url: '/drive/v3/files/123', method: 'GET' }).allowed, false)
	assert.equal(evaluatePolicy(relPolicy, { url: '/calendar/v3/calendars', method: 'GET' }).allowed, true)
	const originPolicy = [
		{ action: 'allow', origin: 'https://sheets.googleapis.com', path: '/v4/spreadsheets/**' }
	]
	assert.equal(evaluatePolicy(originPolicy, { url: 'https://sheets.googleapis.com/v4/spreadsheets/123', method: 'GET' }).allowed, true)
	assert.equal(evaluatePolicy(originPolicy, { url: 'https://docs.googleapis.com/v4/spreadsheets/123', method: 'GET' }).allowed, false)
	assert.equal(evaluatePolicy(originPolicy, { url: 'https://www.googleapis.com/drive/v3/files', method: 'GET' }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'allow', origin: 'https://www.googleapis.com', path: '/drive/**' }], { url: '/drive/v3/files', method: 'GET' }).allowed, false, 'Bare path without baseUrl must not default to googleapis.com')
	const traversalResult = evaluatePolicy(originPolicy, { url: 'https://sheets.googleapis.com/v4/spreadsheets/public/%2e%2e/secret', method: 'GET' })
	assert.equal(traversalResult.allowed, false)
	assert.match(traversalResult.reason, /path traversal/i)
})

test('evaluatePolicy matches URLs with query parameters in url string', () => {
	const sheetPolicy = [
		{ action: 'allow', origin: 'https://sheets.googleapis.com', path: '/v4/spreadsheets/123' }
	]
	assert.equal(evaluatePolicy(sheetPolicy, { url: 'https://sheets.googleapis.com/v4/spreadsheets/123?includeGridData=true' }).allowed, true)
})

test('executeTool google_api enforces link policy and auth tools decode policy', async () => {
	const policyObj = [
		{
			action: 'deny',
			methods: ['DELETE'],
			description: 'Deletions are forbidden'
		},
		{
			action: 'allow',
			path: '/calendar/v3/calendars/work/**'
		}
	]
	const { session } = createTestSession({
		account: 'policy-test@example.com',
		admin: true,
		policy: policyObj
	})
	const statusRes = await executeTool('admin', { action: 'whoami' }, session.token)
	assert.equal(statusRes.isError, undefined)
	const statusParsed = JSON.parse(statusRes.content[0].text)
	assert.deepEqual(statusParsed.session.apps[0].policy, policyObj)
	const listRes = await executeTool('admin', { action: 'list' }, session.token)
	assert.equal(listRes.isError, undefined)
	const listParsed = JSON.parse(listRes.content[0].text)
	const foundSession = listParsed.sessions.find(s => s.id === session.id)
	assert.deepEqual(foundSession.apps[0].policy, policyObj)
	const deniedDeleteRes = await executeTool('google_api', {
		url: 'https://www.googleapis.com/calendar/v3/calendars/work/events/123',
		method: 'DELETE'
	}, session.token)
	assert.equal(deniedDeleteRes.isError, true)
	assert.match(deniedDeleteRes.content[0].text, /Policy violation/)
	assert.match(deniedDeleteRes.content[0].text, /Deletions are forbidden/)
	const deniedPathRes = await executeTool('google_api', {
		url: 'https://www.googleapis.com/calendar/v3/calendars/personal/events',
		method: 'GET'
	}, session.token)
	assert.equal(deniedPathRes.isError, true)
	assert.match(deniedPathRes.content[0].text, /Policy violation/)
	assert.match(deniedPathRes.content[0].text, /did not match any allow rule/)
})

test('validatePolicy validates schema and fails fast on errors', () => {
	assert.equal(validatePolicy(null).valid, true)
	assert.equal(validatePolicy('').valid, true)
	assert.equal(validatePolicy('[]').valid, true)
	assert.equal(validatePolicy([]).valid, true)
	assert.equal(validatePolicy('not json').valid, false)
	assert.match(validatePolicy('not json').error, /Invalid JSON policy/)
	assert.equal(validatePolicy('{}').valid, false)
	assert.match(validatePolicy('{}').error, /Policy must be a JSON array of rules/)
	assert.equal(validatePolicy({ rules: [] }).valid, false)
	assert.match(validatePolicy({ rules: [] }).error, /Policy must be a JSON array of rules/)
	assert.equal(validatePolicy(['not-an-object']).valid, false)
	assert.match(validatePolicy(['not-an-object']).error, /Rule at index 0 must be an object/)
	assert.equal(validatePolicy([{ action: 'invalid' }]).valid, false)
	assert.match(validatePolicy([{ action: 'invalid' }]).error, /Rule at index 0 action must be "allow" or "deny"/)
	assert.equal(validatePolicy([{ action: 'allow', method: 'GET' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', method: 'GET' }]).error, /Rule at index 0 has unknown property "method"/)
	assert.equal(validatePolicy([{ action: 'allow', methods: 'GET' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', methods: 'GET' }]).error, /methods must be an array of HTTP method strings/)
	assert.equal(validatePolicy([{ action: 'allow', methods: [] }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', methods: [] }]).error, /methods must be an array of HTTP method strings/)
	assert.equal(validatePolicy([{ action: 'allow', methods: ['INVALID_VERB'] }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', methods: ['INVALID_VERB'] }]).error, /contains invalid HTTP method "INVALID_VERB"/)
	assert.equal(validatePolicy([{ action: 'allow', origin: 123 }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', origin: 123 }]).error, /Rule at index 0 origin must be an HTTPS origin/)
	assert.equal(validatePolicy([{ action: 'allow', origin: 'sheets.googleapis.com' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', origin: 'sheets.googleapis.com' }]).error, /Rule at index 0 origin must be an HTTPS origin/)
	assert.equal(validatePolicy([{ action: 'allow', origin: 'https://sheets.googleapis.com/v4' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', origin: 'https://sheets.googleapis.com/v4' }]).error, /must not contain a path or query/)
	assert.equal(validatePolicy([{ action: 'allow', path: 123 }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', path: 123 }]).error, /Rule at index 0 path must be a non-empty string/)
	assert.equal(validatePolicy([{ action: 'allow', path: '' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', path: '' }]).error, /Rule at index 0 path must be a non-empty string/)
	assert.equal(validatePolicy([{ action: 'allow', path: '   ' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', path: '   ' }]).error, /Rule at index 0 path must be a non-empty string/)
	assert.equal(validatePolicy([{ action: 'allow', path: '/drive/v3/files?q=*' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', path: '/drive/v3/files?q=*' }]).error, /Rule at index 0 path must not contain query parameters/)
	assert.equal(validatePolicy([{ action: 'allow', path: 'https://sheets.googleapis.com/v4/**' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', path: 'https://sheets.googleapis.com/v4/**' }]).error, /use "origin" to specify hostnames/)
	assert.equal(validatePolicy([{ action: 'allow', description: 123 }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', description: 123 }]).error, /Rule at index 0 description must be a string/)
	const validPolicy = [
		{ action: 'allow', methods: ['GET'], origin: 'https://sheets.googleapis.com', path: '/v4/**', query: { includeGridData: ['false', null] }, description: 'Allow sheets GET' },
		{ action: 'allow', methods: ['POST'], path: '/v1/messages', body: { channel: 'C123*', 'recipient.email': ['*@company.com', 'admin@example.org'], urgent: false, retries: 3, debug: null, mode: ['ok', null] } },
		{ action: 'deny' }
	]
	assert.equal(validatePolicy(validPolicy).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', origin: 'https://sheets.googleapis.com/' }]).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', query: null }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', query: null }]).error, /query must be a non-empty object/)
	assert.equal(validatePolicy([{ action: 'allow', query: [] }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', query: [] }]).error, /query must be a non-empty object/)
	assert.equal(validatePolicy([{ action: 'allow', query: {} }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', query: {} }]).error, /query must be a non-empty object/)
	assert.equal(validatePolicy([{ action: 'allow', query: { '': 'val' } }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', query: { '': 'val' } }]).error, /query field key must be a non-empty string/)
	assert.equal(validatePolicy([{ action: 'allow', query: { param: [] } }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', query: { param: [] } }]).error, /query field "param" must be a primitive or non-empty array of primitives/)
	assert.equal(validatePolicy([{ action: 'allow', query: { param: { nested: 'obj' } } }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', query: { param: { nested: 'obj' } } }]).error, /query field "param" must be a primitive or non-empty array of primitives/)
	assert.equal(validatePolicy([{ action: 'allow', query: { param: undefined } }]).valid, false)
	assert.equal(validatePolicy([{ action: 'allow', body: null }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: null }]).error, /body must be a non-empty object/)
	assert.equal(validatePolicy([{ action: 'allow', body: [] }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: [] }]).error, /body must be a non-empty object/)
	assert.equal(validatePolicy([{ action: 'allow', body: {} }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: {} }]).error, /body must be a non-empty object/)
	assert.equal(validatePolicy([{ action: 'allow', body: { '': 'val' } }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: { '': 'val' } }]).error, /body field key must be a non-empty string/)
	assert.equal(validatePolicy([{ action: 'allow', body: { field: [] } }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: { field: [] } }]).error, /body field "field" must be a primitive or non-empty array of primitives/)
	assert.equal(validatePolicy([{ action: 'allow', body: { field: { nested: 'obj' } } }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: { field: { nested: 'obj' } } }]).error, /body field "field" must be a primitive or non-empty array of primitives/)
	assert.equal(validatePolicy([{ action: 'allow', body: { field: ['ok', undefined] } }]).valid, false)
})

test('evaluatePolicy matches request body fields (nested dot-paths, arrays, JSON string, form-urlencoded)', () => {
	const policy = [
		{
			action: 'deny',
			methods: ['POST'],
			path: '/v1/charges',
			body: { currency: 'btc' },
			description: 'Crypto charges forbidden'
		},
		{
			action: 'allow',
			methods: ['POST'],
			path: '/v1/messages',
			body: {
				channel: ['C_PUBLIC_*', 'C_TEAM'],
				'recipient.email': '*@example.com'
			}
		},
		{
			action: 'allow',
			methods: ['POST'],
			path: '/v1/charges',
			body: {
				'metadata.env': 'staging',
				capture: true
			}
		}
	]
	assert.equal(evaluatePolicy(policy, {
		url: 'https://api.slack.com/v1/messages',
		method: 'POST',
		body: { channel: 'C_PUBLIC_123', recipient: { email: 'alice@example.com' } }
	}).allowed, true)
	assert.equal(evaluatePolicy(policy, {
		url: 'https://api.slack.com/v1/messages',
		method: 'POST',
		body: JSON.stringify({ channel: 'C_TEAM', 'recipient.email': 'bob@example.com' })
	}).allowed, true)
	assert.equal(evaluatePolicy(policy, {
		url: 'https://api.slack.com/v1/messages',
		method: 'POST',
		body: { channel: 'C_PRIVATE', recipient: { email: 'alice@example.com' } }
	}).allowed, false)
	assert.equal(evaluatePolicy(policy, {
		url: 'https://api.slack.com/v1/messages',
		method: 'POST',
		body: { channel: 'C_TEAM', recipient: { email: 'alice@evil.com' } }
	}).allowed, false)
	assert.equal(evaluatePolicy(policy, {
		url: 'https://api.slack.com/v1/messages',
		method: 'POST'
	}).allowed, false)
	const denyCrypto = evaluatePolicy(policy, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: 'currency=btc&amount=1000'
	})
	assert.equal(denyCrypto.allowed, false)
	assert.equal(denyCrypto.reason, 'Crypto charges forbidden')
	assert.equal(evaluatePolicy(policy, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: { metadata: { env: 'staging' }, capture: true }
	}).allowed, true)
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/tags', body: { tags: ['urgent-*', 'normal'] } }
	], {
		url: 'https://api.example.com/v1/tags',
		method: 'POST',
		body: { tags: ['normal', 'urgent-fix'] }
	}).allowed, true, 'Array body value must be allowed when every element matches at least one pattern')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/tags', body: { tags: 'urgent-*' } }
	], {
		url: 'https://api.example.com/v1/tags',
		method: 'POST',
		body: { tags: ['normal', 'urgent-fix'] }
	}).allowed, false, 'Array body value must be denied when any element fails to match')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/tags', body: { tags: 'urgent-*' } }
	], {
		url: 'https://api.example.com/v1/tags',
		method: 'POST',
		body: { tags: [] }
	}).allowed, false, 'Empty array body value must be denied')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null], debug: null } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: { summary: 'Meeting' }
	}).allowed, true, 'Absent body fields match null or pattern array containing null')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null], debug: null } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: { summary: 'Meeting', sendUpdates: 'none', debug: null }
	}).allowed, true, 'Explicit null or allowed value in body matches pattern array containing null')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null], debug: null } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: { summary: 'Meeting', sendUpdates: 'all' }
	}).allowed, false, 'Disallowed value in body is denied even when null is allowed')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST'
	}).allowed, true, 'Missing req.body defaults to empty object and matches null body rule')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: '<xml>unparseable</xml>'
	}).allowed, false, 'Unparseable non-empty body does not match null body rule')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/proto', body: { toString: '*' } }
	], {
		url: 'https://api.example.com/v1/proto',
		method: 'POST',
		body: {}
	}).allowed, false, 'Prototype property toString must not match on empty object')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/proto', body: { constructor: '*' } }
	], {
		url: 'https://api.example.com/v1/proto',
		method: 'POST',
		body: {}
	}).allowed, false, 'Prototype property constructor must not match on empty object')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/proto', body: { 'nested.valueOf': '*' } }
	], {
		url: 'https://api.example.com/v1/proto',
		method: 'POST',
		body: { nested: {} }
	}).allowed, false, 'Nested prototype property must not match')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/proto', body: { toString: 'hello' } }
	], {
		url: 'https://api.example.com/v1/proto',
		method: 'POST',
		body: 'toString=hello&other=1'
	}).allowed, true, 'Form-urlencoded key named toString must parse cleanly as own property')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/slash', body: { text: 'hello*world', mime: 'application/*' } }
	], {
		url: 'https://api.example.com/v1/slash',
		method: 'POST',
		body: { text: 'hello/cruel/world', mime: 'application/json' }
	}).allowed, true, 'Single star in body value pattern must match across slashes')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/xml', body: { '<?xml version': '"1.0"?>' } }
	], {
		url: 'https://api.example.com/xml',
		method: 'POST',
		body: '<?xml version="1.0"?><request><action>transfer</action></request>'
	}).allowed, false, 'XML string body must not be misparsed as URLSearchParams')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' } },
		{ action: 'allow' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '<x>=1&currency=btc',
		contentType: 'application/x-www-form-urlencoded'
	}).allowed, false, 'Form-urlencoded string starting with < must still be evaluated against body deny rules')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' } },
		{ action: 'allow' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '<x>=1&currency=btc'
	}).allowed, false, 'Form-urlencoded string starting with < without explicit contentType must still match body deny rules')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: '[{"a":"1=2"}]'
	}).allowed, false, 'JSON array string containing = must not fall through to URLSearchParams and match null body rule')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: '{"broken": "a=b"',
		contentType: 'application/json'
	}).allowed, false, 'Malformed JSON string must not fall through to URLSearchParams')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: 'foo=bar',
		contentType: 'text/plain'
	}).allowed, false, 'Non-form/non-JSON contentType must not parse string body as URL-encoded')
})

test('evaluatePolicy matches URL query parameters (exact, glob, null absence, optional array, repeated params)', () => {
	const calendarPolicy = [
		{
			action: 'allow',
			methods: ['GET'],
			path: '/calendar/v3/calendars/primary/events',
			query: {
				singleEvents: 'true',
				orderBy: ['startTime', 'updated']
			}
		},
		{
			action: 'allow',
			methods: ['POST', 'PATCH', 'DELETE'],
			path: '/calendar/v3/calendars/primary/events/**',
			query: {
				sendUpdates: ['none', null],
				conferenceDataVersion: null
			}
		}
	]
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events?singleEvents=true&orderBy=startTime',
		method: 'GET'
	}).allowed, true)
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events?singleEvents=true&orderBy=invalid',
		method: 'GET'
	}).allowed, false)
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
		method: 'GET'
	}).allowed, false, 'Required non-null query parameters must reject URL without query string')
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events/evt123',
		method: 'DELETE'
	}).allowed, true, 'URL without query string matches query rules allowing null')
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events/evt123?sendUpdates=none',
		method: 'DELETE'
	}).allowed, true, 'URL with allowed query parameter value matches')
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events/evt123?sendUpdates=all',
		method: 'DELETE'
	}).allowed, false, 'URL with disallowed query parameter value is denied')
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events/evt123?sendUpdates=none&sendUpdates=all',
		method: 'DELETE'
	}).allowed, false, 'Repeated query parameter must fail when any value is disallowed (.every semantics)')
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events/evt123?sendUpdates=none&sendUpdates=none',
		method: 'DELETE'
	}).allowed, true, 'Repeated query parameter succeeds when every value matches')
	assert.equal(evaluatePolicy(calendarPolicy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events/evt123?conferenceDataVersion=1',
		method: 'POST'
	}).allowed, false, 'Query parameter constrained to standalone null must reject any present value')
	assert.equal(evaluatePolicy([
		{ action: 'allow', path: '/search', query: { q: 'project-*', toString: null } }
	], {
		url: 'https://api.example.com/search?q=project-alpha',
		method: 'GET'
	}).allowed, true, 'Glob pattern and prototype key with null work cleanly on query object')
})

test('rest api /api/whoami, /api/sessions, and /api/sessions/:id', async () => {
	const addr = server.address()
	const unauthRes = await fetch(`http://127.0.0.1:${addr.port}/api/whoami`)
	assert.equal(unauthRes.status, 200)
	const unauthData = await unauthRes.json()
	assert.equal(unauthData.authenticated, false)
	assert.match(unauthData.signInUrl, /\/oauth\/authorize/)
	const unauthSessions = await fetch(`http://127.0.0.1:${addr.port}/api/sessions`)
	assert.equal(unauthSessions.status, 401)
	const user = db.logins.resolveUser('google', 'rest-test@example.com')
	const session1 = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1,
		ip: '127.0.0.1',
		ua: 'TestClient/1.0'
	})
	const session2 = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 0
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Google Rest App'
	})
	db.links.create({ sessionId: session1.id, appId: app.id })
	db.links.create({ sessionId: session2.id, appId: app.id })
	const whoamiRes = await fetch(`http://127.0.0.1:${addr.port}/api/whoami`, {
		headers: { authorization: `Bearer ${session1.token}` }
	})
	assert.equal(whoamiRes.status, 200)
	const whoamiData = await whoamiRes.json()
	assert.equal(whoamiData.authenticated, true)
	assert.equal(whoamiData.user.id, user.id)
	assert.equal(whoamiData.user.account, 'rest-test@example.com')
	assert.equal(whoamiData.session.id, session1.id)
	const listRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions`, {
		headers: { authorization: `Bearer ${session1.token}` }
	})
	assert.equal(listRes.status, 200)
	const listData = await listRes.json()
	assert.equal(listData.sessions.length, 2)
	const getRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions/${session2.id}`, {
		headers: { authorization: `Bearer ${session1.token}` }
	})
	assert.equal(getRes.status, 200)
	const getData = await getRes.json()
	assert.equal(getData.session.id, session2.id)
	assert.equal(getData.session.token, undefined)
	const invalidJsonRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions`, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${session1.token}`,
			'content-type': 'application/json'
		},
		body: '{bad-json'
	})
	assert.equal(invalidJsonRes.status, 400)
	const delSpecificRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions/${session2.id}`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${session1.token}` }
	})
	assert.equal(delSpecificRes.status, 200)
	const delData = await delSpecificRes.json()
	assert.equal(delData.revoked, true)
	assert.equal(db.tokens.get(session2.id), null)
	const delAllRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${session1.token}` }
	})
	assert.equal(delAllRes.status, 200)
	assert.equal(db.tokens.get(session1.id), null)
})

test('mcp admin tool with whoami and get actions', async () => {
	const { user, session } = createTestSession({ account: 'mcp-whoami@example.com' })
	const whoamiResult = await executeTool('admin', { action: 'whoami' }, session.token)
	assert.equal(whoamiResult.isError, undefined)
	const parsedWhoami = JSON.parse(whoamiResult.content[0].text)
	assert.equal(parsedWhoami.authenticated, true)
	assert.equal(parsedWhoami.user.id, user.id)
	assert.equal(parsedWhoami.user.account, 'mcp-whoami@example.com')
	assert.equal(parsedWhoami.session.id, session.id)
	const getResult = await executeTool('admin', { action: 'get', sessionId: session.id }, session.token)
	assert.equal(getResult.isError, undefined)
	const parsedGet = JSON.parse(getResult.content[0].text)
	assert.equal(parsedGet.session.id, session.id)
	assert.equal(parsedGet.session.token, undefined)
})

test('transparent rest proxy /api/google/*', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'rest-proxy@example.com' })
	const notFoundRes = await fetch(`http://127.0.0.1:${addr.port}/api/google`, {
		headers: { authorization: `Bearer ${session.token}` }
	})
	assert.equal(notFoundRes.status, 404)
	const unauthRes = await fetch(`http://127.0.0.1:${addr.port}/api/google/drive/v3/files`)
	assert.equal(unauthRes.status, 401)
	const forbiddenDomainRes = await fetch(`http://127.0.0.1:${addr.port}/api/google/https://evil.com/leak`, {
		headers: { authorization: `Bearer ${session.token}` }
	})
	assert.equal(forbiddenDomainRes.status, 403)
})

test('mcp tools/list filtering based on session admin status', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'mcp-tools-filter@example.com')
	const adminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1
	})
	const workerSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 0
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Google Filter App',
		expiresAt: Date.now() + 3600000
	})
	db.links.create({ sessionId: adminSession.id, appId: app.id })
	db.links.create({ sessionId: workerSession.id, appId: app.id })
	const adminRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${adminSession.token}`
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 100,
			method: 'tools/list',
			params: {}
		})
	})
	assert.equal(adminRes.status, 200)
	const adminData = await adminRes.json()
	assert.deepEqual(adminData.result.tools.map(t => t.name), ['admin', 'google_api'])
	const workerRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${workerSession.token}`
		},
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 101,
			method: 'tools/list',
			params: {}
		})
	})
	assert.equal(workerRes.status, 200)
	const workerData = await workerRes.json()
	assert.deepEqual(workerData.result.tools.map(t => t.name), ['google_api'])
})

test('non-admin session auth restrictions and self-management', async () => {
	const user = db.logins.resolveUser('google', 'non-admin-auth@example.com')
	const session1 = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 0
	})
	const session2 = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 0
	})
	const whoamiResult = await executeTool('admin', { action: 'whoami' }, session1.token)
	assert.equal(whoamiResult.isError, undefined)
	const whoamiParsed = JSON.parse(whoamiResult.content[0].text)
	assert.equal(whoamiParsed.authenticated, true)
	assert.equal(whoamiParsed.session.admin, false)
	const listResult = await executeTool('admin', { action: 'list' }, session1.token)
	assert.equal(listResult.isError, true)
	assert.match(listResult.content[0].text, /requires admin privileges/)
	const getOtherResult = await executeTool('admin', { action: 'get', sessionId: session2.id }, session1.token)
	assert.equal(getOtherResult.isError, true)
	assert.match(getOtherResult.content[0].text, /requires admin privileges/)
	const getSelfResult = await executeTool('admin', { action: 'get', sessionId: session1.id }, session1.token)
	assert.equal(getSelfResult.isError, undefined)
	const getSelfParsed = JSON.parse(getSelfResult.content[0].text)
	assert.equal(getSelfParsed.session.id, session1.id)
	const revokeOthersResult = await executeTool('admin', { action: 'revoke', allOthers: true }, session1.token)
	assert.equal(revokeOthersResult.isError, true)
	assert.match(revokeOthersResult.content[0].text, /requires admin privileges/)
	assert.ok(db.tokens.get(session2.id))
	const revokeOtherIdResult = await executeTool('admin', { action: 'revoke', sessionId: session2.id }, session1.token)
	assert.equal(revokeOtherIdResult.isError, true)
	assert.match(revokeOtherIdResult.content[0].text, /requires admin privileges/)
	assert.ok(db.tokens.get(session2.id))
	const revokeSelfResult = await executeTool('admin', { action: 'revoke', sessionId: session1.id }, session1.token)
	assert.equal(revokeSelfResult.isError, undefined)
	assert.equal(db.tokens.get(session1.id), null)
	assert.ok(db.tokens.get(session2.id))
})

test('oauth consent flow with admin parameter', async () => {
	const addr = server.address()
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const consentAdmin = new URLSearchParams({
		provider: 'google',
		redirect_uri: 'https://chatgpt.com/callback',
		state: 'client-state-admin',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		admin: 'true'
	})
	const consentAdminRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentAdmin.toString(),
		redirect: 'manual'
	})
	assert.equal(consentAdminRes.status, 302)
	const stateAdminToken = new URL(consentAdminRes.headers.get('location')).searchParams.get('state')
	const rowAdmin = db.tokens.get(stateAdminToken)
	assert.ok(rowAdmin)
	assert.equal(rowAdmin.admin, true)
	const consentNoAdmin = new URLSearchParams({
		provider: 'google',
		redirect_uri: 'https://chatgpt.com/callback',
		state: 'client-state-no-admin',
		code_challenge: challenge,
		code_challenge_method: 'S256'
	})
	const consentNoAdminRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentNoAdmin.toString(),
		redirect: 'manual'
	})
	assert.equal(consentNoAdminRes.status, 302)
	const stateNoAdminToken = new URL(consentNoAdminRes.headers.get('location')).searchParams.get('state')
	const rowNoAdmin = db.tokens.get(stateNoAdminToken)
	assert.ok(rowNoAdmin)
	assert.equal(rowNoAdmin.admin, false)
})

test('admin verification flow (/oauth/verify) with connected app selection and JSON token exchange', async () => {
	const addr = server.address()
	const existingUser = db.logins.resolveUser('google', 'magic-admin@example.com')
	const existingApp = db.tokens.create({
		userId: existingUser.id,
		provider: 'google',
		type: 'oauth',
		name: 'Personal Google',
		credentials: { accessToken: 'ya29.existing', account: 'magic-admin@example.com' },
		scopes: 'https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.readonly',
		expiresAt: Date.now() + 3600000
	})
	const stateWithoutUser = db.tokens.createState({ mode: 'verify', sessionName: 'Missing User Session' })
	const invalidGetVerify = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${stateWithoutUser}`)
	assert.equal(invalidGetVerify.status, 400, 'GET /oauth/verify must fail loud with 400 when state has no valid userId')
	const invalidPostVerify = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: stateWithoutUser }).toString()
	})
	assert.equal(invalidPostVerify.status, 400, 'POST /oauth/verify must fail loud with 400 when state has no valid userId')
	const stateWrongMode = db.tokens.createState({ mode: 'login', userId: existingUser.id })
	const wrongModeGet = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${stateWrongMode}`)
	assert.equal(wrongModeGet.status, 400, 'GET /oauth/verify must reject non-verify oauth_state rows')
	const wrongModePost = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: stateWrongMode }).toString()
	})
	assert.equal(wrongModePost.status, 400, 'POST /oauth/verify must reject non-verify oauth_state rows')
	const verifyCode = db.tokens.createState({
		mode: 'verify',
		userId: existingUser.id,
		sessionName: 'Admin Magic Session',
		admin: 1,
		clientRedirectUri: 'https://antigravity.google/oauth-callback',
		clientState: 'magic-state-abc'
	})
	const getVerifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${verifyCode}`, {
		redirect: 'manual'
	})
	assert.equal(getVerifyRes.status, 200)
	const verifyHtml = await getVerifyRes.text()
	assert.match(verifyHtml, /Link connected apps/)
	assert.match(verifyHtml, /Personal Google · drive \(rw\), gmail \(ro\)/)
	assert.match(verifyHtml, new RegExp(`value="${existingApp.id}" checked`))
	const verifyBody = new URLSearchParams({
		code: verifyCode,
		app_id: existingApp.id
	})
	const verifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: verifyBody.toString(),
		redirect: 'manual'
	})
	assert.equal(verifyRes.status, 302)
	const targetLocation = verifyRes.headers.get('location')
	assert.ok(targetLocation)
	const targetUrl = new URL(targetLocation)
	assert.equal(targetUrl.hostname, 'antigravity.google')
	assert.equal(targetUrl.searchParams.get('state'), 'magic-state-abc')
	const authCode = targetUrl.searchParams.get('code')
	assert.ok(authCode)
	const tokenRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			code: authCode,
			redirect_uri: 'https://antigravity.google/oauth-callback',
			grant_type: 'authorization_code'
		})
	})
	assert.equal(tokenRes.status, 200)
	assert.equal(tokenRes.headers.get('cache-control'), 'no-store')
	const tokenData = await tokenRes.json()
	assert.ok(tokenData.access_token)
	const createdSession = db.tokens.getByToken(tokenData.access_token)
	assert.equal(createdSession.admin, true)
	assert.equal(createdSession.name, 'Admin Magic Session')
	const sessionLinks = db.links.listBySessionId(createdSession.id)
	assert.equal(sessionLinks.length, 1)
	assert.equal(sessionLinks[0].appId, existingApp.id)
	const createdUser = db.users.get(createdSession.userId)
	assert.deepEqual(Object.keys(createdUser), ['id', 'created', 'updated'])
})

test('30-day dormancy pruning scopes only expiring self sessions and exempts static bearer sessions', () => {
	const user = db.logins.resolveUser('google', 'dormancy@example.com')
	const oldDate = new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString()
	const activeSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		expiresAt: Date.now() + 3600000
	})
	const dormantSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		expiresAt: Date.now() + 3600000
	})
	const staticSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		expiresAt: null
	})
	const upstreamApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Upstream App'
	})
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(oldDate, dormantSession.id)
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(oldDate, staticSession.id)
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(oldDate, upstreamApp.id)
	const expState = db.tokens.createState({ mode: 'login' })
	const expCode = db.tokens.createAuthCode({ userId: user.id, clientRedirectUri: 'https://chatgpt.com/callback' })
	db.sqlite.prepare('UPDATE tokens SET expires_at = ? WHERE id IN (?, ?)').run(Date.now() - 1000, expState, expCode)
	assert.equal(db.tokens.getState(expState), null, 'Expired oauth_state is rejected at read time before prune')
	assert.equal(db.tokens.consumeState(expState), null, 'Expired oauth_state cannot be consumed before prune')
	assert.equal(db.tokens.consumeAuthCode(expCode), null, 'Expired oauth_code cannot be consumed before prune')
	assert.equal(db.tokens.getByToken(dormantSession.token), null, 'Dormant bearer token is rejected at read time before prune')
	assert.equal(db.tokens.getActiveSession(dormantSession.id), null, 'Dormant bearer session is inactive at read time before prune')
	assert.ok(!db.tokens.listByUserId(user.id).some(t => t.id === dormantSession.id), 'Dormant bearer session is excluded from listByUserId before prune')
	db.tokens.prune(30 * 24 * 60 * 60 * 1000)
	assert.equal(db.tokens.get(dormantSession.id), null)
	assert.equal(db.tokens.get(expState), null)
	assert.equal(db.tokens.get(expCode), null)
	assert.ok(db.tokens.get(activeSession.id))
	assert.ok(db.tokens.get(staticSession.id), 'Static bearer sessions (expires_at IS NULL) must not be pruned by dormancy')
	assert.ok(db.tokens.get(upstreamApp.id), 'Upstream apps must not be pruned by dormancy')
})

test('admin tool administrative actions: create_session, list_apps, connect_app, link_app, unlink_app', async () => {
	const user = db.logins.resolveUser('google', 'admin-actions@example.com')
	const adminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1
	})
	const googleApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Main Google',
		expiresAt: Date.now() + 3600000
	})
	const missingBaseRes = await executeTool('admin', {
		action: 'connect_app',
		provider: 'stripe',
		name: 'Stripe Missing Base',
		apiKey: 'sk_test_12345'
	}, adminSession.token)
	assert.equal(missingBaseRes.isError, true)
	assert.match(missingBaseRes.content[0].text, /Valid https:\/\/ baseUrl is required/)
	for (const ssrfUrl of ['https://169.254.169.254/latest/meta-data', 'https://10.0.0.1/api', 'https://192.168.1.1/api', 'https://172.16.0.5/api', 'https://0.0.0.0/api', 'https://[fe80::1]/api']) {
		const ssrfRes = await executeTool('admin', {
			action: 'connect_app',
			provider: 'custom',
			apiKey: 'sk_ssrf',
			baseUrl: ssrfUrl
		}, adminSession.token)
		assert.equal(ssrfRes.isError, true, `Must reject private/metadata baseUrl: ${ssrfUrl}`)
		assert.match(ssrfRes.content[0].text, /Valid https:\/\/ baseUrl is required/)
	}
	const connectRes = await executeTool('admin', {
		action: 'connect_app',
		provider: 'stripe',
		name: 'Stripe Prod',
		account: 'acct_stripe_prod_123',
		apiKey: 'sk_test_12345',
		baseUrl: 'https://api.stripe.com/'
	}, adminSession.token)
	assert.equal(connectRes.isError, undefined)
	const connectData = JSON.parse(connectRes.content[0].text)
	assert.equal(connectData.connected, true)
	assert.equal(connectData.app.provider, 'stripe')
	assert.equal(connectData.app.account, 'acct_stripe_prod_123')
	assert.equal(connectData.app.baseUrl, 'https://api.stripe.com')
	const stripeAppId = connectData.app.id
	const reauthRes = await executeTool('admin', {
		action: 'connect_app',
		appId: googleApp.id
	}, adminSession.token)
	assert.equal(reauthRes.isError, undefined)
	const reauthData = JSON.parse(reauthRes.content[0].text)
	assert.equal(reauthData.actionRequired, 'oauth_flow')
	assert.ok(reauthData.connectUrl.includes(`reauth_app_id=${googleApp.id}`))
	const appsRes = await executeTool('admin', { action: 'list_apps' }, adminSession.token)
	assert.equal(appsRes.isError, undefined)
	const appsData = JSON.parse(appsRes.content[0].text)
	assert.equal(appsData.apps.length, 2)
	const sessionsBeforeBadCreate = db.tokens.listByUserId(user.id, { provider: 'self' }).length
	const badLinkCreateRes = await executeTool('admin', {
		action: 'create_session',
		name: 'Should Not Exist',
		linkAppIds: ['nonexistent-app-id']
	}, adminSession.token)
	assert.equal(badLinkCreateRes.isError, true, 'create_session with invalid linkAppIds must fail loud')
	assert.match(badLinkCreateRes.content[0].text, /App not found/)
	assert.equal(db.tokens.listByUserId(user.id, { provider: 'self' }).length, sessionsBeforeBadCreate, 'Failed create_session must not leave orphan session')
	const newSessRes = await executeTool('admin', {
		action: 'create_session',
		name: 'Chef Agent',
		admin: false,
		linkAppIds: [googleApp.id]
	}, adminSession.token)
	assert.equal(newSessRes.isError, undefined)
	const newSessData = JSON.parse(newSessRes.content[0].text)
	assert.equal(newSessData.created, true)
	assert.equal(newSessData.session.name, 'Chef Agent')
	const chefSessionId = newSessData.session.id
	const linkRes = await executeTool('admin', {
		action: 'link_app',
		sessionId: chefSessionId,
		appId: stripeAppId,
		policy: [{ action: 'allow', path: '/**' }]
	}, adminSession.token)
	assert.equal(linkRes.isError, undefined)
	const linkData = JSON.parse(linkRes.content[0].text)
	assert.equal(linkData.linked, true)
	const unlinkRes = await executeTool('admin', {
		action: 'unlink_app',
		sessionId: chefSessionId,
		appId: stripeAppId
	}, adminSession.token)
	assert.equal(unlinkRes.isError, undefined)
	const unlinkData = JSON.parse(unlinkRes.content[0].text)
	assert.equal(unlinkData.unlinked, true)
	const otherTenant = db.logins.resolveUser('google', 'other-tenant@example.com')
	const otherAdmin = db.tokens.create({ userId: otherTenant.id, provider: 'self', admin: 1 })
	const crossTenantUnlinkSessionRes = await executeTool('admin', {
		action: 'unlink_app',
		sessionId: chefSessionId,
		appId: googleApp.id
	}, otherAdmin.token)
	assert.equal(crossTenantUnlinkSessionRes.isError, true)
	assert.match(crossTenantUnlinkSessionRes.content[0].text, /Session not found/)
	const otherApp = db.tokens.create({ userId: otherTenant.id, provider: 'google', type: 'oauth', name: 'Other Google' })
	const crossTenantUnlinkAppRes = await executeTool('admin', {
		action: 'unlink_app',
		sessionId: chefSessionId,
		appId: otherApp.id
	}, adminSession.token)
	assert.equal(crossTenantUnlinkAppRes.isError, true)
	assert.match(crossTenantUnlinkAppRes.content[0].text, /App not found/)
	assert.equal(db.links.listBySessionId(chefSessionId).length, 1, 'Cross-tenant unlink must not remove link')
	const disconnectRes = await executeTool('admin', {
		action: 'disconnect_app',
		appId: stripeAppId,
		revoke: false
	}, adminSession.token)
	assert.equal(disconnectRes.isError, undefined)
	const disconnectData = JSON.parse(disconnectRes.content[0].text)
	assert.equal(disconnectData.disconnected, true)
	assert.equal(db.tokens.get(stripeAppId), null)
})

test('multi-account disambiguation in google_api tool', async () => {
	const user = db.logins.resolveUser('google', 'multi-account@example.com')
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self'
	})
	const personalApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Personal Google',
		credentials: { accessToken: 'ya29.personal' },
		expiresAt: Date.now() + 3600000
	})
	const workApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Work Google',
		credentials: { accessToken: 'ya29.work' },
		expiresAt: Date.now() + 3600000
	})
	db.links.create({ sessionId: session.id, appId: personalApp.id, policy: [{ action: 'allow', path: '/drive/**' }] })
	db.links.create({ sessionId: session.id, appId: workApp.id, policy: [{ action: 'allow', path: '/calendar/**' }] })
	const resWithAppId = await executeTool('google_api', {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
		appId: workApp.id
	}, session.token)
	assert.equal(resWithAppId.isError, true)
	assert.doesNotMatch(resWithAppId.content[0].text, /Policy violation/)
})

test('in-place upstream re-auth flow enforces admin, ownership, and account continuity without changing session token', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'reauth@example.com')
	const otherUser = db.logins.resolveUser('google', 'attacker@example.com')
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		name: 'Persistent Agent Session',
		admin: 0
	})
	const adminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		name: 'Owner Admin Session',
		admin: 1
	})
	const attackerAdmin = db.tokens.create({
		userId: otherUser.id,
		provider: 'self',
		name: 'Attacker Admin Session',
		admin: 1
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Expiring App',
		credentials: { accessToken: 'ya29.old', refreshToken: '1//old-refresh', account: 'reauth@example.com' },
		scopes: 'https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/calendar',
		expiresAt: Date.now() - 1000
	})
	db.links.create({ sessionId: session.id, appId: app.id })
	db.links.create({ sessionId: adminSession.id, appId: app.id })
	const crossUserConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			session_id: attackerAdmin.id,
			reauth_app_id: app.id
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(crossUserConsentRes.status, 403)
	const noSessionConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			reauth_app_id: app.id
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(noSessionConsentRes.status, 403)
	const nonAdminConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			session_id: session.id,
			reauth_app_id: app.id
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(nonAdminConsentRes.status, 403, 'Non-admin session must not initiate reauth_app_id consent')
	const connectHtmlRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/connect?session_id=${adminSession.id}&reauth_app_id=${app.id}`)
	assert.equal(connectHtmlRes.status, 200)
	const connectHtml = await connectHtmlRes.text()
	assert.match(connectHtml, /"services":"drive,calendar"/, 'GET /providers/:provider/connect pre-populates granted services for reauth_app_id')
	assert.match(connectHtml, /"write":"calendar"/, 'GET /providers/:provider/connect pre-populates write services for reauth_app_id')
	const validConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			session_id: adminSession.id,
			reauth_app_id: app.id,
			services: 'drive,calendar',
			write: 'calendar'
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(validConsentRes.status, 302)
	const redirectUrl = new URL(validConsentRes.headers.get('location'))
	assert.equal(redirectUrl.searchParams.get('login_hint'), 'reauth@example.com', 'Re-auth consent passes upstream account as login_hint')
	const apiKeyApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'api_key',
		name: 'API Key App',
		credentials: { apiKey: 'key_123', baseUrl: 'https://www.googleapis.com' }
	})
	const apiKeyReauthConsent = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			session_id: adminSession.id,
			reauth_app_id: apiKeyApp.id
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(apiKeyReauthConsent.status, 403, 'reauth_app_id must reject non-oauth apps (e.g. api_key)')
	let mockReturnedEmail = 'wrong-personal@gmail.com'
	const origFetch = globalThis.fetch
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			const bodyStr = init?.body ? String(init.body) : ''
			if (bodyStr.includes('grant_type=refresh_token')) {
				return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Token expired' }), { status: 400, headers: { 'content-type': 'application/json' } })
			}
			return new Response(JSON.stringify({ access_token: 'ya29.new-fresh-token', refresh_token: '1//new-refresh', expires_in: 3600, scope: app.scopes }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: mockReturnedEmail, verified_email: true }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	try {
		const nonAdminProxyErr = await executeTool('google_api', { url: 'https://www.googleapis.com/drive/v3/files' }, session.token, `http://127.0.0.1:${addr.port}`)
		assert.equal(nonAdminProxyErr.isError, true)
		assert.match(nonAdminProxyErr.content[0].text, /Ask an admin to re-authenticate/)
		assert.doesNotMatch(nonAdminProxyErr.content[0].text, /reauth_app_id/, 'Non-admin proxy refresh failure must not leak reauth URL')
		const adminProxyErr = await executeTool('google_api', { url: 'https://www.googleapis.com/drive/v3/files' }, adminSession.token, `http://127.0.0.1:${addr.port}`)
		assert.equal(adminProxyErr.isError, true)
		assert.match(adminProxyErr.content[0].text, new RegExp(`reauth_app_id=${app.id}`), 'Admin proxy refresh failure includes clickable reauth URL')
		const nonAdminCbState = db.tokens.createState({ sessionId: session.id, reauthAppId: app.id, provider: 'google' })
		const nonAdminCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${nonAdminCbState}`)
		assert.equal(nonAdminCbRes.status, 403, 'Callback rejects non-admin session on reauth_app_id')
		const mismatchState = redirectUrl.searchParams.get('state')
		const mismatchCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${mismatchState}`)
		assert.equal(mismatchCbRes.status, 409, 'Callback rejects upstream account mismatch on reauth_app_id with 409')
		assert.match(await mismatchCbRes.text(), /expected account "reauth@example\.com", got "wrong-personal@gmail\.com"/)
		assert.equal(db.tokens.get(app.id).credentials.account, 'reauth@example.com', 'Mismatched reauth never overwrites app account')
		assert.equal(db.tokens.get(app.id).credentials.accessToken, 'ya29.old', 'Mismatched reauth never overwrites app token')
		mockReturnedEmail = 'reauth@example.com'
		const matchingState = db.tokens.createState({ sessionId: adminSession.id, reauthAppId: app.id, provider: 'google' })
		const matchingCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${matchingState}`)
		assert.equal(matchingCbRes.status, 200)
	} finally {
		globalThis.fetch = origFetch
	}
	const initialSessionToken = session.token
	const reloadedApp = db.tokens.get(app.id)
	assert.equal(reloadedApp.credentials.accessToken, 'ya29.new-fresh-token')
	assert.equal(reloadedApp.credentials.account, 'reauth@example.com')
	const reloadedSession = db.tokens.get(session.id)
	assert.equal(reloadedSession.token, initialSessionToken, 'Session token remains unchanged across upstream re-auth')
})

test('rest api /api/apps and /api/links endpoints', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'rest-apps@example.com')
	const adminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1
	})
	const postAppRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({
			provider: 'anthropic',
			name: 'Anthropic Key',
			apiKey: 'sk-ant-12345',
			baseUrl: 'https://api.anthropic.com'
		})
	})
	assert.equal(postAppRes.status, 201)
	const postAppData = await postAppRes.json()
	assert.equal(postAppData.connected, true)
	const newAppId = postAppData.app.id
	const getAppsRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
		headers: { authorization: `Bearer ${adminSession.token}` }
	})
	assert.equal(getAppsRes.status, 200)
	const getAppsData = await getAppsRes.json()
	assert.ok(getAppsData.apps.some(a => a.id === newAppId))
	const postLinkRes = await fetch(`http://127.0.0.1:${addr.port}/api/links`, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({
			sessionId: adminSession.id,
			appId: newAppId,
			policy: [{ action: 'allow' }]
		})
	})
	assert.equal(postLinkRes.status, 201)
	const postLinkData = await postLinkRes.json()
	assert.equal(postLinkData.linked, true)
	const deleteLinkRes = await fetch(`http://127.0.0.1:${addr.port}/api/links?sessionId=${adminSession.id}&appId=${newAppId}`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${adminSession.token}` }
	})
	assert.equal(deleteLinkRes.status, 200)
	const deleteLinkData = await deleteLinkRes.json()
	assert.equal(deleteLinkData.unlinked, true)
	const deleteAppRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps/${newAppId}?revoke=false`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${adminSession.token}` }
	})
	assert.equal(deleteAppRes.status, 200)
	const deleteAppData = await deleteAppRes.json()
	assert.equal(deleteAppData.disconnected, true)
	assert.equal(db.tokens.get(newAppId), null)
})

test('login-key lifecycle (link_login / unlink_login), REST /api/logins, configured-provider consent, and pending shares without stub users', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'user-props@example.com')
	const adminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1
	})
	const workerSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 0
	})
	const retiredActionRes = await executeTool('admin', {
		action: 'update_user',
		name: 'Retired'
	}, adminSession.token)
	assert.equal(retiredActionRes.isError, true)
	assert.match(retiredActionRes.content[0].text, /Unknown action: update_user/)
	const retiredRestRes = await fetch(`http://127.0.0.1:${addr.port}/api/user`, {
		method: 'PATCH',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ name: 'Retired' })
	})
	assert.equal(retiredRestRes.status, 404, '/api/user must be retired (404)')
	const nonAdminLinkRes = await executeTool('admin', {
		action: 'link_login',
		provider: 'google'
	}, workerSession.token)
	assert.equal(nonAdminLinkRes.isError, true)
	assert.match(nonAdminLinkRes.content[0].text, /requires admin privileges/)
	const nonAdminUnlinkRes = await executeTool('admin', {
		action: 'unlink_login',
		provider: 'google'
	}, workerSession.token)
	assert.equal(nonAdminUnlinkRes.isError, true)
	assert.match(nonAdminUnlinkRes.content[0].text, /requires admin privileges/)
	const missingProviderLink = await executeTool('admin', {
		action: 'link_login'
	}, adminSession.token)
	assert.equal(missingProviderLink.isError, true)
	assert.match(missingProviderLink.content[0].text, /OAuth provider is required/)
	const invalidProviderRes = await executeTool('admin', {
		action: 'link_login',
		provider: 'stripe'
	}, adminSession.token)
	assert.equal(invalidProviderRes.isError, true)
	assert.match(invalidProviderRes.content[0].text, /Invalid or unsupported OAuth provider/)
	const lockoutUnlinkRes = await executeTool('admin', {
		action: 'unlink_login',
		provider: 'google'
	}, adminSession.token)
	assert.equal(lockoutUnlinkRes.isError, true)
	assert.match(lockoutUnlinkRes.content[0].text, /Cannot unlink your only login key/)
	const lockoutRestRes = await fetch(`http://127.0.0.1:${addr.port}/api/logins?provider=google`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${adminSession.token}` }
	})
	assert.equal(lockoutRestRes.status, 400, 'DELETE /api/logins must reject removing the sole login key with 400')
	const whoamiRes = await executeTool('admin', { action: 'whoami' }, adminSession.token)
	const whoamiData = JSON.parse(whoamiRes.content[0].text)
	assert.equal(whoamiData.user.name, undefined, 'users.name is retired from whoami')
	assert.equal(whoamiData.user.account, 'user-props@example.com')
	assert.equal(whoamiData.user.logins.length, 1)
	assert.equal(whoamiData.user.logins[0].provider, 'google')
	assert.equal(whoamiData.user.logins[0].account, 'user-props@example.com')
	assert.ok(whoamiData.user.logins[0].id)
	assert.equal(requireAuthProvider('google'), google)
	delete process.env.GITHUB_CLIENT_ID
	assert.throws(() => requireAuthProvider('github'), /Invalid or unsupported OAuth provider: github/)
	assert.throws(() => requireAuthProvider('stripe'), /Invalid or unsupported OAuth provider: stripe/)
	const unconfiguredProviderRes = await executeTool('admin', {
		action: 'link_login',
		provider: 'github'
	}, adminSession.token)
	assert.equal(unconfiguredProviderRes.isError, true, 'Unconfigured OAuth provider must be rejected in link_login')
	const unconfiguredAuthPage = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?provider=github`)
	assert.doesNotMatch(await unconfiguredAuthPage.text(), /"id":"github"/, 'handleAuthorize must not inject unconfigured query.provider into providers list')
	const unconfiguredConsentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ provider: 'github' }).toString(),
		redirect: 'manual'
	})
	assert.equal(unconfiguredConsentRes.status, 400, 'POST /oauth/authorize/consent must reject unconfigured provider with 400 instead of 500')
	const unconfiguredConsentData = await unconfiguredConsentRes.json()
	assert.equal(unconfiguredConsentData.error, 'invalid_request')
	assert.match(unconfiguredConsentData.error_description, /Invalid or unsupported OAuth provider: github/)
	process.env.GITHUB_CLIENT_ID = 'gh-test-client-id'
	process.env.GITHUB_CLIENT_SECRET = 'gh-test-client-secret'
	const expiredAdminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1,
		expiresAt: Date.now() - 5000
	})
	const nonBearerAdminCode = db.tokens.createAuthCode({
		userId: user.id,
		admin: 1,
		clientRedirectUri: 'https://chatgpt.com/callback'
	})
	assert.ok(db.tokens.create({ userId: user.id, provider: 'self', token: null }).token, 'db.tokens.create must always mint a non-null token for self bearer sessions')
	for (const invalidSid of [expiredAdminSession.id, nonBearerAdminCode]) {
		const expConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ session_id: invalidSid, provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(expConsent.status, 403, 'Inactive/expired session_id must be rejected on /oauth/authorize/consent')
		const expProvConsent = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ session_id: invalidSid }).toString(),
			redirect: 'manual'
		})
		assert.equal(expProvConsent.status, 403, 'Inactive/expired session_id must be rejected on /providers/:provider/consent')
	}
	const shay = db.logins.resolveUser('google', 'shay@example.com')
	const shayAdmin = db.tokens.create({ userId: shay.id, provider: 'self', admin: 1 })
	const shayApp = db.tokens.create({
		userId: shay.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Shay Pre-Shared Stripe',
		credentials: { apiKey: 'sk_test_preshared', baseUrl: 'https://api.stripe.com' }
	})
	const shayApp2 = db.tokens.create({
		userId: shay.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Shay Overlap Stripe',
		credentials: { apiKey: 'sk_test_overlap', baseUrl: 'https://api.stripe.com' }
	})
	const bareHandleNoProvRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp.id,
		account: 'jessetane'
	}, shayAdmin.token)
	assert.equal(bareHandleNoProvRes.isError, true, 'Bare handle without @ or provider must fail loud with 400 when recipient has not signed in')
	assert.match(bareHandleNoProvRes.content[0].text, /Provider is required/)
	for (const badSpec of [':foo', 'github:', 'github:foo:bar', 'github: :foo']) {
		const badShareRes = await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: badSpec
		}, shayAdmin.token)
		assert.equal(badShareRes.isError, true, `Malformed colon spec "${badSpec}" must fail loud in share_app`)
		assert.match(badShareRes.content[0].text, /Malformed account identifier/)
		const badUnlinkRes = await executeTool('admin', {
			action: 'unlink_login',
			account: badSpec
		}, adminSession.token)
		assert.equal(badUnlinkRes.isError, true, `Malformed colon spec "${badSpec}" must fail loud in unlink_login`)
		assert.match(badUnlinkRes.content[0].text, /Malformed account identifier/)
	}
	const conflictingPrefixRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp.id,
		account: 'github:jessetane',
		provider: 'google'
	}, shayAdmin.token)
	assert.equal(conflictingPrefixRes.isError, true, 'Conflicting provider and account prefix must fail loud')
	assert.match(conflictingPrefixRes.content[0].text, /Conflicting provider/)
	const unconfiguredShareProvRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp.id,
		account: 'jessetane',
		provider: 'stripe'
	}, shayAdmin.token)
	assert.equal(unconfiguredShareProvRes.isError, true, 'Non-OAuth / unconfigured provider must fail loud in share_app')
	assert.match(unconfiguredShareProvRes.content[0].text, /Invalid or unsupported OAuth provider/)
	delete process.env.GITHUB_CLIENT_ID
	const unconfGhShareRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp.id,
		account: 'github:jessetane'
	}, shayAdmin.token)
	assert.equal(unconfGhShareRes.isError, true, 'Unconfigured OAuth provider must fail loud in share_app')
	process.env.GITHUB_CLIENT_ID = 'gh-test-client-id'
	const precApp = db.tokens.create({
		userId: shay.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Shay Precedence Stripe',
		credentials: { apiKey: 'sk_prec', baseUrl: 'https://api.stripe.com' }
	})
	db.tokens.upsertShare({
		userId: null,
		account: 'prec@acme.com',
		authProvider: null,
		appId: precApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['GET'], path: '/v1/unscoped' }]
	})
	db.tokens.upsertShare({
		userId: null,
		account: 'prec@acme.com',
		authProvider: 'google',
		appId: precApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['POST'], path: '/v1/scoped' }]
	})
	const unverifiedPrecUser = db.logins.resolveUser('custom_unverified_idp', 'prec@acme.com')
	assert.equal(db.tokens.listByUserId(unverifiedPrecUser.id).filter(t => t.type === 'share').length, 0, 'Unverified-email provider must never claim unscoped pending email shares')
	const precUser = db.logins.resolveUser('google', 'prec@acme.com')
	const precShares = db.tokens.listByUserId(precUser.id).filter(t => t.type === 'share')
	assert.equal(precShares.length, 1, 'Overlapping unscoped and provider-scoped pending shares deduplicate to 1')
	assert.deepEqual(precShares[0].credentials.policy, [{ action: 'allow', methods: ['POST'], path: '/v1/scoped' }], 'Provider-scoped pending share wins precedence over unscoped pending share')
	const seqApp = db.tokens.create({
		userId: shay.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Shay Sequential Precedence Stripe',
		credentials: { apiKey: 'sk_seq', baseUrl: 'https://api.stripe.com' }
	})
	const unscopedSeqPending = db.tokens.upsertShare({
		userId: null,
		account: 'seq@acme.com',
		authProvider: null,
		appId: seqApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['GET'], path: '/v1/unscoped-seq' }]
	})
	db.tokens.upsertShare({
		userId: null,
		account: 'seq@acme.com',
		authProvider: 'github',
		appId: seqApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['POST'], path: '/v1/scoped-seq' }]
	})
	const seqUser = db.logins.resolveUser('google', 'seq@acme.com')
	const seqSession = db.tokens.create({ userId: seqUser.id, provider: 'self', admin: 1 })
	const seqSharesAfterGoogle = db.tokens.listByUserId(seqUser.id).filter(t => t.type === 'share')
	assert.equal(seqSharesAfterGoogle.length, 1)
	assert.equal(seqSharesAfterGoogle[0].updated, unscopedSeqPending.updated, 'Claiming pending share preserves owner-authored updated timestamp')
	assert.equal(seqSharesAfterGoogle[0].credentials.authProvider, 'google', 'Claiming unscoped pending share stamps claiming provider onto authProvider')
	assert.deepEqual(seqSharesAfterGoogle[0].credentials.policy, [{ action: 'allow', methods: ['GET'], path: '/v1/unscoped-seq' }])
	db.links.create({ sessionId: seqSession.id, appId: seqSharesAfterGoogle[0].id })
	db.logins.upsert({ userId: seqUser.id, provider: 'github', account: 'seq@acme.com' })
	const seqSharesAfterGithub = db.tokens.listByUserId(seqUser.id).filter(t => t.type === 'share')
	assert.equal(seqSharesAfterGithub.length, 1)
	assert.equal(seqSharesAfterGithub[0].id, seqSharesAfterGoogle[0].id, 'Sequential provider-scoped claim updates existing share row in place')
	assert.equal(seqSharesAfterGithub[0].credentials.authProvider, 'github', 'Sequential provider-scoped claim updates authProvider')
	assert.deepEqual(seqSharesAfterGithub[0].credentials.policy, [{ action: 'allow', methods: ['POST'], path: '/v1/scoped-seq' }], 'Provider-scoped pending share upgrades previously claimed unscoped share on same handle')
	assert.equal(db.links.listBySessionId(seqSession.id).length, 1, 'Existing session links remain intact across sequential share upgrade')
	db.tokens.upsertShare({
		userId: null,
		account: 'seq-other-handle',
		authProvider: 'github',
		appId: seqApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['DELETE'], path: '/v1/cross-handle-clobber' }]
	})
	db.logins.upsert({ userId: seqUser.id, provider: 'github', account: 'seq-other-handle' })
	const seqSharesAfterCrossHandle = db.tokens.listByUserId(seqUser.id).filter(t => t.type === 'share')
	assert.deepEqual(seqSharesAfterCrossHandle[0].credentials.policy, [{ action: 'allow', methods: ['POST'], path: '/v1/scoped-seq' }], 'Pending share on a second handle never clobbers an existing claimed share on primary handle')
	const staleSeqApp = db.tokens.create({
		userId: shay.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Shay Stale Pending Guard Stripe',
		credentials: { apiKey: 'sk_stale', baseUrl: 'https://api.stripe.com' }
	})
	const staleGhPending = db.tokens.upsertShare({
		userId: null,
		account: 'stale@acme.com',
		authProvider: 'github',
		appId: staleSeqApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['DELETE'], path: '/v1/old-permissive' }]
	})
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run('2020-01-01T00:00:00.000Z', staleGhPending.id)
	db.tokens.upsertShare({
		userId: null,
		account: 'stale@acme.com',
		authProvider: null,
		appId: staleSeqApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['GET'], path: '/v1/initial' }]
	})
	const staleUser = db.logins.resolveUser('google', 'stale@acme.com')
	db.tokens.upsertShare({
		userId: staleUser.id,
		account: 'stale@acme.com',
		appId: staleSeqApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['GET'], path: '/v1/newer-strict' }]
	})
	db.logins.upsert({ userId: staleUser.id, provider: 'github', account: 'stale@acme.com' })
	const staleSharesAfterGh = db.tokens.listByUserId(staleUser.id).filter(t => t.type === 'share')
	assert.deepEqual(staleSharesAfterGh[0].credentials.policy, [{ action: 'allow', methods: ['GET'], path: '/v1/newer-strict' }], 'Stale pending share with older updated timestamp never clobbers newer claimed share policy')
	db.tokens.upsertShare({
		userId: null,
		account: 'seq-extra@acme.com',
		authProvider: null,
		appId: seqApp.id,
		provider: 'stripe',
		policy: [{ action: 'allow', methods: ['GET'], path: '/v1/should-not-clobber' }]
	})
	db.logins.upsert({ userId: seqUser.id, provider: 'google', account: 'seq-extra@acme.com' })
	const seqSharesAfterUnscoped = db.tokens.listByUserId(seqUser.id).filter(t => t.type === 'share')
	assert.deepEqual(seqSharesAfterUnscoped[0].credentials.policy, [{ action: 'allow', methods: ['POST'], path: '/v1/scoped-seq' }], 'Unscoped pending share never clobbers an already-claimed provider-scoped share')
	const usersCountBefore = db.sqlite.prepare('SELECT COUNT(*) AS count FROM users').get().count
	const loginsCountBefore = db.sqlite.prepare('SELECT COUNT(*) AS count FROM logins').get().count
	const preShareRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp.id,
		account: 'jessetane',
		provider: 'github'
	}, shayAdmin.token)
	assert.equal(preShareRes.isError, undefined)
	const preShareData = JSON.parse(preShareRes.content[0].text)
	assert.equal(preShareData.userId, null, 'Pending share must have userId: null')
	assert.equal(preShareData.account, 'jessetane')
	assert.equal(preShareData.provider, 'github')
	const overlapPendingShareRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp2.id,
		account: 'github:jessetane'
	}, shayAdmin.token)
	assert.equal(overlapPendingShareRes.isError, undefined)
	const overlapDirectShareRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp2.id,
		account: 'user-props@example.com'
	}, shayAdmin.token)
	assert.equal(overlapDirectShareRes.isError, undefined)
	const selfOwnedApp = db.tokens.create({
		userId: user.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'User Own App',
		credentials: { apiKey: 'sk_own', baseUrl: 'https://api.stripe.com' }
	})
	db.tokens.upsertShare({
		userId: null,
		account: 'jessetane',
		authProvider: 'github',
		appId: selfOwnedApp.id,
		provider: 'stripe'
	})
	assert.equal(db.sqlite.prepare('SELECT COUNT(*) AS count FROM users').get().count, usersCountBefore, 'Pending share must never create stub users')
	assert.equal(db.sqlite.prepare('SELECT COUNT(*) AS count FROM logins').get().count, loginsCountBefore, 'Pending share must never create fake login rows')
	const shayAppsBeforeClaim = JSON.parse((await executeTool('admin', { action: 'list_apps' }, shayAdmin.token)).content[0].text).apps
	const shayAppEntryBefore = shayAppsBeforeClaim.find(a => a.id === shayApp.id)
	assert.deepEqual(shayAppEntryBefore.shares, [{ userId: null, account: 'jessetane', provider: 'github', policy: null }])
	const restLinkLoginRes = await fetch(`http://127.0.0.1:${addr.port}/api/logins`, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ provider: 'github' })
	})
	assert.equal(restLinkLoginRes.status, 200)
	const restLinkLoginData = await restLinkLoginRes.json()
	assert.equal(restLinkLoginData.actionRequired, 'oauth_flow')
	const providerFlowRes = await executeTool('admin', {
		action: 'link_login',
		provider: 'github'
	}, adminSession.token, `http://127.0.0.1:${addr.port}`)
	assert.equal(providerFlowRes.isError, undefined)
	const providerFlowData = JSON.parse(providerFlowRes.content[0].text)
	assert.equal(providerFlowData.actionRequired, 'oauth_flow')
	assert.ok(providerFlowData.connectUrl.includes(`session_id=${adminSession.id}`))
	assert.ok(providerFlowData.connectUrl.includes('provider=github'))
	const authPageRes = await fetch(providerFlowData.connectUrl)
	assert.equal(authPageRes.status, 200)
	const authPageHtml = await authPageRes.text()
	assert.match(authPageHtml, /Link sign-in provider/)
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			session_id: adminSession.id,
			provider: 'github'
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 302)
	const authStateToken = new URL(consentRes.headers.get('location')).searchParams.get('state')
	assert.ok(authStateToken)
	let ghMockLogin = 'jessetane'
	const origFetch = globalThis.fetch
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://github.com/login/oauth/access_token') {
			return new Response(JSON.stringify({ access_token: 'gho_auth_link', token_type: 'bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://api.github.com/user') {
			return new Response(JSON.stringify({ login: ghMockLogin }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.auth_link', token_type: 'Bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: 'user-props@example.com' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${authStateToken}`)
		assert.equal(cbRes.status, 200, 'Linking GitHub handle claims matching pending shares and succeeds with 200')
		const cbHtml = await cbRes.text()
		assert.match(cbHtml, /Login Linked/)
		assert.match(cbHtml, /Linked <strong>jessetane<\/strong>/)
		const userAppsAfterClaim = JSON.parse((await executeTool('admin', { action: 'list_apps' }, adminSession.token)).content[0].text).apps
		assert.ok(userAppsAfterClaim.some(a => a.type === 'share' && a.name === 'Shay Pre-Shared Stripe'), 'Pending share is claimed on link_login callback')
		const shayAppsAfterClaim = JSON.parse((await executeTool('admin', { action: 'list_apps' }, shayAdmin.token)).content[0].text).apps
		assert.deepEqual(shayAppsAfterClaim.find(a => a.id === shayApp.id).shares, [{ userId: user.id, account: 'jessetane', provider: 'github', policy: null }], 'Claimed share preserves authProvider on share metadata')
		const overlapShares = userAppsAfterClaim.filter(a => a.type === 'share' && a.name === 'Shay Overlap Stripe')
		assert.equal(overlapShares.length, 1, 'Pending share deduplicates overlapping shares for the same upstream appId')
		assert.equal(userAppsAfterClaim.some(a => a.type === 'share' && a.name === 'User Own App'), false, 'Pending share for self-owned app is discarded on claim')
		const updatedWhoami = JSON.parse((await executeTool('admin', { action: 'whoami' }, adminSession.token)).content[0].text)
		assert.equal(updatedWhoami.user.account, 'user-props@example.com', 'Primary account resolves from oldest auth token (ORDER BY created ASC)')
		assert.deepEqual(updatedWhoami.user.logins.map(l => ({ provider: l.provider, account: l.account })), [
			{ provider: 'google', account: 'user-props@example.com' },
			{ provider: 'github', account: 'jessetane' }
		])
		const selfShareViaSecondaryRes = await executeTool('admin', {
			action: 'share_app',
			appId: selfOwnedApp.id,
			account: 'jessetane'
		}, adminSession.token)
		assert.equal(selfShareViaSecondaryRes.isError, true, 'Self-sharing must be rejected across all bound auth keys')
		assert.match(selfShareViaSecondaryRes.content[0].text, /Cannot share an app with yourself/)
		const shareViaSecondaryRes = await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'jessetane',
			policy: [{ action: 'allow', methods: ['GET'] }]
		}, shayAdmin.token)
		assert.equal(shareViaSecondaryRes.isError, undefined)
		const shareViaSecondaryData = JSON.parse(shareViaSecondaryRes.content[0].text)
		assert.equal(shareViaSecondaryData.userId, user.id, 'Sharing via secondary linked login handle resolves to existing multi-key user')
		assert.equal(shareViaSecondaryData.account, 'jessetane', 'share_app returns the shared target handle and never leaks unrelated primary email')
		assert.equal(JSON.stringify(shareViaSecondaryData).includes('user-props@example.com'), false, 'Primary email must never leak when sharing via secondary handle')
		const shayAppsPrivacyCheck = JSON.parse((await executeTool('admin', { action: 'list_apps' }, shayAdmin.token)).content[0].text).apps
		const shayAppPrivacyShares = shayAppsPrivacyCheck.find(a => a.id === shayApp.id).shares
		assert.equal(shayAppPrivacyShares[0].account, 'jessetane', 'list_apps shares reports shared target handle without leaking private primary email')
		assert.equal(JSON.stringify(shayAppPrivacyShares).includes('user-props@example.com'), false, 'list_apps shares must never deanonymize recipient across login keys')
		const unshareViaSecondaryRes = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'jessetane'
		}, shayAdmin.token)
		assert.equal(unshareViaSecondaryRes.isError, undefined)
		assert.equal(JSON.parse(unshareViaSecondaryRes.content[0].text).unshared, true, 'Unsharing via secondary linked login handle removes share from multi-key user')
		const collidingOtherProviderUser = db.logins.resolveUser('custom_idp', 'jessetane')
		assert.notEqual(collidingOtherProviderUser.id, user.id, 'resolveUserByAuth for a different provider with same handle must create distinct user')
		const ambiguousShareRes = await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'jessetane'
		}, shayAdmin.token)
		assert.equal(ambiguousShareRes.isError, true, 'Bare handle matching multiple distinct users across providers must fail loud with 400')
		assert.match(ambiguousShareRes.content[0].text, /Ambiguous account "jessetane" matches multiple users/)
		const disambiguatedShareRes = await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'jessetane',
			provider: 'github'
		}, shayAdmin.token)
		assert.equal(disambiguatedShareRes.isError, undefined)
		const disambiguatedShareData = JSON.parse(disambiguatedShareRes.content[0].text)
		assert.equal(disambiguatedShareData.userId, user.id)
		assert.equal(disambiguatedShareData.provider, 'github', 'share_app to existing user preserves explicit provider')
		const roundTripUnshareRes = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'jessetane'
		}, shayAdmin.token)
		assert.equal(roundTripUnshareRes.isError, undefined, 'unshare_app without provider succeeds unambiguously when only one user on targetApp holds that handle')
		assert.equal(JSON.parse(roundTripUnshareRes.content[0].text).unshared, true)
		await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'github:jessetane'
		}, shayAdmin.token)
		db.tokens.upsertShare({
			userId: collidingOtherProviderUser.id,
			account: 'jessetane',
			authProvider: 'custom_idp',
			appId: shayApp.id,
			provider: 'stripe'
		})
		const trulyAmbiguousUnshare = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'jessetane'
		}, shayAdmin.token)
		assert.equal(trulyAmbiguousUnshare.isError, true, 'unshare_app fails loud with 400 when multiple distinct recipients on the same app match bare handle')
		assert.equal(db.tokens.removeShare({ appId: shayApp.id, account: 'custom_idp:jessetane' }), true)
		const crossProvHolder = db.logins.resolveUser('custom_idp', 'sharedhandle')
		const crossProvLinker = db.logins.resolveUser('google', 'linker@example.com')
		const crossProvSession = db.tokens.create({ userId: crossProvLinker.id, provider: 'self', admin: 1 })
		const crossProvState = db.tokens.createState({
			mode: 'auth',
			sessionId: crossProvSession.id,
			provider: 'github'
		})
		ghMockLogin = 'sharedhandle'
		const crossProvCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${crossProvState}`)
		assert.equal(crossProvCbRes.status, 200)
		assert.equal(db.logins.findUserByAccount('github:sharedhandle').id, crossProvLinker.id)
		assert.equal(db.logins.findUserByAccount('sharedhandle', 'github').id, crossProvLinker.id)
		assert.equal(db.logins.findUserByAccount('sharedhandle', 'custom_idp').id, crossProvHolder.id)
		ghMockLogin = 'jessetane'
		const googleLoginState = db.tokens.createState({ mode: 'login', provider: 'google', sessionName: 'Google Key Login' })
		const googleLoginCb = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${googleLoginState}`, { redirect: 'manual' })
		assert.equal(googleLoginCb.status, 302)
		const googleVerifyCode = new URL(googleLoginCb.headers.get('location'), `http://127.0.0.1:${addr.port}`).searchParams.get('code')
		assert.equal(db.tokens.getState(googleVerifyCode).userId, user.id)
		const githubLoginState = db.tokens.createState({ mode: 'login', provider: 'github', sessionName: 'GitHub Key Login' })
		const githubLoginCb = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${githubLoginState}`, { redirect: 'manual' })
		assert.equal(githubLoginCb.status, 302)
		const githubVerifyCode = new URL(githubLoginCb.headers.get('location'), `http://127.0.0.1:${addr.port}`).searchParams.get('code')
		const githubVerifyState = db.tokens.getState(githubVerifyCode)
		assert.equal(githubVerifyState.userId, user.id)
		assert.equal(githubVerifyState.account, undefined, 'oauth_state does not carry vestigial account metadata')
		const ghVerifyGetRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${githubVerifyCode}`)
		assert.equal(ghVerifyGetRes.status, 200)
		assert.match(await ghVerifyGetRes.text(), /Activate session for <strong>user-props@example\.com<\/strong>/, 'GET /oauth/verify resolves canonical account via getAccountByUserId')
		const ghVerifyPostRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: githubVerifyCode }).toString()
		})
		assert.equal(ghVerifyPostRes.status, 200)
		assert.match(await ghVerifyPostRes.text(), /user:\s*user-props@example\.com/, 'POST /oauth/verify resolves same canonical account as GET /oauth/verify')
		const otherUser = db.logins.resolveUser('github', 'taken-gh-user')
		const otherAdmin = db.tokens.create({ userId: otherUser.id, provider: 'self', admin: 1 })
		const conflictSideEffectApp = db.tokens.create({
			userId: shay.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Conflict Side-Effect Guard App',
			credentials: { apiKey: 'sk_conflict', baseUrl: 'https://api.stripe.com' }
		})
		const conflictPendingShare = db.tokens.upsertShare({
			userId: null,
			account: 'jessetane',
			authProvider: 'github',
			appId: conflictSideEffectApp.id,
			provider: 'stripe'
		})
		const conflictState = db.tokens.createState({
			mode: 'auth',
			sessionId: otherAdmin.id,
			provider: 'github'
		})
		const conflictCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${conflictState}`)
		assert.equal(conflictCbRes.status, 409)
		assert.match(await conflictCbRes.text(), /already registered to another user/)
		assert.equal(db.tokens.get(conflictPendingShare.id).userId, null, '409 link_login conflict must have zero side effects and never claim pending shares for another user')
		db.tokens.remove(conflictSideEffectApp.id)
		const unlinkGoogleRes = await fetch(`http://127.0.0.1:${addr.port}/api/logins?provider=google`, {
			method: 'DELETE',
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(unlinkGoogleRes.status, 200)
		const unlinkGoogleData = await unlinkGoogleRes.json()
		assert.equal(unlinkGoogleData.unlinked, true)
		assert.equal(unlinkGoogleData.login.provider, 'google')
		assert.equal(unlinkGoogleData.logins.length, 1)
		assert.equal(unlinkGoogleData.logins[0].provider, 'github')
		const whoamiAfterUnlink = JSON.parse((await executeTool('admin', { action: 'whoami' }, adminSession.token)).content[0].text)
		assert.equal(whoamiAfterUnlink.user.account, 'jessetane', 'After unlinking oldest login key, account resolves to remaining first login key')
		const unlinkLastGithubRes = await executeTool('admin', {
			action: 'unlink_login',
			provider: 'github'
		}, adminSession.token)
		assert.equal(unlinkLastGithubRes.isError, true, 'Cannot unlink sole remaining login key')
		const relinkedGoogle = db.logins.upsert({ userId: user.id, provider: 'google', account: 'user-props@example.com' })
		assert.deepEqual(Object.keys(relinkedGoogle).sort(), ['account', 'created', 'id', 'provider', 'userId'])
		const unlinkByPathRes = await fetch(`http://127.0.0.1:${addr.port}/api/logins/${encodeURIComponent(relinkedGoogle.id)}`, {
			method: 'DELETE',
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(unlinkByPathRes.status, 200, 'DELETE /api/logins/:id unlinks login key by canonical loginId')
		assert.equal((await unlinkByPathRes.json()).login.id, relinkedGoogle.id)
		db.logins.upsert({ userId: user.id, provider: 'google', account: 'user-props@example.com' })
		const unlinkGithubPrefixedMcp = await executeTool('admin', {
			action: 'unlink_login',
			account: 'github:jessetane'
		}, adminSession.token)
		assert.equal(unlinkGithubPrefixedMcp.isError, undefined, 'unlink_login normalizes provider:account syntax inside removeAuth')
		assert.equal(JSON.parse(unlinkGithubPrefixedMcp.content[0].text).unlinked, true)
		const unshareAfterUnlinkScopedRes = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'github:jessetane'
		}, shayAdmin.token)
		assert.equal(unshareAfterUnlinkScopedRes.isError, undefined)
		assert.equal(JSON.parse(unshareAfterUnlinkScopedRes.content[0].text).unshared, true, 'Owner can still unshare provider:account even after recipient unlinks that login key')
		db.logins.upsert({ userId: user.id, provider: 'github', account: 'jessetane' })
		await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'github:jessetane'
		}, shayAdmin.token)
		await executeTool('admin', {
			action: 'unlink_login',
			provider: 'github',
			account: 'jessetane'
		}, adminSession.token)
		const unshareAfterUnlinkBareRes = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'jessetane'
		}, shayAdmin.token)
		assert.equal(unshareAfterUnlinkBareRes.isError, undefined)
		assert.equal(JSON.parse(unshareAfterUnlinkBareRes.content[0].text).unshared, true, 'Owner can also unshare bare handle after recipient unlinks that login key')
		db.logins.upsert({ userId: user.id, provider: 'github', account: 'jesse-unique-gh' })
		const bareToExistingShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'jesse-unique-gh',
			policy: [{ action: 'allow', methods: ['GET'] }]
		}, shayAdmin.token)).content[0].text)
		assert.equal(bareToExistingShare.provider, 'github', 'Sharing bare handle to existing user resolves and stamps matched auth provider')
		const reshareWithoutProvider = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'jesse-unique-gh',
			policy: [{ action: 'allow', methods: ['GET', 'POST'] }]
		}, shayAdmin.token)).content[0].text)
		assert.equal(reshareWithoutProvider.provider, 'github', 'Re-sharing without provider preserves resolved authProvider on claimed share')
		await executeTool('admin', {
			action: 'unlink_login',
			account: 'github:jesse-unique-gh'
		}, adminSession.token)
		const unsharePrefixedAfterBareShare = JSON.parse((await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'github:jesse-unique-gh'
		}, shayAdmin.token)).content[0].text)
		assert.equal(unsharePrefixedAfterBareShare.unshared, true, 'unshare_app with provider:account succeeds after unlink even when originally shared without explicit provider')
		await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'pending-email@acme.com'
		}, shayAdmin.token)
		const unsharePendingWithProvider = JSON.parse((await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'google:pending-email@acme.com'
		}, shayAdmin.token)).content[0].text)
		assert.equal(unsharePendingWithProvider.unshared, true, 'unshare_app with provider:account removes unclaimed unscoped pending email share')
		await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'scoped-guard@acme.com'
		}, shayAdmin.token)
		await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'github:scoped-guard@acme.com'
		}, shayAdmin.token)
		const unshareWrongProviderGuard = JSON.parse((await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'google:scoped-guard@acme.com'
		}, shayAdmin.token)).content[0].text)
		assert.equal(unshareWrongProviderGuard.unshared, false, 'unshare_app with non-matching provider must not fall back to unscoped pending share when a provider-scoped share exists for that account')
		const ambiguousPendingUnshare = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'scoped-guard@acme.com'
		}, shayAdmin.token)
		assert.equal(ambiguousPendingUnshare.isError, true, 'unshare_app without provider fails loud with 400 when multiple pending shares match account')
		assert.match(ambiguousPendingUnshare.content[0].text, /Ambiguous account "scoped-guard@acme.com"/)
		assert.equal(db.tokens.removeShare({ appId: shayApp.id, account: 'github:scoped-guard@acme.com' }), true)
		assert.equal(db.tokens.removeShare({ appId: shayApp.id, account: 'scoped-guard@acme.com' }), true)
		db.logins.upsert({ userId: user.id, provider: 'github', account: 'secret-gh-handle' })
		const emailOnlyShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'user-props@example.com'
		}, shayAdmin.token)).content[0].text)
		const crossKeyOracleScoped = JSON.parse((await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'github:secret-gh-handle'
		}, shayAdmin.token)).content[0].text)
		assert.equal(crossKeyOracleScoped.unshared, false, 'unshare_app must never match or delete a share via an unrelated secondary auth key')
		const crossKeyOracleBare = JSON.parse((await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'secret-gh-handle'
		}, shayAdmin.token)).content[0].text)
		assert.equal(crossKeyOracleBare.unshared, false, 'unshare_app without provider must never deanonymize or delete a share via an unrelated secondary auth key')
		assert.ok(db.tokens.get(emailOnlyShare.shareId), 'Share granted to primary email remains intact when probing unrelated secondary handle')
		await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'github:user-props@example.com'
		}, shayAdmin.token)
		const claimedPlusPendingAmbiguous = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'user-props@example.com'
		}, shayAdmin.token)
		assert.equal(claimedPlusPendingAmbiguous.isError, true, 'unshare_app without provider fails loud with 400 when claimed + pending shares collide on account')
		assert.equal(db.tokens.removeShare({ appId: shayApp.id, account: 'github:user-props@example.com' }), true)
		assert.equal(db.tokens.removeShare({ appId: shayApp.id, account: 'google:user-props@example.com' }), true)
		await executeTool('admin', {
			action: 'unlink_login',
			account: 'github:secret-gh-handle'
		}, adminSession.token)
		const specialLoginId = 'login:special/id%1'
		db.sqlite.prepare(`
			INSERT INTO logins (id, user_id, provider, account, created)
			VALUES (?, ?, 'github', 'encoded-gh', ?)
		`).run(specialLoginId, user.id, new Date().toISOString())
		const specialSession = db.tokens.create({
			id: 'sess:special/id%1',
			userId: user.id,
			provider: 'self',
			name: 'Encoded Session',
			admin: 0
		})
		const specialApp = db.tokens.create({
			id: 'app:special/id%1',
			userId: user.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Encoded App',
			credentials: { apiKey: 'sk_enc', baseUrl: 'https://api.stripe.com' }
		})
		const encSessionGet = await fetch(`http://127.0.0.1:${addr.port}/api/sessions/${encodeURIComponent(specialSession.id)}`, {
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(encSessionGet.status, 200, 'GET /api/sessions/:id percent-decodes path parameter')
		const encAppPatch = await fetch(`http://127.0.0.1:${addr.port}/api/apps/${encodeURIComponent(specialApp.id)}`, {
			method: 'PATCH',
			headers: { authorization: `Bearer ${adminSession.token}`, 'content-type': 'application/json' },
			body: JSON.stringify({ name: 'Renamed Encoded App' })
		})
		assert.equal(encAppPatch.status, 200, 'PATCH /api/apps/:id percent-decodes path parameter')
		const encAppDelete = await fetch(`http://127.0.0.1:${addr.port}/api/apps/${encodeURIComponent(specialApp.id)}?revoke=false`, {
			method: 'DELETE',
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(encAppDelete.status, 200, 'DELETE /api/apps/:id percent-decodes path parameter')
		const encLoginDelete = await fetch(`http://127.0.0.1:${addr.port}/api/logins/${encodeURIComponent(specialLoginId)}`, {
			method: 'DELETE',
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(encLoginDelete.status, 200, 'DELETE /api/logins/:id percent-decodes path parameter')
		for (const badPath of ['/api/logins/%E0%A4%A', '/api/sessions/%E0%A4%A', '/api/apps/%E0%A4%A']) {
			const badPathRes = await fetch(`http://127.0.0.1:${addr.port}${badPath}`, {
				method: 'DELETE',
				headers: { authorization: `Bearer ${adminSession.token}` }
			})
			assert.equal(badPathRes.status, 400, `Malformed percent-encoding on ${badPath} fails loud with 400`)
		}
		google.ssoOnly = true
		try {
			const ssoUser = db.logins.resolveUser('google', 'sso-locked@example.com')
			const ssoAdmin = db.tokens.create({ userId: ssoUser.id, provider: 'self', admin: 1 })
			const ssoLinkAttempt = await executeTool('admin', {
				action: 'link_login',
				provider: 'github'
			}, ssoAdmin.token)
			assert.equal(ssoLinkAttempt.isError, true, 'link_login must enforce ssoOnly restriction upfront')
			assert.match(ssoLinkAttempt.content[0].text, /SSO-only provider restriction/)
			const ssoConsentAttempt = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ session_id: ssoAdmin.id, provider: 'github' }).toString(),
				redirect: 'manual'
			})
			assert.equal(ssoConsentAttempt.status, 403, 'handleAuthorizeConsent must enforce ssoOnly restriction')
			const ssoState = db.tokens.createState({
				mode: 'auth',
				sessionId: ssoAdmin.id,
				provider: 'github'
			})
			const ssoCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${ssoState}`)
			assert.equal(ssoCbRes.status, 403)
			assert.match(await ssoCbRes.text(), /SSO-only provider restriction/)
			const ssoApp = db.tokens.create({
				userId: ssoUser.id,
				provider: 'stripe',
				type: 'api_key',
				name: 'Enterprise Stripe',
				credentials: { apiKey: 'sk_ent', baseUrl: 'https://api.stripe.com' }
			})
			const ssoCrossProvShare = await executeTool('admin', {
				action: 'share_app',
				appId: ssoApp.id,
				account: 'newhire@corp.com',
				provider: 'github'
			}, ssoAdmin.token)
			assert.equal(ssoCrossProvShare.isError, true, 'ssoOnly sharer must not create cross-provider share')
			assert.match(ssoCrossProvShare.content[0].text, /SSO-only provider restriction/)
			const ssoPendingShare = JSON.parse((await executeTool('admin', {
				action: 'share_app',
				appId: ssoApp.id,
				account: 'newhire@corp.com'
			}, ssoAdmin.token)).content[0].text)
			assert.equal(ssoPendingShare.provider, 'google', 'ssoOnly sharer binds pending share to ssoOnly provider')
			const ghImpersonator = db.logins.resolveUser('github', 'newhire@corp.com')
			assert.equal(db.tokens.listByUserId(ghImpersonator.id).filter(t => t.type === 'share').length, 0, 'Consumer provider must not claim enterprise ssoOnly pending share')
			const googleCorpUser = db.logins.resolveUser('google', 'newhire@corp.com')
			assert.equal(db.tokens.listByUserId(googleCorpUser.id).filter(t => t.type === 'share').length, 1, 'Matching ssoOnly provider claims pending share')
			db.tokens.upsertShare({
				userId: null,
				account: 'legacy-unscoped@corp.com',
				authProvider: null,
				appId: ssoApp.id,
				provider: 'stripe'
			})
			db.tokens.upsertShare({
				userId: null,
				account: 'contractor-gh',
				authProvider: 'github',
				appId: ssoApp.id,
				provider: 'stripe'
			})
			const ssoRevokeUnscoped = JSON.parse((await executeTool('admin', {
				action: 'unshare_app',
				appId: ssoApp.id,
				account: 'legacy-unscoped@corp.com'
			}, ssoAdmin.token)).content[0].text)
			assert.equal(ssoRevokeUnscoped.unshared, true, 'ssoOnly admin can revoke pre-existing unscoped shares on their app')
			const ssoRevokeCrossProv = JSON.parse((await executeTool('admin', {
				action: 'unshare_app',
				appId: ssoApp.id,
				account: 'github:contractor-gh'
			}, ssoAdmin.token)).content[0].text)
			assert.equal(ssoRevokeCrossProv.unshared, true, 'ssoOnly admin can revoke pre-existing cross-provider shares on their app')
			db.tokens.upsertShare({
				userId: null,
				account: 'unscoped@corp.com',
				authProvider: null,
				appId: shayApp.id,
				provider: 'stripe'
			})
			const ssoUnscopedUser = db.logins.resolveUser('google', 'unscoped@corp.com')
			assert.equal(db.tokens.listByUserId(ssoUnscopedUser.id).filter(t => t.type === 'share').length, 1, 'ssoOnly login verifying email ownership claims unscoped pending email share')
		} finally {
			google.ssoOnly = false
		}
	} finally {
		globalThis.fetch = origFetch
	}
})

test('admin update_app action', async () => {
	const user = db.logins.resolveUser('google', 'update-app@example.com')
	const adminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1
	})
	const workerSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 0
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Original App Name',
		credentials: {
			accessToken: 'ya29.fake',
			account: 'owner@gmail.com'
		},
		expiresAt: Date.now() + 3600000
	})
	const nonAdminRes = await executeTool('admin', {
		action: 'update_app',
		appId: app.id,
		name: 'Renamed App'
	}, workerSession.token)
	assert.equal(nonAdminRes.isError, true)
	assert.match(nonAdminRes.content[0].text, /requires admin privileges/)
	const notFoundRes = await executeTool('admin', {
		action: 'update_app',
		appId: 'non-existent-app-id',
		name: 'Renamed App'
	}, adminSession.token)
	assert.equal(notFoundRes.isError, true)
	assert.match(notFoundRes.content[0].text, /App not found/)
	const updateRes = await executeTool('admin', {
		action: 'update_app',
		appId: app.id,
		name: 'Personal Google Workspace'
	}, adminSession.token)
	assert.equal(updateRes.isError, undefined)
	const updateData = JSON.parse(updateRes.content[0].text)
	assert.equal(updateData.updated, true)
	assert.equal(updateData.app.id, app.id)
	assert.equal(updateData.app.name, 'Personal Google Workspace')
	assert.equal(updateData.app.account, 'owner@gmail.com')
	const dbApp = db.tokens.get(app.id)
	assert.equal(dbApp.name, 'Personal Google Workspace')
	for (const forbiddenPatch of [{ account: 'spoofed@gmail.com' }, { apiKey: 'sk_injected' }, { baseUrl: 'https://api.stripe.com' }]) {
		const res = await executeTool('admin', {
			action: 'update_app',
			appId: app.id,
			...forbiddenPatch
		}, adminSession.token)
		assert.equal(res.isError, true, 'update_app must reject api_key-only fields on oauth apps')
		assert.match(res.content[0].text, /can only be updated on api_key apps/)
	}
	assert.equal(db.tokens.get(app.id).credentials.account, 'owner@gmail.com')
})

test('admin update_session action', async () => {
	const user = db.logins.resolveUser('google', 'update-session@example.com')
	const adminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		name: 'Admin Main',
		admin: 1
	})
	const workerSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		name: 'Worker Initial',
		admin: 0
	})
	const selfRenameRes = await executeTool('admin', {
		action: 'update_session',
		name: 'Worker Renamed'
	}, workerSession.token)
	assert.equal(selfRenameRes.isError, undefined)
	const selfRenameData = JSON.parse(selfRenameRes.content[0].text)
	assert.equal(selfRenameData.session.name, 'Worker Renamed')
	const nonAdminEscalateRes = await executeTool('admin', {
		action: 'update_session',
		admin: true
	}, workerSession.token)
	assert.equal(nonAdminEscalateRes.isError, true)
	assert.match(nonAdminEscalateRes.content[0].text, /requires admin privileges/)
	const adminPromoteRes = await executeTool('admin', {
		action: 'update_session',
		sessionId: workerSession.id,
		name: 'Promoted Admin',
		admin: true
	}, adminSession.token)
	assert.equal(adminPromoteRes.isError, undefined)
	const adminPromoteData = JSON.parse(adminPromoteRes.content[0].text)
	assert.equal(adminPromoteData.session.name, 'Promoted Admin')
	assert.equal(adminPromoteData.session.admin, true)
	assert.equal(adminPromoteData.session.token, undefined, 'Plaintext token is not returned when not rotated')
	assert.equal(db.tokens.get(workerSession.id).admin, true)
	const oldWorkerToken = workerSession.token
	const rotateRes = await executeTool('admin', {
		action: 'update_session',
		sessionId: workerSession.id,
		rotateToken: true
	}, adminSession.token)
	assert.equal(rotateRes.isError, undefined)
	const rotateData = JSON.parse(rotateRes.content[0].text)
	assert.ok(rotateData.session.token, 'New token is returned on rotation')
	assert.notEqual(rotateData.session.token, oldWorkerToken, 'New token differs from old token')
	const newWorkerToken = rotateData.session.token
	const oldAuthCheck = await executeTool('admin', { action: 'whoami' }, oldWorkerToken)
	const oldAuthData = JSON.parse(oldAuthCheck.content[0].text)
	assert.equal(oldAuthData.authenticated, false, 'Old token is invalidated immediately')
	const newAuthCheck = await executeTool('admin', { action: 'whoami' }, newWorkerToken)
	const newAuthData = JSON.parse(newAuthCheck.content[0].text)
	assert.equal(newAuthData.authenticated, true, 'New token authenticates successfully')
	assert.equal(newAuthData.session.expiresAt, null, 'Rotating embedded session token keeps expiresAt: null')
	const oauthSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		name: 'Expiring OAuth Session',
		expiresAt: Date.now() - 5000
	})
	const rotateOauthRes = await executeTool('admin', {
		action: 'update_session',
		sessionId: oauthSession.id,
		rotateToken: true
	}, adminSession.token)
	assert.equal(rotateOauthRes.isError, undefined)
	const rotateOauthData = JSON.parse(rotateOauthRes.content[0].text)
	assert.ok(rotateOauthData.session.token)
	assert.ok(rotateOauthData.session.expiresAt > Date.now() + 3500 * 1000, 'Rotating an expiring/expired OAuth session extends expiresAt by 1h')
})

test('provider_api fail-loud on unlinked session or missing appId', async () => {
	const user = db.logins.resolveUser('google', 'unlinked-fail@example.com')
	const sessionNoApps = db.tokens.create({
		userId: user.id,
		provider: 'self'
	})
	const noAppRes = await executeTool('google_api', {
		url: 'https://www.googleapis.com/drive/v3/files'
	}, sessionNoApps.token)
	assert.equal(noAppRes.isError, true)
	assert.match(noAppRes.content[0].text, /No Google app linked to session/)
	const noStripeRes = await executeTool('stripe_api', {
		url: '/v1/customers'
	}, sessionNoApps.token)
	assert.equal(noStripeRes.isError, true)
	assert.match(noStripeRes.content[0].text, /No Stripe app linked to session/)
	const { session } = createTestSession({ account: 'linked-fail@example.com' })
	const invalidAppRes = await executeTool('google_api', {
		url: 'https://www.googleapis.com/drive/v3/files',
		appId: 'non-existent-app-id'
	}, session.token)
	assert.equal(invalidAppRes.isError, true)
	assert.match(invalidAppRes.content[0].text, /App not linked to session or not found: non-existent-app-id/)
	await assert.rejects(
		async () => {
			await api.proxy.request({
				provider: 'google',
				url: 'https://www.googleapis.com/drive/v3/files',
				appId: 'non-existent-app-id'
			}, session.token)
		},
		err => {
			assert.equal(err.status, 404)
			assert.match(err.message, /App not linked to session or not found: non-existent-app-id/)
			return true
		}
	)
	await assert.rejects(
		async () => {
			await api.proxy.request({
				provider: 'google',
				url: 'https://www.googleapis.com/drive/v3/files'
			}, sessionNoApps.token)
		},
		err => {
			assert.equal(err.status, 403)
			assert.match(err.message, /No Google app linked to session/)
			return true
		}
	)
})

test('provider-agnostic dynamic <provider>_api tools, REST /api/:provider/* proxy, and RFC 7591 DCR', async () => {
	const http = await import('node:http')
	const upstreamRequests = []
	const mockUpstream = http.createServer((req, res) => {
		upstreamRequests.push({
			method: req.method,
			url: req.url,
			auth: req.headers.authorization
		})
		res.statusCode = 200
		res.setHeader('content-type', 'application/json')
		res.end(JSON.stringify({ ok: true, path: req.url, auth: req.headers.authorization }))
	})
	await new Promise(resolve => mockUpstream.listen(0, '127.0.0.1', resolve))
	const upstreamPort = mockUpstream.address().port
	const baseUrl = `http://127.0.0.1:${upstreamPort}`
	try {
		const addr = server.address()
		const regRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/register`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				client_id: 'attacker_chosen_id',
				client_secret: 'attacker_chosen_secret',
				client_name: 'Test MCP Agent',
				redirect_uris: ['http://localhost:9999/cb']
			})
		})
		assert.equal(regRes.status, 201)
		const regData = await regRes.json()
		assert.ok(regData.client_id)
		assert.notEqual(regData.client_id, 'attacker_chosen_id', 'DCR must ignore caller-supplied client_id')
		assert.equal(regData.client_secret, undefined)
		assert.equal(regData.client_name, 'Test MCP Agent')
		assert.deepEqual(regData.grant_types, ['authorization_code', 'refresh_token'])
		const confRegRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/register`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({
				client_name: 'Confidential MCP Agent',
				redirect_uris: ['http://localhost:9999/cb'],
				token_endpoint_auth_method: 'client_secret_post'
			})
		})
		assert.equal(confRegRes.status, 201)
		const confRegData = await confRegRes.json()
		assert.equal(confRegData.token_endpoint_auth_method, 'none', 'Stateless DCR normalizes token_endpoint_auth_method to none')
		assert.equal(confRegData.client_secret, undefined, 'Stateless DCR must not issue unverified client_secret')
		assert.equal(confRegData.client_secret_expires_at, undefined)
		const user = db.logins.resolveUser('google', 'multi-provider@example.com')
		const session = db.tokens.create({
			userId: user.id,
			provider: 'self',
			admin: 1
		})
		const connectRes = await executeTool('admin', {
			action: 'connect_app',
			provider: 'stripe',
			name: 'Stripe Test',
			account: 'acct_test_1',
			apiKey: 'sk_test_mock_999',
			baseUrl
		}, session.token)
		assert.equal(connectRes.isError, undefined)
		const connectData = JSON.parse(connectRes.content[0].text)
		const stripeAppId = connectData.app.id
		assert.equal(connectData.app.baseUrl, baseUrl)
		await executeTool('admin', {
			action: 'link_app',
			sessionId: session.id,
			appId: stripeAppId,
			policy: [
				{ action: 'allow', methods: ['GET'], path: '/v1/customers/**' },
				{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { currency: 'usd', 'metadata.team': 'core' } }
			]
		}, session.token)
		const toolsRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				authorization: `Bearer ${session.token}`
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 200,
				method: 'tools/list',
				params: {}
			})
		})
		const toolsData = await toolsRes.json()
		const toolNames = toolsData.result.tools.map(t => t.name)
		assert.deepEqual(toolNames, ['admin', 'stripe_api'])
		const adminSchemaProps = toolsData.result.tools.find(t => t.name === 'admin').inputSchema.properties
		assert.ok(adminSchemaProps.linkAppIds, 'admin tool schema exposes linkAppIds for create_session')
		const allowedRes = await executeTool('stripe_api', {
			url: '/v1/customers/cus_123',
			account: 'acct_test_1'
		}, session.token)
		assert.equal(allowedRes.isError, undefined)
		const allowedBody = JSON.parse(allowedRes.content[0].text)
		assert.equal(allowedBody.ok, true)
		assert.equal(allowedBody.path, '/v1/customers/cus_123')
		assert.equal(allowedBody.auth, 'Bearer sk_test_mock_999')
		const deniedMethodRes = await executeTool('stripe_api', {
			url: '/v1/customers/cus_123',
			method: 'DELETE'
		}, session.token)
		assert.equal(deniedMethodRes.isError, true)
		assert.match(deniedMethodRes.content[0].text, /Policy violation/)
		const restRes = await fetch(`http://127.0.0.1:${addr.port}/api/stripe/v1/customers/cus_456/?expand=subscriptions&account=acct_test_1&app_id=${stripeAppId}`, {
			headers: { authorization: `Bearer ${session.token}` }
		})
		assert.equal(restRes.status, 200)
		const restData = await restRes.json()
		assert.equal(restData.ok, true)
		assert.equal(restData.path, '/v1/customers/cus_456/?expand=subscriptions')
		const allowedPostRes = await executeTool('stripe_api', {
			url: '/v1/charges',
			method: 'POST',
			body: { currency: 'usd', metadata: { team: 'core' } }
		}, session.token)
		assert.equal(allowedPostRes.isError, undefined)
		const deniedBodyRes = await executeTool('stripe_api', {
			url: '/v1/charges',
			method: 'POST',
			body: { currency: 'eur', metadata: { team: 'core' } }
		}, session.token)
		assert.equal(deniedBodyRes.isError, true)
		assert.match(deniedBodyRes.content[0].text, /Policy violation/)
		const restPostDenied = await fetch(`http://127.0.0.1:${addr.port}/api/stripe/v1/charges`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${session.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({ currency: 'eur', metadata: { team: 'core' } })
		})
		assert.equal(restPostDenied.status, 403)
	} finally {
		await new Promise(resolve => mockUpstream.close(resolve))
	}
})

test('usage logging: 30-day rolling window, proxy log capture, MCP list_logs, and GET /api/logs', async () => {
	const http = await import('node:http')
	const mockUpstream = http.createServer((req, res) => {
		if (req.url === '/v1/fail') {
			res.statusCode = 500
			res.setHeader('content-type', 'application/json')
			res.end(JSON.stringify({ error: 'upstream explosion' }))
			return
		}
		if (req.url === '/v1/created') {
			res.statusCode = 201
			res.setHeader('content-type', 'application/json')
			res.end(JSON.stringify({ created: true }))
			return
		}
		res.statusCode = 200
		res.setHeader('content-type', 'application/json')
		res.end(JSON.stringify({ ok: true }))
	})
	await new Promise(resolve => mockUpstream.listen(0, '127.0.0.1', resolve))
	const upstreamPort = mockUpstream.address().port
	const baseUrl = `http://127.0.0.1:${upstreamPort}`
	try {
		const addr = server.address()
		const user = db.logins.resolveUser('google', 'logs-test@example.com')
		const adminSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
		const workerSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
		const app = db.tokens.create({
			userId: user.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Stripe Logs App',
			credentials: { apiKey: 'sk_test_logs', baseUrl }
		})
		db.links.create({
			sessionId: workerSession.id,
			appId: app.id,
			policy: [
				{ action: 'allow', methods: ['GET'], path: '/v1/ok' },
				{ action: 'allow', methods: ['POST'], path: '/v1/created' },
				{ action: 'allow', methods: ['GET'], path: '/v1/fail' }
			]
		})
		const okRes = await executeTool('stripe_api', { url: '/v1/ok' }, workerSession.token)
		assert.equal(okRes.isError, undefined)
		const createdRes = await executeTool('stripe_api', { url: '/v1/created', method: 'POST' }, workerSession.token)
		assert.equal(createdRes.isError, undefined)
		const deniedRes = await executeTool('stripe_api', { url: '/v1/denied' }, workerSession.token)
		assert.equal(deniedRes.isError, true)
		const failRes = await executeTool('stripe_api', { url: '/v1/fail' }, workerSession.token)
		assert.equal(failRes.isError, true)
		const oldLog = db.logs.create({
			userId: user.id,
			sessionId: workerSession.id,
			appId: app.id,
			provider: 'stripe',
			method: 'GET',
			url: `${baseUrl}/v1/old`,
			allowed: true,
			status: 200,
			duration: 5
		})
		const oldDate = new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString()
		db.sqlite.prepare('UPDATE logs SET created = ? WHERE id = ?').run(oldDate, oldLog.id)
		const prePruneRes = await executeTool('admin', { action: 'list_logs' }, adminSession.token)
		assert.equal(JSON.parse(prePruneRes.content[0].text).logs.length, 4, 'list_logs enforces 30-day retention window at query time before prune')
		db.logs.prune()
		assert.equal(db.sqlite.prepare('SELECT id FROM logs WHERE id = ?').get(oldLog.id), undefined, 'db.logs.prune() physically deletes expired log row')
		const adminLogsRes = await executeTool('admin', { action: 'list_logs' }, adminSession.token)
		assert.equal(adminLogsRes.isError, undefined)
		const { logs } = JSON.parse(adminLogsRes.content[0].text)
		assert.equal(logs.length, 4, '30-day pruning removes 35-day-old log entry and keeps 4 recent entries')
		assert.equal(logs[0].url, `${baseUrl}/v1/fail`)
		assert.equal(logs[0].allowed, true)
		assert.equal(logs[0].status, 500)
		assert.match(logs[0].error, /upstream explosion/)
		assert.equal(logs[1].url, `${baseUrl}/v1/denied`)
		assert.equal(logs[1].allowed, false)
		assert.equal(logs[1].status, 403)
		assert.equal(logs[2].url, `${baseUrl}/v1/created`)
		assert.equal(logs[2].allowed, true)
		assert.equal(logs[2].status, 201)
		assert.equal(logs[3].url, `${baseUrl}/v1/ok`)
		assert.equal(logs[3].allowed, true)
		assert.equal(logs[3].status, 200)
		assert.equal(logs[3].error, null)
		const selfLogsRes = await executeTool('admin', { action: 'list_logs' }, workerSession.token)
		assert.equal(selfLogsRes.isError, undefined)
		const selfLogsData = JSON.parse(selfLogsRes.content[0].text)
		assert.equal(selfLogsData.logs.length, 4)
		const crossSessionLogsRes = await executeTool('admin', {
			action: 'list_logs',
			sessionId: adminSession.id
		}, workerSession.token)
		assert.equal(crossSessionLogsRes.isError, true)
		assert.match(crossSessionLogsRes.content[0].text, /requires admin privileges/)
		const restDeniedOnlyRes = await fetch(`http://127.0.0.1:${addr.port}/api/logs?allowed=false&limit=10`, {
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(restDeniedOnlyRes.status, 200)
		const restDeniedData = await restDeniedOnlyRes.json()
		assert.equal(restDeniedData.logs.length, 1)
		assert.equal(restDeniedData.logs[0].allowed, false)
		assert.equal(restDeniedData.logs[0].url, `${baseUrl}/v1/denied`)
		const restAllowedNumericRes = await fetch(`http://127.0.0.1:${addr.port}/api/logs?allowed=1&limit=10`, {
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(restAllowedNumericRes.status, 200)
		const restAllowedNumericData = await restAllowedNumericRes.json()
		assert.equal(restAllowedNumericData.logs.length, 3)
		assert.ok(restAllowedNumericData.logs.every(l => l.allowed === true))
	} finally {
		await new Promise(resolve => mockUpstream.close(resolve))
	}
})

test('upstream credential conventions (Basic, Query-param, Bearer), form-urlencoded object serialization, and XML/+json content types', async () => {
	const http = await import('node:http')
	const captured = []
	const mockUpstream = http.createServer((req, res) => {
		const chunks = []
		req.on('data', c => chunks.push(c))
		req.on('end', () => {
			const rawBody = Buffer.concat(chunks).toString('utf8')
			captured.push({
				method: req.method,
				url: req.url,
				headers: req.headers,
				body: rawBody
			})
			if (req.url.startsWith('/xml.response')) {
				res.statusCode = 200
				res.setHeader('content-type', 'application/xml; charset=iso-8859-1')
				res.end(Buffer.from('<?xml version="1.0" encoding="iso-8859-1"?><ApiResponse Status="OK"><CommandResponse>caf\xe9</CommandResponse></ApiResponse>', 'latin1'))
				return
			}
			if (req.url.startsWith('/soap')) {
				res.statusCode = 200
				res.setHeader('content-type', 'application/soap+xml; charset=utf-8')
				res.end('<soap:Envelope><soap:Body><Result>ok</Result></soap:Body></soap:Envelope>')
				return
			}
			if (req.url.startsWith('/problem')) {
				res.statusCode = 200
				res.setHeader('content-type', 'application/problem+json')
				res.end(JSON.stringify({ type: 'about:blank', title: 'Not Really An Error', detail: 'parsed as json' }))
				return
			}
			res.statusCode = 200
			res.setHeader('content-type', 'application/json')
			res.end(JSON.stringify({
				ok: true,
				url: req.url,
				auth: req.headers.authorization || null,
				contentType: req.headers['content-type'] || null,
				body: rawBody
			}))
		})
	})
	await new Promise(resolve => mockUpstream.listen(0, '127.0.0.1', resolve))
	const upstreamPort = mockUpstream.address().port
	const baseUrl = `http://127.0.0.1:${upstreamPort}`
	try {
		const addr = server.address()
		const user = db.logins.resolveUser('google', 'conventions@example.com')
		const session = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
		const mailgunConnect = await executeTool('admin', {
			action: 'connect_app',
			provider: 'mailgun',
			name: 'Mailgun Basic',
			apiKey: '  api:key-mailgun-secret  ',
			baseUrl
		}, session.token)
		const mailgunAppId = JSON.parse(mailgunConnect.content[0].text).app.id
		await executeTool('admin', {
			action: 'link_app',
			sessionId: session.id,
			appId: mailgunAppId,
			policy: [
				{
					action: 'deny',
					methods: ['POST'],
					path: '/v3/messages',
					body: { forbidden: '1' }
				},
				{
					action: 'allow',
					methods: ['POST'],
					path: '/v3/messages',
					body: { from: 'noreply@example.com', tag: ['onboarding', 'welcome'] }
				}
			]
		}, session.token)
		const mgRes = await executeTool('mailgun_api', {
			url: '/v3/messages',
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				Authorization: 'Bearer attacker-attempt'
			},
			body: {
				from: 'noreply@example.com',
				to: 'alice@example.com',
				tag: ['onboarding', 'welcome'],
				vars: { plan: 'pro' }
			}
		}, session.token)
		assert.equal(mgRes.isError, undefined)
		const mgData = JSON.parse(mgRes.content[0].text)
		assert.equal(mgData.auth, `Basic ${Buffer.from('api:key-mailgun-secret').toString('base64')}`)
		assert.equal(mgData.contentType, 'application/x-www-form-urlencoded')
		assert.equal(mgData.body, 'from=noreply%40example.com&to=alice%40example.com&tag=onboarding&tag=welcome&vars=%7B%22plan%22%3A%22pro%22%7D')
		const mgBypassAttempt = await executeTool('mailgun_api', {
			url: '/v3/messages',
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: '<x>=1&from=noreply@example.com&tag=welcome&forbidden=1'
		}, session.token)
		assert.equal(mgBypassAttempt.isError, true, 'Form-urlencoded string starting with < must not bypass body deny rules')
		assert.match(mgBypassAttempt.content[0].text, /Policy violation/)
		const mgDenied = await executeTool('mailgun_api', {
			url: '/v3/messages',
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: {
				from: 'spoof@evil.com',
				to: 'alice@example.com',
				tag: ['welcome']
			}
		}, session.token)
		assert.equal(mgDenied.isError, true)
		assert.match(mgDenied.content[0].text, /Policy violation/)
		const preformattedBasicApp = db.tokens.create({
			userId: user.id,
			provider: 'twilio',
			type: 'api_key',
			name: 'Twilio Preformatted',
			credentials: { apiKey: 'basic dXNlcm5hbWU6cGFzc3dvcmQ=', baseUrl }
		})
		db.links.create({ sessionId: session.id, appId: preformattedBasicApp.id, policy: [{ action: 'allow' }] })
		const twilioRes = await executeTool('twilio_api', { url: '/2010-04-01/Accounts' }, session.token)
		assert.equal(twilioRes.isError, undefined)
		assert.equal(JSON.parse(twilioRes.content[0].text).auth, 'Basic dXNlcm5hbWU6cGFzc3dvcmQ=')
		const ncConnect = await executeTool('admin', {
			action: 'connect_app',
			provider: 'namecheap',
			name: 'Namecheap XML',
			apiKey: ' ?ApiUser=jtane&ApiKey=topsecret123&UserName=jtane&ClientIp=1.2.3.4 ',
			baseUrl
		}, session.token)
		const ncAppId = JSON.parse(ncConnect.content[0].text).app.id
		await executeTool('admin', {
			action: 'link_app',
			sessionId: session.id,
			appId: ncAppId,
			policy: [{ action: 'allow', path: '/**' }]
		}, session.token)
		const ncRes = await executeTool('namecheap_api', {
			url: '/xml.response?Command=namecheap.domains.getList&apikey=evil_override&APIUSER=hacker',
			headers: { Authorization: 'Bearer should-be-stripped' }
		}, session.token)
		assert.equal(ncRes.isError, undefined)
		assert.match(ncRes.content[0].text, /<CommandResponse>café<\/CommandResponse>/)
		const ncCaptured = captured.find(r => r.url.startsWith('/xml.response'))
		assert.ok(ncCaptured)
		assert.equal(ncCaptured.headers.authorization, undefined, 'Query-param auth must not send Authorization header')
		const ncParsedUrl = new URL(ncCaptured.url, baseUrl)
		assert.equal(ncParsedUrl.searchParams.get('Command'), 'namecheap.domains.getList')
		assert.equal(ncParsedUrl.searchParams.get('ApiUser'), 'jtane')
		assert.equal(ncParsedUrl.searchParams.get('APIUSER'), null, 'Case-insensitive colliding caller query param APIUSER must be stripped')
		assert.equal(ncParsedUrl.searchParams.get('ApiKey'), 'topsecret123')
		assert.equal(ncParsedUrl.searchParams.get('apikey'), null, 'Case-insensitive colliding caller query param apikey must be stripped')
		assert.equal(ncParsedUrl.searchParams.get('ClientIp'), '1.2.3.4')
		assert.deepEqual(ncParsedUrl.searchParams.getAll('ApiKey'), ['topsecret123'], 'Caller query param must not duplicate or override secret query param')
		const logsRes = await executeTool('admin', { action: 'list_logs', provider: 'namecheap' }, session.token)
		const ncLogs = JSON.parse(logsRes.content[0].text).logs
		assert.equal(ncLogs.length, 1)
		assert.ok(!ncLogs[0].url.includes('topsecret123'), 'Secret query credentials must never leak into db.logs')
		assert.equal(ncLogs[0].url, `${baseUrl}/xml.response?Command=namecheap.domains.getList&apikey=evil_override&APIUSER=hacker`)
		const updateKeyRes = await executeTool('admin', {
			action: 'update_app',
			appId: ncAppId,
			apiKey: '?ApiUser=jtane&ApiKey=rotatedsecret456&UserName=jtane&ClientIp=5.6.7.8'
		}, session.token)
		assert.equal(updateKeyRes.isError, undefined)
		captured.length = 0
		await executeTool('namecheap_api', { url: '/xml.response?Command=namecheap.domains.getList' }, session.token)
		const rotatedParsedUrl = new URL(captured[0].url, baseUrl)
		assert.equal(rotatedParsedUrl.searchParams.get('ApiKey'), 'rotatedsecret456')
		assert.equal(rotatedParsedUrl.searchParams.get('ClientIp'), '5.6.7.8')
		const restXmlRes = await fetch(`http://127.0.0.1:${addr.port}/api/namecheap/xml.response?Command=namecheap.domains.getList`, {
			headers: { authorization: `Bearer ${session.token}` }
		})
		assert.equal(restXmlRes.status, 200)
		assert.equal(restXmlRes.headers.get('content-type'), 'application/xml; charset=utf-8')
		assert.match(await restXmlRes.text(), /<ApiResponse Status="OK">/)
		const soapRes = await executeTool('namecheap_api', {
			url: '/soap',
			method: 'POST',
			body: '  <soap:Envelope><soap:Body><Ping/></soap:Body></soap:Envelope>'
		}, session.token)
		assert.equal(soapRes.isError, undefined)
		assert.equal(soapRes.content[0].text, '<soap:Envelope><soap:Body><Result>ok</Result></soap:Body></soap:Envelope>')
		const soapCaptured = captured.find(r => r.url.startsWith('/soap'))
		assert.equal(soapCaptured.headers['content-type'], 'application/xml')
		const problemRes = await executeTool('namecheap_api', { url: '/problem' }, session.token)
		assert.equal(problemRes.isError, undefined)
		const problemData = JSON.parse(problemRes.content[0].text)
		assert.equal(problemData.detail, 'parsed as json')
	} finally {
		await new Promise(resolve => mockUpstream.close(resolve))
	}
})

test('unified provider factory, github oauth + api_key provider, and unauthenticated consent/callback protections', async () => {
	const http = await import('node:http')
	assert.equal(isGithubAllowedUrl('https://api.github.com/repos/jessetane/jump').allowed, true)
	assert.equal(isGithubAllowedUrl('http://api.github.com/repos/jessetane/jump').allowed, false)
	assert.equal(isGithubAllowedUrl('https://evil.com/repos').allowed, false)
	assert.equal(getProvider('github').normalizeTargetUrl('repos/jessetane/jump'), 'https://api.github.com/repos/jessetane/jump')
	assert.equal(getProvider('github').normalizeTargetUrl('/user/repos'), 'https://api.github.com/user/repos')
	assert.equal(getProvider('google').normalizeTargetUrl('sheets.googleapis.com/v4/spreadsheets/123'), 'https://sheets.googleapis.com/v4/spreadsheets/123')
	assert.equal(getProvider('google').normalizeTargetUrl('drive/v3/files'), 'https://www.googleapis.com/drive/v3/files')
	assert.equal(summarizeScopes('public_repo,gist', githubServices), 'repo (ro), gist (rw)')
	assert.equal(summarizeScopes('read:user,public_repo,gist', githubServices), 'repo (ro), gist (rw)')
	assert.equal(summarizeScopes('read:user,user:email,public_repo', githubServices), 'repo, user (ro)')
	assert.equal(summarizeScopes('read:audit_log,admin:org', githubServices), 'org (rw), audit_log (ro)')
	assert.equal(summarizeScopes('repo, workflow, notifications', githubServices), 'repo (rw), workflow (rw), notifications (ro)')
	assert.equal(summarizeScopes('read:packages,write:packages,delete:packages', githubServices), 'packages (rw)')
	assert.equal(summarizeScopes('read:packages', githubServices), 'packages (ro)')
	const customProv = createProvider({ id: 'custom_oauth', name: 'CustomOAuth', baseUrl: 'https://api.custom.dev/v2', oauth: { authUrl: 'https://custom.dev/auth', tokenUrl: 'https://custom.dev/token', userInfoUrl: 'https://custom.dev/me' } })
	assert.equal(customProv.isAllowedUrl('https://api.custom.dev/v2/items').allowed, true)
	assert.equal(customProv.isAllowedUrl('https://api.custom.dev/v1/items').allowed, false)
	const wildcardNoBaseProv = createProvider({ id: 'wildcard_only', name: 'WildcardOnly', baseUrl: null, allowedHosts: ['*.example.org'] })
	assert.equal(wildcardNoBaseProv.isAllowedUrl('https://api.example.org/v1/test').allowed, true)
	assert.equal(wildcardNoBaseProv.isAllowedUrl('https://evil.org/v1/test').allowed, false)
	process.env.OKTA_TEST_SSO_ONLY = 'true'
	try {
		const envSsoProv = createProvider({ id: 'okta_test', name: 'OktaTest', oauth: { authUrl: 'https://okta.test/auth', tokenUrl: 'https://okta.test/token', userInfoUrl: 'https://okta.test/me' } })
		assert.equal(envSsoProv.ssoOnly, true, '<PROVIDER>_SSO_ONLY=true env variable configures ssoOnly on createProvider')
	} finally {
		delete process.env.OKTA_TEST_SSO_ONLY
	}
	const addr = server.address()
	const origFetchGoogle = globalThis.fetch
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.unverified', refresh_token: '1//new', expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: 'spoof@corp.com', verified_email: false }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetchGoogle(input, init)
	}
	try {
		await assert.rejects(() => google.exchangeCode('code', 'http://localhost/cb'), /Could not retrieve account identifier from Google/, 'Google provider must reject unverified_email userinfo responses')
	} finally {
		globalThis.fetch = origFetchGoogle
	}
	let refreshCalls = 0
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			refreshCalls++
			await new Promise(resolve => setTimeout(resolve, 15))
			return new Response(JSON.stringify({ access_token: `ya29.dedup_${refreshCalls}`, expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetchGoogle(input, init)
	}
	try {
		const refreshOwner = db.logins.resolveUser('google', 'dedup-refresh@example.com')
		const expiringApp = db.tokens.create({
			userId: refreshOwner.id,
			provider: 'google',
			type: 'oauth',
			name: 'Expiring Dedup Google',
			credentials: { accessToken: 'ya29.stale', refreshToken: '1//dedup-refresh' },
			expiresAt: Date.now() - 1000
		})
		const [t1, t2, t3] = await Promise.all([
			google.getFreshToken(expiringApp),
			google.getFreshToken(expiringApp),
			google.getFreshToken(expiringApp)
		])
		assert.equal(refreshCalls, 1, 'Concurrent getFreshToken calls must deduplicate in-flight upstream refresh')
		assert.equal(t1.token, 'ya29.dedup_1')
		assert.equal(t2.token, 'ya29.dedup_1')
		assert.equal(t3.token, 'ya29.dedup_1')
	} finally {
		globalThis.fetch = origFetchGoogle
	}
	const user = db.logins.resolveUser('google', 'github-test@example.com')
	const adminSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
	const noParamsConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: '',
		redirect: 'manual'
	})
	assert.equal(noParamsConsentRes.status, 403)
	assert.match(await noParamsConsentRes.text(), /admin session required/)
	const connectPageRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/connect?session_id=${adminSession.id}&services=repo,gist,notifications&write=repo,gist`)
	assert.equal(connectPageRes.status, 200)
	const connectHtml = await connectPageRes.text()
	assert.match(connectHtml, /"provider":\{"id":"github","name":"GitHub"\}/)
	assert.match(connectHtml, /"id":"gist","name":"Gists","ro":false,"rw":true/)
	assert.match(connectHtml, /"id":"notifications","name":"Notifications","ro":true,"rw":false/)
	assert.doesNotMatch(connectHtml, /defaultServices/)
	delete process.env.GITHUB_CLIENT_ID
	const missingEnvConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ session_id: adminSession.id }).toString(),
		redirect: 'manual'
	})
	assert.equal(missingEnvConsentRes.status, 500)
	assert.match(await missingEnvConsentRes.text(), /GITHUB_CLIENT_ID environment variable is missing/)
	process.env.GITHUB_CLIENT_ID = 'gh-test-client-id'
	process.env.GITHUB_CLIENT_SECRET = 'gh-test-client-secret'
	const consentBody = new URLSearchParams({
		session_id: adminSession.id,
		app_name: 'My GitHub'
	})
	consentBody.append('services', 'REPO,GIST,NOTIFICATIONS')
	consentBody.append('write', 'GIST')
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 302)
	const authUrl = new URL(consentRes.headers.get('location'))
	assert.equal(authUrl.origin, 'https://github.com')
	assert.equal(authUrl.pathname, '/login/oauth/authorize')
	assert.equal(authUrl.searchParams.get('client_id'), 'gh-test-client-id')
	const scopes = authUrl.searchParams.get('scope').split(' ')
	assert.deepEqual(scopes, ['read:user', 'public_repo', 'gist', 'notifications'])
	const stateToken = authUrl.searchParams.get('state')
	assert.ok(stateToken)
	const origFetch = globalThis.fetch
	const revokedCalls = []
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://github.com/login/oauth/access_token') {
			const bodyParams = new URLSearchParams(init?.body || '')
			if (bodyParams.get('code') === 'bad-gh-code') {
				return new Response(JSON.stringify({
					error: 'bad_verification_code',
					error_description: 'The code passed is incorrect or expired.'
				}), { status: 200, headers: { 'content-type': 'application/json' } })
			}
			return new Response(JSON.stringify({
				access_token: 'gho_test_oauth_token',
				scope: 'read:user,public_repo,gist,notifications',
				token_type: 'bearer'
			}), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://api.github.com/user') {
			return new Response(JSON.stringify({
				login: 'octocat',
				id: 1
			}), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u.startsWith('https://api.github.com/applications/')) {
			revokedCalls.push({ url: u, method: init?.method, headers: init?.headers, body: init?.body })
			return new Response(null, { status: 204 })
		}
		return origFetch(input, init)
	}
	try {
		const badStateToken = db.tokens.createState({
			sessionId: adminSession.id,
			provider: 'github'
		})
		const badCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=bad-gh-code&state=${badStateToken}`)
		assert.equal(badCbRes.status, 502)
		assert.match(await badCbRes.text(), /The code passed is incorrect or expired/)
		const orphanStateToken = db.tokens.createState({
			sessionId: 'deleted-session-id',
			provider: 'github'
		})
		const orphanCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=good-code&state=${orphanStateToken}`)
		assert.equal(orphanCbRes.status, 403)
		assert.match(await orphanCbRes.text(), /Access denied: admin session required/)
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=good-code&state=${stateToken}`)
		assert.equal(cbRes.status, 200)
		const cbHtml = await cbRes.text()
		assert.match(cbHtml, /GitHub Connected/)
		assert.match(cbHtml, /Connected <strong>octocat<\/strong>/)
		const appsListRes = await executeTool('admin', { action: 'list_apps' }, adminSession.token)
		const { apps } = JSON.parse(appsListRes.content[0].text)
		const ghOauthApp = apps.find(a => a.provider === 'github' && a.type === 'oauth')
		assert.ok(ghOauthApp)
		assert.equal(ghOauthApp.name, 'My GitHub')
		assert.equal(ghOauthApp.account, 'octocat')
		assert.equal(ghOauthApp.expiresAt, null)
		assert.equal(ghOauthApp.scopes, 'read:user,public_repo,gist,notifications')
		const rawGhToken = db.tokens.get(ghOauthApp.id)
		assert.deepEqual(rawGhToken.credentials, {
			accessToken: 'gho_test_oauth_token',
			refreshToken: null,
			account: 'octocat'
		})
		const disconnectOauthRes = await executeTool('admin', {
			action: 'disconnect_app',
			appId: ghOauthApp.id,
			revoke: true
		}, adminSession.token)
		assert.equal(disconnectOauthRes.isError, undefined)
		assert.equal(revokedCalls.length, 1)
		assert.equal(revokedCalls[0].url, 'https://api.github.com/applications/gh-test-client-id/token')
		assert.equal(revokedCalls[0].method, 'DELETE')
		assert.equal(JSON.parse(revokedCalls[0].body).access_token, 'gho_test_oauth_token')
	} finally {
		globalThis.fetch = origFetch
	}
	const capturedUpstream = []
	const mockGhServer = http.createServer((req, res) => {
		capturedUpstream.push({
			url: req.url,
			headers: req.headers
		})
		res.statusCode = 200
		res.setHeader('content-type', 'application/json')
		res.end(JSON.stringify({ full_name: 'jessetane/jump', ua: req.headers['user-agent'] }))
	})
	await new Promise(resolve => mockGhServer.listen(0, '127.0.0.1', resolve))
	const mockGhUrl = `http://127.0.0.1:${mockGhServer.address().port}`
	try {
		const patConnectRes = await executeTool('admin', {
			action: 'connect_app',
			provider: 'github',
			name: 'GitHub PAT',
			account: 'jessetane',
			apiKey: 'ghp_personal_access_token_123',
			baseUrl: mockGhUrl
		}, adminSession.token)
		assert.equal(patConnectRes.isError, undefined)
		const patApp = JSON.parse(patConnectRes.content[0].text).app
		assert.equal(patApp.provider, 'github')
		assert.equal(patApp.type, 'api_key')
		assert.equal(patApp.account, 'jessetane')
		await executeTool('admin', {
			action: 'link_app',
			sessionId: adminSession.id,
			appId: patApp.id,
			policy: [{ action: 'allow', methods: ['GET'], path: '/repos/jessetane/**' }]
		}, adminSession.token)
		const ghApiRes = await executeTool('github_api', {
			url: '/repos/jessetane/jump'
		}, adminSession.token)
		assert.equal(ghApiRes.isError, undefined)
		const ghData = JSON.parse(ghApiRes.content[0].text)
		assert.equal(ghData.full_name, 'jessetane/jump')
		assert.equal(ghData.ua, 'jump')
		assert.equal(capturedUpstream.length, 1)
		assert.equal(capturedUpstream[0].headers.authorization, 'Bearer ghp_personal_access_token_123')
		assert.equal(capturedUpstream[0].headers['user-agent'], 'jump')
	} finally {
		await new Promise(resolve => mockGhServer.close(resolve))
	}
})

test('local token sign-in fallback, bootstrapLocalAdmin, and in-place SQLite legacy user migration', async () => {
	const addr = server.address()
	const freshMaster = db.sqlite.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name = 'users' ORDER BY type, name").all()
	const origGoogleId = process.env.GOOGLE_CLIENT_ID
	const origGithubId = process.env.GITHUB_CLIENT_ID
	try {
		delete process.env.GOOGLE_CLIENT_ID
		delete process.env.GITHUB_CLIENT_ID
		assert.deepEqual(listAuthProviders(), [])
		const authPageRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize`)
		assert.equal(authPageRes.status, 200)
		const authHtml = await authPageRes.text()
		assert.match(authHtml, /"providers":\[\]/)
		assert.match(authHtml, /"localAuth":true/)
		const localUser = db.users.create()
		assert.deepEqual(Object.keys(localUser).sort(), ['created', 'id', 'updated'])
		const localAdminSession = db.tokens.create({
			userId: localUser.id,
			provider: 'self',
			name: 'Local Admin',
			admin: 1
		})
		const localWorkerSession = db.tokens.create({
			userId: localUser.id,
			provider: 'self',
			name: 'Local Worker',
			admin: 0
		})
		const nonAdminConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ token: localWorkerSession.token, session_name: 'Via Worker' }).toString(),
			redirect: 'manual'
		})
		assert.equal(nonAdminConsent.status, 403)
		assert.match(await nonAdminConsent.text(), /valid admin bearer token required/)
		const adminConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ token: localAdminSession.token, session_name: 'Via Local Token', admin: '1' }).toString(),
			redirect: 'manual'
		})
		assert.equal(adminConsent.status, 200, 'Local token sign-in with 0 apps returns bearer token directly without /oauth/verify hop')
		const directText = await adminConsent.text()
		assert.match(directText, /user:\s*localhost/)
		const tokenMatch = directText.match(/token:\s*([a-f0-9-]+)/)
		assert.ok(tokenMatch)
		const newSession = db.tokens.getByToken(tokenMatch[1])
		assert.equal(newSession.userId, localUser.id)
		assert.equal(newSession.name, 'Via Local Token')
		assert.equal(newSession.admin, true)
		assert.equal(newSession.account, 'localhost')
		const localApp = db.tokens.create({
			userId: localUser.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Local Stripe',
			credentials: { apiKey: 'sk_local', baseUrl: 'https://api.stripe.com' }
		})
		const adminConsentWithApp = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ token: localAdminSession.token, session_name: 'Via Local Verify', admin: '1' }).toString(),
			redirect: 'manual'
		})
		assert.equal(adminConsentWithApp.status, 302, 'Local token sign-in with connected apps redirects to /oauth/verify')
		const verifyLoc = new URL(adminConsentWithApp.headers.get('location'), `http://127.0.0.1:${addr.port}`)
		assert.equal(verifyLoc.pathname, '/oauth/verify')
		const code = verifyLoc.searchParams.get('code')
		assert.ok(code)
		const verifyPostRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code, app_id: localApp.id }).toString()
		})
		assert.equal(verifyPostRes.status, 200)
		db.tokens.remove(localApp.id)
		db.sqlite.exec("DELETE FROM tokens WHERE provider = 'self'")
		db.tokens.create({ userId: localUser.id, provider: 'self', admin: 0, name: 'Non-admin Only' })
		db.tokens.create({ userId: localUser.id, provider: 'self', admin: 1, expiresAt: Date.now() - 5000, name: 'Expired Admin' })
		const bootstrapped = bootstrapLocalAdmin()
		assert.ok(bootstrapped, 'bootstrapLocalAdmin mints admin session when only non-admin or expired admin sessions exist')
		assert.equal(bootstrapped.provider, 'self')
		assert.equal(bootstrapped.admin, true)
		assert.equal(bootstrapped.account, 'localhost')
		assert.equal(bootstrapLocalAdmin(), null, 'bootstrapLocalAdmin is a no-op once an active admin session exists')
	} finally {
		if (origGoogleId !== undefined) process.env.GOOGLE_CLIENT_ID = origGoogleId
		if (origGithubId !== undefined) process.env.GITHUB_CLIENT_ID = origGithubId
	}
	const now = new Date().toISOString()
	const legacyUserId = 'legacy-google-user-1'
	const legacySurvivingShareId = 'legacy-surviving-share-1'
	const legacyEmailStubId = 'legacy-email-stub-1'
	const legacyEmailStubShareId = 'legacy-email-stub-share-1'
	const legacyDupUserId = 'legacy-dup-user-1'
	const legacyDupShareId = 'legacy-dup-share-1'
	const legacyDormantLogsId = 'legacy-dormant-logs-1'
	const legacyDormantEmptyId = 'legacy-dormant-empty-1'
	const stubOwner = db.logins.resolveUser('google', 'stub-owner@acme.com')
	const stubUpstreamApp = db.tokens.create({
		userId: stubOwner.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Legacy Pre-Shared Stripe',
		credentials: { apiKey: 'sk_legacy_stub', baseUrl: 'https://api.stripe.com' }
	})
	const legacyLinkedSession = db.tokens.create({
		userId: stubOwner.id,
		provider: 'self',
		name: 'Legacy TokenLinks Session',
		admin: 1
	})
	db.sqlite.exec('PRAGMA foreign_keys = OFF;')
	db.sqlite.exec(`
		PRAGMA user_version = 0;
		CREATE TEMP TABLE users_mig_tmp AS SELECT id, created, updated FROM users;
		DROP TABLE users;
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			name TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL
		);
		CREATE INDEX idx_users_email ON users(email);
		INSERT INTO users (id, email, name, created, updated)
			SELECT id, id || '@placeholder.local', 'Placeholder', created, updated FROM users_mig_tmp;
		DROP TABLE users_mig_tmp;
		CREATE TEMP TABLE tokens_mig_tmp AS SELECT * FROM tokens WHERE user_id IS NOT NULL;
		DROP TABLE tokens;
		CREATE TABLE tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
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
			updated TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);
		INSERT INTO tokens SELECT * FROM tokens_mig_tmp;
		DROP TABLE tokens_mig_tmp;
		CREATE TABLE token_links (
			session_token_id TEXT NOT NULL,
			app_token_id TEXT NOT NULL,
			policy TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL,
			PRIMARY KEY (session_token_id, app_token_id)
		);
		INSERT INTO token_links (session_token_id, app_token_id, policy, created, updated)
			VALUES ('${legacyLinkedSession.id}', '${stubUpstreamApp.id}', '[{"action":"allow"}]', '${now}', '${now}');
		CREATE TABLE oauth_states (state TEXT PRIMARY KEY, redirect_uri TEXT);
		CREATE TABLE oauth_codes (code TEXT PRIMARY KEY, session_token_id TEXT);
	`)
	db.sqlite.exec('PRAGMA foreign_keys = ON;')
	db.sqlite.prepare('INSERT INTO users (id, email, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyUserId,
		'legacy@gmail.com',
		'Legacy User',
		now,
		now
	)
	db.tokens.create({
		userId: legacyUserId,
		provider: 'self',
		name: 'Legacy Real User Session',
		admin: 1
	})
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, credentials, created, updated)
		VALUES (?, ?, 'stripe', 'share', ?, ?, ?)
	`).run(legacySurvivingShareId, legacyUserId, JSON.stringify({ appId: stubUpstreamApp.id, policy: null }), now, now)
	db.sqlite.prepare('INSERT INTO users (id, email, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyDupUserId,
		'LEGACY@gmail.com',
		'Duplicate Case User',
		now,
		now
	)
	const dupSession = db.tokens.create({
		userId: legacyDupUserId,
		provider: 'self',
		name: 'Duplicate Case Session',
		admin: 0
	})
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, credentials, created, updated)
		VALUES (?, ?, 'stripe', 'share', ?, ?, ?)
	`).run(legacyDupShareId, legacyDupUserId, JSON.stringify({ appId: stubUpstreamApp.id, policy: null }), now, now)
	db.links.create({
		sessionId: dupSession.id,
		appId: legacyDupShareId
	})
	db.sqlite.prepare('INSERT INTO users (id, email, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyDormantLogsId,
		'dormant-logs@gmail.com',
		'Dormant User With Logs',
		now,
		now
	)
	db.logs.create({
		userId: legacyDormantLogsId,
		provider: 'stripe',
		method: 'GET',
		url: 'https://api.stripe.com/v1/charges',
		status: 200,
		durationMs: 12
	})
	db.sqlite.prepare('INSERT INTO users (id, email, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyDormantEmptyId,
		'dormant-empty@gmail.com',
		'Dormant User Zero Tokens',
		now,
		now
	)
	db.sqlite.prepare('INSERT INTO users (id, email, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyEmailStubId,
		'EmailStub@acme.com',
		null,
		now,
		now
	)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, credentials, created, updated)
		VALUES (?, ?, 'stripe', 'share', ?, ?, ?)
	`).run(legacyEmailStubShareId, legacyEmailStubId, JSON.stringify({ appId: stubUpstreamApp.id, policy: null }), now, now)
	db.init()
	assert.equal(db.sqlite.prepare('PRAGMA user_version').get().user_version, 1)
	assert.equal(db.sqlite.prepare('PRAGMA foreign_key_check').all().length, 0, 'Zero foreign-key violations after users.email migration and duplicate share link repointing')
	assert.equal(db.sqlite.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name IN ('token_links', 'oauth_states', 'oauth_codes')").get().count, 0, 'Legacy token_links, oauth_states, and oauth_codes tables are dropped')
	const migratedTokenLinks = db.links.listBySessionId(legacyLinkedSession.id)
	assert.equal(migratedTokenLinks.length, 1, 'Legacy token_links rows are migrated into links')
	assert.equal(migratedTokenLinks[0].appId, stubUpstreamApp.id)
	const migratedEmailMaster = db.sqlite.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name = 'users' ORDER BY type, name").all()
	assert.deepEqual(migratedEmailMaster, freshMaster, 'Migrated users.email DB matches fresh pure-anchor DDL with no leftover columns or indexes')
	const migratedUser = db.users.get(legacyUserId)
	assert.ok(migratedUser)
	assert.deepEqual(Object.keys(migratedUser).sort(), ['created', 'id', 'updated'])
	assert.equal(db.users.get(legacyDupUserId), null, 'Case-insensitive duplicate legacy user row is merged into survivor')
	assert.equal(db.tokens.get(dupSession.id).userId, legacyUserId, 'Duplicate legacy user session is re-parented to surviving user')
	assert.equal(db.tokens.get(legacyDupShareId), null, 'Duplicate share for same upstream appId is deduplicated on user merge')
	const repointedLinks = db.links.listBySessionId(dupSession.id)
	assert.equal(repointedLinks.length, 1, 'Session link to deduplicated share is preserved rather than orphaned')
	assert.equal(repointedLinks[0].appId, legacySurvivingShareId, 'Session link app_id is repointed to surviving share row')
	assert.ok(db.users.get(legacyDormantLogsId), 'Zero-session legacy user with historical logs is preserved as real user')
	assert.equal(db.logins.getAccountByUserId(legacyDormantLogsId), 'dormant-logs@gmail.com')
	assert.equal(db.logs.listByUserId(legacyDormantLogsId).length, 1, 'Historical logs for zero-session legacy user are preserved')
	assert.ok(db.users.get(legacyDormantEmptyId), 'Zero-session, zero-share legacy user is preserved and backfilled rather than treated as stub')
	assert.equal(db.logins.getAccountByUserId(legacyDormantEmptyId), 'dormant-empty@gmail.com')
	assert.equal(db.logins.getAccountByUserId(legacyUserId), 'legacy@gmail.com')
	const backfilledLogins = db.logins.listByUserId(legacyUserId)
	assert.equal(backfilledLogins.length, 1)
	assert.equal(backfilledLogins[0].provider, 'google')
	assert.equal(backfilledLogins[0].account, 'legacy@gmail.com')
	assert.equal(backfilledLogins[0].userId, legacyUserId)
	const resolvedLegacy = db.logins.resolveUser('google', 'LEGACY@gmail.com')
	assert.equal(resolvedLegacy.id, legacyUserId)
	assert.equal(db.users.get(legacyEmailStubId), null, 'Zero-session stub user in users.email DB is converted to pending share and never fabricated as google auth')
	assert.equal(db.tokens.get(legacyEmailStubShareId).userId, null)
	assert.equal(db.tokens.get(legacyEmailStubShareId).account, 'emailstub@acme.com')
	const legacyStubUserId = 'legacy-stub-user-1'
	const legacyShareId = 'legacy-stub-share-1'
	const legacyPrefixedStubId = 'legacy-prefixed-stub-1'
	const legacyPrefixedShareId = 'legacy-prefixed-share-1'
	const legacyBareStubId = 'legacy-bare-stub-1'
	const legacyBareShareId = 'legacy-bare-share-1'
	const legacyBareStateId = 'legacy-bare-state-1'
	const legacyBareRealUserId = 'legacy-bare-real-1'
	const legacyLocalBootstrapId = 'legacy-local-bootstrap-1'
	const legacyMixedAuthUser = db.users.create({ id: 'legacy-mixed-auth-user-1' })
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, created, updated)
		VALUES ('legacy-mixed-auth-token-1', ?, ' GitHub ', 'auth', '   ', 'GitHub:MixedCaseHandle', ?, ?, ?)
	`).run(legacyMixedAuthUser.id, JSON.stringify({ account: ' MixedCaseHandle ' }), now, now)
	db.sqlite.exec('PRAGMA foreign_keys = OFF;')
	db.sqlite.exec(`
		PRAGMA user_version = 0;
		CREATE TEMP TABLE users_acc_tmp AS SELECT id, created, updated FROM users;
		DROP TABLE users;
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			account TEXT UNIQUE NOT NULL,
			name TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL
		);
		CREATE INDEX idx_users_account ON users(account);
		INSERT INTO users (id, account, name, created, updated)
			SELECT id, id, NULL, created, updated FROM users_acc_tmp;
		DROP TABLE users_acc_tmp;
	`)
	db.sqlite.exec('PRAGMA foreign_keys = ON;')
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyStubUserId,
		'Stub-Recipient@acme.com',
		null,
		now,
		now
	)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, credentials, created, updated)
		VALUES (?, ?, 'stripe', 'share', ?, ?, ?)
	`).run(legacyShareId, legacyStubUserId, JSON.stringify({ appId: stubUpstreamApp.id, policy: null }), now, now)
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyPrefixedStubId,
		'github:PrefixedHandle',
		null,
		now,
		now
	)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, credentials, created, updated)
		VALUES (?, ?, 'stripe', 'share', ?, ?, ?)
	`).run(legacyPrefixedShareId, legacyPrefixedStubId, JSON.stringify({ appId: stubUpstreamApp.id, policy: null }), now, now)
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyBareStubId,
		'BareStubHandle',
		null,
		now,
		now
	)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, credentials, created, updated)
		VALUES (?, ?, 'stripe', 'share', ?, ?, ?)
	`).run(legacyBareShareId, legacyBareStubId, JSON.stringify({ appId: stubUpstreamApp.id, policy: null }), now, now)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, token, expires_at, created, updated)
		VALUES (?, ?, 'github', 'oauth_state', 'expired-state-tok', ?, ?, ?)
	`).run(legacyBareStateId, legacyBareStubId, Date.now() - 60000, now, now)
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyBareRealUserId,
		'RealBareGhUser',
		'Real Bare User',
		now,
		now
	)
	db.tokens.create({
		userId: legacyBareRealUserId,
		provider: 'self',
		name: 'Real Bare Session',
		admin: 1
	})
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyLocalBootstrapId,
		'localhost',
		null,
		now,
		now
	)
	db.tokens.create({
		userId: legacyLocalBootstrapId,
		provider: 'self',
		name: 'Legacy Local Bootstrap Session',
		admin: 1
	})
	const caseCollideSurvivorId = 'legacy-case-collide-1'
	const caseCollideDupId = 'legacy-case-collide-2'
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		caseCollideSurvivorId,
		caseCollideSurvivorId,
		null,
		'2024-01-01T00:00:00.000Z',
		'2024-01-01T00:00:00.000Z'
	)
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		caseCollideDupId,
		caseCollideDupId,
		null,
		'2024-01-02T00:00:00.000Z',
		'2024-01-02T00:00:00.000Z'
	)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, created, updated)
		VALUES ('case-collide-auth-1', ?, 'github', 'auth', 'CaseCollide', 'github:CaseCollide', NULL, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')
	`).run(caseCollideSurvivorId)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, created, updated)
		VALUES ('case-collide-auth-2', ?, 'GitHub', 'auth', 'casecollide', 'GitHub:casecollide', NULL, '2024-01-02T00:00:00.000Z', '2024-01-02T00.000Z')
	`).run(caseCollideDupId)
	const caseCollideDupSession = db.tokens.create({
		userId: caseCollideDupId,
		provider: 'self',
		name: 'Duplicate Case Collide Session',
		admin: 1
	})
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, name, token, credentials, created, updated)
		VALUES ('malformed-empty-auth-1', ?, 'github', 'auth', '   ', 'github:   ', NULL, ?, ?)
	`).run(legacyLocalBootstrapId, now, now)
	const stubAliceId = 'legacy-stub-alice-1'
	const stubAliceShareId = 'legacy-stub-alice-share-1'
	const realAliceId = 'legacy-real-alice-1'
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		stubAliceId,
		'alice-preshared@acme.com',
		null,
		'2024-01-01T00:00:00.000Z',
		'2024-01-01T00:00:00.000Z'
	)
	db.sqlite.prepare(`
		INSERT INTO tokens (id, user_id, provider, type, credentials, created, updated)
		VALUES (?, ?, 'stripe', 'share', ?, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')
	`).run(stubAliceShareId, stubAliceId, JSON.stringify({ appId: stubUpstreamApp.id, policy: [{ action: 'allow', methods: ['GET'] }] }))
	db.sqlite.prepare('INSERT INTO users (id, account, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		realAliceId,
		'google:alice-preshared@acme.com',
		'Real Alice',
		'2024-02-01T00:00:00.000Z',
		'2024-02-01T00:00:00.000Z'
	)
	db.tokens.create({
		userId: realAliceId,
		provider: 'self',
		name: 'Real Alice Session',
		admin: 1
	})
	assert.doesNotThrow(() => db.tokens.init(), 'tokens.init() is strictly DDL-only and never crashes on case-colliding or malformed auth rows')
	db.init()
	assert.equal(db.sqlite.prepare('PRAGMA user_version').get().user_version, 1)
	assert.equal(db.sqlite.prepare('PRAGMA foreign_key_check').all().length, 0, 'Zero foreign-key violations after single-pass atomic migration')
	assert.equal(db.sqlite.prepare("SELECT COUNT(*) AS count FROM tokens WHERE type = 'auth'").get().count, 0, 'All legacy tokens(type = auth) rows are migrated out of tokens into logins')
	const normalizedMixedAuth = db.logins.listByUserId(legacyMixedAuthUser.id)
	assert.equal(normalizedMixedAuth.length, 1)
	assert.equal(normalizedMixedAuth[0].provider, 'github', 'db.init() normalizes legacy auth provider to lowercase')
	assert.equal(normalizedMixedAuth[0].account, 'mixedcasehandle', 'db.init() normalizes empty/mixed-case auth account from credentials.account')
	assert.equal(normalizedMixedAuth[0].userId, legacyMixedAuthUser.id)
	assert.equal(db.logins.resolveUser('github', 'mixedcasehandle').id, legacyMixedAuthUser.id)
	assert.ok(db.users.get(caseCollideSurvivorId), 'Case-colliding auth normalization preserves older user as survivor')
	assert.equal(db.users.get(caseCollideDupId), null, 'Case-colliding auth normalization merges and drops duplicate user')
	assert.equal(db.logins.resolveUser('github', 'casecollide').id, caseCollideSurvivorId)
	assert.equal(db.tokens.get(caseCollideDupSession.id).userId, caseCollideSurvivorId, 'Duplicate user sessions are merged onto survivor')
	assert.equal(db.tokens.get('malformed-empty-auth-1'), null, 'Malformed auth row with empty account is deleted instead of leaving NULL zombie auth row')
	assert.equal(db.users.get(stubAliceId), null, 'Pre-shared stub user created before real user is removed on migration')
	assert.ok(db.users.get(realAliceId), 'Real user created after stub user is preserved')
	const claimedAliceShare = db.tokens.get(stubAliceShareId)
	assert.equal(claimedAliceShare.userId, realAliceId, 'Converted pending share from earlier stub user is immediately claimed by existing real user at end of migrate()')
	assert.equal(claimedAliceShare.account, 'alice-preshared@acme.com')
	assert.equal(claimedAliceShare.credentials.authProvider, 'google')
	const migratedAccountMaster = db.sqlite.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name = 'users' ORDER BY type, name").all()
	assert.deepEqual(migratedAccountMaster, freshMaster, 'Migrated users.account/users.name DB matches fresh pure-anchor DDL')
	assert.equal(db.users.get(legacyStubUserId), null, 'Unclaimed stub user from users.account DB is removed on migration rather than bound to google')
	assert.equal(db.logins.listByUserId(legacyStubUserId).length, 0)
	assert.equal(db.users.get(legacyBareStubId), null, 'Stub user with expired oauth_state is still classified as stub and dropped')
	assert.equal(db.tokens.get(legacyBareStateId), null, 'Ephemeral oauth_state row on stub user is cleaned up without FK orphans')
	const migratedBareShare = db.tokens.get(legacyBareShareId)
	assert.equal(migratedBareShare.userId, null)
	assert.equal(migratedBareShare.account, 'barestubhandle')
	assert.equal(migratedBareShare.credentials.authProvider, 'github', 'Bare-handle stub share defaults authProvider to github to preserve pending share invariant')
	assert.ok(db.users.get(legacyBareRealUserId), 'Real legacy bare-handle user is preserved')
	assert.equal(db.logins.resolveUser('github', 'realbareghuser').id, legacyBareRealUserId, 'Real legacy bare-handle user in users.account DB backfills github:account')
	assert.ok(db.users.get(legacyLocalBootstrapId), 'Legacy localhost bootstrap user is preserved')
	assert.equal(db.logins.listByUserId(legacyLocalBootstrapId).length, 0, 'Legacy localhost bootstrap user never fabricates fake OAuth login key')
	assert.equal(db.logins.getAccountByUserId(legacyLocalBootstrapId), 'localhost')
	const migratedPendingShare = db.tokens.get(legacyShareId)
	assert.ok(migratedPendingShare)
	assert.equal(migratedPendingShare.userId, null, 'Stub user share is migrated to pending share with user_id = NULL')
	assert.equal(migratedPendingShare.account, 'stub-recipient@acme.com')
	const unverifiedClaimAttempt = db.logins.resolveUser('custom_idp', 'stub-recipient@acme.com')
	assert.ok(unverifiedClaimAttempt)
	assert.equal(db.tokens.get(legacyShareId).userId, null, 'Migrated unscoped pending email share cannot be claimed by unverified provider')
	const claimedRecipient = db.logins.resolveUser('google', 'stub-recipient@acme.com')
	assert.equal(db.tokens.get(legacyShareId).userId, claimedRecipient.id, 'Migrated pending share is claimed by verified-email provider')
	const migratedPrefixedShare = db.tokens.get(legacyPrefixedShareId)
	assert.equal(migratedPrefixedShare.userId, null)
	assert.equal(migratedPrefixedShare.account, 'prefixedhandle', 'provider:account stub splits cleanAccount into tokens.name')
	assert.equal(migratedPrefixedShare.credentials.authProvider, 'github', 'provider:account stub binds credentials.authProvider')
	const wrongProvClaim = db.logins.resolveUser('google', 'prefixedhandle')
	assert.equal(db.tokens.get(legacyPrefixedShareId).userId, null, 'google login must not claim github-scoped migrated pending share')
	assert.ok(wrongProvClaim)
	const rightProvClaim = db.logins.resolveUser('github', 'prefixedhandle')
	assert.equal(db.tokens.get(legacyPrefixedShareId).userId, rightProvClaim.id, 'github login claims github-scoped migrated pending share')
})

test('shared apps: share_app, unshare_app, ceiling policy enforcement, audit logs, and REST /api/shares', async () => {
	const http = await import('node:http')
	const upstreamCaptured = []
	const mockUpstream = http.createServer((req, res) => {
		upstreamCaptured.push({
			method: req.method,
			url: req.url,
			auth: req.headers.authorization
		})
		res.statusCode = 200
		res.setHeader('content-type', 'application/json')
		res.end(JSON.stringify({ ok: true, path: req.url, method: req.method, auth: req.headers.authorization }))
	})
	await new Promise(resolve => mockUpstream.listen(0, '127.0.0.1', resolve))
	const upstreamPort = mockUpstream.address().port
	const baseUrl = `http://127.0.0.1:${upstreamPort}`
	try {
		const addr = server.address()
		const sarah = db.logins.resolveUser('google', 'sarah@acme.com')
		const sarahAdmin = db.tokens.create({ userId: sarah.id, provider: 'self', admin: 1 })
		const sarahWorker = db.tokens.create({ userId: sarah.id, provider: 'self', admin: 0 })
		const connectRes = await executeTool('admin', {
			action: 'connect_app',
			provider: 'stripe',
			name: 'Acme Stripe',
			account: 'acct_acme_main',
			apiKey: 'sk_live_sarah_secret_123',
			baseUrl
		}, sarahAdmin.token)
		assert.equal(connectRes.isError, undefined)
		const sarahApp = JSON.parse(connectRes.content[0].text).app
		const nonAdminShare = await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'dan@acme.com'
		}, sarahWorker.token)
		assert.equal(nonAdminShare.isError, true)
		assert.match(nonAdminShare.content[0].text, /requires admin privileges/)
		const missingAppShare = await executeTool('admin', {
			action: 'share_app',
			account: 'dan@acme.com'
		}, sarahAdmin.token)
		assert.equal(missingAppShare.isError, true)
		assert.match(missingAppShare.content[0].text, /appId is required/)
		const missingAccountShare = await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: '   '
		}, sarahAdmin.token)
		assert.equal(missingAccountShare.isError, true)
		assert.match(missingAccountShare.content[0].text, /Valid recipient account identifier is required/)
		const selfShare = await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'SARAH@acme.com'
		}, sarahAdmin.token)
		assert.equal(selfShare.isError, true)
		assert.match(selfShare.content[0].text, /Cannot share an app with yourself/)
		const invalidPolicyShare = await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'dan@acme.com',
			policy: [{ action: 'not_valid' }]
		}, sarahAdmin.token)
		assert.equal(invalidPolicyShare.isError, true)
		assert.match(invalidPolicyShare.content[0].text, /action must be "allow" or "deny"/)
		const ceilingPolicy = [
			{ action: 'allow', methods: ['GET'], path: '/v1/customers/**' },
			{ action: 'allow', methods: ['GET', 'POST'], path: '/v1/invoices/**' }
		]
		const shareRes = await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'Dan@acme.com',
			policy: ceilingPolicy
		}, sarahAdmin.token)
		assert.equal(shareRes.isError, undefined)
		const shareData = JSON.parse(shareRes.content[0].text)
		assert.equal(shareData.shared, true)
		assert.equal(shareData.appId, sarahApp.id)
		assert.equal(shareData.userId, null, 'Pre-sharing with unauthenticated recipient stores pending share with userId: null')
		assert.equal(shareData.account, 'dan@acme.com')
		assert.deepEqual(shareData.policy, ceilingPolicy)
		const shareId = shareData.shareId
		assert.ok(shareId)
		assert.notEqual(shareId, sarahApp.id)
		assert.equal(db.logins.findUserByAccount('dan@acme.com'), null, 'Pre-sharing never creates stub user or fake auth row')
		const updatedCeilingPolicy = [
			{ action: 'allow', methods: ['GET'], path: '/v1/customers/**' },
			{ action: 'allow', methods: ['GET'], path: '/v1/invoices/**' }
		]
		const reshareRes = await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'dan@acme.com',
			policy: updatedCeilingPolicy
		}, sarahAdmin.token)
		assert.equal(reshareRes.isError, undefined)
		const reshareData = JSON.parse(reshareRes.content[0].text)
		assert.equal(reshareData.shareId, shareId, 'Re-sharing updates existing pending share token in place without creating duplicates')
		assert.deepEqual(reshareData.policy, updatedCeilingPolicy)
		const sarahAppsRes = await executeTool('admin', { action: 'list_apps' }, sarahAdmin.token)
		const sarahApps = JSON.parse(sarahAppsRes.content[0].text).apps
		const sarahStripe = sarahApps.find(a => a.id === sarahApp.id)
		assert.ok(sarahStripe)
		assert.equal(sarahStripe.shares.length, 1)
		assert.equal(sarahStripe.shares[0].userId, null)
		assert.equal(sarahStripe.shares[0].account, 'dan@acme.com')
		assert.deepEqual(sarahStripe.shares[0].policy, updatedCeilingPolicy)
		const dan = db.logins.resolveUser('google', 'dan@acme.com')
		assert.ok(dan)
		const sarahAppsAfterClaim = JSON.parse((await executeTool('admin', { action: 'list_apps' }, sarahAdmin.token)).content[0].text).apps
		assert.equal(sarahAppsAfterClaim.find(a => a.id === sarahApp.id).shares[0].userId, dan.id, 'Pending share transitions cleanly to claimed userId once Dan signs in')
		const danAdmin = db.tokens.create({ userId: dan.id, provider: 'self', admin: 1 })
		const danAppsRes = await executeTool('admin', { action: 'list_apps' }, danAdmin.token)
		const danApps = JSON.parse(danAppsRes.content[0].text).apps
		assert.equal(danApps.length, 1)
		const danShare = danApps[0]
		assert.equal(danShare.id, shareId)
		assert.equal(danShare.provider, 'stripe')
		assert.equal(danShare.type, 'share')
		assert.equal(danShare.name, 'Acme Stripe')
		assert.equal(danShare.account, 'acct_acme_main')
		assert.equal(danShare.baseUrl, baseUrl)
		assert.equal(danShare.sharedBy, 'sarah@acme.com')
		assert.deepEqual(danShare.policy, updatedCeilingPolicy)
		assert.equal(JSON.stringify(danShare).includes('sk_live_sarah_secret_123'), false, 'Upstream API key must never leak in recipient list_apps')
		const rawShareToken = db.tokens.get(shareId)
		assert.equal(JSON.stringify(rawShareToken).includes('sk_live_sarah_secret_123'), false, 'Upstream API key must never leak in formatted share token')
		await executeTool('admin', {
			action: 'update_app',
			appId: sarahApp.id,
			name: ''
		}, sarahAdmin.token)
		const danAppsAfterClearName = JSON.parse((await executeTool('admin', { action: 'list_apps' }, danAdmin.token)).content[0].text).apps
		assert.equal(danAppsAfterClearName[0].name, null, 'Clearing upstream app name reflects as null on recipient share without falling back to stale snapshot')
		await executeTool('admin', {
			action: 'update_app',
			appId: sarahApp.id,
			name: 'Acme Global Stripe'
		}, sarahAdmin.token)
		const danAppsAfterRename = JSON.parse((await executeTool('admin', { action: 'list_apps' }, danAdmin.token)).content[0].text).apps
		assert.equal(danAppsAfterRename[0].name, 'Acme Global Stripe', 'Upstream app rename dynamically reflects in recipient list_apps')
		const danUpdateAttempt = await executeTool('admin', {
			action: 'update_app',
			appId: shareId,
			name: 'Hacked Name'
		}, danAdmin.token)
		assert.equal(danUpdateAttempt.isError, true)
		assert.match(danUpdateAttempt.content[0].text, /App not found/)
		const danReshareAttempt = await executeTool('admin', {
			action: 'share_app',
			appId: shareId,
			account: 'eve@acme.com'
		}, danAdmin.token)
		assert.equal(danReshareAttempt.isError, true)
		assert.match(danReshareAttempt.content[0].text, /App not found/)
		const danReauthAttempt = await executeTool('admin', {
			action: 'connect_app',
			appId: shareId
		}, danAdmin.token)
		assert.equal(danReauthAttempt.isError, true)
		assert.match(danReauthAttempt.content[0].text, /App not found/)
		const danAgentRes = await executeTool('admin', {
			action: 'create_session',
			name: 'Dan Agent',
			linkAppIds: [shareId],
			policy: [
				{ action: 'allow', methods: ['GET'], path: '/v1/customers/**' },
				{ action: 'allow', methods: ['POST'], path: '/v1/invoices/**' }
			]
		}, danAdmin.token)
		assert.equal(danAgentRes.isError, undefined)
		const danAgentSession = JSON.parse(danAgentRes.content[0].text).session
		const danWhoamiRes = await executeTool('admin', { action: 'whoami' }, danAgentSession.token)
		const danWhoami = JSON.parse(danWhoamiRes.content[0].text)
		assert.equal(danWhoami.session.apps.length, 1)
		assert.equal(danWhoami.session.apps[0].id, shareId)
		assert.equal(danWhoami.session.apps[0].type, 'share')
		assert.equal(danWhoami.session.apps[0].name, 'Acme Global Stripe')
		assert.equal(danWhoami.session.apps[0].account, 'acct_acme_main')
		assert.equal(danWhoami.session.apps[0].sharedBy, 'sarah@acme.com')
		const danToolsRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				authorization: `Bearer ${danAgentSession.token}`
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 301,
				method: 'tools/list',
				params: {}
			})
		})
		const danTools = (await danToolsRes.json()).result.tools
		assert.equal(danTools.length, 1)
		assert.equal(danTools[0].name, 'stripe_api')
		assert.match(danTools[0].description, /acct_acme_main/)
		const allowedCustRes = await executeTool('stripe_api', {
			url: '/v1/customers/cus_shared_1'
		}, danAgentSession.token)
		assert.equal(allowedCustRes.isError, undefined)
		const allowedCustData = JSON.parse(allowedCustRes.content[0].text)
		assert.equal(allowedCustData.ok, true)
		assert.equal(allowedCustData.auth, 'Bearer sk_live_sarah_secret_123')
		const deniedByCeilingRes = await executeTool('stripe_api', {
			url: '/v1/invoices/inv_1',
			method: 'POST',
			body: { amount: 500 }
		}, danAgentSession.token)
		assert.equal(deniedByCeilingRes.isError, true, 'POST /v1/invoices/inv_1 is allowed by Dan session link policy, but must be denied by Sarah ceiling policy')
		assert.match(deniedByCeilingRes.content[0].text, /Policy violation/)
		const deniedBySessionRes = await executeTool('stripe_api', {
			url: '/v1/invoices/inv_1',
			method: 'GET'
		}, danAgentSession.token)
		assert.equal(deniedBySessionRes.isError, true, 'GET /v1/invoices/inv_1 is allowed by Sarah ceiling policy, but must be denied by Dan session link policy')
		assert.match(deniedBySessionRes.content[0].text, /Policy violation/)
		const danLogsRes = await executeTool('admin', { action: 'list_logs', appId: shareId }, danAdmin.token)
		const danLogs = JSON.parse(danLogsRes.content[0].text).logs
		assert.equal(danLogs.length, 3, 'Dan sees all 3 requests when filtering by his shareId')
		assert.ok(danLogs.every(l => l.appId === shareId), 'Recipient logs resolve appId to shareId and never leak owner upstreamApp.id')
		assert.ok(danLogs.every(l => l.appId !== sarahApp.id), 'Owner upstreamApp.id is never exposed to recipient')
		const danAllLogs = JSON.parse((await executeTool('admin', { action: 'list_logs' }, danAdmin.token)).content[0].text).logs
		assert.equal(danAllLogs.length, 3)
		assert.ok(danAllLogs.every(l => l.appId === shareId), 'Unfiltered recipient logs also resolve appId to shareId')
		const danProbeUpstreamIdLogs = JSON.parse((await executeTool('admin', { action: 'list_logs', appId: sarahApp.id }, danAdmin.token)).content[0].text).logs
		assert.equal(danProbeUpstreamIdLogs.length, 0, 'Recipient filtering by owner upstreamApp.id returns 0 logs')
		const eve = db.logins.resolveUser('google', 'eve@acme.com')
		const eveSession = db.tokens.create({ userId: eve.id, provider: 'self', admin: 1 })
		const eveSpoofRes = await executeTool('stripe_api', {
			url: '/v1/customers/spoof_attempt',
			appId: sarahApp.id
		}, eveSession.token)
		assert.equal(eveSpoofRes.isError, true)
		const sarahLogsRes = await executeTool('admin', { action: 'list_logs', appId: sarahApp.id }, sarahAdmin.token)
		const sarahLogs = JSON.parse(sarahLogsRes.content[0].text).logs
		assert.equal(sarahLogs.length, 3, 'Sarah sees all 3 requests made by Dan through her shared app (and 0 spoofed unlinked requests from Eve)')
		assert.equal(sarahLogs[0].userId, dan.id)
		assert.equal(sarahLogs[0].account, 'dan@acme.com')
		assert.equal(sarahLogs[0].appId, sarahApp.id)
		db.logins.upsert({ userId: dan.id, provider: 'github', account: 'dan-public' })
		const sarahPrivacyAppRes = await executeTool('admin', {
			action: 'connect_app',
			provider: 'stripe',
			name: 'Sarah Privacy Stripe',
			account: 'acct_sarah_privacy',
			apiKey: 'sk_live_sarah_privacy_456',
			baseUrl
		}, sarahAdmin.token)
		const sarahPrivacyApp = JSON.parse(sarahPrivacyAppRes.content[0].text).app
		const danPublicShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: sarahPrivacyApp.id,
			account: 'github:dan-public',
			policy: [{ action: 'allow', methods: ['GET'] }]
		}, sarahAdmin.token)).content[0].text)
		const danPublicSession = JSON.parse((await executeTool('admin', {
			action: 'create_session',
			name: 'Dan Public Session',
			linkAppIds: [danPublicShare.shareId]
		}, danAdmin.token)).content[0].text).session
		const danPublicProxyRes = await executeTool('stripe_api', {
			url: '/v1/customers/cus_public_handle'
		}, danPublicSession.token)
		assert.equal(danPublicProxyRes.isError, undefined)
		const sarahPrivacyLogsText = (await executeTool('admin', {
			action: 'list_logs',
			appId: sarahPrivacyApp.id
		}, sarahAdmin.token)).content[0].text
		const sarahPrivacyLogs = JSON.parse(sarahPrivacyLogsText).logs
		assert.equal(sarahPrivacyLogs.length, 1)
		assert.equal(sarahPrivacyLogs[0].account, 'dan-public', 'Owner list_logs shows shared secondary handle rather than recipient private primary email')
		assert.equal(sarahPrivacyLogsText.includes('dan@acme.com'), false, 'Owner list_logs must never leak recipient unrelated primary email')
		const danOwnPrivacyLogs = JSON.parse((await executeTool('admin', {
			action: 'list_logs',
			appId: danPublicShare.shareId
		}, danAdmin.token)).content[0].text).logs
		assert.equal(danOwnPrivacyLogs.length, 1)
		assert.equal(danOwnPrivacyLogs[0].account, 'dan@acme.com', 'Recipient own list_logs resolves their own canonical account')
		await executeTool('admin', {
			action: 'unshare_app',
			appId: sarahPrivacyApp.id,
			account: 'github:dan-public'
		}, sarahAdmin.token)
		const sarahPrivacyLogsAfterUnshareText = (await executeTool('admin', {
			action: 'list_logs',
			appId: sarahPrivacyApp.id
		}, sarahAdmin.token)).content[0].text
		const sarahPrivacyLogsAfterUnshare = JSON.parse(sarahPrivacyLogsAfterUnshareText).logs
		assert.equal(sarahPrivacyLogsAfterUnshare.length, 1)
		assert.equal(sarahPrivacyLogsAfterUnshare[0].userId, dan.id)
		assert.equal(sarahPrivacyLogsAfterUnshare[0].account, undefined, 'After unshare_app removes share row, owner list_logs omits account instead of falling back to recipient primary email')
		assert.equal(sarahPrivacyLogsAfterUnshareText.includes('dan@acme.com'), false, 'Historical owner list_logs after unshare_app must never leak recipient unrelated primary email')
		await executeTool('admin', {
			action: 'disconnect_app',
			appId: sarahPrivacyApp.id,
			revoke: false
		}, sarahAdmin.token)
		await executeTool('admin', {
			action: 'unlink_login',
			account: 'github:dan-public'
		}, danAdmin.token)
		const expiredOauthApp = db.tokens.create({
			userId: sarah.id,
			provider: 'google',
			type: 'oauth',
			name: 'Sarah Expired Google',
			credentials: { accessToken: 'ya29.expired', refreshToken: '1//invalid-refresh', account: 'sarah@acme.com' },
			expiresAt: Date.now() - 120000
		})
		const googleShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: expiredOauthApp.id,
			account: 'dan@acme.com',
			policy: [{ action: 'allow' }]
		}, sarahAdmin.token)).content[0].text)
		await executeTool('admin', {
			action: 'link_app',
			sessionId: danAgentSession.id,
			appId: googleShare.shareId
		}, danAdmin.token)
		const origFetch = globalThis.fetch
		globalThis.fetch = async (input, init) => {
			const u = typeof input === 'string' ? input : input.url
			if (u === 'https://oauth2.googleapis.com/token') {
				return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Token has been expired or revoked.' }), {
					status: 400,
					headers: { 'content-type': 'application/json' }
				})
			}
			return origFetch(input, init)
		}
		try {
			const refreshFailRes = await executeTool('google_api', {
				url: 'https://www.googleapis.com/drive/v3/files'
			}, danAgentSession.token)
			assert.equal(refreshFailRes.isError, true)
			assert.match(refreshFailRes.content[0].text, /Ask the app owner \(sarah@acme\.com\) to re-authenticate/)
			assert.doesNotMatch(refreshFailRes.content[0].text, /reauth_app_id/, 'Shared app refresh failure must not leak upstreamApp.id or broken reauth URL to recipient')
			assert.equal(refreshFailRes.content[0].text.includes(expiredOauthApp.id), false)
		} finally {
			globalThis.fetch = origFetch
		}
		await executeTool('admin', {
			action: 'disconnect_app',
			appId: expiredOauthApp.id,
			revoke: false
		}, sarahAdmin.token)
		const restShareRes = await fetch(`http://127.0.0.1:${addr.port}/api/shares`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${sarahAdmin.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				appId: sarahApp.id,
				account: 'chloe@acme.com',
				policy: [{ action: 'allow', methods: ['GET'], path: '/v1/**' }]
			})
		})
		assert.equal(restShareRes.status, 201)
		const restShareData = await restShareRes.json()
		assert.equal(restShareData.shared, true)
		assert.equal(restShareData.userId, null)
		assert.equal(restShareData.account, 'chloe@acme.com')
		const restUnshareRes = await fetch(`http://127.0.0.1:${addr.port}/api/shares?appId=${encodeURIComponent(sarahApp.id)}&account=${encodeURIComponent('chloe@acme.com')}`, {
			method: 'DELETE',
			headers: {
				authorization: `Bearer ${sarahAdmin.token}`,
				'content-type': 'text/plain'
			},
			body: 'non-json-payload-ignored-by-delete'
		})
		assert.equal(restUnshareRes.status, 200)
		const restUnshareData = await restUnshareRes.json()
		assert.equal(restUnshareData.unshared, true)
		assert.equal(db.tokens.get(restShareData.shareId), null, 'Unsharing pending share removes unclaimed share row')
		const restShareBodyRes = await fetch(`http://127.0.0.1:${addr.port}/api/shares`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${sarahAdmin.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				appId: sarahApp.id,
				account: 'body-unshare@acme.com'
			})
		})
		assert.equal(restShareBodyRes.status, 201)
		const restUnshareBodyRes = await fetch(`http://127.0.0.1:${addr.port}/api/shares`, {
			method: 'DELETE',
			headers: {
				authorization: `Bearer ${sarahAdmin.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				appId: sarahApp.id,
				account: 'body-unshare@acme.com'
			})
		})
		assert.equal(restUnshareBodyRes.status, 200, 'DELETE /api/shares supports JSON body fallback')
		assert.equal((await restUnshareBodyRes.json()).unshared, true)
		await fetch(`http://127.0.0.1:${addr.port}/api/links`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${sarahAdmin.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				sessionId: sarahWorker.id,
				appId: sarahApp.id
			})
		})
		const restUnlinkBodyRes = await fetch(`http://127.0.0.1:${addr.port}/api/links`, {
			method: 'DELETE',
			headers: {
				authorization: `Bearer ${sarahAdmin.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				sessionId: sarahWorker.id,
				appId: sarahApp.id
			})
		})
		assert.equal(restUnlinkBodyRes.status, 200, 'DELETE /api/links supports JSON body fallback')
		assert.equal((await restUnlinkBodyRes.json()).unlinked, true)
		const unshareDanRes = await executeTool('admin', {
			action: 'unshare_app',
			appId: sarahApp.id,
			account: 'dan@acme.com'
		}, sarahAdmin.token)
		assert.equal(unshareDanRes.isError, undefined)
		assert.equal(JSON.parse(unshareDanRes.content[0].text).unshared, true)
		assert.equal(db.tokens.get(shareId), null, 'Share token is removed on unshare_app')
		assert.equal(db.links.listBySessionId(danAgentSession.id).length, 0, 'Session links to the share token are cascade-deleted on unshare_app')
		const danLogsAfterUnshare = JSON.parse((await executeTool('admin', { action: 'list_logs' }, danAdmin.token)).content[0].text).logs
		assert.ok(danLogsAfterUnshare.length >= 3)
		assert.ok(danLogsAfterUnshare.every(l => l.appId === null), 'After unshare_app, recipient historical logs resolve appId to null and never leak owner upstreamApp.id')
		const danProbeAfterUnshare = JSON.parse((await executeTool('admin', { action: 'list_logs', appId: sarahApp.id }, danAdmin.token)).content[0].text).logs
		assert.equal(danProbeAfterUnshare.length, 0, 'Probing owner upstreamApp.id after unshare_app still returns 0 logs')
		const sarahLogsAfterUnshare = JSON.parse((await executeTool('admin', { action: 'list_logs', appId: sarahApp.id }, sarahAdmin.token)).content[0].text).logs
		assert.equal(sarahLogsAfterUnshare.length, 3, 'Owner still sees all historical logs for her upstreamApp.id after unsharing')
		assert.equal(sarahLogsAfterUnshare[0].account, undefined, 'Historical cross-user logs omit account once share row is removed')
		const afterUnshareProxy = await executeTool('stripe_api', {
			url: '/v1/customers/cus_shared_1'
		}, danAgentSession.token)
		assert.equal(afterUnshareProxy.isError, true)
		assert.match(afterUnshareProxy.content[0].text, /No Stripe app linked to session/)
		const reshare2 = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'dan@acme.com',
			policy: [{ action: 'allow' }]
		}, sarahAdmin.token)).content[0].text)
		const verifyCode = db.tokens.createState({
			mode: 'verify',
			userId: dan.id,
			admin: 1
		})
		const verifyGetRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${verifyCode}`)
		assert.equal(verifyGetRes.status, 200)
		const verifyHtml = await verifyGetRes.text()
		assert.match(verifyHtml, /Acme Global Stripe/)
		assert.match(verifyHtml, /acct_acme_main/)
		assert.match(verifyHtml, new RegExp(reshare2.shareId))
		const verifyPostRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: verifyCode, app_id: reshare2.shareId }).toString()
		})
		assert.equal(verifyPostRes.status, 200)
		const verifyPostText = await verifyPostRes.text()
		const tokenMatch = verifyPostText.match(/token:\s*([a-f0-9-]+)/)
		assert.ok(tokenMatch)
		const verifiedSession = db.tokens.getByToken(tokenMatch[1])
		assert.equal(db.links.listBySessionId(verifiedSession.id).length, 1)
		assert.equal(db.links.listBySessionId(verifiedSession.id)[0].appId, reshare2.shareId)
		await executeTool('admin', {
			action: 'link_app',
			sessionId: danAgentSession.id,
			appId: reshare2.shareId
		}, danAdmin.token)
		assert.equal(db.links.listBySessionId(danAgentSession.id).length, 1)
		const danSelfDisconnect = await executeTool('admin', {
			action: 'disconnect_app',
			appId: reshare2.shareId
		}, danAdmin.token)
		assert.equal(danSelfDisconnect.isError, undefined)
		assert.equal(db.tokens.get(reshare2.shareId), null, 'Recipient can disconnect/remove a shared app from their own account')
		assert.ok(db.tokens.get(sarahApp.id), 'Recipient disconnecting a shared app does not remove owner upstream app')
		const reshare3 = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'dan@acme.com',
			policy: [{ action: 'allow' }]
		}, sarahAdmin.token)).content[0].text)
		await executeTool('admin', {
			action: 'link_app',
			sessionId: danAgentSession.id,
			appId: reshare3.shareId
		}, danAdmin.token)
		assert.equal(db.links.listBySessionId(danAgentSession.id).length, 1)
		await executeTool('admin', {
			action: 'disconnect_app',
			appId: sarahApp.id,
			revoke: false
		}, sarahAdmin.token)
		assert.equal(db.tokens.get(reshare3.shareId), null, 'Disconnecting upstream app cleans up all downstream share tokens')
		assert.equal(db.links.listBySessionId(danAgentSession.id).length, 0, 'Disconnecting upstream app cascade-deletes all recipient session links')
		const tempOwner = db.users.create()
		const tempOwnerApp = db.tokens.create({
			userId: tempOwner.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Temp Owner Stripe',
			credentials: { apiKey: 'sk_temp', baseUrl }
		})
		const tempShare = db.tokens.upsertShare({
			userId: dan.id,
			account: 'dan@acme.com',
			authProvider: 'google',
			appId: tempOwnerApp.id,
			provider: 'stripe'
		})
		db.links.create({ sessionId: danAgentSession.id, appId: tempShare.id })
		db.sqlite.prepare('DELETE FROM users WHERE id = ?').run(tempOwner.id)
		assert.equal(db.tokens.get(tempShare.id), null, 'Deleting owner user row cascades through upstream app trigger to delete downstream shares')
		assert.equal(db.links.listBySessionId(danAgentSession.id).length, 0, 'Cascaded share deletion cleans up recipient session links')
	} finally {
		await new Promise(resolve => mockUpstream.close(resolve))
	}
})

test('db.logins transactions use BEGIN IMMEDIATE to wait on WAL write locks instead of throwing SQLITE_BUSY', async () => {
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
	assert.ok(resolved?.id, 'resolveUser waits on busy_timeout under concurrent WAL write lock')
	await new Promise((resolve, reject) => {
		worker.once('exit', code => code === 0 ? resolve() : reject(new Error(`Worker exited with ${code}`)))
		worker.once('error', reject)
	})
	db.logins.upsert({ userId: resolved.id, provider: 'github', account: 'wal-gh-user' })
	const removed = db.logins.remove(resolved.id, { provider: 'github' })
	assert.equal(removed.account, 'wal-gh-user')
	assert.throws(() => db.logins.remove(resolved.id, { provider: 'google' }), /Cannot unlink your only login key/)
})

test('redactLogArgs scrubs credentials and auth headers without mutating input', () => {
	const raw = {
		action: 'connect_app',
		provider: 'stripe',
		apiKey: 'sk_live_secret_123',
		credentials: { accessToken: 'tok_abc' },
		token: 'bearer_xyz',
		headers: {
			Authorization: 'Bearer secret',
			'X-Api-Key': 'key_123',
			Cookie: 'sid=abc',
			'Content-Type': 'application/json'
		},
		body: { amount: 500 }
	}
	const redacted = redactLogArgs(raw)
	assert.equal(redacted.action, 'connect_app')
	assert.equal(redacted.provider, 'stripe')
	assert.equal(redacted.apiKey, '[REDACTED]')
	assert.equal(redacted.credentials, '[REDACTED]')
	assert.equal(redacted.token, '[REDACTED]')
	assert.equal(redacted.headers.Authorization, '[REDACTED]')
	assert.equal(redacted.headers['X-Api-Key'], '[REDACTED]')
	assert.equal(redacted.headers.Cookie, '[REDACTED]')
	assert.equal(redacted.headers['Content-Type'], 'application/json')
	assert.deepEqual(redacted.body, { amount: 500 })
	assert.equal(raw.apiKey, 'sk_live_secret_123', 'Original args must not be mutated')
	assert.equal(raw.headers.Authorization, 'Bearer secret', 'Original headers must not be mutated')
})

test('teardown server', (t, done) => {
	server.close(() => {
		fs.rmSync(testDbPath, { force: true })
		fs.rmSync(`${testDbPath}-wal`, { force: true })
		fs.rmSync(`${testDbPath}-shm`, { force: true })
		done()
	})
})
