import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

const dirname = path.dirname(fileURLToPath(import.meta.url))
const testDbPath = path.join(dirname, 'test.db')
process.env.DB_PATH = testDbPath
process.env.NODE_ENV = 'test'
process.env.GOOGLE_CLIENT_ID = 'test-client-id'
process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret'
process.env.ALLOWED_REDIRECT_DOMAINS = 'localhost,127.0.0.1,chatgpt.com,antigravity.google,antigravity,cursor,vscode'

fs.rmSync(testDbPath, { force: true })
fs.rmSync(`${testDbPath}-wal`, { force: true })
fs.rmSync(`${testDbPath}-shm`, { force: true })

const { server, bootstrapLocalAdmin } = await import('../index.js')
const db = await import('../db/index.js')
const { google, github, createProvider, getProvider, listAuthProviders, summarizeScopes } = await import('../providers/index.js')
const { isAllowedUrl: isGoogleAllowedUrl, services: googleServices } = google
const { isAllowedUrl: isGithubAllowedUrl, services: githubServices } = github
const { readResponseBody } = await import('../api/proxy.js')
const { executeTool } = await import('../mcp.js')
const { isAllowedRedirectUri, deriveClientName } = await import('../oauth.js')
const api = await import('../api/index.js')
const { evaluatePolicy, matchPattern, parsePolicy, validatePolicy } = await import('../policy.js')

function createTestSession (opts = {}) {
	const {
		account = 'user@example.com',
		name = 'Test User',
		admin = false,
		accessToken = 'ya29.fake-token',
		refreshToken = '1//fake-refresh',
		expiresAt = Date.now() + 3600000,
		scopes = null,
		policy = null,
		ip = '127.0.0.1',
		ua = 'TestClient/1.0'
	} = opts
	const user = db.users.upsert({ account, name })
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
	const user = db.users.upsert({ account: 'mcp-init@example.com' })
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
	const { session } = createTestSession({ account: 'test@example.com', name: 'Test User' })
	const code = db.tokens.createAuthCode({
		sessionId: session.id,
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
		sessionId: session.id,
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
	assert.equal(data.access_token, session.token)
	assert.ok(data.refresh_token)
	assert.equal(data.token_type, 'Bearer')
	assert.equal(data.expires_in, 3600)
	assert.equal(data.scope, 'mcp')
	assert.equal(db.tokens.consumeAuthCode(code2), null)
	const issuedSession = db.tokens.get(session.id)
	assert.ok(issuedSession.expiresAt > Date.now())
	assert.equal(issuedSession.credentials.refreshToken, data.refresh_token)
	const nonSelfApp = db.tokens.create({
		userId: issuedSession.userId,
		provider: 'google',
		type: 'oauth',
		name: 'Non-self App'
	})
	assert.equal(db.tokens.issueOauthTokens(nonSelfApp.id), null, 'issueOauthTokens must return null on non-self/bearer row')
	const reissuedSession = db.tokens.issueOauthTokens(session.id)
	assert.equal(reissuedSession.credentials.refreshToken, data.refresh_token, 'Re-issuing OAuth tokens preserves existing refreshToken')
})

test('oauth refresh_token grant rotation, access_token expiration, and embedded session indefinite TTL', async () => {
	const addr = server.address()
	const { session } = createTestSession({ account: 'refresh-flow@example.com', name: 'Refresh User', admin: true })
	const code = db.tokens.createAuthCode({
		sessionId: session.id,
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
	assert.equal(initialTokens.access_token, session.token)
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
	assert.equal(db.tokens.get(session.id), null, 'Dormant session must be pruned on refresh attempt')
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
	let verifyLoc
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=google-code&state=${bearerStateToken}`, { redirect: 'manual' })
		assert.equal(cbRes.status, 302)
		verifyLoc = cbRes.headers.get('location')
	} finally {
		globalThis.fetch = origFetch
	}
	const verifyMagicCode = new URL(verifyLoc).searchParams.get('code')
	const bearerVerifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: verifyMagicCode }).toString(),
		redirect: 'manual'
	})
	assert.equal(bearerVerifyRes.status, 302)
	const bearerCode = new URL(bearerVerifyRes.headers.get('location')).searchParams.get('code')
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
	const mismatchCodeSession = db.tokens.create({ userId: bearerSession.userId, provider: 'self' })
	const boundCode = db.tokens.createAuthCode({
		sessionId: mismatchCodeSession.id,
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
		sessionId: mismatchCodeSession.id,
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
		sessionId: session.id,
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
		sessionId: session.id,
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
		sessionId: session.id,
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
	assert.equal(successData.access_token, session.token)
})

test('isAllowedRedirectUri exact and wildcard matching', () => {
	assert.equal(isAllowedRedirectUri('https://chatgpt.com/callback'), true)
	assert.equal(isAllowedRedirectUri('https://foo.chatgpt.com/callback'), false)
	assert.equal(isAllowedRedirectUri('https://localhost:3000/cb'), true)
	assert.equal(isAllowedRedirectUri('https://antigravity.google/oauth-callback'), true)
	assert.equal(isAllowedRedirectUri('antigravity://auth-callback'), true)
	assert.equal(isAllowedRedirectUri('cursor://anyscheme/callback'), true)
	assert.equal(isAllowedRedirectUri('vscode://callback'), true)
	assert.equal(isAllowedRedirectUri('https://evil.com/callback'), false)
	assert.equal(isAllowedRedirectUri('malicious://callback'), false)
	assert.equal(isAllowedRedirectUri(''), false)
	assert.equal(isAllowedRedirectUri(null), false)
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
	let verifyLocation
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=google-auth-code&state=${loginStateToken}`, { redirect: 'manual' })
		assert.equal(cbRes.status, 302)
		verifyLocation = cbRes.headers.get('location')
	} finally {
		globalThis.fetch = origFetch
	}
	const verifyCode = new URL(verifyLocation).searchParams.get('code')
	assert.ok(verifyCode)
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
		body: new URLSearchParams({ code: verifyCode }).toString(),
		redirect: 'manual'
	})
	assert.equal(postVerifyRes.status, 302)
	const location = postVerifyRes.headers.get('location')
	const targetUrl = new URL(location)
	assert.equal(targetUrl.hostname, 'chatgpt.com')
	assert.equal(targetUrl.searchParams.get('state'), 'client-state-123')
	const code = targetUrl.searchParams.get('code')
	assert.ok(code)
	assert.equal(db.tokens.getState(verifyCode), null, 'POST /oauth/verify must consume verify state')
	const agentUser = db.users.getByAccount('agent@example.com')
	const unexchangedSessions = db.tokens.listByUserId(agentUser.id, { provider: 'self' })
	assert.deepEqual(unexchangedSessions, [], 'listByUserId must filter out unexchanged pending self sessions')
	const codeRow = db.sqlite.prepare("SELECT * FROM tokens WHERE id = ? AND type = 'oauth_code'").get(code)
	const codeMeta = JSON.parse(codeRow.credentials)
	const pendingSession = db.tokens.get(codeMeta.sessionId)
	assert.ok(pendingSession)
	assert.equal(pendingSession.token, null, 'Unexchanged OAuth session must have token: null until /oauth/token is called')
	assert.ok(pendingSession.expiresAt > Date.now(), 'Unexchanged OAuth session must have temporary 10m expiresAt')
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
	let verifyLoc
	try {
		const cbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=browser-code&state=${loginStateToken}`, { redirect: 'manual' })
		assert.equal(cbRes.status, 302)
		verifyLoc = cbRes.headers.get('location')
	} finally {
		globalThis.fetch = origFetch
	}
	const magicCode = new URL(verifyLoc).searchParams.get('code')
	const getVerifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${magicCode}`)
	assert.equal(getVerifyRes.status, 200)
	assert.match(await getVerifyRes.text(), /<form method="POST" action="\/oauth\/verify">/)
	const postVerifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: magicCode }).toString()
	})
	assert.equal(postVerifyRes.status, 200)
	const verifyText = await postVerifyRes.text()
	assert.match(verifyText, /user: browser@example\.com/)
	assert.match(verifyText, /Authorization: Bearer/)
	const browserUser = db.users.getByAccount('browser@example.com')
	const browserSessions = db.tokens.listByUserId(browserUser.id, { provider: 'self' })
	assert.equal(browserSessions.length, 1)
	assert.equal(browserSessions[0].expiresAt, null, 'Direct browser verify without redirect_uri must have expiresAt: null')
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
	const { session: sessionRefreshRevoke, app: refreshSharedApp } = createTestSession({ account: 'revoke-refresh@example.com' })
	const issuedRefresh = db.tokens.issueOauthTokens(sessionRefreshRevoke.id)
	assert.ok(issuedRefresh.credentials?.refreshToken)
	db.sqlite.prepare('UPDATE tokens SET expires_at = ? WHERE id = ?').run(Date.now() - 5000, sessionRefreshRevoke.id)
	const revokeByRefreshRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: issuedRefresh.credentials.refreshToken }).toString()
	})
	assert.equal(revokeByRefreshRes.status, 200)
	assert.equal(db.tokens.get(sessionRefreshRevoke.id), null, 'Revoking by refresh_token must delete the session even if access_token expired')
	assert.ok(db.tokens.get(refreshSharedApp.id), 'Revoking by refresh_token must preserve shared upstream app')
})

test('mcp auth whoami, list, and revoke', async () => {
	const user = db.users.upsert({ account: 'sessions-tool@example.com' })
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
	const user = db.users.upsert({ account: 'rest-test@example.com' })
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
	const user = db.users.upsert({ account: 'mcp-tools-filter@example.com' })
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
	const user = db.users.upsert({ account: 'non-admin-auth@example.com' })
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
	const existingUser = db.users.upsert({ account: 'magic-admin@example.com' })
	const existingApp = db.tokens.create({
		userId: existingUser.id,
		provider: 'google',
		type: 'oauth',
		name: 'Personal Google',
		credentials: { accessToken: 'ya29.existing', account: 'magic-admin@example.com' },
		scopes: 'https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.readonly',
		expiresAt: Date.now() + 3600000
	})
	const stateWithoutUser = db.tokens.createState({ account: 'missing-user@example.com' })
	const invalidGetVerify = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${stateWithoutUser}`)
	assert.equal(invalidGetVerify.status, 400, 'GET /oauth/verify must fail loud with 400 when state has no valid userId')
	const invalidPostVerify = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: stateWithoutUser }).toString()
	})
	assert.equal(invalidPostVerify.status, 400, 'POST /oauth/verify must fail loud with 400 when state has no valid userId')
	const verifyCode = db.tokens.createState({
		userId: existingUser.id,
		account: 'magic-admin@example.com',
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
	assert.equal(createdUser.name, null)
})

test('30-day dormancy pruning scopes only expiring self sessions and exempts static bearer sessions', () => {
	const user = db.users.upsert({ account: 'dormancy@example.com' })
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
	db.tokens.pruneDormant(30 * 24 * 60 * 60 * 1000)
	assert.equal(db.tokens.get(dormantSession.id), null)
	assert.ok(db.tokens.get(activeSession.id))
	assert.ok(db.tokens.get(staticSession.id), 'Static bearer sessions (expires_at IS NULL) must not be pruned by dormancy')
	assert.ok(db.tokens.get(upstreamApp.id), 'Upstream apps must not be pruned by dormancy')
})

test('admin tool administrative actions: create_session, list_apps, connect_app, link_app, unlink_app', async () => {
	const user = db.users.upsert({ account: 'admin-actions@example.com' })
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
	const otherTenant = db.users.upsert({ account: 'other-tenant@example.com' })
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
	const user = db.users.upsert({ account: 'multi-account@example.com' })
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

test('in-place upstream re-auth flow enforces ownership and updates app credentials without changing session token', async () => {
	const addr = server.address()
	const user = db.users.upsert({ account: 'reauth@example.com' })
	const otherUser = db.users.upsert({ account: 'attacker@example.com' })
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		name: 'Persistent Agent Session'
	})
	const attackerSession = db.tokens.create({
		userId: otherUser.id,
		provider: 'self',
		name: 'Attacker Session'
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Expiring App',
		credentials: { accessToken: 'ya29.old', refreshToken: '1//old-refresh' },
		expiresAt: Date.now() - 1000
	})
	db.links.create({ sessionId: session.id, appId: app.id })
	const crossUserConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			session_id: attackerSession.id,
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
	const validConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			session_id: session.id,
			reauth_app_id: app.id
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(validConsentRes.status, 302)
	const initialSessionToken = session.token
	const updatedCreds = { accessToken: 'ya29.new-fresh-token', refreshToken: '1//new-refresh' }
	db.tokens.updateCredentials(app.id, {
		credentials: updatedCreds,
		expiresAt: Date.now() + 3600000
	})
	const reloadedApp = db.tokens.get(app.id)
	assert.equal(reloadedApp.credentials.accessToken, 'ya29.new-fresh-token')
	const reloadedSession = db.tokens.get(session.id)
	assert.equal(reloadedSession.token, initialSessionToken, 'Session token remains unchanged across upstream re-auth')
})

test('rest api /api/apps and /api/links endpoints', async () => {
	const addr = server.address()
	const user = db.users.upsert({ account: 'rest-apps@example.com' })
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

test('admin update_user action with name and multi-key OAuth provider linking + ssoOnly', async () => {
	const addr = server.address()
	const user = db.users.upsert({ account: 'user-props@example.com', name: 'Initial Name' })
	db.tokens.upsertAuth({ userId: user.id, provider: 'google', account: 'user-props@example.com' })
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
	const nonAdminRes = await executeTool('admin', {
		action: 'update_user',
		name: 'Hacker Name'
	}, workerSession.token)
	assert.equal(nonAdminRes.isError, true)
	assert.match(nonAdminRes.content[0].text, /requires admin privileges/)
	const updateRes = await executeTool('admin', {
		action: 'update_user',
		id: 'fake-id-attempt',
		account: 'fake-account-attempt@example.com',
		name: 'Jesse Tane'
	}, adminSession.token)
	assert.equal(updateRes.isError, undefined)
	const updateData = JSON.parse(updateRes.content[0].text)
	assert.equal(updateData.updated, true)
	assert.equal(updateData.user.id, user.id)
	assert.equal(updateData.user.account, 'user-props@example.com')
	assert.equal(updateData.user.name, 'Jesse Tane')
	const whoamiRes = await executeTool('admin', { action: 'whoami' }, adminSession.token)
	const whoamiData = JSON.parse(whoamiRes.content[0].text)
	assert.equal(whoamiData.user.name, 'Jesse Tane')
	assert.equal(whoamiData.user.account, 'user-props@example.com')
	assert.deepEqual(whoamiData.user.logins, [{ provider: 'google', account: 'user-props@example.com' }])
	const invalidProviderRes = await executeTool('admin', {
		action: 'update_user',
		name: 'Should Not Persist',
		provider: 'stripe'
	}, adminSession.token)
	assert.equal(invalidProviderRes.isError, true)
	assert.match(invalidProviderRes.content[0].text, /Invalid or unsupported OAuth provider/)
	assert.equal(db.users.get(user.id).name, 'Jesse Tane', 'update_user must validate provider before mutating name')
	delete process.env.GITHUB_CLIENT_ID
	const unconfiguredProviderRes = await executeTool('admin', {
		action: 'update_user',
		provider: 'github'
	}, adminSession.token)
	assert.equal(unconfiguredProviderRes.isError, true, 'Unconfigured OAuth provider must be rejected in update_user')
	const unconfiguredAuthPage = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?provider=github`)
	assert.doesNotMatch(await unconfiguredAuthPage.text(), /"id":"github"/, 'handleAuthorize must not inject unconfigured query.provider into providers list')
	process.env.GITHUB_CLIENT_ID = 'gh-test-client-id'
	process.env.GITHUB_CLIENT_SECRET = 'gh-test-client-secret'
	const restUserPatchRes = await fetch(`http://127.0.0.1:${addr.port}/api/user`, {
		method: 'PATCH',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ name: 'Jesse Updated Via REST' })
	})
	assert.equal(restUserPatchRes.status, 200)
	const restUserPatchData = await restUserPatchRes.json()
	assert.equal(restUserPatchData.updated, true)
	assert.equal(restUserPatchData.user.name, 'Jesse Updated Via REST')
	const expiredAdminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1,
		expiresAt: Date.now() - 5000
	})
	const unexchangedAdminSession = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1,
		token: null,
		expiresAt: Date.now() + 60000
	})
	for (const invalidSid of [expiredAdminSession.id, unexchangedAdminSession.id]) {
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
	const shay = db.users.upsert({ account: 'shay@example.com' })
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
	const preShareRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp.id,
		account: 'jessetane'
	}, shayAdmin.token)
	assert.equal(preShareRes.isError, undefined)
	const overlapStubShareRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp2.id,
		account: 'jessetane'
	}, shayAdmin.token)
	assert.equal(overlapStubShareRes.isError, undefined)
	const overlapDirectShareRes = await executeTool('admin', {
		action: 'share_app',
		appId: shayApp2.id,
		account: 'user-props@example.com'
	}, shayAdmin.token)
	assert.equal(overlapDirectShareRes.isError, undefined)
	const preSharedStubUser = db.users.getByAccount('jessetane')
	assert.ok(preSharedStubUser)
	assert.notEqual(preSharedStubUser.id, user.id, 'Pre-sharing with unlinked handle creates an unclaimed stub user')
	assert.equal(db.tokens.hasAuthTokens(preSharedStubUser.id), false)
	const providerFlowRes = await executeTool('admin', {
		action: 'update_user',
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
	assert.match(authPageHtml, /Update account sign-in/)
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
		assert.equal(cbRes.status, 200, 'Linking GitHub handle that had an unclaimed pre-share stub must claim stub and succeed with 200')
		const cbHtml = await cbRes.text()
		assert.match(cbHtml, /Account Updated/)
		assert.match(cbHtml, /Signed in as <strong>jessetane<\/strong>/)
		assert.equal(db.users.get(preSharedStubUser.id), null, 'Unclaimed stub user is deleted after being claimed')
		const userAppsAfterClaim = JSON.parse((await executeTool('admin', { action: 'list_apps' }, adminSession.token)).content[0].text).apps
		assert.ok(userAppsAfterClaim.some(a => a.type === 'share' && a.name === 'Shay Pre-Shared Stripe'), 'Pre-shared app on stub user is transferred to authenticated user on claim')
		const overlapShares = userAppsAfterClaim.filter(a => a.type === 'share' && a.name === 'Shay Overlap Stripe')
		assert.equal(overlapShares.length, 1, 'claimStubUser deduplicates overlapping shares for the same upstream appId')
		const updatedWhoami = JSON.parse((await executeTool('admin', { action: 'whoami' }, adminSession.token)).content[0].text)
		assert.equal(updatedWhoami.user.account, 'jessetane')
		assert.deepEqual(updatedWhoami.user.logins, [
			{ provider: 'google', account: 'user-props@example.com' },
			{ provider: 'github', account: 'jessetane' }
		])
		const shareViaOldLoginRes = await executeTool('admin', {
			action: 'share_app',
			appId: shayApp.id,
			account: 'user-props@example.com',
			policy: [{ action: 'allow', methods: ['GET'] }]
		}, shayAdmin.token)
		assert.equal(shareViaOldLoginRes.isError, undefined)
		assert.equal(JSON.parse(shareViaOldLoginRes.content[0].text).userId, user.id, 'Sharing via secondary linked login handle resolves to existing multi-key user without creating a duplicate user')
		const unshareViaOldLoginRes = await executeTool('admin', {
			action: 'unshare_app',
			appId: shayApp.id,
			account: 'user-props@example.com'
		}, shayAdmin.token)
		assert.equal(unshareViaOldLoginRes.isError, undefined)
		assert.equal(JSON.parse(unshareViaOldLoginRes.content[0].text).unshared, true, 'Unsharing via secondary linked login handle removes share from multi-key user')
		const collidingOtherProviderUser = db.tokens.resolveUserByAuth('custom_idp', 'jessetane')
		assert.notEqual(collidingOtherProviderUser.id, user.id, 'resolveUserByAuth for a different provider with same handle must not hijack existing authenticated user')
		assert.equal(db.tokens.resolveUserByAuth('google', 'user-props@example.com').id, user.id)
		assert.equal(db.tokens.resolveUserByAuth('github', 'jessetane').id, user.id)
		const crossProvHolder = db.tokens.resolveUserByAuth('custom_idp', 'sharedhandle')
		assert.equal(crossProvHolder.account, 'sharedhandle')
		const crossProvLinker = db.tokens.resolveUserByAuth('google', 'linker@example.com')
		const crossProvSession = db.tokens.create({ userId: crossProvLinker.id, provider: 'self', admin: 1 })
		const crossProvState = db.tokens.createState({
			mode: 'auth',
			sessionId: crossProvSession.id,
			provider: 'github'
		})
		ghMockLogin = 'sharedhandle'
		const crossProvCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${crossProvState}`)
		assert.equal(crossProvCbRes.status, 200, 'Linking an unclaimed provider:account handle when another provider user holds unqualified users.account must succeed with 200')
		assert.equal(db.users.get(crossProvLinker.id).account, 'github:sharedhandle')
		assert.equal(db.tokens.findUserByAccount('github:sharedhandle').id, crossProvLinker.id)
		assert.equal(db.tokens.findUserByAccount('sharedhandle', 'github').id, crossProvLinker.id)
		assert.equal(db.tokens.findUserByAccount('sharedhandle', 'custom_idp').id, crossProvHolder.id)
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
		assert.equal(db.tokens.getState(githubVerifyCode).userId, user.id)
		const otherUser = db.users.upsert({ account: 'taken-gh-user' })
		db.tokens.upsertAuth({ userId: otherUser.id, provider: 'github', account: 'taken-gh-user' })
		const otherAdmin = db.tokens.create({ userId: otherUser.id, provider: 'self', admin: 1 })
		const conflictState = db.tokens.createState({
			mode: 'auth',
			sessionId: otherAdmin.id,
			provider: 'github'
		})
		const conflictCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${conflictState}`)
		assert.equal(conflictCbRes.status, 409)
		assert.match(await conflictCbRes.text(), /already registered to another user/)
		google.ssoOnly = true
		try {
			const ssoUser = db.users.upsert({ account: 'sso-locked@example.com' })
			db.tokens.upsertAuth({ userId: ssoUser.id, provider: 'google', account: 'sso-locked@example.com' })
			const ssoAdmin = db.tokens.create({ userId: ssoUser.id, provider: 'self', admin: 1 })
			const ssoState = db.tokens.createState({
				mode: 'auth',
				sessionId: ssoAdmin.id,
				provider: 'github'
			})
			const ssoCbRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${ssoState}`)
			assert.equal(ssoCbRes.status, 403)
			assert.match(await ssoCbRes.text(), /SSO-only provider restriction/)
		} finally {
			google.ssoOnly = false
		}
	} finally {
		globalThis.fetch = origFetch
	}
})

test('admin update_app action', async () => {
	const user = db.users.upsert({ account: 'update-app@example.com' })
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
})

test('admin update_session action', async () => {
	const user = db.users.upsert({ account: 'update-session@example.com' })
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
	const user = db.users.upsert({ account: 'unlinked-fail@example.com' })
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
				client_name: 'Test MCP Agent',
				redirect_uris: ['http://localhost:9999/cb']
			})
		})
		assert.equal(regRes.status, 201)
		const regData = await regRes.json()
		assert.ok(regData.client_id)
		assert.equal(regData.client_name, 'Test MCP Agent')
		assert.deepEqual(regData.grant_types, ['authorization_code', 'refresh_token'])
		const user = db.users.upsert({ account: 'multi-provider@example.com' })
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
		const user = db.users.upsert({ account: 'logs-test@example.com' })
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
		db.logs.prune()
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
		const user = db.users.upsert({ account: 'conventions@example.com' })
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
	const addr = server.address()
	const user = db.users.upsert({ account: 'github-test@example.com', name: 'GitHub Tester' })
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

test('local token sign-in fallback, bootstrapLocalAdmin, and in-place SQLite email-to-account migration', async () => {
	const addr = server.address()
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
		const localUser = db.users.upsert({ account: 'localadmin' })
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
		assert.equal(adminConsent.status, 302)
		const verifyLoc = new URL(adminConsent.headers.get('location'), `http://127.0.0.1:${addr.port}`)
		assert.equal(verifyLoc.pathname, '/oauth/verify')
		const code = verifyLoc.searchParams.get('code')
		assert.ok(code)
		const verifyPostRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code }).toString()
		})
		assert.equal(verifyPostRes.status, 200)
		const verifyText = await verifyPostRes.text()
		const tokenMatch = verifyText.match(/token:\s*([a-f0-9-]+)/)
		assert.ok(tokenMatch)
		const newSession = db.tokens.getByToken(tokenMatch[1])
		assert.equal(newSession.userId, localUser.id)
		assert.equal(newSession.name, 'Via Local Token')
		assert.equal(newSession.admin, true)
		db.sqlite.exec("DELETE FROM tokens WHERE provider = 'self'")
		const bootstrapped = bootstrapLocalAdmin()
		assert.ok(bootstrapped)
		assert.equal(bootstrapped.provider, 'self')
		assert.equal(bootstrapped.admin, true)
		assert.equal(bootstrapped.account, 'localhost')
		assert.equal(bootstrapLocalAdmin(), null, 'bootstrapLocalAdmin is a no-op once a session exists')
	} finally {
		if (origGoogleId !== undefined) process.env.GOOGLE_CLIENT_ID = origGoogleId
		if (origGithubId !== undefined) process.env.GITHUB_CLIENT_ID = origGithubId
	}
	db.sqlite.exec('DROP INDEX IF EXISTS idx_users_account')
	db.sqlite.exec('ALTER TABLE users RENAME COLUMN account TO email')
	db.sqlite.exec('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
	const legacyUserId = 'legacy-google-user-1'
	const now = new Date().toISOString()
	db.sqlite.prepare('INSERT INTO users (id, email, name, created, updated) VALUES (?, ?, ?, ?, ?)').run(
		legacyUserId,
		'legacy@gmail.com',
		'Legacy User',
		now,
		now
	)
	db.users.init()
	db.tokens.init()
	const migratedUser = db.users.getByAccount('legacy@gmail.com')
	assert.ok(migratedUser)
	assert.equal(migratedUser.id, legacyUserId)
	assert.equal(migratedUser.account, 'legacy@gmail.com')
	const backfilledLogins = db.tokens.listAuthByUserId(legacyUserId)
	assert.equal(backfilledLogins.length, 1)
	assert.equal(backfilledLogins[0].provider, 'google')
	assert.equal(backfilledLogins[0].token, 'google:legacy@gmail.com')
	assert.equal(backfilledLogins[0].credentials.account, 'legacy@gmail.com')
	const resolvedLegacy = db.tokens.resolveUserByAuth('google', 'LEGACY@gmail.com')
	assert.equal(resolvedLegacy.id, legacyUserId)
	const postMigrationStub = db.users.upsert({ account: 'stub-after-migration@acme.com' })
	db.users.init()
	db.tokens.init()
	assert.equal(db.tokens.hasAuthTokens(postMigrationStub.id), false, 'Re-running init() on an already-migrated DB must not bind unclaimed pre-share stubs to google')
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
		const sarah = db.users.upsert({ account: 'sarah@acme.com', name: 'Sarah' })
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
		assert.equal(shareData.account, 'dan@acme.com')
		assert.deepEqual(shareData.policy, ceilingPolicy)
		const shareId = shareData.shareId
		assert.ok(shareId)
		assert.notEqual(shareId, sarahApp.id)
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
		assert.equal(reshareData.shareId, shareId, 'Re-sharing updates existing share token in place without creating duplicates')
		assert.deepEqual(reshareData.policy, updatedCeilingPolicy)
		const sarahAppsRes = await executeTool('admin', { action: 'list_apps' }, sarahAdmin.token)
		const sarahApps = JSON.parse(sarahAppsRes.content[0].text).apps
		const sarahStripe = sarahApps.find(a => a.id === sarahApp.id)
		assert.ok(sarahStripe)
		assert.equal(sarahStripe.shares.length, 1)
		assert.equal(sarahStripe.shares[0].account, 'dan@acme.com')
		assert.deepEqual(sarahStripe.shares[0].policy, updatedCeilingPolicy)
		const dan = db.users.getByAccount('dan@acme.com')
		assert.ok(dan)
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
		const eve = db.users.upsert({ account: 'eve@acme.com', name: 'Eve' })
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
			userId: dan.id,
			account: 'dan@acme.com',
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
	} finally {
		await new Promise(resolve => mockUpstream.close(resolve))
	}
})

test('teardown server', (t, done) => {
	server.close(() => {
		fs.rmSync(testDbPath, { force: true })
		fs.rmSync(`${testDbPath}-wal`, { force: true })
		fs.rmSync(`${testDbPath}-shm`, { force: true })
		done()
	})
})
