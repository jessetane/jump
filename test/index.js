import test from 'node:test'
import assert from 'node:assert/strict'
import dns from 'node:dns'
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
const { isAllowedRedirectUri, deriveClientName } = await import('../oauth.js')
const api = await import('../api/index.js')
const { evaluatePolicy, matchPattern, parsePolicy, validatePolicy } = await import('../policy.js')
const { parseSsoDomains, shouldClaimUnscoped } = await import('../sso.js')
const { getBaseUrl, validateBaseUrl, resolveTargetUrl, hasPathTraversal } = await import('../util.js')

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
	assert.match(text, /href="\/style\.css"/)
	assert.equal(res.headers.get('access-control-allow-origin'), null, 'GET / HTML page must not expose wildcard CORS')
	const putRootRes = await fetch(`http://127.0.0.1:${addr.port}/`, { method: 'PUT' })
	assert.equal(putRootRes.status, 405, 'Unsupported methods on / return 405')
	const authHtmlRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize`)
	assert.equal(authHtmlRes.headers.get('access-control-allow-origin'), null, 'Browser OAuth authorize screen must not expose wildcard CORS')
	assert.equal(authHtmlRes.headers.get('referrer-policy'), 'same-origin')
	assert.equal(authHtmlRes.headers.get('x-frame-options'), 'DENY')
	const cssRes = await fetch(`http://127.0.0.1:${addr.port}/style.css`)
	assert.equal(cssRes.status, 200)
	assert.equal(cssRes.headers.get('content-type'), 'text/css; charset=utf-8')
	const cssText = await cssRes.text()
	assert.match(cssText, /\.view\s*\{/)
	assert.match(cssText, /@media\s*\(min-width:\s*520px\)/)
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
	assert.equal(isGoogleAllowedUrl('https://fcm.googleapis.com/v1/projects/myproj/messages:send').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://sheets.googleapis.com/v4/spreadsheets').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://docs.googleapis.com/v1/documents').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://calendar.googleapis.com/calendar/v3/events').allowed, true)
	assert.equal(isGoogleAllowedUrl('https://googleapis.com/test').allowed, true)
	assert.equal(isGoogleAllowedUrl('http://www.googleapis.com/test').allowed, false)
	assert.equal(isGoogleAllowedUrl('https://evil.com').allowed, false)
	assert.equal(isGoogleAllowedUrl('https://evilgoogleapis.com').allowed, false)
	assert.equal(isGoogleAllowedUrl('https://localhost:8080').allowed, false)
	assert.equal(isGoogleAllowedUrl('not-a-url').allowed, false)
	assert.equal(validateBaseUrl('https://fcc.gov/api/v1'), 'https://fcc.gov/api/v1')
	assert.equal(validateBaseUrl('https://fda.gov/v1/drugs/'), 'https://fda.gov/v1/drugs')
	assert.equal(validateBaseUrl('https://fcm.googleapis.com'), 'https://fcm.googleapis.com')
	assert.equal(validateBaseUrl('https://[fc00::1]'), null)
	assert.equal(validateBaseUrl('https://[fd12:3456::1]'), null)
	assert.equal(validateBaseUrl('https://[fe80::1]'), null)
	assert.equal(validateBaseUrl('https://[feb0::1]'), null)
	assert.equal(resolveTargetUrl('https:/api.example.com/v1/items'), 'https://api.example.com/v1/items')
	assert.equal(resolveTargetUrl('/v1/items', 'https://api.example.com/base/'), 'https://api.example.com/base/v1/items')
	assert.equal(resolveTargetUrl('v1/items', null), 'v1/items')
	assert.equal(hasPathTraversal('/v2/tenant-a/%2e%2e/tenant-b'), true)
	assert.equal(hasPathTraversal('/v2/commits/v1.0..v2.0?q=..'), false)
	const scopedProv = createProvider({ id: 'scoped_test', baseUrl: 'https://api.custom.dev/v2/tenant-a' })
	assert.equal(scopedProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/items').allowed, true)
	assert.equal(scopedProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/commits/v1..v2').allowed, true)
	assert.equal(scopedProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/%2e%2e/tenant-b').allowed, false)
	assert.equal(scopedProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/../tenant-b').allowed, false)
	const appScopedProv = createProvider('app_scoped_test')
	const appTokenScoped = { credentials: { baseUrl: 'https://api.custom.dev/v2/tenant-a' } }
	assert.equal(appScopedProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/%2e%2e/tenant-b', appTokenScoped).allowed, false)
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
	const origFetch = globalThis.fetch
	const origLookup = dns.promises.lookup
	let capturedInit = null
	dns.promises.lookup = async (host, opts) => {
		if (host === 'www.googleapis.com') return [{ address: '142.250.80.46', family: 4 }]
		return origLookup(host, opts)
	}
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://www.googleapis.com/drive/v3/files') {
			capturedInit = init
			return new Response(JSON.stringify({ files: [] }), {
				status: 200,
				headers: { 'content-type': 'application/json' }
			})
		}
		return origFetch(input, init)
	}
	try {
		const result = await executeTool('google_api', {
			url: 'https://www.googleapis.com/drive/v3/files',
			method: 'GET',
			body: { unwanted: 'payload' }
		}, session.token)
		assert.equal(result.isError, undefined)
		assert.equal(capturedInit?.body, undefined, 'GET request must strip body before fetch')
	} finally {
		globalThis.fetch = origFetch
		dns.promises.lookup = origLookup
	}
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
		name: 'Test OAuth Session',
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
		name: 'Test OAuth Session',
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
		name: 'Refresh User',
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
	const unnamedRegRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/register`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			redirect_uris: ['http://localhost:8080/cb']
		})
	})
	const unnamedRegData = await unnamedRegRes.json()
	assert.equal(deriveClientName(unnamedRegData.client_id), null, 'DCR client_id registered without client_name derives null')
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
	assert.equal(bearerState.name, 'Embedded MCP Client', 'DCR client_id registered with client_name preserves client_name as name')
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
	assert.equal(bearerSession.name, 'Embedded MCP Client')
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
	assert.equal(stateObj.name, 'Coding Agent')
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
	assert.equal(db.sqlite.prepare('SELECT COUNT(*) AS count FROM links WHERE app_id = ?').get(connectedApp.id).count, 0, 'App links must not be created until /oauth/token exchanges the auth code')
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
	assert.equal(stateObj.name, 'Browser Session')
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
	const setupCode = db.tokens.createState({ mode: 'setup_connect', sessionId: session.id, provider: 'google' })
	const connectRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/connect?code=${setupCode}`)
	assert.equal(connectRes.status, 200)
	const connectHtml = await connectRes.text()
	assert.match(connectHtml, /Configure API services access/)
	assert.match(connectHtml, /Sign in with Google/)
	assert.match(connectHtml, /action="\/providers\/google\/consent"/)
	assert.equal(connectHtml.includes(session.id), false, 'Connect HTML never embeds raw session_id')
	const missingCodeConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ session_id: session.id }).toString(),
		redirect: 'manual'
	})
	assert.equal(missingCodeConsentRes.status, 403, 'POST /providers/:provider/consent requires valid setup_connect code')
	const invalidCodeConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: 'non-existent-code' }).toString(),
		redirect: 'manual'
	})
	assert.equal(invalidCodeConsentRes.status, 403)
	const nonSelfSetup = db.tokens.createState({ mode: 'setup_connect', sessionId: nonSelfToken.id, provider: 'google' })
	const nonSelfConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: nonSelfSetup }).toString(),
		redirect: 'manual'
	})
	assert.equal(nonSelfConsentRes.status, 403)
	const nonAdminSetup = db.tokens.createState({ mode: 'setup_connect', sessionId: workerSession.id, provider: 'google' })
	const nonAdminInitialConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: nonAdminSetup }).toString(),
		redirect: 'manual'
	})
	assert.equal(nonAdminInitialConsentRes.status, 403)
	const wrongModeSetup = db.tokens.createState({ mode: 'setup_link', sessionId: session.id, provider: 'google' })
	const wrongModeConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: wrongModeSetup }).toString(),
		redirect: 'manual'
	})
	assert.equal(wrongModeConsentRes.status, 403, 'setup_link code must be rejected on /providers/:provider/consent')
	const consentBody = new URLSearchParams({
		code: setupCode,
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
	const replayConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	assert.equal(replayConsentRes.status, 403, 'setup_connect code is single-use and rejected on replay')
	const location = consentRes.headers.get('location')
	const targetUrl = new URL(location)
	assert.equal(targetUrl.hostname, 'accounts.google.com')
	assert.match(targetUrl.searchParams.get('scope'), /drive\.readonly/)
	assert.match(targetUrl.searchParams.get('scope'), /calendar\b/)
	assert.doesNotMatch(targetUrl.searchParams.get('scope'), /gmail/)
	const stateParam = targetUrl.searchParams.get('state')
	assert.ok(stateParam)
	const stateRow = db.tokens.consumeState(stateParam)
	assert.equal(stateRow.mode, 'connect')
	assert.equal(stateRow.sessionId, session.id)
	assert.equal(stateRow.name, 'Custom Work Google')
	assert.equal(stateRow.provider, 'google')
	assert.equal(db.tokens.consumeState(stateParam), null, 'consumeState atomically deletes state on first consumption')
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
	for (const endpoint of ['/oauth/token', '/oauth/revoke']) {
		const badOauthJson = await fetch(`http://127.0.0.1:${addr.port}${endpoint}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: '{"corrupt'
		})
		assert.equal(badOauthJson.status, 400, `${endpoint} fails loud with 400 on malformed JSON body`)
		const badOauthData = await badOauthJson.json()
		assert.equal(badOauthData.error, 'invalid_request')
		assert.match(badOauthData.error_description, /Invalid JSON body/)
	}
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

test('mcp auth whoami, list_sessions, and revoke_session', async () => {
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
	const listResult = await executeTool('admin', { action: 'list_sessions' }, session1.token)
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
	const revokeAppAsSessionResult = await api.auth.revokeSession(session1.token, { sessionId: app.id })
	assert.equal(revokeAppAsSessionResult.revoked, false, 'api.auth.revokeSession must reject non-self app IDs')
	assert.ok(db.tokens.get(app.id), 'api.auth.revokeSession must not delete upstream app token')
	const ephemeralCode = db.tokens.createAuthCode({ userId: user.id, clientRedirectUri: 'https://chatgpt.com/callback' })
	const revokeCodeAsSessionResult = await api.auth.revokeSession(session1.token, { sessionId: ephemeralCode })
	assert.equal(revokeCodeAsSessionResult.revoked, false, 'api.auth.revokeSession must reject non-bearer self rows (oauth_code / oauth_state)')
	assert.ok(db.tokens.get(ephemeralCode), 'api.auth.revokeSession must not delete oauth_code row')
	const revokeOtherResult = await executeTool('admin', { action: 'revoke_session', allOthers: true }, session1.token)
	assert.equal(revokeOtherResult.isError, undefined)
	const revokeOtherParsed = JSON.parse(revokeOtherResult.content[0].text)
	assert.equal(revokeOtherParsed.revoked, true)
	assert.equal(revokeOtherParsed.count, 1)
	assert.equal(db.tokens.get(session2.id), null)
	assert.ok(db.tokens.get(session1.id))
	const revokeCurrentResult = await executeTool('admin', { action: 'revoke_session' }, session1.token)
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
	const listRes = await executeTool('admin', { action: 'list_sessions' }, session.token)
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
	assert.equal(validatePolicy([{ action: 'allow', body: null }]).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', body: '*<DomainList>*' }]).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', body: ['*<Get>*', '*<List>*'] }]).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', body: { currency: 'usd' }, bodyType: 'json' }]).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', body: { currency: 'usd' }, bodyType: 'form' }]).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', body: '' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: '   ' }]).error, /body pattern must be a non-empty string/)
	assert.equal(validatePolicy([{ action: 'allow', body: [] }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: [] }]).error, /body array must be a non-empty array of non-empty pattern strings/)
	assert.equal(validatePolicy([{ action: 'allow', body: ['ok', ''] }]).valid, false)
	assert.equal(validatePolicy([{ action: 'allow', body: 123 }]).valid, false)
	assert.equal(validatePolicy([{ action: 'allow', bodyType: 'form' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', bodyType: 'form' }]).error, /bodyType is only valid when body is a field-map object/)
	assert.equal(validatePolicy([{ action: 'allow', body: '*<Ping>*', bodyType: 'form' }]).valid, false)
	assert.equal(validatePolicy([{ action: 'allow', body: null, bodyType: 'json' }]).valid, false)
	assert.equal(validatePolicy([{ action: 'allow', body: { a: '1' }, bodyType: 'xml' }]).valid, false)
	assert.match(validatePolicy([{ action: 'allow', body: { a: '1' }, bodyType: 'xml' }]).error, /bodyType must be "json" or "form"/)
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

test('evaluatePolicy matches request body fields (nested dot-paths, arrays, JSON, explicit form, raw globs, empty null)', () => {
	const policy = [
		{
			action: 'deny',
			methods: ['POST'],
			path: '/v1/charges',
			body: { currency: 'btc' },
			bodyType: 'form',
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
			path: '/v1/orders',
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
		body: Buffer.from(JSON.stringify({ channel: 'C_TEAM', recipient: { email: 'carol@example.com' } }))
	}).allowed, true, 'Raw Buffer JSON body parses cleanly when rule inspects body')
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
		url: 'https://api.stripe.com/v1/orders',
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
		{ action: 'allow', methods: ['POST'], path: '/v1/proto', body: { toString: 'hello' }, bodyType: 'form' }
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
		{ action: 'allow', methods: ['POST'], path: '/v1/form', body: { '<foo>': 'bar>' }, bodyType: 'form' }
	], {
		url: 'https://api.stripe.com/v1/form',
		method: 'POST',
		body: '<foo>=bar>'
	}).allowed, true, 'Explicit bodyType: form parses <foo>=bar> without header guessing')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' }, bodyType: 'form' },
		{ action: 'allow' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '{"currency":"btc"}'
	}).allowed, false, 'Deny rule with bodyType: form must fail closed when non-form JSON payload is sent')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' } },
		{ action: 'allow' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: 'currency=btc&amount=1000'
	}).allowed, false, 'Deny rule with default bodyType: json must fail closed when form-urlencoded string is sent')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' }, bodyType: 'form' },
		{ action: 'allow' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: { currency: 'btc' },
		objectFormat: 'json'
	}).allowed, false, 'Deny rule with bodyType: form must fail closed when MCP caller sends JSON object')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/soap', body: '*<DomainList*>*' }
	], {
		url: 'https://api.namecheap.com/soap',
		method: 'POST',
		body: '<soap:Envelope>\n  <soap:Body>\n    <DomainList/>\n  </soap:Body>\n</soap:Envelope>'
	}).allowed, true, 'String glob body rule matches multiline XML across newlines')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/soap', body: ['*<DeleteDomain*', '*<Transfer*'] },
		{ action: 'allow', methods: ['POST'], path: '/soap', body: '*<soap:Envelope>*' }
	], {
		url: 'https://api.namecheap.com/soap',
		method: 'POST',
		body: '<soap:Envelope><soap:Body><DeleteDomain id="1"/></soap:Body></soap:Envelope>'
	}).allowed, false, 'Array of string globs in deny rule blocks matching XML body')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/v1/any', body: '*secret_token*' },
		{ action: 'allow' }
	], {
		url: 'https://api.example.com/v1/any',
		method: 'POST',
		body: { nested: { key: 'my_secret_token_123' } }
	}).allowed, false, 'String glob rule inspects serialized wire text when MCP caller passes a JS object')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/ping', body: null }
	], {
		url: 'https://api.example.com/v1/ping',
		method: 'POST'
	}).allowed, true, 'body: null allows empty request body')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/ping', body: null }
	], {
		url: 'https://api.example.com/v1/ping',
		method: 'POST',
		body: Buffer.alloc(0)
	}).allowed, true, 'body: null allows 0-byte Buffer body')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/ping', body: null }
	], {
		url: 'https://api.example.com/v1/ping',
		method: 'POST',
		body: 'non-empty'
	}).allowed, false, 'body: null rejects non-empty request body')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/raw' }
	], {
		url: 'https://api.example.com/v1/raw',
		method: 'POST',
		body: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff, 0x00])
	}).allowed, true, 'Rules without body never inspect or parse raw binary request bodies')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: '[{"a":"1=2"}]'
	}).allowed, false, 'JSON array string must not match object body rule')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: '{"broken": "a=b"'
	}).allowed, false, 'Malformed JSON string must not match object body rule')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/events', body: { sendUpdates: ['none', null] } }
	], {
		url: 'https://api.example.com/v1/events',
		method: 'POST',
		body: 'foo=bar'
	}).allowed, false, 'Form string must not match default bodyType: json rule')
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

test('mcp admin tool with whoami and get_session actions', async () => {
	const { user, session } = createTestSession({ account: 'mcp-whoami@example.com' })
	const whoamiResult = await executeTool('admin', { action: 'whoami' }, session.token)
	assert.equal(whoamiResult.isError, undefined)
	const parsedWhoami = JSON.parse(whoamiResult.content[0].text)
	assert.equal(parsedWhoami.authenticated, true)
	assert.equal(parsedWhoami.user.id, user.id)
	assert.equal(parsedWhoami.user.account, 'mcp-whoami@example.com')
	assert.equal(parsedWhoami.session.id, session.id)
	const getResult = await executeTool('admin', { action: 'get_session', sessionId: session.id }, session.token)
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
	const listResult = await executeTool('admin', { action: 'list_sessions' }, session1.token)
	assert.equal(listResult.isError, true)
	assert.match(listResult.content[0].text, /requires admin privileges/)
	const getOtherResult = await executeTool('admin', { action: 'get_session', sessionId: session2.id }, session1.token)
	assert.equal(getOtherResult.isError, true)
	assert.match(getOtherResult.content[0].text, /requires admin privileges/)
	const getSelfResult = await executeTool('admin', { action: 'get_session', sessionId: session1.id }, session1.token)
	assert.equal(getSelfResult.isError, undefined)
	const getSelfParsed = JSON.parse(getSelfResult.content[0].text)
	assert.equal(getSelfParsed.session.id, session1.id)
	const revokeOthersResult = await executeTool('admin', { action: 'revoke_session', allOthers: true }, session1.token)
	assert.equal(revokeOthersResult.isError, true)
	assert.match(revokeOthersResult.content[0].text, /requires admin privileges/)
	assert.ok(db.tokens.get(session2.id))
	const revokeOtherIdResult = await executeTool('admin', { action: 'revoke_session', sessionId: session2.id }, session1.token)
	assert.equal(revokeOtherIdResult.isError, true)
	assert.match(revokeOtherIdResult.content[0].text, /requires admin privileges/)
	assert.ok(db.tokens.get(session2.id))
	const revokeSelfResult = await executeTool('admin', { action: 'revoke_session', sessionId: session1.id }, session1.token)
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
	const stateWithoutUser = db.tokens.createState({ mode: 'verify', name: 'Missing User Session' })
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
		name: 'Admin Magic Session',
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
	const namedOauthRes = await executeTool('admin', {
		action: 'connect_app',
		provider: 'google',
		name: 'Work Google'
	}, adminSession.token, `http://127.0.0.1:${server.address().port}`)
	assert.equal(namedOauthRes.isError, undefined)
	const namedOauthData = JSON.parse(namedOauthRes.content[0].text)
	assert.equal(namedOauthData.actionRequired, 'oauth_flow')
	const namedConnectUrl = new URL(namedOauthData.connectUrl)
	assert.equal(namedConnectUrl.searchParams.get('session_id'), null, 'connectUrl never embeds raw session_id')
	const namedSetupState = db.tokens.getState(namedConnectUrl.searchParams.get('code'))
	assert.equal(namedSetupState.mode, 'setup_connect')
	assert.equal(namedSetupState.sessionId, adminSession.id)
	assert.equal(namedSetupState.name, 'Work Google')
	const reauthRes = await executeTool('admin', {
		action: 'connect_app',
		appId: googleApp.id
	}, adminSession.token)
	assert.equal(reauthRes.isError, undefined)
	const reauthData = JSON.parse(reauthRes.content[0].text)
	assert.equal(reauthData.actionRequired, 'oauth_flow')
	const reauthConnectUrl = new URL(reauthData.connectUrl)
	assert.equal(reauthConnectUrl.searchParams.get('session_id'), null)
	const reauthSetupState = db.tokens.getState(reauthConnectUrl.searchParams.get('code'))
	assert.equal(reauthSetupState.mode, 'setup_connect')
	assert.equal(reauthSetupState.reauthAppId, googleApp.id)
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
	const crossUserSetup = db.tokens.createState({ mode: 'setup_connect', sessionId: attackerAdmin.id, provider: 'google', reauthAppId: app.id })
	const crossUserConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: crossUserSetup
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
	const nonAdminReauthSetup = db.tokens.createState({ mode: 'setup_connect', sessionId: session.id, provider: 'google', reauthAppId: app.id })
	const nonAdminConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: nonAdminReauthSetup
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(nonAdminConsentRes.status, 403, 'Non-admin session must not initiate reauth_app_id consent')
	const validReauthSetup = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSession.id, provider: 'google', reauthAppId: app.id })
	const connectHtmlRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/connect?code=${validReauthSetup}`)
	assert.equal(connectHtmlRes.status, 200)
	const connectHtml = await connectHtmlRes.text()
	assert.match(connectHtml, /"services":"drive,calendar"/, 'GET /providers/:provider/connect pre-populates granted services for reauth_app_id')
	assert.match(connectHtml, /"write":"calendar"/, 'GET /providers/:provider/connect pre-populates write services for reauth_app_id')
	const validConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: validReauthSetup,
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
	const apiKeyReauthSetup = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSession.id, provider: 'google', reauthAppId: apiKeyApp.id })
	const apiKeyReauthConsent = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: apiKeyReauthSetup
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
		const reauthUrlMatch = adminProxyErr.content[0].text.match(/Re-authenticate:\s*(http\S+)/)
		assert.ok(reauthUrlMatch, 'Admin proxy refresh failure includes clickable reauth URL')
		const parsedProxyReauth = new URL(reauthUrlMatch[1])
		assert.equal(parsedProxyReauth.searchParams.get('session_id'), null, 'Proxy reauth URL never leaks raw session_id')
		const proxySetupState = db.tokens.getState(parsedProxyReauth.searchParams.get('code'))
		assert.equal(proxySetupState?.mode, 'setup_connect')
		assert.equal(proxySetupState?.reauthAppId, app.id)
		assert.equal(proxySetupState?.sessionId, adminSession.id)
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
		const expLinkSetup = db.tokens.createState({ mode: 'setup_link', sessionId: invalidSid, provider: 'github' })
		const expConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: expLinkSetup, provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(expConsent.status, 403, 'Inactive/expired session bound to setup_link code must be rejected on /oauth/authorize/consent')
		const expConnectSetup = db.tokens.createState({ mode: 'setup_connect', sessionId: invalidSid, provider: 'google' })
		const expProvConsent = await fetch(`http://127.0.0.1:${addr.port}/providers/google/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: expConnectSetup }).toString(),
			redirect: 'manual'
		})
		assert.equal(expProvConsent.status, 403, 'Inactive/expired session bound to setup_connect code must be rejected on /providers/:provider/consent')
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
	const precUser = db.logins.resolveUser('google', 'prec@acme.com', { allowUnscoped: true })
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
	const seqUser = db.logins.resolveUser('google', 'seq@acme.com', { allowUnscoped: true })
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
	const staleUser = db.logins.resolveUser('google', 'stale@acme.com', { allowUnscoped: true })
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
	db.logins.upsert({ userId: seqUser.id, provider: 'google', account: 'seq-extra@acme.com', allowUnscoped: true })
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
	const linkConnectUrl = new URL(providerFlowData.connectUrl)
	assert.equal(linkConnectUrl.searchParams.get('session_id'), null, 'link_login connectUrl never embeds raw session_id')
	const linkSetupCode = linkConnectUrl.searchParams.get('code')
	assert.ok(linkSetupCode)
	const authPageRes = await fetch(providerFlowData.connectUrl)
	assert.equal(authPageRes.status, 200)
	const authPageHtml = await authPageRes.text()
	assert.match(authPageHtml, /Link sign-in provider/)
	assert.match(authPageHtml, /"linkMode":true/)
	assert.equal(authPageHtml.includes(adminSession.id), false, 'Link authorize HTML never embeds raw session_id')
	const setupCallbackReplay = await fetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${linkSetupCode}`)
	assert.equal(setupCallbackReplay.status, 403, 'setup_link code cannot be used directly at /oauth/callback')
	const freshLinkRes = await executeTool('admin', {
		action: 'link_login',
		provider: 'github'
	}, adminSession.token, `http://127.0.0.1:${addr.port}`)
	const freshLinkCode = new URL(JSON.parse(freshLinkRes.content[0].text).connectUrl).searchParams.get('code')
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: freshLinkCode,
			provider: 'github'
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 302)
	const replayLinkConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: freshLinkCode,
			provider: 'github'
		}).toString(),
		redirect: 'manual'
	})
	assert.equal(replayLinkConsent.status, 403, 'setup_link code is single-use and rejected on replay')
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
		const googleLoginState = db.tokens.createState({ mode: 'login', provider: 'google', name: 'Google Key Login' })
		const googleLoginCb = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${googleLoginState}`, { redirect: 'manual' })
		assert.equal(googleLoginCb.status, 302)
		const googleVerifyCode = new URL(googleLoginCb.headers.get('location'), `http://127.0.0.1:${addr.port}`).searchParams.get('code')
		assert.equal(db.tokens.getState(googleVerifyCode).userId, user.id)
		const githubLoginState = db.tokens.createState({ mode: 'login', provider: 'github', name: 'GitHub Key Login' })
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
	} finally {
		globalThis.fetch = origFetch
	}
})

test('SSO_DOMAINS pinning, login isolation, strict outbound sharing, and verifiedEmail claim protection', async () => {
	const addr = server.address()
	const origFetch = globalThis.fetch
	const origSsoDomains = process.env.SSO_DOMAINS
	let googleMockEmail = 'alice@corp.com'
	let ghMockLogin = 'contractor-gh'
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.sso', token_type: 'Bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: googleMockEmail }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://github.com/login/oauth/access_token') {
			return new Response(JSON.stringify({ access_token: 'gho_sso', token_type: 'bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://api.github.com/user') {
			return new Response(JSON.stringify({ login: ghMockLogin }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	process.env.SSO_DOMAINS = 'corp.com:google, strictcorp.com:google:strict, partner.io:github'
	try {
		ghMockLogin = 'alice@corp.com'
		const wrongLoginState = db.tokens.createState({ mode: 'login', provider: 'github' })
		const wrongLoginRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${wrongLoginState}`, { redirect: 'manual' })
		assert.equal(wrongLoginRes.status, 403, 'Login on pinned domain with wrong provider must fail with 403')
		assert.match(await wrongLoginRes.text(), /SSO domain "corp\.com"/)
		assert.equal(db.logins.findUserByAccount('alice@corp.com', 'github'), null, 'Rejected SSO login must not create user or login row')
		googleMockEmail = 'alice@corp.com'
		const validLoginState = db.tokens.createState({ mode: 'login', provider: 'google' })
		const validLoginRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${validLoginState}`, { redirect: 'manual' })
		assert.equal(validLoginRes.status, 200, 'Login on pinned domain with pinned provider succeeds')
		assert.match(await validLoginRes.text(), /user:\s*alice@corp\.com/)
		const corpUser = db.logins.findUserByAccount('alice@corp.com', 'google')
		assert.ok(corpUser?.id)
		const corpAdmin = db.tokens.create({ userId: corpUser.id, provider: 'self', admin: 1 })
		ghMockLogin = 'flex-user@flex.com'
		const flexGhState = db.tokens.createState({ mode: 'login', provider: 'github' })
		const flexGhRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${flexGhState}`, { redirect: 'manual' })
		assert.equal(flexGhRes.status, 200, 'Login on unpinned domain succeeds with github')
		googleMockEmail = 'flex-user@flex.com'
		const flexGoogleState = db.tokens.createState({ mode: 'login', provider: 'google' })
		const flexGoogleRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${flexGoogleState}`, { redirect: 'manual' })
		assert.equal(flexGoogleRes.status, 200, 'Login on unpinned domain succeeds with google')
		const linkOtherFromPinned = await executeTool('admin', {
			action: 'link_login',
			provider: 'github'
		}, corpAdmin.token)
		assert.equal(linkOtherFromPinned.isError, true, 'link_login rejects linking another provider onto a user holding a pinned domain login')
		assert.match(linkOtherFromPinned.content[0].text, /SSO domain "corp\.com"/)
		const preLinkSetup = db.tokens.createState({ mode: 'setup_link', sessionId: corpAdmin.id, provider: 'github' })
		const getOtherFromPinned = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?code=${preLinkSetup}`)
		assert.equal(getOtherFromPinned.status, 403, 'GET /oauth/authorize rejects setup_link code targeting another provider onto a pinned domain user')
		const consentOtherFromPinned = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: preLinkSetup, provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(consentOtherFromPinned.status, 403, 'handleAuthorizeConsent rejects linking another provider onto a pinned domain user')
		ghMockLogin = 'alice-gh'
		const authCbOtherFromPinnedState = db.tokens.createState({ mode: 'auth', sessionId: corpAdmin.id, provider: 'github' })
		const authCbOtherFromPinned = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${authCbOtherFromPinnedState}`)
		assert.equal(authCbOtherFromPinned.status, 403, 'handleCallback mode=auth rejects linking another provider onto a pinned domain user')
		assert.equal(db.logins.findUserByAccount('alice-gh', 'github'), null)
		const linkSameFromPinned = await executeTool('admin', {
			action: 'link_login',
			provider: 'google'
		}, corpAdmin.token)
		assert.equal(linkSameFromPinned.isError, undefined, 'link_login allows linking on the pinned provider itself')
		const ghUser = db.logins.resolveUser('github', 'contractor-gh')
		const ghAdmin = db.tokens.create({ userId: ghUser.id, provider: 'self', admin: 1 })
		googleMockEmail = 'bob@corp.com'
		const linkPinnedOntoOtherState = db.tokens.createState({ mode: 'auth', sessionId: ghAdmin.id, provider: 'google' })
		const linkPinnedOntoOtherRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${linkPinnedOntoOtherState}`)
		assert.equal(linkPinnedOntoOtherRes.status, 403, 'User with other-provider logins cannot link a login in a pinned domain')
		assert.equal(db.logins.findUserByAccount('bob@corp.com', 'google'), null)
		googleMockEmail = 'bob@flex.com'
		const linkUnpinnedOntoOtherState = db.tokens.createState({ mode: 'auth', sessionId: ghAdmin.id, provider: 'google' })
		const linkUnpinnedOntoOtherRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${linkUnpinnedOntoOtherState}`)
		assert.equal(linkUnpinnedOntoOtherRes.status, 200, 'User with other-provider logins can link an unpinned email domain')
		assert.equal(db.logins.findUserByAccount('bob@flex.com', 'google')?.id, ghUser.id)
		const flexOnlyUser = db.logins.resolveUser('google', 'carol@flex.com')
		const flexOnlyAdmin = db.tokens.create({ userId: flexOnlyUser.id, provider: 'self', admin: 1 })
		ghMockLogin = 'carol@corp.com'
		const linkPinnedWrongProvState = db.tokens.createState({ mode: 'auth', sessionId: flexOnlyAdmin.id, provider: 'github' })
		const linkPinnedWrongProvRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${linkPinnedWrongProvState}`)
		assert.equal(linkPinnedWrongProvRes.status, 403, 'Linking a login in a pinned domain with wrong provider must fail with 403')
		assert.equal(db.logins.findUserByAccount('carol@corp.com', 'github'), null)
		const flexApp = db.tokens.create({
			userId: flexOnlyUser.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Flex Stripe',
			credentials: { apiKey: 'sk_flex', baseUrl: 'https://api.stripe.com' }
		})
		const conflictPinnedRestShare = await fetch(`http://127.0.0.1:${addr.port}/api/shares`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${flexOnlyAdmin.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({
				appId: flexApp.id,
				account: 'newhire@corp.com',
				provider: 'github'
			})
		})
		assert.equal(conflictPinnedRestShare.status, 403, 'Sharing to pinned domain with explicit conflicting provider fails with 403 regardless of sharer')
		const autoPinnedShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: flexApp.id,
			account: 'newhire@corp.com'
		}, flexOnlyAdmin.token)).content[0].text)
		assert.equal(autoPinnedShare.provider, 'google', 'Sharing to pinned domain auto-resolves authProvider to pinned provider')
		ghMockLogin = 'newhire@corp.com'
		const ghImpersonatorState = db.tokens.createState({ mode: 'login', provider: 'github' })
		const ghImpersonatorRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${ghImpersonatorState}`, { redirect: 'manual' })
		assert.equal(ghImpersonatorRes.status, 403, 'Wrong provider callback must not sign in or claim pinned-domain pending share')
		assert.equal(db.tokens.get(autoPinnedShare.shareId).userId, null)
		googleMockEmail = 'newhire@corp.com'
		const googleCorpState = db.tokens.createState({ mode: 'login', provider: 'google' })
		const googleCorpRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${googleCorpState}`, { redirect: 'manual' })
		assert.equal(googleCorpRes.status, 302, 'Pinned provider callback claims pending share and redirects to verify')
		const googleCorpUser = db.logins.findUserByAccount('newhire@corp.com', 'google')
		assert.equal(db.tokens.listByUserId(googleCorpUser.id).filter(t => t.type === 'share').length, 1, 'Pinned provider claims pending share via /oauth/callback')
		const unscopedCorpPending = db.tokens.upsertShare({
			userId: null,
			account: 'unscoped@corp.com',
			authProvider: null,
			appId: flexApp.id,
			provider: 'stripe'
		})
		ghMockLogin = 'unscoped@corp.com'
		const ghCorpState = db.tokens.createState({ mode: 'login', provider: 'github' })
		const ghCorpRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${ghCorpState}`, { redirect: 'manual' })
		assert.equal(ghCorpRes.status, 403, 'Wrong provider callback must not claim unscoped pending share on pinned domain')
		assert.equal(db.tokens.get(unscopedCorpPending.id).userId, null)
		googleMockEmail = 'unscoped@corp.com'
		const googleUnscopedCorpState = db.tokens.createState({ mode: 'login', provider: 'google' })
		const googleUnscopedCorpRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${googleUnscopedCorpState}`, { redirect: 'manual' })
		assert.equal(googleUnscopedCorpRes.status, 302)
		const googleCorpUnscopedUser = db.logins.findUserByAccount('unscoped@corp.com', 'google')
		assert.equal(db.tokens.listByUserId(googleCorpUnscopedUser.id).filter(t => t.type === 'share').length, 1, 'Pinned provider claims unscoped pending share on pinned domain via /oauth/callback')
		const unscopedPartnerPending = db.tokens.upsertShare({
			userId: null,
			account: 'member@partner.io',
			authProvider: null,
			appId: flexApp.id,
			provider: 'stripe'
		})
		googleMockEmail = 'member@partner.io'
		const googlePartnerState = db.tokens.createState({ mode: 'login', provider: 'google' })
		const googlePartnerRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${googlePartnerState}`, { redirect: 'manual' })
		assert.equal(googlePartnerRes.status, 403, 'Even verifiedEmail provider callback must not claim unscoped share on domain pinned to another provider')
		assert.equal(db.tokens.get(unscopedPartnerPending.id).userId, null)
		ghMockLogin = 'member@partner.io'
		const githubPartnerState = db.tokens.createState({ mode: 'login', provider: 'github' })
		const githubPartnerRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${githubPartnerState}`, { redirect: 'manual' })
		assert.equal(githubPartnerRes.status, 302)
		const githubPartnerUser = db.logins.findUserByAccount('member@partner.io', 'github')
		assert.equal(db.tokens.listByUserId(githubPartnerUser.id).filter(t => t.type === 'share').length, 1, 'Pinned provider claims unscoped pending share on its pinned domain even without verifiedEmail')
		const unscopedFlexPending = db.tokens.upsertShare({
			userId: null,
			account: 'unscoped@flex.com',
			authProvider: null,
			appId: flexApp.id,
			provider: 'stripe'
		})
		ghMockLogin = 'unscoped@flex.com'
		const ghFlexState = db.tokens.createState({ mode: 'login', provider: 'github' })
		const ghFlexRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${ghFlexState}`, { redirect: 'manual' })
		assert.equal(ghFlexRes.status, 200, 'Unpinned email domain allows github login without claiming unscoped pending share')
		const ghFlexUser = db.logins.findUserByAccount('unscoped@flex.com', 'github')
		assert.equal(db.tokens.listByUserId(ghFlexUser.id).filter(t => t.type === 'share').length, 0, 'Unpinned email domain still requires verifiedEmail to claim unscoped pending share')
		assert.equal(db.tokens.get(unscopedFlexPending.id).userId, null)
		googleMockEmail = 'unscoped@flex.com'
		const googleFlexState = db.tokens.createState({ mode: 'login', provider: 'google' })
		const googleFlexRes = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${googleFlexState}`, { redirect: 'manual' })
		assert.equal(googleFlexRes.status, 302)
		const googleFlexUser = db.logins.findUserByAccount('unscoped@flex.com', 'google')
		assert.equal(db.tokens.listByUserId(googleFlexUser.id).filter(t => t.type === 'share').length, 1, 'verifiedEmail provider claims unscoped pending share on unpinned domain via /oauth/callback')
		const corpApp = db.tokens.create({
			userId: corpUser.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Non-Strict Corp Stripe',
			credentials: { apiKey: 'sk_corp', baseUrl: 'https://api.stripe.com' }
		})
		const nonStrictCrossShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: corpApp.id,
			account: 'github:ext-contractor'
		}, corpAdmin.token)).content[0].text)
		assert.equal(nonStrictCrossShare.provider, 'github', 'Non-strict pinned sharer can share out to other providers')
		const nonStrictPartnerShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: corpApp.id,
			account: 'ally@partner.io'
		}, corpAdmin.token)).content[0].text)
		assert.equal(nonStrictPartnerShare.provider, 'github', 'Non-strict pinned sharer auto-resolves partner pinned domain provider')
		const nonStrictFlexShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: corpApp.id,
			account: 'bob@flex.com'
		}, corpAdmin.token)).content[0].text)
		assert.equal(nonStrictFlexShare.userId, ghUser.id, 'Non-strict share to unpinned domain resolves existing user via findUserByAccount')
		const strictUser = db.logins.resolveUser('google', 'boss@strictcorp.com')
		const strictAdmin = db.tokens.create({ userId: strictUser.id, provider: 'self', admin: 1 })
		const strictApp = db.tokens.create({
			userId: strictUser.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Strict Corp Stripe',
			credentials: { apiKey: 'sk_strict', baseUrl: 'https://api.stripe.com' }
		})
		const strictCrossShare = await executeTool('admin', {
			action: 'share_app',
			appId: strictApp.id,
			account: 'ext-contractor',
			provider: 'github'
		}, strictAdmin.token)
		assert.equal(strictCrossShare.isError, true, 'Strict pinned sharer must not create explicit cross-provider share')
		assert.match(strictCrossShare.content[0].text, /SSO domain "strictcorp\.com" requires sharing within "google"/)
		const strictPartnerCrossShare = await executeTool('admin', {
			action: 'share_app',
			appId: strictApp.id,
			account: 'ally@partner.io'
		}, strictAdmin.token)
		assert.equal(strictPartnerCrossShare.isError, true, 'Strict pinned sharer must not share to domain pinned to another provider')
		const strictDefaultEmailShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: strictApp.id,
			account: 'outside@flex.com'
		}, strictAdmin.token)).content[0].text)
		assert.equal(strictDefaultEmailShare.provider, 'google', 'Strict pinned sharer defaults unpinned target without provider to strict pinned provider')
		const strictDefaultBareShare = JSON.parse((await executeTool('admin', {
			action: 'share_app',
			appId: strictApp.id,
			account: 'bare-strict-target'
		}, strictAdmin.token)).content[0].text)
		assert.equal(strictDefaultBareShare.provider, 'google', 'Strict pinned sharer defaults bare target without provider to strict pinned provider')
		db.tokens.upsertShare({
			userId: null,
			account: 'legacy-unscoped@strictcorp.com',
			authProvider: null,
			appId: strictApp.id,
			provider: 'stripe'
		})
		db.tokens.upsertShare({
			userId: null,
			account: 'legacy-gh',
			authProvider: 'github',
			appId: strictApp.id,
			provider: 'stripe'
		})
		const strictRevokeUnscoped = JSON.parse((await executeTool('admin', {
			action: 'unshare_app',
			appId: strictApp.id,
			account: 'legacy-unscoped@strictcorp.com'
		}, strictAdmin.token)).content[0].text)
		assert.equal(strictRevokeUnscoped.unshared, true, 'Strict SSO admin can revoke pre-existing unscoped shares on their app')
		const strictRevokeCross = JSON.parse((await executeTool('admin', {
			action: 'unshare_app',
			appId: strictApp.id,
			account: 'github:legacy-gh'
		}, strictAdmin.token)).content[0].text)
		assert.equal(strictRevokeCross.unshared, true, 'Strict SSO admin can revoke pre-existing cross-provider shares on their app')
	} finally {
		globalThis.fetch = origFetch
		if (origSsoDomains === undefined) delete process.env.SSO_DOMAINS
		else process.env.SSO_DOMAINS = origSsoDomains
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
	const adminSessionNoApps = db.tokens.create({
		userId: user.id,
		provider: 'self',
		admin: 1
	})
	const noAppRes = await executeTool('google_api', {
		url: 'https://www.googleapis.com/drive/v3/files'
	}, sessionNoApps.token)
	assert.equal(noAppRes.isError, true)
	assert.match(noAppRes.content[0].text, /No Google app linked to session\. Ask an admin to link one\./)
	assert.doesNotMatch(noAppRes.content[0].text, /\/providers\/google\/connect/)
	const adminNoAppRes = await executeTool('google_api', {
		url: 'https://www.googleapis.com/drive/v3/files'
	}, adminSessionNoApps.token)
	assert.equal(adminNoAppRes.isError, true)
	assert.match(adminNoAppRes.content[0].text, /No Google app linked to session\. Use connect_app or link_app to attach one\./)
	const noStripeRes = await executeTool('stripe_api', {
		url: '/v1/customers'
	}, sessionNoApps.token)
	assert.equal(noStripeRes.isError, true)
	assert.match(noStripeRes.content[0].text, /No Stripe app linked to session\. Ask an admin to link one\./)
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
					body: { forbidden: '1' },
					bodyType: 'form'
				},
				{
					action: 'allow',
					methods: ['POST'],
					path: '/v3/messages',
					body: { from: 'noreply@example.com', tag: ['onboarding', 'welcome'] },
					bodyType: 'form'
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
			headers: {
				authorization: `Bearer ${session.token}`,
				'x-custom-trace': 'trace-abc-123'
			}
		})
		assert.equal(restXmlRes.status, 200)
		assert.equal(restXmlRes.headers.get('content-type'), 'application/xml; charset=iso-8859-1')
		const restXmlBuf = Buffer.from(await restXmlRes.arrayBuffer())
		assert.equal(restXmlBuf.toString('latin1'), '<?xml version="1.0" encoding="iso-8859-1"?><ApiResponse Status="OK"><CommandResponse>caf\xe9</CommandResponse></ApiResponse>', 'REST proxy preserves raw Latin-1 bytes and upstream charset header untouched')
		const restXmlCaptured = captured.findLast(r => r.url.startsWith('/xml.response'))
		assert.equal(restXmlCaptured.headers['x-custom-trace'], 'trace-abc-123', 'REST proxy must pass safe caller headers through')
		captured.length = 0
		const soapRes = await executeTool('namecheap_api', {
			url: '/soap',
			method: 'POST',
			body: '  <soap:Envelope><soap:Body><Ping/></soap:Body></soap:Envelope>'
		}, session.token)
		assert.equal(soapRes.isError, undefined)
		assert.equal(soapRes.content[0].text, '<soap:Envelope><soap:Body><Result>ok</Result></soap:Body></soap:Envelope>')
		const soapCaptured = captured.find(r => r.url.startsWith('/soap'))
		assert.equal(soapCaptured.headers['content-type'], undefined, 'Dumb proxy must never inject Content-Type on string bodies')
		captured.length = 0
		const explicitSoapRes = await executeTool('namecheap_api', {
			url: '/soap',
			method: 'POST',
			headers: { 'Content-Type': 'application/soap+xml; charset=utf-8' },
			body: '<soap:Envelope><soap:Body><Ping/></soap:Body></soap:Envelope>'
		}, session.token)
		assert.equal(explicitSoapRes.isError, undefined)
		assert.equal(captured[0].headers['content-type'], 'application/soap+xml; charset=utf-8', 'Explicit caller Content-Type is forwarded intact')
		captured.length = 0
		const rawRestPost = await fetch(`http://127.0.0.1:${addr.port}/api/namecheap/raw-upload`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${session.token}`,
				cookie: 'jump_sid=should_not_leak',
				'x-api-key': 'jump_key_should_not_leak',
				'x-upstream-header': 'keep-me'
			},
			body: Buffer.from('raw-unlabelled-payload')
		})
		assert.equal(rawRestPost.status, 200)
		const rawRestData = await rawRestPost.json()
		assert.equal(rawRestData.contentType, null, 'REST proxy must not inject Content-Type when client omits it')
		assert.equal(rawRestData.body, 'raw-unlabelled-payload')
		assert.equal(captured[0].headers['x-upstream-header'], 'keep-me')
		assert.equal(captured[0].headers.cookie, undefined, 'Jump Cookie header must not leak upstream')
		assert.equal(captured[0].headers['x-api-key'], undefined, 'Jump X-Api-Key header must not leak upstream')
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
	assert.equal(Object.hasOwn(google, 'ssoOnly'), false, 'ssoOnly is retired from provider objects')
	const parsedSso = parseSsoDomains(' Acme.COM:Google , partner.io:GitHub:STRICT , ')
	assert.deepEqual(parsedSso.get('acme.com'), { domain: 'acme.com', provider: 'google', strict: false })
	assert.deepEqual(parsedSso.get('partner.io'), { domain: 'partner.io', provider: 'github', strict: true })
	assert.throws(() => parseSsoDomains('acme.com'), /Invalid SSO_DOMAINS entry/)
	assert.throws(() => parseSsoDomains('acme.com:google:bogus'), /Invalid SSO_DOMAINS entry/)
	assert.throws(() => parseSsoDomains('acme.com:google,acme.com:github'), /Duplicate domain/)
	const origSsoUnit = process.env.SSO_DOMAINS
	process.env.SSO_DOMAINS = 'pinned.io:github'
	try {
		assert.equal(shouldClaimUnscoped('github', 'u@pinned.io', { verifiedEmail: false }), true)
		assert.equal(shouldClaimUnscoped('google', 'u@pinned.io', { verifiedEmail: true }), false)
		assert.equal(shouldClaimUnscoped('github', 'u@open.io', { verifiedEmail: false }), false)
		assert.equal(shouldClaimUnscoped('google', 'u@open.io', { verifiedEmail: true }), true)
	} finally {
		if (origSsoUnit === undefined) delete process.env.SSO_DOMAINS
		else process.env.SSO_DOMAINS = origSsoUnit
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
	const ghSetupCode = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSession.id, provider: 'github' })
	const connectPageRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/connect?code=${ghSetupCode}&services=repo,gist,notifications&write=repo,gist`)
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
		body: new URLSearchParams({ code: ghSetupCode }).toString(),
		redirect: 'manual'
	})
	assert.equal(missingEnvConsentRes.status, 500)
	assert.match(await missingEnvConsentRes.text(), /GITHUB_CLIENT_ID environment variable is missing/)
	process.env.GITHUB_CLIENT_ID = 'gh-test-client-id'
	process.env.GITHUB_CLIENT_SECRET = 'gh-test-client-secret'
	const ghValidSetupCode = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSession.id, provider: 'github' })
	const consentBody = new URLSearchParams({
		code: ghValidSetupCode,
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
		if (u.startsWith('https://api.github.com/applications/') || u === 'https://oauth2.googleapis.com/revoke') {
			revokedCalls.push({ url: u, method: init?.method, headers: init?.headers, body: init?.body, signal: init?.signal })
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
		assert.ok(revokedCalls[0].signal instanceof AbortSignal, 'GitHub revoke must set AbortSignal timeout')
		const gRevokeApp = db.tokens.create({
			userId: user.id,
			provider: 'google',
			type: 'oauth',
			credentials: { accessToken: 'ya29.to_revoke', refreshToken: '1//to_revoke' }
		})
		const disconnectGoogleRes = await executeTool('admin', {
			action: 'disconnect_app',
			appId: gRevokeApp.id,
			revoke: true
		}, adminSession.token)
		assert.equal(disconnectGoogleRes.isError, undefined)
		assert.equal(revokedCalls.length, 2)
		assert.equal(revokedCalls[1].url, 'https://oauth2.googleapis.com/revoke')
		assert.ok(revokedCalls[1].signal instanceof AbortSignal, 'Google revoke must set AbortSignal timeout')
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
	const gatedAdminUser = db.users.create()
	const gatedAdminSession = db.tokens.create({ userId: gatedAdminUser.id, provider: 'self', admin: 1 })
	const gatedLocalConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: gatedAdminSession.token, session_name: 'Blocked Local Token' }).toString(),
		redirect: 'manual'
	})
	assert.equal(gatedLocalConsent.status, 403, 'POST /oauth/authorize/consent rejects localToken when OAuth providers are configured')
	assert.match(await gatedLocalConsent.text(), /local token sign-in is disabled/)
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
	const legacyDupUserId = 'legacy-dup-user-1'
	const legacyDormantLogsId = 'legacy-dormant-logs-1'
	db.sqlite.exec('PRAGMA foreign_keys = OFF;')
	db.sqlite.exec(`
		PRAGMA user_version = 0;
		CREATE TEMP TABLE users_mig_tmp AS SELECT id, created, updated FROM users;
		DROP TABLE users;
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			name TEXT,
			picture TEXT,
			created TEXT NOT NULL,
			updated TEXT NOT NULL
		);
		CREATE INDEX idx_users_email ON users(email);
		INSERT INTO users (id, email, name, picture, created, updated)
			SELECT id, id || '@placeholder.local', 'Placeholder', NULL, created, updated FROM users_mig_tmp;
		DROP TABLE users_mig_tmp;
	`)
	db.sqlite.exec('PRAGMA foreign_keys = ON;')
	db.sqlite.prepare('INSERT INTO users (id, email, name, picture, created, updated) VALUES (?, ?, ?, ?, ?, ?)').run(
		legacyUserId,
		'legacy@gmail.com',
		'Legacy User',
		'https://example.com/avatar.png',
		now,
		now
	)
	const legacyAdminSession = db.tokens.create({
		userId: legacyUserId,
		provider: 'self',
		name: 'Legacy Real User Session',
		admin: 1
	})
	const legacyGoogleApp = db.tokens.create({
		userId: legacyUserId,
		provider: 'google',
		type: 'oauth',
		name: 'Google',
		credentials: { accessToken: 'ya29.legacy', refreshToken: '1//legacy', account: 'legacy@gmail.com' }
	})
	db.links.create({
		sessionId: legacyAdminSession.id,
		appId: legacyGoogleApp.id
	})
	db.sqlite.prepare('INSERT INTO users (id, email, name, picture, created, updated) VALUES (?, ?, ?, ?, ?, ?)').run(
		legacyDupUserId,
		'LEGACY@gmail.com',
		'Duplicate Case User',
		null,
		now,
		now
	)
	const dupSession = db.tokens.create({
		userId: legacyDupUserId,
		provider: 'self',
		name: 'Duplicate Case Session',
		admin: 0
	})
	db.sqlite.prepare('INSERT INTO users (id, email, name, picture, created, updated) VALUES (?, ?, ?, ?, ?, ?)').run(
		legacyDormantLogsId,
		'dormant-logs@gmail.com',
		'Dormant User With Logs',
		null,
		now,
		now
	)
	db.logs.create({
		userId: legacyDormantLogsId,
		provider: 'stripe',
		method: 'GET',
		url: 'https://api.stripe.com/v1/charges',
		allowed: true,
		status: 200,
		duration: 12
	})
	db.init()
	assert.equal(db.sqlite.prepare('PRAGMA user_version').get().user_version, 1)
	assert.equal(db.sqlite.prepare('PRAGMA foreign_key_check').all().length, 0, 'Zero foreign-key violations after users.email migration')
	const migratedEmailMaster = db.sqlite.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name = 'users' ORDER BY type, name").all()
	assert.deepEqual(migratedEmailMaster, freshMaster, 'Migrated users.email DB matches fresh pure-anchor DDL with no leftover columns or indexes')
	const migratedUser = db.users.get(legacyUserId)
	assert.ok(migratedUser)
	assert.deepEqual(Object.keys(migratedUser).sort(), ['created', 'id', 'updated'])
	assert.equal(db.tokens.getByToken(legacyAdminSession.token)?.userId, legacyUserId, 'Existing bearer sessions remain active after migration')
	assert.equal(db.links.listBySessionId(legacyAdminSession.id).length, 1, 'Existing session-to-app links survive users table rebuild without CASCADE deletion')
	assert.equal(db.users.get(legacyDupUserId), null, 'Case-insensitive duplicate legacy user row is merged into survivor')
	assert.equal(db.tokens.get(dupSession.id).userId, legacyUserId, 'Duplicate legacy user session is re-parented to surviving user')
	assert.ok(db.users.get(legacyDormantLogsId), 'Zero-session legacy user with historical logs is preserved as real user')
	assert.equal(db.logins.getAccountByUserId(legacyDormantLogsId), 'dormant-logs@gmail.com')
	assert.equal(db.logs.listByUserId(legacyDormantLogsId).length, 1, 'Historical logs for zero-session legacy user are preserved')
	assert.equal(db.logins.getAccountByUserId(legacyUserId), 'legacy@gmail.com')
	const backfilledLogins = db.logins.listByUserId(legacyUserId)
	assert.equal(backfilledLogins.length, 1)
	assert.equal(backfilledLogins[0].provider, 'google')
	assert.equal(backfilledLogins[0].account, 'legacy@gmail.com')
	assert.equal(backfilledLogins[0].userId, legacyUserId)
	const resolvedLegacy = db.logins.resolveUser('google', 'LEGACY@gmail.com')
	assert.equal(resolvedLegacy.id, legacyUserId)
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
		const dan = db.logins.resolveUser('google', 'dan@acme.com', { allowUnscoped: true })
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

test('hasPathTraversal backslash handling and getBaseUrl host/port edge cases', () => {
	assert.equal(hasPathTraversal('https://www.googleapis.com/drive/v3\\..\\..\\oauth2/v2/userinfo'), true)
	assert.equal(hasPathTraversal('/v2/tenant-a\\..\\tenant-b'), true)
	assert.equal(hasPathTraversal('..\\secret'), true)
	assert.equal(hasPathTraversal('v1\\..'), true)
	assert.equal(isGoogleAllowedUrl('https://www.googleapis.com/drive/v3\\..\\..\\oauth2/v2/userinfo').allowed, false)
	const scopedProv = createProvider({ id: 'scoped_backslash', baseUrl: 'https://api.custom.dev/v2/tenant-a' })
	assert.equal(scopedProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a\\..\\tenant-b').allowed, false)
	assert.equal(evaluatePolicy([{ action: 'allow' }], {
		url: 'https://www.googleapis.com/drive/v3\\..\\..\\oauth2/v2/userinfo'
	}).allowed, false)
	assert.equal(getBaseUrl({ headers: { host: 'localhost.evil.com' } }), 'https://localhost.evil.com')
	assert.equal(getBaseUrl({ headers: { host: '127.0.0.1.evil.com' } }), 'https://127.0.0.1.evil.com')
	assert.equal(getBaseUrl({ headers: { 'x-forwarded-host': 'jump.acme.com:443', 'x-forwarded-proto': 'https' } }), 'https://jump.acme.com')
	assert.equal(getBaseUrl({ headers: { host: 'jump.acme.com:80', 'x-forwarded-proto': 'http' } }), 'http://jump.acme.com')
	assert.equal(getBaseUrl({ headers: { host: 'jump.acme.com:80', 'x-forwarded-proto': 'https' } }), 'https://jump.acme.com:80')
	assert.equal(getBaseUrl({ headers: { host: 'jump.acme.com:' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { host: 'a.com:0' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { host: 'localhost:80' } }), 'http://localhost')
	assert.equal(getBaseUrl({ headers: { host: '[::1]:8080' } }), 'http://[::1]:8080')
	assert.equal(getBaseUrl({ headers: { host: 'jump.acme.com?foo=bar' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { host: 'jump.acme.com#frag' } }), 'http://localhost:8080')
	assert.equal(getBaseUrl({ headers: { host: '@jump.acme.com' } }), 'http://localhost:8080')
	assert.equal(typeof db.users.userAccountSql, 'function')
})

test('updateCredentials nullable fields and upfront OAuth CLIENT_SECRET validation without burning setup codes', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'pass1-oauth-env@example.com')
	const adminSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
	const oauthApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Nullable Test App',
		credentials: { accessToken: 'ya29.init', refreshToken: '1//init' },
		expiresAt: Date.now() + 3600000,
		scopes: 'scope.a scope.b'
	})
	const untouchedUpdate = db.tokens.updateCredentials(oauthApp.id, {
		credentials: { accessToken: 'ya29.step1', refreshToken: '1//init' }
	})
	assert.ok(untouchedUpdate.expiresAt > Date.now(), 'Omitted expiresAt remains untouched')
	assert.equal(untouchedUpdate.scopes, 'scope.a scope.b', 'Omitted scopes remains untouched')
	assert.equal(untouchedUpdate.name, 'Nullable Test App', 'Omitted name remains untouched')
	const clearedUpdate = db.tokens.updateCredentials(oauthApp.id, {
		credentials: { accessToken: 'ya29.step2', refreshToken: '1//init' },
		expiresAt: null,
		scopes: null
	})
	assert.equal(clearedUpdate.expiresAt, null, 'Explicit expiresAt: null clears stale expiration')
	assert.equal(clearedUpdate.scopes, null, 'Explicit scopes: null clears stale scopes')
	assert.equal(clearedUpdate.name, 'Nullable Test App')
	const prevGhId = process.env.GITHUB_CLIENT_ID
	const prevGhSecret = process.env.GITHUB_CLIENT_SECRET
	try {
		process.env.GITHUB_CLIENT_ID = 'gh-only-id'
		delete process.env.GITHUB_CLIENT_SECRET
		assert.equal(listAuthProviders().some(p => p.id === 'github'), false, 'Provider without CLIENT_SECRET must not be advertised')
		assert.throws(() => requireAuthProvider('github'), /Invalid or unsupported OAuth provider: github/)
		const missingSecretConnectRes = await executeTool('admin', {
			action: 'connect_app',
			provider: 'github'
		}, adminSession.token)
		assert.equal(missingSecretConnectRes.isError, true, 'connect_app must fail loud when CLIENT_SECRET is missing')
		assert.match(missingSecretConnectRes.content[0].text, /Invalid or unsupported OAuth provider: github/)
		const ghSetupWithoutSecret = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSession.id, provider: 'github' })
		const stateCountBefore = db.sqlite.prepare("SELECT COUNT(*) AS count FROM tokens WHERE type = 'oauth_state'").get().count
		const missingSecretConnectPageRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/connect?code=${ghSetupWithoutSecret}`)
		assert.equal(missingSecretConnectPageRes.status, 500, 'GET /providers/:provider/connect must fail loud upfront when CLIENT_SECRET is missing')
		assert.match(await missingSecretConnectPageRes.text(), /GITHUB_CLIENT_SECRET environment variable is missing/)
		const missingSecretConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: ghSetupWithoutSecret }).toString(),
			redirect: 'manual'
		})
		assert.equal(missingSecretConsentRes.status, 500, 'POST /providers/:provider/consent must fail loud upfront when CLIENT_SECRET is missing')
		assert.match(await missingSecretConsentRes.text(), /GITHUB_CLIENT_SECRET environment variable is missing/)
		assert.ok(db.tokens.getState(ghSetupWithoutSecret), 'Upfront CLIENT_SECRET failure must not consume single-use setupCode')
		assert.equal(db.sqlite.prepare("SELECT COUNT(*) AS count FROM tokens WHERE type = 'oauth_state'").get().count, stateCountBefore, 'Upfront CLIENT_SECRET failure must not leak orphaned oauth_state rows')
		const linkSetupWithoutSecret = db.tokens.createState({ mode: 'setup_link', sessionId: adminSession.id, provider: 'github' })
		const missingSecretAuthConsentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: linkSetupWithoutSecret, provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(missingSecretAuthConsentRes.status, 400, 'POST /oauth/authorize/consent must reject unconfigured provider with 400')
		assert.ok(db.tokens.getState(linkSetupWithoutSecret), 'Failed requireAuthProvider on /oauth/authorize/consent must not burn setupCode')
		process.env.GITHUB_CLIENT_SECRET = 'gh-secret'
		assert.equal(listAuthProviders().some(p => p.id === 'github'), true)
		const recoveredConsentRes = await fetch(`http://127.0.0.1:${addr.port}/providers/github/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: ghSetupWithoutSecret }).toString(),
			redirect: 'manual'
		})
		assert.equal(recoveredConsentRes.status, 302, 'Unconsumed setupCode remains valid once env is restored')
		const recoveredAuthConsentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: linkSetupWithoutSecret, provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(recoveredAuthConsentRes.status, 302, 'Unconsumed setup_link code remains valid once env is restored')
		assert.equal(db.tokens.getState(linkSetupWithoutSecret), null, 'setup_link code is consumed once consent succeeds')
	} finally {
		if (prevGhId === undefined) delete process.env.GITHUB_CLIENT_ID
		else process.env.GITHUB_CLIENT_ID = prevGhId
		if (prevGhSecret === undefined) delete process.env.GITHUB_CLIENT_SECRET
		else process.env.GITHUB_CLIENT_SECRET = prevGhSecret
	}
	const boundCodeOmitted = db.tokens.createAuthCode({
		userId: user.id,
		clientId: 'client_bound_strict',
		clientRedirectUri: 'http://localhost:8080/cb'
	})
	const omittedClientRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			grant_type: 'authorization_code',
			code: boundCodeOmitted,
			redirect_uri: 'http://localhost:8080/cb'
		})
	})
	assert.equal(omittedClientRes.status, 400, 'Bound auth code must reject omitted client_id on /oauth/token')
	const omittedClientData = await omittedClientRes.json()
	assert.equal(omittedClientData.error, 'invalid_grant')
	assert.equal(omittedClientData.error_description, 'client_id mismatch')
})

test('reserved REST subpaths and MCP JSON-RPC malformed/prototype request hardening', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'pass1-rpc-rest@example.com')
	const adminSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
	for (const reservedSubpath of ['/api/health/extra', '/api/whoami/extra', '/api/WHOAMI/extra', '/api/links/123', '/api/shares/123', '/api/logs/123']) {
		const subRes = await fetch(`http://127.0.0.1:${addr.port}${reservedSubpath}`, {
			headers: { authorization: `Bearer ${adminSession.token}` }
		})
		assert.equal(subRes.status, 404, `${reservedSubpath} must return 404 instead of treating route segment as upstream provider`)
		const subData = await subRes.json()
		assert.equal(subData.error, 'not found')
	}
	assert.equal(db.logs.listByUserId(user.id, { provider: 'whoami' }).length, 0, 'Reserved /api/* subpaths must not log fake provider proxy entries')
	for (const nonObjectBody of ['null', '123', '"hello"', '[]', '{"jsonrpc":"2.0","id":42}']) {
		const mcpBadRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				authorization: `Bearer ${adminSession.token}`
			},
			body: nonObjectBody
		})
		assert.equal(mcpBadRes.status, 200, `Non-object/invalid JSON-RPC body ${nonObjectBody} must not return 202`)
		const mcpBadData = await mcpBadRes.json()
		assert.equal(mcpBadData.jsonrpc, '2.0')
		assert.equal(mcpBadData.error?.code, -32600)
	}
	const protoMethodRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${adminSession.token}`
		},
		body: JSON.stringify({ jsonrpc: '2.0', id: 43, method: 'toString', params: {} })
	})
	assert.equal(protoMethodRes.status, 200)
	assert.equal((await protoMethodRes.json()).error?.code, -32601, 'Object.prototype keys must not resolve as RPC methods')
	const invalidMethodRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${adminSession.token}`
		},
		body: JSON.stringify({ jsonrpc: '2.0', id: 42, method: 123 })
	})
	assert.equal(invalidMethodRes.status, 200)
	const invalidMethodData = await invalidMethodRes.json()
	assert.equal(invalidMethodData.id, 42, 'Invalid non-string method must preserve JSON-RPC id')
	assert.equal(invalidMethodData.error?.code, -32600)
	const zeroIdInvalidMethodRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${adminSession.token}`
		},
		body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: '' })
	})
	assert.equal(zeroIdInvalidMethodRes.status, 200)
	const zeroIdInvalidMethodData = await zeroIdInvalidMethodRes.json()
	assert.equal(zeroIdInvalidMethodData.id, 0, 'Empty method must preserve falsy JSON-RPC id: 0')
	assert.equal(zeroIdInvalidMethodData.error?.code, -32600)
})

test('strict requireBoolean parsing across admin, allOthers, revoke, and allowed filters', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'pass1-booleans@example.com')
	const adminSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
	const targetSess = db.tokens.create({ userId: user.id, provider: 'self', name: 'Bool Target', admin: 1 })
	const demoteStringFalse = await fetch(`http://127.0.0.1:${addr.port}/api/sessions/${targetSess.id}`, {
		method: 'PATCH',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ admin: 'false' })
	})
	assert.equal(demoteStringFalse.status, 200)
	assert.equal((await demoteStringFalse.json()).session.admin, false, 'admin: "false" must demote rather than escalate via Boolean("false")')
	assert.equal(db.tokens.get(targetSess.id).admin, false)
	await fetch(`http://127.0.0.1:${addr.port}/api/sessions/${targetSess.id}`, {
		method: 'PATCH',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ admin: 'true' })
	})
	assert.equal(db.tokens.get(targetSess.id).admin, true)
	const demoteZeroStr = await fetch(`http://127.0.0.1:${addr.port}/api/sessions/${targetSess.id}`, {
		method: 'PATCH',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ admin: '0' })
	})
	assert.equal(demoteZeroStr.status, 200)
	assert.equal((await demoteZeroStr.json()).session.admin, false, 'admin: "0" must evaluate to false')
	const invalidAdminUpdate = await fetch(`http://127.0.0.1:${addr.port}/api/sessions/${targetSess.id}`, {
		method: 'PATCH',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ admin: 'not-a-bool' })
	})
	assert.equal(invalidAdminUpdate.status, 400)
	const createStrFalseRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions`, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ name: 'NonAdmin From String', admin: 'false' })
	})
	assert.equal(createStrFalseRes.status, 201)
	assert.equal((await createStrFalseRes.json()).session.admin, false)
	const revUser = db.logins.resolveUser('google', 'revoke-bool-test@example.com')
	const revAdmin = db.tokens.create({ userId: revUser.id, provider: 'self', admin: 1 })
	const revSibling1 = db.tokens.create({ userId: revUser.id, provider: 'self', name: 'Sibling 1' })
	const revSibling2 = db.tokens.create({ userId: revUser.id, provider: 'self', name: 'Sibling 2' })
	const mcpRevokeFalseRes = await executeTool('admin', {
		action: 'revoke_session',
		allOthers: 'false'
	}, revSibling1.token)
	assert.equal(mcpRevokeFalseRes.isError, undefined)
	const mcpRevokeFalseData = JSON.parse(mcpRevokeFalseRes.content[0].text)
	assert.equal(mcpRevokeFalseData.isCurrent, true, 'allOthers: "false" must revoke current session only, not siblings')
	assert.equal(db.tokens.get(revSibling1.id), null)
	assert.ok(db.tokens.get(revSibling2.id), 'Sibling 2 must remain intact when allOthers is "false"')
	const invalidAllOthersRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions?allOthers=invalid`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${revAdmin.token}` }
	})
	assert.equal(invalidAllOthersRes.status, 400)
	const numericAllOthersRes = await fetch(`http://127.0.0.1:${addr.port}/api/sessions?allOthers=1`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${revAdmin.token}` }
	})
	assert.equal(numericAllOthersRes.status, 200)
	const numericAllOthersData = await numericAllOthersRes.json()
	assert.equal(numericAllOthersData.revoked, true)
	assert.equal(numericAllOthersData.count, 1)
	assert.equal(db.tokens.get(revSibling2.id), null, 'DELETE /api/sessions?allOthers=1 must revoke all other sessions')
	const tempApp = db.tokens.create({
		userId: revUser.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Revoke Bool Stripe',
		credentials: { apiKey: 'sk_rev_bool', baseUrl: 'https://api.stripe.com' }
	})
	const invalidRevokeAppRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps/${tempApp.id}?revoke=invalid`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${revAdmin.token}` }
	})
	assert.equal(invalidRevokeAppRes.status, 400)
	assert.ok(db.tokens.get(tempApp.id), 'Invalid ?revoke=invalid must not delete app')
	const caseFalseRevokeAppRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps/${tempApp.id}?revoke=FALSE`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${revAdmin.token}` }
	})
	assert.equal(caseFalseRevokeAppRes.status, 200)
	assert.equal(db.tokens.get(tempApp.id), null)
	const invalidAllowedRestRes = await fetch(`http://127.0.0.1:${addr.port}/api/logs?allowed=invalid`, {
		headers: { authorization: `Bearer ${revAdmin.token}` }
	})
	assert.equal(invalidAllowedRestRes.status, 400)
	assert.match((await invalidAllowedRestRes.json()).error, /allowed must be a boolean/)
	const invalidAllowedMcpRes = await executeTool('admin', {
		action: 'list_logs',
		allowed: 'invalid'
	}, revAdmin.token)
	assert.equal(invalidAllowedMcpRes.isError, true)
	assert.match(invalidAllowedMcpRes.content[0].text, /allowed must be a boolean/)
	assert.throws(() => db.logs.listByUserId(revUser.id, { allowed: 'invalid' }), /allowed must be a boolean/)
	const logFilterUser = db.users.create()
	db.logs.create({ userId: logFilterUser.id, provider: 'stripe', method: 'GET', url: 'https://api.stripe.com/v1/ok', allowed: true, status: 200 })
	db.logs.create({ userId: logFilterUser.id, provider: 'stripe', method: 'DELETE', url: 'https://api.stripe.com/v1/no', allowed: false, error: 'Policy violation' })
	const allowedTrueLogs = db.logs.listByUserId(logFilterUser.id, { allowed: 'true' })
	assert.equal(allowedTrueLogs.length, 1)
	assert.equal(allowedTrueLogs[0].allowed, true)
	const allowedFalseLogs = db.logs.listByUserId(logFilterUser.id, { allowed: 'false' })
	assert.equal(allowedFalseLogs.length, 1)
	assert.equal(allowedFalseLogs[0].allowed, false)
})

test('connectApp and updateApp strict input validation parity and formatApp symmetry', async () => {
	const addr = server.address()
	const user = db.logins.resolveUser('google', 'pass1-app-validation@example.com')
	const adminSession = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
	const oauthApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Existing Google OAuth',
		credentials: { accessToken: 'ya29.init', refreshToken: '1//init' }
	})
	const stripeApp = db.tokens.create({
		userId: user.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Stripe Existing',
		credentials: { apiKey: 'sk_existing', baseUrl: 'https://api.stripe.com' }
	})
	const ghPatApp = db.tokens.create({
		userId: user.id,
		provider: 'github',
		type: 'api_key',
		name: 'GitHub PAT Existing',
		credentials: { apiKey: 'ghp_existing', baseUrl: 'https://api.github.com' }
	})
	const appCountBefore = db.tokens.listByUserId(user.id).filter(t => t.provider !== 'self').length
	const mismatchProvConnect = await executeTool('admin', {
		action: 'connect_app',
		appId: oauthApp.id,
		provider: 'github'
	}, adminSession.token)
	assert.equal(mismatchProvConnect.isError, true)
	assert.match(mismatchProvConnect.content[0].text, /belongs to provider "google", not "github"/)
	const apiKeyReauthAttempt = await executeTool('admin', {
		action: 'connect_app',
		appId: stripeApp.id
	}, adminSession.token)
	assert.equal(apiKeyReauthAttempt.isError, true)
	assert.match(apiKeyReauthAttempt.content[0].text, /use update_app/)
	const ghPatReauthAttempt = await executeTool('admin', {
		action: 'connect_app',
		appId: ghPatApp.id
	}, adminSession.token)
	assert.equal(ghPatReauthAttempt.isError, true)
	assert.match(ghPatReauthAttempt.content[0].text, /use update_app/)
	const oauthWithKeyAttempt = await executeTool('admin', {
		action: 'connect_app',
		appId: oauthApp.id,
		apiKey: 'should-fail'
	}, adminSession.token)
	assert.equal(oauthWithKeyAttempt.isError, true)
	assert.match(oauthWithKeyAttempt.content[0].text, /use update_app/)
	const missingKeyStripeAttempt = await executeTool('admin', {
		action: 'connect_app',
		provider: 'stripe',
		baseUrl: 'https://api.stripe.com'
	}, adminSession.token)
	assert.equal(missingKeyStripeAttempt.isError, true)
	assert.match(missingKeyStripeAttempt.content[0].text, /apiKey is required/)
	assert.equal(db.tokens.listByUserId(user.id).filter(t => t.provider !== 'self').length, appCountBefore, 'Rejected connect_app calls must not create orphan app rows')
	for (const badProvider of ['', '   ', 123, true, {}]) {
		const badProvRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${adminSession.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({ provider: badProvider })
		})
		assert.equal(badProvRes.status, 400, `connectApp must reject explicit non-string/blank provider ${JSON.stringify(badProvider)} with 400`)
		assert.match((await badProvRes.json()).error, /provider must be a non-empty string/)
	}
	const blankMetaRes = await executeTool('admin', {
		action: 'connect_app',
		provider: 'stripe',
		name: '   ',
		account: '   ',
		apiKey: 'sk_blank_meta',
		baseUrl: 'https://api.stripe.com'
	}, adminSession.token)
	assert.equal(blankMetaRes.isError, undefined)
	const blankMetaData = JSON.parse(blankMetaRes.content[0].text)
	assert.equal(blankMetaData.app.name, 'Stripe', 'Whitespace-only name falls back to providerDef.name')
	assert.equal(blankMetaData.app.account, null, 'Whitespace-only account is ignored instead of stored as empty string')
	assert.ok(blankMetaData.app.created, 'connect_app returns canonical formatApp shape including created/updated')
	assert.ok(blankMetaData.app.updated)
	assert.equal('account' in db.tokens.get(blankMetaData.app.id).credentials, false)
	const trimmedMetaRes = await executeTool('admin', {
		action: 'connect_app',
		provider: '  Stripe  ',
		name: '  Trimmed Stripe  ',
		account: '  acct_trimmed  ',
		apiKey: '  sk_trimmed  ',
		baseUrl: 'https://api.stripe.com'
	}, adminSession.token)
	assert.equal(trimmedMetaRes.isError, undefined)
	const trimmedMetaData = JSON.parse(trimmedMetaRes.content[0].text)
	assert.equal(trimmedMetaData.app.provider, 'stripe')
	assert.equal(trimmedMetaData.app.name, 'Trimmed Stripe')
	assert.equal(trimmedMetaData.app.account, 'acct_trimmed')
	for (const badAppId of ['', '   ', 123, null]) {
		const badAppIdRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${adminSession.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({ appId: badAppId })
		})
		assert.equal(badAppIdRes.status, 400, `connectApp must reject explicit invalid appId ${JSON.stringify(badAppId)} with 400`)
		assert.match((await badAppIdRes.json()).error, /appId must be a non-empty string/)
	}
	for (const badVal of [123, true, {}]) {
		const badNameRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${adminSession.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({ provider: 'stripe', name: badVal, apiKey: 'sk_bad_name', baseUrl: 'https://api.stripe.com' })
		})
		assert.equal(badNameRes.status, 400, `connectApp must reject non-string name ${JSON.stringify(badVal)} with 400`)
		assert.match((await badNameRes.json()).error, /name must be a string/)
		const badAccountRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${adminSession.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({ provider: 'stripe', account: badVal, apiKey: 'sk_bad_acct', baseUrl: 'https://api.stripe.com' })
		})
		assert.equal(badAccountRes.status, 400, `connectApp must reject non-string account ${JSON.stringify(badVal)} with 400`)
		assert.match((await badAccountRes.json()).error, /account must be a string/)
	}
	const selfProvRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
		method: 'POST',
		headers: {
			authorization: `Bearer ${adminSession.token}`,
			'content-type': 'application/json'
		},
		body: JSON.stringify({ provider: 'self', apiKey: 'sk_self', baseUrl: 'https://api.stripe.com' })
	})
	assert.equal(selfProvRes.status, 400)
	assert.match((await selfProvRes.json()).error, /provider cannot be "self"/)
	for (const badBase of ['', false, null]) {
		const ghBadBaseRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps`, {
			method: 'POST',
			headers: {
				authorization: `Bearer ${adminSession.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({ provider: 'github', apiKey: 'ghp_123', baseUrl: badBase })
		})
		assert.equal(ghBadBaseRes.status, 400, `connectApp must reject explicit falsy baseUrl ${JSON.stringify(badBase)} on preset provider`)
		assert.match((await ghBadBaseRes.json()).error, /Valid https:\/\/ baseUrl is required/)
	}
	const updApp = db.tokens.create({
		userId: user.id,
		provider: 'stripe',
		type: 'api_key',
		name: 'Update Parity Stripe',
		credentials: { apiKey: 'sk_keep_intact', baseUrl: 'https://api.stripe.com' }
	})
	for (const badKey of ['', '   ', null, 123]) {
		const badUpdateKeyRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps/${updApp.id}`, {
			method: 'PATCH',
			headers: {
				authorization: `Bearer ${adminSession.token}`,
				'content-type': 'application/json'
			},
			body: JSON.stringify({ apiKey: badKey })
		})
		assert.equal(badUpdateKeyRes.status, 400, `updateApp must reject invalid apiKey ${JSON.stringify(badKey)} with 400`)
		assert.match((await badUpdateKeyRes.json()).error, /apiKey must be a non-empty string/)
		assert.equal(db.tokens.get(updApp.id).credentials.apiKey, 'sk_keep_intact')
	}
	for (const badId of ['', '   ', null, 123]) {
		const badUpdIdRes = await executeTool('admin', {
			action: 'update_app',
			appId: badId,
			name: 'Should Fail'
		}, adminSession.token)
		assert.equal(badUpdIdRes.isError, true, `updateApp must reject invalid appId ${JSON.stringify(badId)} with 400`)
		assert.match(badUpdIdRes.content[0].text, /appId must be a non-empty string/)
	}
	const clearedNameUpdRes = await executeTool('admin', {
		action: 'update_app',
		appId: `  ${updApp.id}  `,
		name: '   ',
		account: '  acct_single_write  '
	}, adminSession.token)
	assert.equal(clearedNameUpdRes.isError, undefined)
	const clearedNameUpdData = JSON.parse(clearedNameUpdRes.content[0].text)
	assert.equal(clearedNameUpdData.app.name, null, 'Whitespace-only name clears name to null in single updateCredentials write')
	assert.equal(clearedNameUpdData.app.account, 'acct_single_write')
	assert.equal(db.tokens.get(updApp.id).name, null)
})

test('linear-time glob matching, strict form body validation, SSRF host checks, form Origin CSRF guard, DCR client_name, and REST response headers', async () => {
	const addr = server.address()
	const redosStart = performance.now()
	const resRedos = evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/soap', body: '*<a>*<a>*<a>*<a>*<a>*</b>*' },
		{ action: 'allow' }
	], {
		url: 'https://api.example.com/soap',
		method: 'POST',
		body: '<a>'.repeat(2000)
	})
	assert.equal(resRedos.allowed, true)
	assert.ok(performance.now() - redosStart < 25, 'Linear-time wildcard matcher completes in milliseconds without ReDoS')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { destination: null }, bodyType: 'form' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '--b=1\r\nContent-Disposition: form-data; name="destination"\r\n\r\nacct_evil\r\n--b=1--'
	}).allowed, false, 'Multipart payload with = and CRLF must not parse as form-urlencoded')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { destination: null }, bodyType: 'form' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '<?xml version="1.0"?><root><x>a=b</x></root>'
	}).allowed, false, 'XML payload containing whitespace must not parse as form-urlencoded')
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/flags', body: { dry_run: '', mode: 'fast' }, bodyType: 'form' }
	], {
		url: 'https://api.example.com/v1/flags',
		method: 'POST',
		body: 'dry_run&mode=fast'
	}).allowed, true, 'Valueless form-urlencoded flag (dry_run) parses cleanly')
	const prevEnv = process.env.NODE_ENV
	process.env.NODE_ENV = 'production'
	try {
		assert.equal(validateBaseUrl('https://localhost.'), null, 'Trailing dot localhost. must be blocked in production')
		assert.equal(validateBaseUrl('https://sub.localhost.'), null)
		assert.equal(validateBaseUrl('https://[fc0::1]'), null, 'Short IPv6 ULA [fc0::1] must be blocked')
		assert.equal(validateBaseUrl('https://[fd1::1]'), null, 'Short IPv6 ULA [fd1::1] must be blocked')
		assert.equal(validateBaseUrl('https://100.64.0.1'), null, 'CGNAT / Tailscale 100.64.0.0/10 must be blocked')
		assert.equal(validateBaseUrl('https://100.127.255.254'), null)
		assert.equal(validateBaseUrl('https://100.128.0.1'), 'https://100.128.0.1', 'Public 100.128.0.1 outside 100.64/10 remains allowed')
		assert.equal(validateBaseUrl('https://metadata.google.internal'), null)
	} finally {
		process.env.NODE_ENV = prevEnv
	}
	const headHealth = await fetch(`http://127.0.0.1:${addr.port}/api/health`, { method: 'HEAD' })
	assert.equal(headHealth.status, 200)
	const regRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/register`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			client_name: 'Claude Code',
			redirect_uris: ['http://127.0.0.1:9999/cb']
		})
	})
	assert.equal(regRes.status, 201)
	const { client_id: registeredClientId } = await regRes.json()
	assert.equal(deriveClientName(registeredClientId), 'Claude Code', 'Stateless DCR client_id preserves client_name')
	const authPage = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?client_id=${encodeURIComponent(registeredClientId)}&redirect_uri=${encodeURIComponent('http://127.0.0.1:9999/cb')}&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256`)
	assert.equal(authPage.status, 200)
	assert.match(await authPage.text(), /"clientName":"Claude Code"/)
	const crossOriginConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: {
			origin: 'https://evil.example.com',
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: 'provider=google'
	})
	assert.equal(crossOriginConsent.status, 403, 'Cross-origin form POST to /oauth/authorize/consent must be rejected')
	const sameOriginConsent = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: {
			origin: `http://127.0.0.1:${addr.port}`,
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: 'provider=google',
		redirect: 'manual'
	})
	assert.equal(sameOriginConsent.status, 302, 'Same-origin form POST to /oauth/authorize/consent succeeds')
	const logUser = db.users.create()
	const longLog = db.logs.create({
		userId: logUser.id,
		provider: 'stripe',
		method: 'GET',
		url: `https://api.stripe.com/${'x'.repeat(3000)}`,
		allowed: true,
		status: 500,
		error: 'e'.repeat(5000)
	})
	assert.equal(longLog.url.length, 2049)
	assert.equal(longLog.error.length, 2049)
	const http = await import('node:http')
	const headerUpstream = http.createServer((req, res) => {
		res.statusCode = 200
		res.setHeader('content-type', 'application/json')
		res.setHeader('etag', '"v1-abc"')
		res.setHeader('x-ratelimit-remaining', '49')
		res.setHeader('set-cookie', 'upstream_secret=1; HttpOnly')
		res.end(JSON.stringify({ ok: true }))
	})
	await new Promise(resolve => headerUpstream.listen(0, '127.0.0.1', resolve))
	try {
		const upPort = headerUpstream.address().port
		const u = db.logins.resolveUser('google', 'rest-headers@example.com')
		const s = db.tokens.create({ userId: u.id, provider: 'self', admin: 1 })
		const app = db.tokens.create({
			userId: u.id,
			provider: 'github',
			type: 'api_key',
			credentials: { apiKey: 'ghp_hdr', baseUrl: `http://127.0.0.1:${upPort}` }
		})
		db.links.create({ sessionId: s.id, appId: app.id })
		const restRes = await fetch(`http://127.0.0.1:${addr.port}/api/github/repos`, {
			headers: { authorization: `Bearer ${s.token}` }
		})
		assert.equal(restRes.status, 200)
		assert.equal(restRes.headers.get('etag'), '"v1-abc"')
		assert.equal(restRes.headers.get('x-ratelimit-remaining'), '49')
		assert.equal(restRes.headers.get('set-cookie'), null, 'Upstream Set-Cookie must not attach to jump origin')
	} finally {
		await new Promise(resolve => headerUpstream.close(resolve))
	}
})

test('validated upstream redirects, double-slash/encoded path normalization, and %2F intra-segment preservation', async () => {
	assert.equal(hasPathTraversal('/v1/public/%252e%252e/admin'), true, 'Double-encoded %252e traversal must be blocked')
	assert.equal(hasPathTraversal('/v1/public%5cadmin'), true, 'Encoded backslash %5c anywhere in path must be blocked')
	assert.equal(hasPathTraversal('/storage/v1/b/my-bucket/o/folder%2Ffile.pdf'), false, 'Legitimate intra-segment %2F must remain allowed')
	const denyAdminPolicy = [
		{ action: 'deny', path: '/v1/admin/**' },
		{ action: 'allow', path: '/v1/**' }
	]
	assert.equal(evaluatePolicy(denyAdminPolicy, {
		url: 'https://api.example.com/v1//admin/delete',
		method: 'DELETE'
	}).allowed, false, 'Repeated slashes /v1//admin/delete must not bypass /v1/admin/** deny rule')
	assert.equal(evaluatePolicy(denyAdminPolicy, {
		url: 'https://api.example.com///v1///admin',
		method: 'GET'
	}).allowed, false)
	assert.equal(evaluatePolicy([
		{ action: 'allow', path: '/storage/v1/b/my-bucket/o/*' }
	], {
		url: 'https://storage.googleapis.com/storage/v1/b/my-bucket/o/folder%2Ffile.pdf',
		method: 'GET'
	}).allowed, true, 'Single-segment * matches GCS object key with %2F without splitting into two segments')
	const http = await import('node:http')
	const cdnReceived = []
	const cdnServer = http.createServer((req, res) => {
		cdnReceived.push({ method: req.method, url: req.url, headers: req.headers })
		res.statusCode = 200
		res.setHeader('content-type', 'application/octet-stream')
		res.end(Buffer.from('archive-bytes'))
	})
	await new Promise(resolve => cdnServer.listen(0, '127.0.0.1', resolve))
	const cdnPort = cdnServer.address().port
	const apiServer = http.createServer((req, res) => {
		if (req.url === '/repos/acme/app/tarball') {
			res.statusCode = 302
			res.setHeader('location', `http://127.0.0.1:${cdnPort}/download/tarball.tar.gz?sig=signed123`)
			res.end()
			return
		}
		if (req.url === '/ssrf-metadata') {
			res.statusCode = 302
			res.setHeader('location', 'http://169.254.169.254/latest/meta-data/')
			res.end()
			return
		}
		if (req.url === '/ssrf-private') {
			res.statusCode = 302
			res.setHeader('location', 'https://10.0.0.1/internal')
			res.end()
			return
		}
		if (req.url === '/post-303') {
			res.statusCode = 303
			res.setHeader('location', `http://127.0.0.1:${cdnPort}/after-post`)
			res.end()
			return
		}
		if (req.url === '/public/bounce-to-admin') {
			res.statusCode = 302
			res.setHeader('location', '/admin/secrets')
			res.end()
			return
		}
		if (req.url === '/admin/secrets') {
			res.statusCode = 200
			res.setHeader('content-type', 'application/json')
			res.end(JSON.stringify({ leaked: 'top-secret', auth: req.headers.authorization || null }))
			return
		}
		if (req.url.startsWith('/qauth/start')) {
			res.statusCode = 302
			res.setHeader('location', '/qauth/dest?page=2')
			res.end()
			return
		}
		if (req.url.startsWith('/qauth/dest')) {
			res.statusCode = 200
			res.setHeader('content-type', 'application/json')
			res.end(JSON.stringify({ url: req.url }))
			return
		}
		if (req.url.startsWith('/qauth/cdn')) {
			res.statusCode = 302
			res.setHeader('location', `http://127.0.0.1:${cdnPort}/cdn-file?ApiKey=should_not_be_reattached`)
			res.end()
			return
		}
		if (req.url.startsWith('/loop')) {
			res.statusCode = 302
			res.setHeader('location', '/loop')
			res.end()
			return
		}
		res.statusCode = 404
		res.end()
	})
	await new Promise(resolve => apiServer.listen(0, '127.0.0.1', resolve))
	const apiPort = apiServer.address().port
	try {
		const addr = server.address()
		const u = db.logins.resolveUser('google', 'redirects@example.com')
		const s = db.tokens.create({ userId: u.id, provider: 'self', admin: 1 })
		const app = db.tokens.create({
			userId: u.id,
			provider: 'github',
			type: 'api_key',
			credentials: { apiKey: 'ghp_secret_token', baseUrl: `http://127.0.0.1:${apiPort}` }
		})
		db.links.create({
			sessionId: s.id,
			appId: app.id,
			policy: [
				{ action: 'deny', path: '/admin/**' },
				{ action: 'allow', path: '/**' }
			]
		})
		const okRedirect = await executeTool('github_api', {
			url: '/repos/acme/app/tarball'
		}, s.token)
		assert.equal(okRedirect.isError, undefined)
		const okData = JSON.parse(okRedirect.content[0].text)
		assert.equal(Buffer.from(okData.data, 'base64').toString('utf8'), 'archive-bytes')
		assert.equal(cdnReceived.length, 1)
		assert.equal(cdnReceived[0].headers.authorization, undefined, 'Cross-origin redirect must strip upstream Authorization header')
		const restRawRedirect = await fetch(`http://127.0.0.1:${addr.port}/api/github/repos/acme/app/tarball`, {
			headers: { authorization: `Bearer ${s.token}` },
			redirect: 'manual'
		})
		assert.equal(restRawRedirect.status, 302, 'REST /api/:provider/* returns 302 Location directly without following')
		assert.equal(restRawRedirect.headers.get('location'), `http://127.0.0.1:${cdnPort}/download/tarball.tar.gz?sig=signed123`)
		const sameOriginBypass = await executeTool('github_api', {
			url: '/public/bounce-to-admin'
		}, s.token)
		assert.equal(sameOriginBypass.isError, true, 'Same-origin redirect to policy-denied path must be blocked')
		assert.match(sameOriginBypass.content[0].text, /Policy violation/)
		const qApp = db.tokens.create({
			userId: u.id,
			provider: 'namecheap',
			type: 'api_key',
			credentials: { apiKey: '?ApiKey=nc_top_secret', baseUrl: `http://127.0.0.1:${apiPort}` }
		})
		db.links.create({ sessionId: s.id, appId: qApp.id, policy: [{ action: 'allow', path: '/qauth/**' }] })
		const qSameOrigin = await executeTool('namecheap_api', { url: '/qauth/start' }, s.token)
		assert.equal(qSameOrigin.isError, undefined, 'Same-origin redirect preserves query-param credentials')
		assert.equal(JSON.parse(qSameOrigin.content[0].text).url, '/qauth/dest?page=2&ApiKey=nc_top_secret')
		cdnReceived.length = 0
		const qCrossOrigin = await executeTool('namecheap_api', { url: '/qauth/cdn' }, s.token)
		assert.equal(qCrossOrigin.isError, undefined)
		assert.equal(cdnReceived[0].url.includes('nc_top_secret'), false, 'Cross-origin redirect never attaches query-param credentials')
		cdnReceived.length = 0
		const post303 = await executeTool('github_api', {
			url: '/post-303',
			method: 'POST',
			body: { hello: 'world' }
		}, s.token)
		assert.equal(post303.isError, undefined)
		assert.equal(cdnReceived[0].method, 'GET', '303 redirect downgrades POST to GET')
		assert.equal(cdnReceived[0].headers['content-type'], undefined, 'Downgraded GET redirect strips Content-Type')
		const metadataRedirect = await executeTool('github_api', {
			url: '/ssrf-metadata'
		}, s.token)
		assert.equal(metadataRedirect.isError, true)
		assert.match(metadataRedirect.content[0].text, /Blocked unsafe upstream redirect target/)
		const privateRedirect = await executeTool('github_api', {
			url: '/ssrf-private'
		}, s.token)
		assert.equal(privateRedirect.isError, true)
		assert.match(privateRedirect.content[0].text, /Blocked unsafe upstream redirect target/)
		const loopRedirect = await executeTool('github_api', {
			url: '/loop'
		}, s.token)
		assert.equal(loopRedirect.isError, true)
		assert.match(loopRedirect.content[0].text, /Too many upstream redirects/)
	} finally {
		await new Promise(resolve => apiServer.close(resolve))
		await new Promise(resolve => cdnServer.close(resolve))
	}
})

test('upstream SSRF filter blocks IANA special-purpose IP literals and private/special DNS answers before fetch', async () => {
	for (const blockedUrl of [
		'https://[64:ff9b::a9fe:a9fe]',
		'https://[64:ff9b:1::1]',
		'https://[2002:a9fe:a9fe::]',
		'https://[::a9fe:a9fe]',
		'https://[::ffff:127.0.0.1]',
		'https://[::ffff:1.1.1.1]',
		'https://[100::1]',
		'https://[2001::1]',
		'https://[2001:2::1]',
		'https://[2001:db8::1]',
		'https://[3fff::1]',
		'https://[ff02::1]',
		'https://192.0.0.1',
		'https://192.0.2.1',
		'https://192.88.99.1',
		'https://198.18.0.1',
		'https://198.51.100.1',
		'https://203.0.113.1',
		'https://224.0.0.1',
		'https://240.0.0.1',
		'https://255.255.255.255'
	]) {
		assert.equal(validateBaseUrl(blockedUrl), null, `Special-purpose IP literal must be rejected: ${blockedUrl}`)
	}
	for (const allowedUrl of [
		'https://1.1.1.1',
		'https://100.128.0.1',
		'https://[2606:4700:4700::1111]',
		'https://[2001:4860:4860::8888]'
	]) {
		assert.equal(validateBaseUrl(allowedUrl), allowedUrl, `Global unicast IP literal must be allowed: ${allowedUrl}`)
	}
	const addr = server.address()
	const u = db.logins.resolveUser('google', 'dns-ssrf@example.com')
	const s = db.tokens.create({ userId: u.id, provider: 'self', admin: 1 })
	const dnsFixtures = {
		'loopback-v4.example.test': [{ address: '127.0.0.1', family: 4 }],
		'loopback-v6.example.test': [{ address: '::1', family: 6 }],
		'rfc1918.example.test': [{ address: '10.0.0.5', family: 4 }],
		'rfc6598.example.test': [{ address: '100.64.1.20', family: 4 }],
		'nat64.example.test': [{ address: '64:ff9b::a9fe:a9fe', family: 6 }],
		'ula.example.test': [{ address: 'fd00:ec2::254', family: 6 }],
		'mixed.example.test': [{ address: '93.184.216.34', family: 4 }, { address: '192.168.1.10', family: 4 }],
		'public.example.test': [{ address: '93.184.216.34', family: 4 }]
	}
	const origLookup = dns.promises.lookup
	const origFetch = globalThis.fetch
	const upstreamFetches = []
	dns.promises.lookup = async (host, opts) => {
		if (Object.hasOwn(dnsFixtures, host)) return dnsFixtures[host]
		return origLookup(host, opts)
	}
	globalThis.fetch = async (input, init) => {
		const urlStr = typeof input === 'string' ? input : input.url
		const parsed = new URL(urlStr)
		if (parsed.hostname.endsWith('.example.test')) {
			upstreamFetches.push(urlStr)
			if (parsed.hostname === 'public.example.test' && parsed.pathname === '/bounce-to-cgnat') {
				return new Response(null, {
					status: 302,
					headers: { location: 'https://rfc6598.example.test/internal' }
				})
			}
			return new Response(JSON.stringify({ ok: true }), {
				status: 200,
				headers: { 'content-type': 'application/json' }
			})
		}
		return origFetch(input, init)
	}
	try {
		for (const [idx, host] of [
			'loopback-v4.example.test',
			'loopback-v6.example.test',
			'rfc1918.example.test',
			'rfc6598.example.test',
			'nat64.example.test',
			'ula.example.test',
			'mixed.example.test'
		].entries()) {
			const provider = `ssrf_${idx}`
			const app = db.tokens.create({
				userId: u.id,
				provider,
				type: 'api_key',
				credentials: { apiKey: 'sk_test', baseUrl: `https://${host}` }
			})
			db.links.create({ sessionId: s.id, appId: app.id })
			const mcpRes = await executeTool(`${provider}_api`, { url: '/v1/data' }, s.token)
			assert.equal(mcpRes.isError, true, `MCP request to ${host} must fail`)
			assert.match(mcpRes.content[0].text, /Blocked unsafe upstream host/)
			const restRes = await origFetch(`http://127.0.0.1:${addr.port}/api/${provider}/v1/data`, {
				headers: { authorization: `Bearer ${s.token}` }
			})
			assert.equal(restRes.status, 403, `REST request to ${host} must fail with 403`)
		}
		assert.deepEqual(upstreamFetches, [], 'fetch() must never be called when DNS resolves to a non-public IP')
		const pubApp = db.tokens.create({
			userId: u.id,
			provider: 'ssrf_pub',
			type: 'api_key',
			credentials: { apiKey: 'sk_pub', baseUrl: 'https://public.example.test' }
		})
		db.links.create({ sessionId: s.id, appId: pubApp.id })
		const okPub = await executeTool('ssrf_pub_api', { url: '/v1/ok' }, s.token)
		assert.equal(okPub.isError, undefined, 'Public DNS answer succeeds normally')
		assert.deepEqual(upstreamFetches, ['https://public.example.test/v1/ok'])
		upstreamFetches.length = 0
		const redirectToPrivate = await executeTool('ssrf_pub_api', { url: '/bounce-to-cgnat' }, s.token)
		assert.equal(redirectToPrivate.isError, true, 'Redirect hop resolving to RFC 6598 IP must be blocked')
		assert.match(redirectToPrivate.content[0].text, /Blocked unsafe upstream host/)
		assert.deepEqual(upstreamFetches, ['https://public.example.test/bounce-to-cgnat'], 'fetch() must not follow redirect hop once DNS resolves to private IP')
	} finally {
		dns.promises.lookup = origLookup
		globalThis.fetch = origFetch
	}
})

test('OAUTH_TIMEOUT_MS governs upstream OAuth token, userinfo, refresh, and revoke timeouts', async () => {
	const origFetch = globalThis.fetch
	const origTimeout = process.env.OAUTH_TIMEOUT_MS
	process.env.OAUTH_TIMEOUT_MS = '25'
	globalThis.fetch = (input, init) => new Promise((resolve, reject) => {
		init?.signal?.addEventListener('abort', () => reject(init.signal.reason), { once: true })
	})
	try {
		await assert.rejects(() => google.exchangeCode('slow-code', 'http://localhost/cb'), /aborted|timeout/i)
		const owner = db.logins.resolveUser('google', 'oauth-timeout@example.com')
		const staleApp = db.tokens.create({
			userId: owner.id,
			provider: 'google',
			type: 'oauth',
			credentials: { accessToken: 'ya29.old', refreshToken: '1//slow-refresh' },
			expiresAt: Date.now() - 1000
		})
		await assert.rejects(() => google.getFreshToken(staleApp), /aborted|timeout/i)
		const start = Date.now()
		await google.revokeToken(staleApp)
		assert.ok(Date.now() - start < 1000, 'revokeToken aborts promptly at OAUTH_TIMEOUT_MS')
	} finally {
		globalThis.fetch = origFetch
		if (origTimeout === undefined) delete process.env.OAUTH_TIMEOUT_MS
		else process.env.OAUTH_TIMEOUT_MS = origTimeout
	}
})

test('graceful SIGTERM shutdown finishes in-flight requests despite duplicate signals', async () => {
	const http = await import('node:http')
	const net = await import('node:net')
	const { spawn } = await import('node:child_process')
	const probe = http.createServer()
	await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve))
	const freePort = probe.address().port
	await new Promise(resolve => probe.close(resolve))
	const subDbPath = path.join(dirname, `shutdown-${process.pid}.db`)
	const child = spawn(process.execPath, [path.join(dirname, '..', 'index.js')], {
		cwd: dirname,
		env: {
			...process.env,
			NODE_ENV: 'production',
			HOST: '127.0.0.1',
			PORT: String(freePort),
			DB_PATH: subDbPath
		},
		stdio: ['ignore', 'pipe', 'pipe']
	})
	const agent = new http.Agent({ keepAlive: true })
	let inflight = null
	try {
		await new Promise((resolve, reject) => {
			let out = ''
			child.stdout.on('data', chunk => {
				out += chunk.toString('utf8')
				if (out.includes('jump listening on')) resolve()
			})
			child.once('exit', code => reject(new Error(`Child exited early with code ${code}`)))
		})
		await new Promise((resolve, reject) => {
			const req = http.get(`http://127.0.0.1:${freePort}/api/health`, { agent }, res => {
				res.resume()
				res.on('end', resolve)
			})
			req.on('error', reject)
		})
		const body = JSON.stringify({ redirect_uris: ['http://127.0.0.1:9999/cb'] })
		inflight = net.connect(freePort, '127.0.0.1')
		inflight.on('error', () => {})
		await new Promise(resolve => inflight.once('connect', resolve))
		let rawReply = ''
		inflight.on('data', chunk => { rawReply += chunk.toString('utf8') })
		inflight.write(`POST /oauth/register HTTP/1.1\r\nHost: 127.0.0.1:${freePort}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n`)
		await new Promise(resolve => setTimeout(resolve, 20))
		const exitPromise = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })))
		child.kill('SIGTERM')
		await new Promise(resolve => setTimeout(resolve, 15))
		child.kill('SIGTERM')
		await new Promise(resolve => setTimeout(resolve, 25))
		if (!inflight.destroyed) inflight.write(body)
		await new Promise(resolve => inflight.destroyed ? resolve() : inflight.once('close', resolve))
		assert.match(rawReply, /^HTTP\/1\.1 201 /, 'In-flight request must complete cleanly instead of being killed by duplicate SIGTERM')
		const exitResult = await Promise.race([
			exitPromise,
			new Promise(resolve => setTimeout(() => resolve({ timedOut: true }), 1500).unref())
		])
		assert.equal(exitResult.timedOut, undefined)
		assert.equal(exitResult.code, 0)
		assert.equal(exitResult.signal, null)
	} finally {
		agent.destroy()
		inflight?.destroy()
		if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
		fs.rmSync(subDbPath, { force: true })
		fs.rmSync(`${subDbPath}-wal`, { force: true })
		fs.rmSync(`${subDbPath}-shm`, { force: true })
	}
})

test('link_login merge: true atomically merges two accounts, preserves older user and both sessions, cleans shares, and enforces SSO_DOMAINS', async () => {
	const addr = server.address()
	const origFetch = globalThis.fetch
	const origSso = process.env.SSO_DOMAINS
	let googleMockEmail = 'primary-owner@example.com'
	let ghMockLogin = 'sso-bridge-gh'
	globalThis.fetch = async (input, init) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			return new Response(JSON.stringify({ access_token: 'ya29.merge', token_type: 'Bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			return new Response(JSON.stringify({ email: googleMockEmail, verified_email: true }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://github.com/login/oauth/access_token') {
			return new Response(JSON.stringify({ access_token: 'gho_merge', token_type: 'bearer' }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		if (u === 'https://api.github.com/user') {
			return new Response(JSON.stringify({ login: ghMockLogin }), { status: 200, headers: { 'content-type': 'application/json' } })
		}
		return origFetch(input, init)
	}
	try {
		const olderUser = db.logins.resolveUser('google', 'primary-owner@example.com')
		db.sqlite.prepare('UPDATE users SET created = ? WHERE id = ?').run('2026-01-01T00:00:00.000Z', olderUser.id)
		db.sqlite.prepare('UPDATE logins SET created = ? WHERE user_id = ?').run('2026-01-01T00:00:00.000Z', olderUser.id)
		const olderSession = db.tokens.create({ userId: olderUser.id, provider: 'self', name: 'Older Session', admin: 1 })
		const olderApp = db.tokens.create({
			userId: olderUser.id,
			provider: 'stripe',
			type: 'api_key',
			name: 'Older Stripe',
			credentials: { apiKey: 'sk_older', baseUrl: 'https://api.stripe.com' }
		})
		db.links.create({ sessionId: olderSession.id, appId: olderApp.id })
		const newerUser = db.logins.resolveUser('github', 'accidental-new-gh')
		const newerSession = db.tokens.create({ userId: newerUser.id, provider: 'self', name: 'Newer GH Session', admin: 1 })
		db.logs.create({
			userId: newerUser.id,
			sessionId: newerSession.id,
			appId: null,
			provider: 'github',
			method: 'GET',
			url: 'https://api.github.com/user',
			allowed: true,
			status: 200,
			duration: 12
		})
		await executeTool('admin', {
			action: 'share_app',
			appId: olderApp.id,
			account: 'github:accidental-new-gh'
		}, olderSession.token)
		const thirdParty = db.logins.resolveUser('google', 'thirdparty-sharer@example.com')
		const thirdSession = db.tokens.create({ userId: thirdParty.id, provider: 'self', admin: 1 })
		const thirdApp = db.tokens.create({
			userId: thirdParty.id,
			provider: 'mailgun',
			type: 'api_key',
			name: 'Shared Mailgun',
			credentials: { apiKey: 'key-mg', baseUrl: 'https://api.mailgun.net' }
		})
		await executeTool('admin', { action: 'share_app', appId: thirdApp.id, account: 'primary-owner@example.com' }, thirdSession.token)
		await executeTool('admin', { action: 'share_app', appId: thirdApp.id, account: 'github:accidental-new-gh' }, thirdSession.token)
		const badBoolRes = await executeTool('admin', {
			action: 'link_login',
			provider: 'google',
			merge: 'not-a-bool'
		}, newerSession.token)
		assert.equal(badBoolRes.isError, true)
		assert.match(badBoolRes.content[0].text, /merge must be a boolean/)
		const noMergeInit = JSON.parse((await executeTool('admin', {
			action: 'link_login',
			provider: 'google'
		}, newerSession.token, `http://127.0.0.1:${addr.port}`)).content[0].text)
		const noMergeCode = new URL(noMergeInit.connectUrl).searchParams.get('code')
		const noMergeConsent = await origFetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: noMergeCode, provider: 'google' }).toString(),
			redirect: 'manual'
		})
		const noMergeState = new URL(noMergeConsent.headers.get('location')).searchParams.get('state')
		const noMergeCb = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${noMergeState}`)
		assert.equal(noMergeCb.status, 409, 'Without merge: true, existing account still returns 409')
		assert.match(await noMergeCb.text(), /merge: true/)
		const mergeInit = JSON.parse((await executeTool('admin', {
			action: 'link_login',
			provider: 'google',
			merge: true
		}, newerSession.token, `http://127.0.0.1:${addr.port}`)).content[0].text)
		const mergeSetupCode = new URL(mergeInit.connectUrl).searchParams.get('code')
		const mergeAuthPage = await origFetch(`http://127.0.0.1:${addr.port}/oauth/authorize?code=${mergeSetupCode}`)
		assert.equal(mergeAuthPage.status, 200)
		const mergeAuthHtml = await mergeAuthPage.text()
		assert.match(mergeAuthHtml, /"mergeMode":true/)
		assert.match(mergeAuthHtml, /"linkAccount":"accidental-new-gh"/)
		const mergeConsent = await origFetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: mergeSetupCode, provider: 'google' }).toString(),
			redirect: 'manual'
		})
		assert.equal(mergeConsent.status, 302)
		const mergeState = new URL(mergeConsent.headers.get('location')).searchParams.get('state')
		const mergeCb = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=g-code&state=${mergeState}`)
		assert.equal(mergeCb.status, 200)
		assert.match(await mergeCb.text(), /Accounts Merged/)
		assert.equal(db.users.get(newerUser.id), null, 'Newer user row is removed after merge into older user')
		assert.ok(db.users.get(olderUser.id), 'Older user row survives merge')
		const whoamiFromNewerSession = JSON.parse((await executeTool('admin', { action: 'whoami' }, newerSession.token)).content[0].text)
		assert.equal(whoamiFromNewerSession.user.id, olderUser.id, 'Newer session seamlessly points to surviving older user')
		assert.equal(whoamiFromNewerSession.user.account, 'primary-owner@example.com')
		assert.deepEqual(whoamiFromNewerSession.user.logins.map(l => `${l.provider}:${l.account}`), [
			'google:primary-owner@example.com',
			'github:accidental-new-gh'
		])
		const mergedApps = JSON.parse((await executeTool('admin', { action: 'list_apps' }, newerSession.token)).content[0].text).apps
		assert.equal(mergedApps.filter(a => a.type === 'share' && a.name === 'Older Stripe').length, 0, 'Self-shares are cleaned up on merge')
		assert.equal(mergedApps.filter(a => a.type === 'share' && a.name === 'Shared Mailgun').length, 1, 'Duplicate third-party shares are deduplicated on merge')
		assert.ok(mergedApps.some(a => a.id === olderApp.id), 'Surviving owned apps are accessible from merged session')
		const mergedLogs = JSON.parse((await executeTool('admin', { action: 'list_logs' }, olderSession.token)).content[0].text).logs
		assert.ok(mergedLogs.some(l => l.sessionId === newerSession.id), 'Audit logs from absorbed user are preserved')
		process.env.SSO_DOMAINS = 'isolated.corp:google'
		const pinnedUser = db.logins.resolveUser('google', 'staff@isolated.corp')
		db.sqlite.prepare('INSERT INTO logins (id, user_id, provider, account, created) VALUES (?, ?, ?, ?, ?)').run(
			'sso-bridge-login-id',
			pinnedUser.id,
			'github',
			'sso-bridge-gh',
			new Date().toISOString()
		)
		const outsider = db.logins.resolveUser('google', 'outsider@gmail.com')
		const outsiderAdmin = db.tokens.create({ userId: outsider.id, provider: 'self', admin: 1 })
		const ssoMergeState = db.tokens.createState({
			mode: 'auth',
			sessionId: outsiderAdmin.id,
			provider: 'github',
			merge: true
		})
		const ssoMergeCb = await origFetch(`http://127.0.0.1:${addr.port}/oauth/callback?code=gh-code&state=${ssoMergeState}`)
		assert.equal(ssoMergeCb.status, 403, 'Merge must reject absorbing a user whose logins violate SSO_DOMAINS')
		assert.ok(db.users.get(pinnedUser.id), 'Rejected SSO merge leaves target user untouched')
		assert.ok(db.users.get(outsider.id), 'Rejected SSO merge leaves caller user untouched')
	} finally {
		globalThis.fetch = origFetch
		if (origSso === undefined) delete process.env.SSO_DOMAINS
		else process.env.SSO_DOMAINS = origSso
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
