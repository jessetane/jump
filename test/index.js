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
process.env.ALLOWED_REDIRECT_DOMAINS = 'localhost,127.0.0.1,chatgpt.com'

fs.rmSync(testDbPath, { force: true })
fs.rmSync(`${testDbPath}-wal`, { force: true })
fs.rmSync(`${testDbPath}-shm`, { force: true })

const { server } = await import('../index.js')
const db = await import('../db/index.js')
const { readResponseBody, isGoogleApiUrl } = await import('../providers/google.js')
const { executeTool } = await import('../mcp.js')
const { isAllowedRedirectUri } = await import('../oauth.js')
const api = await import('../api/index.js')
const { evaluatePolicy, matchPattern, parsePolicy, validatePolicy } = await import('../policy.js')

function createTestSession (opts = {}) {
	const {
		email = 'user@example.com',
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
	const user = db.users.upsert({ email, name })
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
		sessionTokenId: session.id,
		appTokenId: app.id,
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
	assert.match(text, /google-mcp/)
	assert.match(text, /\/mcp/)
	assert.match(text, /href="\/oauth\/authorize"/)
})

test('mcp initialize & tools/list', async () => {
	const addr = server.address()
	const initRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: {}
		})
	})
	assert.equal(initRes.status, 200)
	const initData = await initRes.json()
	assert.equal(initData.result.serverInfo.name, 'google-mcp')

	const rootInitRes = await fetch(`http://127.0.0.1:${addr.port}/`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: {}
		})
	})
	assert.equal(rootInitRes.status, 200)
	const rootInitData = await rootInitRes.json()
	assert.equal(rootInitData.result.serverInfo.name, 'google-mcp')

	const notifRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			method: 'notifications/initialized',
			params: {}
		})
	})
	assert.equal(notifRes.status, 202)

	const listRes = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
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
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 3,
			method: 'tools/call',
			params: {
				name: 'admin',
				arguments: { action: 'status' }
			}
		})
	})
	assert.equal(res.status, 200)
	const data = await res.json()
	const parsed = JSON.parse(data.result.content[0].text)
	assert.equal(parsed.authenticated, false)
})

test('mcp google_api tool requires auth', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 4,
			method: 'tools/call',
			params: {
				name: 'google_api',
				arguments: { url: 'drive/v3/files' }
			}
		})
	})
	assert.equal(res.status, 200)
	const data = await res.json()
	assert.equal(data.result.isError, true)
	assert.match(data.result.content[0].text, /Authentication required/)
})

test('mcp rejects tool call without name', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			jsonrpc: '2.0',
			id: 5,
			method: 'tools/call',
			params: {
				arguments: { action: 'status' }
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
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
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

test('isGoogleApiUrl domain restrictions', () => {
	assert.equal(isGoogleApiUrl('https://www.googleapis.com/drive/v3/files'), true)
	assert.equal(isGoogleApiUrl('https://sheets.googleapis.com/v4/spreadsheets'), true)
	assert.equal(isGoogleApiUrl('https://docs.googleapis.com/v1/documents'), true)
	assert.equal(isGoogleApiUrl('https://calendar.googleapis.com/calendar/v3/events'), true)
	assert.equal(isGoogleApiUrl('https://googleapis.com/test'), true)
	assert.equal(isGoogleApiUrl('http://www.googleapis.com/test'), false)
	assert.equal(isGoogleApiUrl('https://evil.com'), false)
	assert.equal(isGoogleApiUrl('https://evilgoogleapis.com'), false)
	assert.equal(isGoogleApiUrl('https://localhost:8080'), false)
	assert.equal(isGoogleApiUrl('not-a-url'), false)
})

test('rejects non-googleapis URLs in google_api tool', async () => {
	const { session } = createTestSession({ email: 'user@example.com' })
	const result = await executeTool('google_api', {
		url: 'https://evil.com/steal-token'
	}, session.token)
	assert.equal(result.isError, true)
	assert.match(result.content[0].text, /Target URL domain not allowed/)
})

test('mcp google_api tool ignores body on GET requests', async () => {
	const { session } = createTestSession({ email: 'getbody@example.com' })
	const result = await executeTool('google_api', {
		url: 'https://www.googleapis.com/drive/v3/files',
		method: 'GET',
		body: { unwanted: 'payload' }
	}, session.token)
	assert.ok(result)
})

test('oauth state flow', async () => {
	const state = db.oauthStates.create({
		clientRedirectUri: 'https://example.com/oauth/return',
		clientState: 'random-state',
		ip: '127.0.0.1'
	})
	assert.ok(state)
	const consumed = db.oauthStates.consume(state)
	assert.equal(consumed.clientState, 'random-state')
	assert.equal(consumed.clientRedirectUri, 'https://example.com/oauth/return')
	assert.equal(db.oauthStates.consume(state), null)
})

test('oauth code exchange flow', async () => {
	const { session } = createTestSession({ email: 'test@example.com', name: 'Test User' })
	const code = db.oauthCodes.create({
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

	const code2 = db.oauthCodes.create({
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
	assert.equal(data.token_type, 'Bearer')
	assert.equal(db.oauthCodes.consume(code2), null)
})

test('well-known oauth discovery endpoints', async () => {
	const addr = server.address()
	const resResource = await fetch(`http://127.0.0.1:${addr.port}/.well-known/oauth-protected-resource`)
	assert.equal(resResource.status, 200)
	const resourceData = await resResource.json()
	assert.ok(Array.isArray(resourceData.authorization_servers))
	const resAuth = await fetch(`http://127.0.0.1:${addr.port}/.well-known/oauth-authorization-server`)
	assert.equal(resAuth.status, 200)
	const authData = await resAuth.json()
	assert.ok(authData.authorization_endpoint.endsWith('/oauth/authorize'))
	assert.ok(authData.token_endpoint.endsWith('/oauth/token'))
	assert.ok(authData.revocation_endpoint.endsWith('/oauth/revoke'))
	assert.deepEqual(authData.code_challenge_methods_supported, ['S256'])
	assert.equal(authData.client_id_metadata_document_supported, true)
})

test('oauth pkce flow with S256', async () => {
	const { session } = createTestSession({ email: 'pkce@example.com', name: 'PKCE User' })
	const addr = server.address()
	const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
	const challenge = createHash('sha256').update(verifier).digest('base64url')
	const codeMissing = db.oauthCodes.create({
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
	const codeWrong = db.oauthCodes.create({
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
	const codeSuccess = db.oauthCodes.create({
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
	assert.equal(isAllowedRedirectUri('https://evil.com/callback'), false)
	assert.equal(isAllowedRedirectUri(''), false)
	assert.equal(isAllowedRedirectUri(null), false)
})

test('oauth pkce authorize endpoint validation and state propagation', async () => {
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
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const authRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?redirect_uri=https://chatgpt.com/callback&state=test-state&code_challenge=${challenge}&code_challenge_method=S256`)
	assert.equal(authRes.status, 200)
	assert.equal(authRes.headers.get('content-type'), 'text/html; charset=utf-8')
	const authHtml = await authRes.text()
	assert.match(authHtml, /"redirect_uri":"https:\/\/chatgpt\.com\/callback"/)
	assert.match(authHtml, /"state":"test-state"/)
	assert.match(authHtml, /"code_challenge":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"/)
	assert.match(authHtml, /"code_challenge_method":"S256"/)
})

test('oauth consent html page and post consent flow', async () => {
	const addr = server.address()
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const pageRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?redirect_uri=https://chatgpt.com/callback&state=client-state-123&code_challenge=${challenge}&code_challenge_method=S256`)
	assert.equal(pageRes.status, 200)
	assert.equal(pageRes.headers.get('content-type'), 'text/html; charset=utf-8')
	const html = await pageRes.text()
	assert.match(html, /Generate Bearer Token/)
	assert.match(html, /action="\/oauth\/authorize\/consent"/)
	assert.match(html, /"redirect_uri":"https:\/\/chatgpt\.com\/callback"/)
	assert.match(html, /"state":"client-state-123"/)

	const consentBody = new URLSearchParams({
		email: 'agent@example.com',
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
	assert.equal(consentRes.status, 200)
	const consentText = await consentRes.text()
	assert.match(consentText, /Check your email/)

	const row = db.sqlite.prepare('SELECT * FROM oauth_states WHERE email = ?').get('agent@example.com')
	assert.ok(row)
	assert.equal(row.client_redirect_uri, 'https://chatgpt.com/callback')
	assert.equal(row.session_name, 'Coding Agent')

	const verifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${row.magic_code}`, {
		redirect: 'manual'
	})
	assert.equal(verifyRes.status, 302)
	const location = verifyRes.headers.get('location')
	const targetUrl = new URL(location)
	assert.equal(targetUrl.hostname, 'chatgpt.com')
	assert.equal(targetUrl.searchParams.get('state'), 'client-state-123')
	const code = targetUrl.searchParams.get('code')
	assert.ok(code)
})

test('direct browser authorize without redirect_uri', async () => {
	const addr = server.address()
	const pageRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize`)
	assert.equal(pageRes.status, 200)
	assert.equal(pageRes.headers.get('content-type'), 'text/html; charset=utf-8')
	const html = await pageRes.text()
	assert.match(html, /Generate Bearer Token/)
	assert.match(html, /action="\/oauth\/authorize\/consent"/)

	const consentBody = new URLSearchParams({
		email: 'browser@example.com',
		session_name: 'Browser Session'
	})
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 200)
	const consentText = await consentRes.text()
	assert.match(consentText, /Check your email/)

	const row = db.sqlite.prepare('SELECT * FROM oauth_states WHERE email = ?').get('browser@example.com')
	assert.ok(row)
	assert.equal(row.session_name, 'Browser Session')

	const verifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${row.magic_code}`)
	assert.equal(verifyRes.status, 200)
	const verifyText = await verifyRes.text()
	assert.match(verifyText, /user: browser@example.com/)
	assert.match(verifyText, /Authorization: Bearer/)
})

test('google provider connect screen and consent flow', async () => {
	const addr = server.address()
	const connectRes = await fetch(`http://127.0.0.1:${addr.port}/providers/google/connect?session_id=sess_123`)
	assert.equal(connectRes.status, 200)
	const connectHtml = await connectRes.text()
	assert.match(connectHtml, /Connect Google Account/)
	assert.match(connectHtml, /action="\/providers\/google\/consent"/)

	const consentBody = new URLSearchParams({
		session_id: 'sess_123',
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
	const stateRow = db.oauthStates.consume(stateParam)
	assert.equal(stateRow.sessionId, 'sess_123')
	assert.equal(stateRow.sessionName, 'Custom Work Google')
	assert.equal(stateRow.provider, 'google')
})

test('authorize page with policy and service query params', async () => {
	const addr = server.address()
	const policyJson = JSON.stringify([{ action: 'allow', path: '/drive/**' }])
	const res = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?services=drive,calendar&write=calendar&policy=${encodeURIComponent(policyJson)}`)
	assert.equal(res.status, 200)
	const html = await res.text()
	assert.match(html, /"policy":/)
	assert.match(html, /"services":"drive,calendar"/)
	assert.match(html, /"write":"calendar"/)
})

test('authorize page with repeated query parameters', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize?services=drive&services=calendar&write=drive&write=calendar`)
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
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
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
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: '{"invalid_json'
	})
	const data = await res.json()
	assert.equal(data.jsonrpc, '2.0')
	assert.equal(data.error?.code, -32700)
})

test('mcp non-POST request returns 405 Method Not Allowed', async () => {
	const addr = server.address()
	const res = await fetch(`http://127.0.0.1:${addr.port}/mcp`, {
		method: 'GET'
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
	const unknownRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: 'nonexistent-token' }).toString()
	})
	assert.equal(unknownRes.status, 200)

	const { session } = createTestSession({ email: 'revoke-endpoint@example.com' })
	assert.ok(db.tokens.get(session.id))
	const revokeRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: session.token }).toString()
	})
	assert.equal(revokeRes.status, 200)
	assert.equal(db.tokens.get(session.id), null)

	const { session: sessionJson } = createTestSession({ email: 'revoke-json@example.com' })
	assert.ok(db.tokens.get(sessionJson.id))
	const revokeJsonRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/revoke`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ token: sessionJson.token })
	})
	assert.equal(revokeJsonRes.status, 200)
	assert.equal(db.tokens.get(sessionJson.id), null)
})

test('mcp auth status, list, and revoke', async () => {
	const user = db.users.upsert({ email: 'sessions-tool@example.com' })
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
	db.links.create({ sessionTokenId: session1.id, appTokenId: app.id })
	db.links.create({ sessionTokenId: session2.id, appTokenId: app.id })

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

test('evaluatePolicy matches relative paths and origin-scoped rules', () => {
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
		email: 'policy-test@example.com',
		admin: true,
		policy: policyObj
	})

	const statusRes = await executeTool('admin', { action: 'status' }, session.token)
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

test('oauth consent flow with policy', async () => {
	const addr = server.address()
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const policyStr = JSON.stringify([
		{ action: 'deny', methods: ['DELETE'] },
		{ action: 'allow', path: '/calendar/v3/calendars/my-cal/**' }
	])
	const consentBody = new URLSearchParams({
		email: 'policy-test@example.com',
		redirect_uri: 'https://chatgpt.com/callback',
		state: 'client-state-policy',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		policy: policyStr
	})
	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString(),
		redirect: 'manual'
	})
	assert.equal(consentRes.status, 200)
	const row = db.sqlite.prepare('SELECT * FROM oauth_states WHERE email = ?').get('policy-test@example.com')
	assert.ok(row)
	assert.equal(row.policy, policyStr)
})

test('oauth consent flow rejects invalid json policy', async () => {
	const addr = server.address()
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const consentBody = new URLSearchParams({
		email: 'policy-invalid@example.com',
		redirect_uri: 'https://chatgpt.com/callback',
		state: 'client-state-policy',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		policy: '{ invalid-json'
	})

	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString()
	})
	assert.equal(consentRes.status, 400)
	const data = await consentRes.json()
	assert.equal(data.error, 'invalid_request')
	assert.match(data.error_description, /Invalid JSON policy/)
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
		{ action: 'allow', methods: ['GET'], origin: 'https://sheets.googleapis.com', path: '/v4/**', description: 'Allow sheets GET' },
		{ action: 'deny' }
	]
	assert.equal(validatePolicy(validPolicy).valid, true)
	assert.equal(validatePolicy([{ action: 'allow', origin: 'https://sheets.googleapis.com/' }]).valid, true)
})

test('oauth consent flow rejects invalid schema policy', async () => {
	const addr = server.address()
	const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
	const consentBody = new URLSearchParams({
		email: 'policy-schema-invalid@example.com',
		redirect_uri: 'https://chatgpt.com/callback',
		state: 'client-state-policy-invalid',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		policy: JSON.stringify([{ action: 'allow', method: 'GET' }])
	})

	const consentRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/authorize/consent`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: consentBody.toString()
	})
	assert.equal(consentRes.status, 400)
	const data = await consentRes.json()
	assert.equal(data.error, 'invalid_request')
	assert.match(data.error_description, /unknown property "method"/)
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

	const user = db.users.upsert({ email: 'rest-test@example.com' })
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
	db.links.create({ sessionTokenId: session1.id, appTokenId: app.id })
	db.links.create({ sessionTokenId: session2.id, appTokenId: app.id })

	const whoamiRes = await fetch(`http://127.0.0.1:${addr.port}/api/whoami`, {
		headers: { authorization: `Bearer ${session1.token}` }
	})
	assert.equal(whoamiRes.status, 200)
	const whoamiData = await whoamiRes.json()
	assert.equal(whoamiData.authenticated, true)
	assert.equal(whoamiData.user.id, user.id)
	assert.equal(whoamiData.user.email, 'rest-test@example.com')
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
	const { user, session } = createTestSession({ email: 'mcp-whoami@example.com' })
	const whoamiResult = await executeTool('admin', { action: 'whoami' }, session.token)
	assert.equal(whoamiResult.isError, undefined)
	const parsedWhoami = JSON.parse(whoamiResult.content[0].text)
	assert.equal(parsedWhoami.authenticated, true)
	assert.equal(parsedWhoami.user.id, user.id)
	assert.equal(parsedWhoami.user.email, 'mcp-whoami@example.com')
	assert.equal(parsedWhoami.session.id, session.id)

	const getResult = await executeTool('admin', { action: 'get', sessionId: session.id }, session.token)
	assert.equal(getResult.isError, undefined)
	const parsedGet = JSON.parse(getResult.content[0].text)
	assert.equal(parsedGet.session.id, session.id)
	assert.equal(parsedGet.session.token, undefined)
})

test('transparent rest proxy /api/google/*', async () => {
	const addr = server.address()
	const { session } = createTestSession({ email: 'rest-proxy@example.com' })
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
	const user = db.users.upsert({ email: 'mcp-tools-filter@example.com' })
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
	db.links.create({ sessionTokenId: adminSession.id, appTokenId: app.id })
	db.links.create({ sessionTokenId: workerSession.id, appTokenId: app.id })

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
	const user = db.users.upsert({ email: 'non-admin-auth@example.com' })
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
		email: 'admin-param@example.com',
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
	assert.equal(consentAdminRes.status, 200)
	const rowAdmin = db.sqlite.prepare('SELECT * FROM oauth_states WHERE email = ?').get('admin-param@example.com')
	assert.ok(rowAdmin)
	assert.equal(rowAdmin.admin, 1)

	const consentNoAdmin = new URLSearchParams({
		email: 'no-admin-param@example.com',
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
	assert.equal(consentNoAdminRes.status, 200)
	const rowNoAdmin = db.sqlite.prepare('SELECT * FROM oauth_states WHERE email = ?').get('no-admin-param@example.com')
	assert.ok(rowNoAdmin)
	assert.equal(rowNoAdmin.admin, 0)
})

test('magic link admin verification flow (/oauth/verify)', async () => {
	const addr = server.address()
	const magicCode = 'test-magic-code-123'
	db.oauthStates.create({
		email: 'magic-admin@example.com',
		sessionName: 'Admin Magic Session',
		admin: 1,
		clientRedirectUri: 'https://chatgpt.com/callback',
		clientState: 'magic-state-abc',
		magicCode,
		magicExpiresAt: Date.now() + 600000
	})

	const verifyRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/verify?code=${magicCode}`, {
		redirect: 'manual'
	})
	assert.equal(verifyRes.status, 302)
	const targetLocation = verifyRes.headers.get('location')
	assert.ok(targetLocation)
	const targetUrl = new URL(targetLocation)
	assert.equal(targetUrl.hostname, 'chatgpt.com')
	assert.equal(targetUrl.searchParams.get('state'), 'magic-state-abc')
	const authCode = targetUrl.searchParams.get('code')
	assert.ok(authCode)

	const tokenRes = await fetch(`http://127.0.0.1:${addr.port}/oauth/token`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			code: authCode,
			redirect_uri: 'https://chatgpt.com/callback',
			grant_type: 'authorization_code'
		}).toString()
	})
	assert.equal(tokenRes.status, 200)
	const tokenData = await tokenRes.json()
	assert.ok(tokenData.access_token)

	const createdSession = db.tokens.getByToken(tokenData.access_token)
	assert.equal(createdSession.admin, true)
	assert.equal(createdSession.name, 'Admin Magic Session')
	const createdUser = db.users.get(createdSession.userId)
	assert.equal(createdUser.name, null)
})

test('30-day dormancy pruning scopes only provider = self', () => {
	const user = db.users.upsert({ email: 'dormancy@example.com' })
	const oldDate = new Date(Date.now() - 35 * 24 * 60 * 60 * 1000).toISOString()
	const activeSession = db.tokens.create({
		userId: user.id,
		provider: 'self'
	})
	const dormantSession = db.tokens.create({
		userId: user.id,
		provider: 'self'
	})
	const upstreamApp = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Upstream App'
	})
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(oldDate, dormantSession.id)
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(oldDate, upstreamApp.id)

	db.tokens.pruneDormant(30 * 24 * 60 * 60 * 1000)

	assert.equal(db.tokens.get(dormantSession.id), null)
	assert.ok(db.tokens.get(activeSession.id))
	assert.ok(db.tokens.get(upstreamApp.id), 'Upstream apps must not be pruned by dormancy')
})

test('admin tool administrative actions: create_session, list_apps, connect_app, link_app, unlink_app', async () => {
	const user = db.users.upsert({ email: 'admin-actions@example.com' })
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

	const connectRes = await executeTool('admin', {
		action: 'connect_app',
		provider: 'stripe',
		name: 'Stripe Prod',
		account: 'acct_stripe_prod_123',
		apiKey: 'sk_test_12345'
	}, adminSession.token)
	assert.equal(connectRes.isError, undefined)
	const connectData = JSON.parse(connectRes.content[0].text)
	assert.equal(connectData.connected, true)
	assert.equal(connectData.app.provider, 'stripe')
	assert.equal(connectData.app.account, 'acct_stripe_prod_123')
	const stripeAppId = connectData.app.id

	const reauthRes = await executeTool('admin', {
		action: 'connect_app',
		provider: 'google',
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
})

test('multi-account disambiguation in google_api tool', async () => {
	const user = db.users.upsert({ email: 'multi-account@example.com' })
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
	db.links.create({ sessionTokenId: session.id, appTokenId: personalApp.id, policy: [{ action: 'allow', path: '/drive/**' }] })
	db.links.create({ sessionTokenId: session.id, appTokenId: workApp.id, policy: [{ action: 'allow', path: '/calendar/**' }] })

	const resWithAppId = await executeTool('google_api', {
		url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events',
		appId: workApp.id
	}, session.token)
	assert.equal(resWithAppId.isError, true)
	assert.doesNotMatch(resWithAppId.content[0].text, /Policy violation/)
})

test('in-place upstream re-auth flow updates app credentials without changing session token', async () => {
	const user = db.users.upsert({ email: 'reauth@example.com' })
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		name: 'Persistent Agent Session'
	})
	const app = db.tokens.create({
		userId: user.id,
		provider: 'google',
		type: 'oauth',
		name: 'Expiring App',
		credentials: { accessToken: 'ya29.old', refreshToken: '1//old-refresh' },
		expiresAt: Date.now() - 1000
	})
	db.links.create({ sessionTokenId: session.id, appTokenId: app.id })

	const initialSessionToken = session.token
	const state = db.oauthStates.create({
		userId: user.id,
		reauthAppId: app.id,
		clientRedirectUri: 'https://chatgpt.com/callback'
	})

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
	const user = db.users.upsert({ email: 'rest-apps@example.com' })
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
			apiKey: 'sk-ant-12345'
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

	const deleteAppRes = await fetch(`http://127.0.0.1:${addr.port}/api/apps/${newAppId}`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${adminSession.token}` }
	})
	assert.equal(deleteAppRes.status, 200)
	const deleteAppData = await deleteAppRes.json()
	assert.equal(deleteAppData.disconnected, true)
	assert.equal(db.tokens.get(newAppId), null)
})

test('admin update_email action', async () => {
	const user1 = db.users.upsert({ email: 'email-owner@example.com', name: 'Original User' })
	const adminSession = db.tokens.create({
		userId: user1.id,
		provider: 'self',
		admin: 1
	})
	const workerSession = db.tokens.create({
		userId: user1.id,
		provider: 'self',
		admin: 0
	})
	const user2 = db.users.upsert({ email: 'taken@example.com', name: 'Other User' })

	const nonAdminRes = await executeTool('admin', {
		action: 'update_email',
		email: 'new-email@example.com'
	}, workerSession.token)
	assert.equal(nonAdminRes.isError, true)
	assert.match(nonAdminRes.content[0].text, /requires admin privileges/)

	const invalidEmailRes = await executeTool('admin', {
		action: 'update_email',
		email: 'not-an-email'
	}, adminSession.token)
	assert.equal(invalidEmailRes.isError, true)
	assert.match(invalidEmailRes.content[0].text, /Valid new email address is required/)

	const conflictRes = await executeTool('admin', {
		action: 'update_email',
		email: 'taken@example.com'
	}, adminSession.token)
	assert.equal(conflictRes.isError, true)
	assert.match(conflictRes.content[0].text, /already registered/)

	const successRes = await executeTool('admin', {
		action: 'update_email',
		email: 'updated-email@example.com'
	}, adminSession.token)
	assert.equal(successRes.isError, undefined)
	const successData = JSON.parse(successRes.content[0].text)
	assert.equal(successData.updated, true)
	assert.equal(successData.user.id, user1.id)
	assert.equal(successData.user.email, 'updated-email@example.com')

	const updatedUser = db.users.get(user1.id)
	assert.equal(updatedUser.email, 'updated-email@example.com')

	const whoamiRes = await executeTool('admin', { action: 'whoami' }, adminSession.token)
	const whoamiData = JSON.parse(whoamiRes.content[0].text)
	assert.equal(whoamiData.user.email, 'updated-email@example.com')
})

test('admin update_user action', async () => {
	const user = db.users.upsert({ email: 'user-props@example.com', name: 'Initial Name' })
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
		email: 'fake-email-attempt@example.com',
		name: 'Jesse Tane'
	}, adminSession.token)
	assert.equal(updateRes.isError, undefined)
	const updateData = JSON.parse(updateRes.content[0].text)
	assert.equal(updateData.updated, true)
	assert.equal(updateData.user.id, user.id)
	assert.equal(updateData.user.email, 'user-props@example.com')
	assert.equal(updateData.user.name, 'Jesse Tane')

	const whoamiRes = await executeTool('admin', { action: 'whoami' }, adminSession.token)
	const whoamiData = JSON.parse(whoamiRes.content[0].text)
	assert.equal(whoamiData.user.name, 'Jesse Tane')
	assert.equal(whoamiData.user.email, 'user-props@example.com')
})

test('admin update_app action', async () => {
	const user = db.users.upsert({ email: 'update-app@example.com' })
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
	const user = db.users.upsert({ email: 'update-session@example.com' })
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
	assert.equal(db.tokens.get(workerSession.id).admin, true)
})

test('teardown server', (t, done) => {
	server.close(() => {
		fs.rmSync(testDbPath, { force: true })
		fs.rmSync(`${testDbPath}-wal`, { force: true })
		fs.rmSync(`${testDbPath}-shm`, { force: true })
		done()
	})
})
