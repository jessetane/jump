import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { useServer, baseUrl, createTestSession, withMockFetch, withEnv, mcp, req, db, providers, oauthMod, bootstrapLocalAdmin } from './helpers.js'

useServer()

test('well-known OAuth discovery endpoints and RFC 9728 401 WWW-Authenticate', async () => {
	const unauth = await req('POST', '/mcp', { body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } })
	assert.equal(unauth.status, 401)
	assert.match(unauth.headers.get('www-authenticate') || '', /Bearer.*\/\.well-known\/oauth-protected-resource/)
	assert.match(unauth.headers.get('www-authenticate') || '', /\/oauth\/authorize/)
	assert.match(unauth.headers.get('access-control-expose-headers') || '', /WWW-Authenticate/)
	const subUnauth = await req('POST', '/mcp/work', { body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } })
	assert.equal(subUnauth.status, 401)
	assert.match(subUnauth.headers.get('www-authenticate') || '', /\/\.well-known\/oauth-protected-resource\/mcp\/work/)
	const resMeta = await req('GET', '/.well-known/oauth-protected-resource')
	assert.equal(resMeta.status, 200)
	assert.ok(Array.isArray(resMeta.data.authorization_servers))
	assert.equal((await req('GET', '/.well-known/oauth-protected-resource/mcp/work')).data.resource, `${baseUrl()}/mcp/work`)
	const asMeta = await req('GET', '/.well-known/oauth-authorization-server')
	assert.equal(asMeta.status, 200)
	assert.deepEqual(asMeta.data.code_challenge_methods_supported, ['S256'])
	assert.deepEqual(asMeta.data.grant_types_supported, ['authorization_code', 'refresh_token'])
	assert.equal(asMeta.data.client_id_metadata_document_supported, true)
	assert.deepEqual((await req('GET', '/.well-known/openid-configuration/mcp')).data, asMeta.data)
})

test('isAllowedRedirectUri allowlists exact/wildcard domains and loopback while rejecting userinfo and unknown hosts', async () => {
	const { isAllowedRedirectUri } = oauthMod
	assert.equal(isAllowedRedirectUri('https://chatgpt.com/callback'), true)
	assert.equal(isAllowedRedirectUri('https://foo.chatgpt.com/callback'), false)
	assert.equal(isAllowedRedirectUri('https://antigravity.google/oauth-callback'), true)
	assert.equal(isAllowedRedirectUri('https://sub.antigravity.google/oauth-callback'), true)
	assert.equal(isAllowedRedirectUri('http://127.0.0.1:8080/cb'), true)
	assert.equal(isAllowedRedirectUri('http://[::1]:8080/cb'), true)
	assert.equal(isAllowedRedirectUri('antigravity://auth-callback'), true)
	assert.equal(isAllowedRedirectUri('custom://localhost/cb'), false)
	assert.equal(isAllowedRedirectUri('https://evil.com/callback'), false)
	assert.equal(isAllowedRedirectUri('https://evil.com@chatgpt.com/callback'), false)
	assert.equal(isAllowedRedirectUri('http://user:pass@127.0.0.1:8080/cb'), false)
	assert.equal(isAllowedRedirectUri('https://chatgpt.com/callback#frag'), false)
	await withEnv({ ALLOWED_REDIRECT_DOMAINS: undefined }, () => {
		assert.equal(isAllowedRedirectUri('http://127.0.0.1:4321/cb'), true)
		assert.equal(isAllowedRedirectUri('https://chatgpt.com/callback'), false)
	})
})

test('DCR RFC 7591 ignores caller-supplied client secrets/IDs, preserves client_name, and separates static bearer clients', async () => {
	for (const badBody of ['null', '[]', '"string"']) {
		const res = await req('POST', '/oauth/register', { headers: { 'content-type': 'application/json' }, body: badBody })
		assert.equal(res.status, 400)
		assert.equal(res.data.error, 'invalid_client_metadata')
	}
	const reg = await req('POST', '/oauth/register', {
		body: { client_id: 'attacker_id', client_secret: 'attacker_secret', client_name: 'Claude Code', redirect_uris: ['http://127.0.0.1:9999/cb'] }
	})
	assert.equal(reg.status, 201)
	assert.notEqual(reg.data.client_id, 'attacker_id')
	assert.equal(reg.data.client_secret, undefined)
	assert.equal(oauthMod.deriveClientName(reg.data.client_id), 'Claude Code')
	assert.equal(oauthMod.deriveClientName('client_12345'), null)
	const bearerReg = await req('POST', '/oauth/register', {
		body: { client_name: 'Embedded Client', redirect_uris: ['http://localhost:8080/cb'], grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none' }
	})
	assert.equal(bearerReg.status, 201)
	assert.ok(bearerReg.data.client_id.startsWith('client_bearer_'))
	const challenge = createHash('sha256').update('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk').digest('base64url')
	const consent = await req('POST', '/oauth/authorize/consent', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ provider: 'google', client_id: bearerReg.data.client_id, redirect_uri: 'http://localhost:8080/cb', code_challenge: challenge, code_challenge_method: 'S256' }).toString(),
		redirect: 'manual'
	})
	const stateToken = new URL(consent.headers.get('location')).searchParams.get('state')
	const cbLoc = await withMockFetch(async (input, init, origFetch) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'ya29.emb', token_type: 'Bearer' })
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') return Response.json({ email: 'embedded-oauth@example.com' })
		return origFetch(input, init)
	}, async origFetch => {
		const cbRes = await origFetch(`${baseUrl()}/oauth/callback?code=g&state=${stateToken}`, { redirect: 'manual' })
		return cbRes.headers.get('location')
	})
	const bearerCode = new URL(cbLoc).searchParams.get('code')
	const tok = await req('POST', '/oauth/token', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ grant_type: 'authorization_code', client_id: bearerReg.data.client_id, code: bearerCode, redirect_uri: 'http://localhost:8080/cb', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' }).toString()
	})
	assert.equal(tok.status, 200)
	assert.equal(tok.data.refresh_token, undefined)
	assert.equal(tok.data.expires_in, undefined)
	assert.equal(db.tokens.getByToken(tok.data.access_token).expiresAt, null)
})

test('PKCE authorize validation, CSRF Origin guard, single-use setup codes, and unconsumed missing CLIENT_SECRET check', async () => {
	assert.equal((await req('GET', '/oauth/authorize?code_challenge=xyz&code_challenge_method=plain')).status, 400)
	assert.equal((await req('GET', '/oauth/authorize?redirect_uri=https://evil.com/cb&code_challenge=xyz&code_challenge_method=S256')).status, 400)
	assert.equal((await req('GET', '/oauth/authorize?redirect_uri=https://chatgpt.com/callback')).status, 400)
	const statesBefore = db.sqlite.prepare("SELECT COUNT(*) AS n FROM tokens WHERE type = 'oauth_state'").get().n
	const okAuth = await req('GET', '/oauth/authorize?redirect_uri=https://chatgpt.com/callback&state=s1&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256')
	assert.equal(okAuth.status, 200)
	assert.equal(db.sqlite.prepare("SELECT COUNT(*) AS n FROM tokens WHERE type = 'oauth_state'").get().n, statesBefore, 'GET /oauth/authorize must stay stateless')
	const crossOrigin = await req('POST', '/oauth/authorize/consent', {
		headers: { origin: 'https://evil.example.com', 'content-type': 'application/x-www-form-urlencoded' },
		body: 'provider=google'
	})
	assert.equal(crossOrigin.status, 403)
	const { session: adminSess } = createTestSession({ account: 'oauth-setup@example.com', admin: true })
	const { session: workerSess, app: nonSelf } = createTestSession({ account: 'oauth-worker@example.com', admin: false })
	const expAdmin = db.tokens.create({ userId: adminSess.userId, provider: 'self', admin: 1, expiresAt: Date.now() - 5000 })
	for (const badState of [
		'',
		db.tokens.createState({ mode: 'setup_connect', sessionId: nonSelf.id, provider: 'google' }),
		db.tokens.createState({ mode: 'setup_connect', sessionId: workerSess.id, provider: 'google' }),
		db.tokens.createState({ mode: 'setup_link', sessionId: adminSess.id, provider: 'google' }),
		db.tokens.createState({ mode: 'setup_connect', sessionId: expAdmin.id, provider: 'google' })
	]) {
		const r = await req('POST', '/providers/google/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: badState }).toString(),
			redirect: 'manual'
		})
		assert.equal(r.status, 403)
	}
	await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: undefined }, async () => {
		const unconfiguredConsent = await req('POST', '/oauth/authorize/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(unconfiguredConsent.status, 400)
		const setupCode = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSess.id, provider: 'github' })
		const missingSecretRes = await req('POST', '/providers/github/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: setupCode }).toString(),
			redirect: 'manual'
		})
		assert.equal(missingSecretRes.status, 500)
		assert.ok(db.tokens.getState(setupCode), 'Upfront missing CLIENT_SECRET check must not burn setupCode')
		process.env.GITHUB_CLIENT_SECRET = 'gh-secret'
		const okConsent = await req('POST', '/providers/github/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: setupCode }).toString(),
			redirect: 'manual'
		})
		assert.equal(okConsent.status, 302)
		const replay = await req('POST', '/providers/github/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: setupCode }).toString(),
			redirect: 'manual'
		})
		assert.equal(replay.status, 403, 'setupCode must be single-use')
	})
})

test('PKCE code exchange, client_id binding, refresh rotation, 60s dedup, /oauth/revoke, and 30-day dormancy pruning', async () => {
	const { session, app } = createTestSession({ account: 'pkce-refresh@example.com', admin: true })
	const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
	const challenge = createHash('sha256').update(verifier).digest('base64url')
	const badCode = db.tokens.createAuthCode({ userId: session.userId, clientId: 'client_a', clientRedirectUri: 'https://chatgpt.com/callback', codeChallenge: challenge, codeChallengeMethod: 'S256' })
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: badCode, redirect_uri: 'https://chatgpt.com/callback', client_id: 'client_a' } })).status, 400, 'Missing code_verifier')
	const wrongClientCode = db.tokens.createAuthCode({ userId: session.userId, clientId: 'client_a', clientRedirectUri: 'https://chatgpt.com/callback' })
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: wrongClientCode, redirect_uri: 'https://chatgpt.com/callback', client_id: 'client_bearer_spoof' } })).status, 400)
	const mismatchRedirectCode = db.tokens.createAuthCode({ userId: session.userId, clientRedirectUri: 'https://chatgpt.com/callback' })
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: mismatchRedirectCode, redirect_uri: 'https://evil.com/cb' } })).status, 400)
	const orphanCode = db.tokens.createAuthCode({ userId: null, clientRedirectUri: 'https://chatgpt.com/callback' })
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: orphanCode, redirect_uri: 'https://chatgpt.com/callback' } })).status, 400)
	const unboundCode = db.tokens.createAuthCode({ userId: session.userId, appIds: [app.id], clientRedirectUri: 'https://chatgpt.com/callback', codeChallenge: challenge, codeChallengeMethod: 'S256' })
	const exchange = await req('POST', '/oauth/token', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ grant_type: 'authorization_code', code: unboundCode, redirect_uri: 'https://chatgpt.com/callback', code_verifier: verifier, client_id: 'client_bearer_downgrade_attempt' }).toString()
	})
	assert.equal(exchange.status, 200)
	assert.equal(exchange.headers.get('cache-control'), 'no-store')
	assert.ok(exchange.data.refresh_token, 'Unbound code must not allow client_bearer_ downgrade')
	assert.equal(db.tokens.consumeAuthCode(unboundCode), null, 'Auth code must be single-use')
	const oauthSess = db.tokens.getByToken(exchange.data.access_token)
	db.sqlite.prepare('UPDATE tokens SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, oauthSess.id)
	assert.equal((await req('GET', '/api/sessions', { token: exchange.data.access_token })).status, 401, 'Expired access_token must return 401')
	const ref1 = await req('POST', '/oauth/token', { body: { grant_type: 'refresh_token', refresh_token: exchange.data.refresh_token } })
	assert.equal(ref1.status, 200)
	assert.notEqual(ref1.data.access_token, exchange.data.access_token)
	assert.equal(ref1.data.refresh_token, exchange.data.refresh_token)
	const refConcurrent = await req('POST', '/oauth/token', { body: { grant_type: 'refresh_token', refresh_token: exchange.data.refresh_token } })
	assert.equal(refConcurrent.data.access_token, ref1.data.access_token, 'Concurrent refresh within 60s returns cached rotated token')
	const expSessionForRevoke = db.tokens.create({ userId: session.userId, provider: 'self', credentials: { refreshToken: 'rt_revoke_exp' }, expiresAt: Date.now() - 5000 })
	const revokeByRefresh = await req('POST', '/oauth/revoke', { body: { token: 'rt_revoke_exp' } })
	assert.equal(revokeByRefresh.status, 200)
	assert.equal(db.tokens.get(expSessionForRevoke.id), null)
	assert.ok(db.tokens.get(app.id), 'Revoking session must never delete upstream app')
	assert.equal((await req('POST', '/oauth/revoke', { body: { token: 123 } })).status, 400)
	const staticSess = db.tokens.create({ userId: session.userId, provider: 'self', expiresAt: null })
	const dormantDate = new Date(Date.now() - 35 * 86400 * 1000).toISOString()
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id IN (?, ?, ?)').run(dormantDate, oauthSess.id, staticSess.id, app.id)
	assert.equal(db.tokens.getByToken(ref1.data.access_token), null, 'Dormant OAuth session excluded at read time')
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'refresh_token', refresh_token: exchange.data.refresh_token } })).status, 400)
	db.tokens.prune(30 * 86400 * 1000)
	assert.equal(db.tokens.get(oauthSess.id), null)
	assert.ok(db.tokens.get(staticSess.id), 'Static bearer session exempt from dormancy pruning')
	assert.ok(db.tokens.get(app.id), 'Upstream app exempt from dormancy pruning')
})

test('two-step /oauth/verify flow, local token fallback gating, and bootstrapLocalAdmin', async () => {
	const { user, app } = createTestSession({ account: 'verify-flow@example.com' })
	const badVerify = db.tokens.createState({ mode: 'verify', userId: null })
	assert.equal((await req('GET', `/oauth/verify?code=${badVerify}`)).status, 400)
	const wrongMode = db.tokens.createState({ mode: 'login', userId: user.id })
	assert.equal((await req('GET', `/oauth/verify?code=${wrongMode}`)).status, 400)
	const verifyCode = db.tokens.createState({ mode: 'verify', userId: user.id, name: 'Verify App', clientRedirectUri: 'https://antigravity.google/oauth-callback', clientState: 'st1' })
	assert.equal((await req('GET', `/oauth/verify?code=${verifyCode}`)).status, 200)
	assert.ok(db.tokens.getState(verifyCode), 'GET /oauth/verify must not consume state (scanner-safe)')
	const postVerify = await req('POST', '/oauth/verify', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: verifyCode, app_id: app.id }).toString(),
		redirect: 'manual'
	})
	assert.equal(postVerify.status, 302)
	assert.equal(db.tokens.getState(verifyCode), null)
	assert.equal(db.sqlite.prepare("SELECT COUNT(*) AS n FROM links WHERE app_id = ?").get(app.id).n, 1, 'Only original createTestSession link exists until /oauth/token exchanges auth code')
	const { session: gatedAdmin } = createTestSession({ account: 'local-gated@example.com', admin: true })
	assert.equal((await req('POST', '/oauth/authorize/consent', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: gatedAdmin.token }).toString()
	})).status, 403, 'Local token sign-in rejected when OAuth providers exist')
	await withEnv({ GOOGLE_CLIENT_ID: undefined, GITHUB_CLIENT_ID: undefined }, async () => {
		assert.deepEqual(providers.listAuthProviders(), [])
		const localUser = db.users.create()
		const localAdmin = db.tokens.create({ userId: localUser.id, provider: 'self', admin: 1 })
		const localWorker = db.tokens.create({ userId: localUser.id, provider: 'self', admin: 0 })
		assert.equal((await req('POST', '/oauth/authorize/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ token: localWorker.token }).toString()
		})).status, 403, 'Non-admin token rejected for local sign-in')
		const okLocal = await req('POST', '/oauth/authorize/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ token: localAdmin.token, session_name: 'Local Sess', admin: '1' }).toString()
		})
		assert.equal(okLocal.status, 200)
		assert.match(okLocal.text, /user:\s*localhost/)
		db.sqlite.exec("DELETE FROM tokens WHERE provider = 'self'")
		db.tokens.create({ userId: localUser.id, provider: 'self', admin: 0 })
		const bootstrapped = bootstrapLocalAdmin()
		assert.ok(bootstrapped?.admin)
		assert.equal(bootstrapLocalAdmin(), null)
	})
})

test('upstream OAuth re-auth account continuity, verified_email, refresh dedup, revoke, and OAUTH_TIMEOUT_MS', async () => {
	let { session: adminSess, app } = createTestSession({ account: 'reauth-owner@example.com', admin: true, expiresAt: Date.now() - 1000 })
	const { session: workerSess } = createTestSession({ account: 'reauth-worker@example.com', admin: false, withApp: false })
	app = db.tokens.updateCredentials(app.id, { credentials: { accessToken: 'ya29.old', refreshToken: '1//old-r', account: 'reauth-owner@example.com' }, expiresAt: Date.now() - 1000 })
	let returnedEmail = 'wrong@example.com'
	let refreshCalls = 0
	await withMockFetch(async (input, init, origFetch) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://oauth2.googleapis.com/token') {
			const form = new URLSearchParams(String(init?.body || ''))
			if (form.get('grant_type') === 'refresh_token') {
				refreshCalls++
				await new Promise(r => setTimeout(r, 10))
				return Response.json({ access_token: `ya29.fresh_${refreshCalls}`, expires_in: 3600 })
			}
			if (!form.get('code') || form.get('code') === 'undefined' || !form.get('redirect_uri')?.startsWith('http')) {
				return Response.json({ error: 'invalid_request' }, { status: 400 })
			}
			return Response.json({ access_token: 'ya29.cb', refresh_token: '1//new-r', expires_in: 3600 })
		}
		if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
			if (returnedEmail === 'UNVERIFIED') return Response.json({ email: 'spoof@corp.com', verified_email: false })
			if (returnedEmail === 'FAIL_401') return Response.json({ error: { message: 'bad token' } }, { status: 401 })
			return Response.json({ email: returnedEmail, verified_email: true })
		}
		if (u === 'https://oauth2.googleapis.com/revoke') return new Response(null, { status: 204 })
		return origFetch(input, init)
	}, async origFetch => {
		const [t1, t2] = await Promise.all([providers.google.resolveCredentials(app), providers.google.resolveCredentials(app)])
		assert.equal(refreshCalls, 1, 'Concurrent upstream token refreshes must deduplicate')
		assert.equal(t1.headers.authorization, 'Bearer ya29.fresh_1')
		assert.equal(t2.headers.authorization, 'Bearer ya29.fresh_1')
		returnedEmail = 'UNVERIFIED'
		await assert.rejects(() => providers.google.exchangeCode({ code: 'code', callbackUrl: 'http://localhost/cb' }), /Could not retrieve account identifier/)
		returnedEmail = 'FAIL_401'
		await assert.rejects(() => providers.google.exchangeCode({ code: 'code', callbackUrl: 'http://localhost/cb' }), err => err.status === 502 && err.message === 'bad token')
		returnedEmail = 'wrong@example.com'
		const mismatchState = db.tokens.createState({ sessionId: adminSess.id, reauthAppId: app.id, provider: 'google' })
		const mismatchRes = await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${mismatchState}`)
		assert.equal(mismatchRes.status, 409, 'Re-auth returning different upstream account must fail with 409')
		assert.equal(db.tokens.get(app.id).credentials.account, 'reauth-owner@example.com')
		returnedEmail = 'reauth-owner@example.com'
		const okState = db.tokens.createState({ sessionId: adminSess.id, reauthAppId: app.id, provider: 'google' })
		const okRes = await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${okState}`)
		assert.equal(okRes.status, 200)
		assert.equal(db.tokens.get(app.id).credentials.accessToken, 'ya29.cb')
		assert.equal(db.tokens.getByToken(adminSess.token)?.id, adminSess.id, 'Session token preserved across re-auth')
		const nonAdminState = db.tokens.createState({ sessionId: workerSess.id, reauthAppId: app.id, provider: 'google' })
		assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${nonAdminState}`)).status, 403)
		const reauthConnect = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'google', appId: app.id })).content[0].text)
		const reauthUrl = new URL(reauthConnect.connectUrl)
		assert.ok((await (await origFetch(`${baseUrl()}${reauthUrl.pathname}${reauthUrl.search}`)).text()).includes(app.id), 'reauth connect page pre-populates reauth_app_id')
		const connectInfo = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'google', name: 'Work Google' })).content[0].text)
		const connectUrl = new URL(connectInfo.connectUrl)
		const connectCode = connectUrl.searchParams.get('code')
		assert.ok((await (await origFetch(`${baseUrl()}${connectUrl.pathname}${connectUrl.search}`)).text()).includes('Work Google'))
		const consentRes = await origFetch(`${baseUrl()}/providers/google/consent`, {
			method: 'POST',
			headers: { origin: baseUrl(), 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: connectCode, services: 'gmail', app_name: 'Work Google' }).toString(),
			redirect: 'manual'
		})
		assert.equal(consentRes.status, 302)
		const consentState = new URL(consentRes.headers.get('location')).searchParams.get('state')
		returnedEmail = 'connected-ui@example.com'
		assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${consentState}`)).status, 200)
		const createdApp = db.tokens.listByUserId(adminSess.userId).find(t => t.type === 'oauth' && t.name === 'Work Google')
		assert.equal(createdApp?.credentials?.account, 'connected-ui@example.com')
		assert.ok(db.links.listBySessionId(adminSess.id).some(l => l.appId === createdApp.id), 'connect flow auto-links new OAuth app')
	})
	await withEnv({ OAUTH_TIMEOUT_MS: '25' }, async () => {
		await withMockFetch((input, init) => {
			const form = new URLSearchParams(String(init?.body || ''))
			if (form.get('code') !== 'slow' || form.get('redirect_uri') !== 'http://localhost/cb') {
				return Response.json({ error: 'invalid_request' }, { status: 400 })
			}
			return new Promise((_, reject) => {
				init?.signal?.addEventListener('abort', () => reject(init.signal.reason), { once: true })
			})
		}, async () => {
			await assert.rejects(() => providers.google.exchangeCode({ code: 'slow', callbackUrl: 'http://localhost/cb' }), /aborted|timeout/i)
			const start = Date.now()
			await providers.google.revokeToken(db.tokens.get(app.id))
			assert.ok(Date.now() - start < 1000)
		})
	})
})
