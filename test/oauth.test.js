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
	const cjkName = '漢'.repeat(64)
	const cjkReg = await req('POST', '/oauth/register', {
		body: { client_name: cjkName, redirect_uris: ['http://127.0.0.1:9999/cb'] }
	})
	assert.equal(cjkReg.status, 201)
	assert.equal(oauthMod.deriveClientName(cjkReg.data.client_id), cjkName)
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
	assert.equal((await req('GET', '/providers/google/connect')).status, 403, 'GET /providers/:provider/connect requires setup code')
	await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: undefined }, async () => {
		const unauthConnect = await req('GET', '/providers/github/connect')
		assert.equal(unauthConnect.status, 403, 'GET /providers/:provider/connect must return 403 before CLIENT_SECRET check')
		const unauthConsent = await req('POST', '/providers/github/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(unauthConsent.status, 403, 'POST /providers/:provider/consent must return 403 before CLIENT_SECRET check')
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
		assert.doesNotMatch(missingSecretRes.text, /GITHUB_CLIENT_SECRET/)
		assert.ok(db.tokens.getState(setupCode), 'Upfront missing CLIENT_SECRET check must not burn setupCode')
		const cbMissingSecretState = db.tokens.createState({ mode: 'login', provider: 'github' })
		const cbMissingSecretRes = await req('GET', `/oauth/callback?code=c&state=${cbMissingSecretState}`)
		assert.equal(cbMissingSecretRes.status, 500)
		assert.doesNotMatch(cbMissingSecretRes.text, /GITHUB_CLIENT_SECRET/)
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
	assert.equal((await req('POST', '/oauth/token', { headers: { 'content-type': 'application/json' }, body: '{bad' })).status, 400)
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'client_credentials' } })).status, 400)
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: badCode, redirect_uri: 'https://chatgpt.com/callback', client_id: 'client_a' } })).status, 400, 'Missing code_verifier')
	const shortVerifierCode = db.tokens.createAuthCode({ userId: session.userId, clientId: 'client_a', clientRedirectUri: 'https://chatgpt.com/callback', codeChallenge: challenge, codeChallengeMethod: 'S256' })
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: shortVerifierCode, redirect_uri: 'https://chatgpt.com/callback', client_id: 'client_a', code_verifier: 'too-short' } })).status, 400)
	const wrongVerifierCode = db.tokens.createAuthCode({ userId: session.userId, clientId: 'client_a', clientRedirectUri: 'https://chatgpt.com/callback', codeChallenge: challenge, codeChallengeMethod: 'S256' })
	assert.equal((await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: wrongVerifierCode, redirect_uri: 'https://chatgpt.com/callback', client_id: 'client_a', code_verifier: 'a'.repeat(43) } })).status, 400)
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

test('parseGrantedServices and summarizeScopes handle delimiters, mixed modes, counts, and subset fallback', () => {
	const { parseGrantedServices, summarizeScopes } = providers
	const gServices = providers.google.services
	assert.deepEqual(parseGrantedServices('', gServices), [])
	assert.deepEqual(parseGrantedServices('https://www.googleapis.com/auth/userinfo.email', null), [])
	assert.equal(summarizeScopes('', gServices), '')
	assert.equal(summarizeScopes('https://www.googleapis.com/auth/userinfo.email', gServices), '')
	assert.deepEqual(
		parseGrantedServices('https://mail.google.com/,https://www.googleapis.com/auth/calendar.readonly', gServices),
		[{ id: 'calendar', modes: ['read'] }, { id: 'gmail', modes: ['write'] }]
	)
	assert.deepEqual(
		parseGrantedServices('https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata https://www.googleapis.com/auth/photoslibrary.appendonly', gServices),
		[{ id: 'photos', modes: ['read', 'write'] }]
	)
	assert.deepEqual(
		parseGrantedServices('admin:org read:packages write:packages', providers.github.services),
		[{ id: 'packages', modes: ['read', 'write'] }, { id: 'org', modes: ['admin'] }]
	)
	assert.deepEqual(
		parseGrantedServices('https://www.googleapis.com/auth/apps.groups.settings https://www.googleapis.com/auth/apps.licensing https://www.googleapis.com/auth/admin.directory.user', gServices),
		[{ id: 'admin', modes: ['write'] }]
	)
	assert.deepEqual(
		parseGrantedServices('https://www.googleapis.com/auth/apps.groups.settings https://www.googleapis.com/auth/apps.licensing https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.reports.audit.readonly', gServices),
		[{ id: 'admin', modes: ['read', 'write'] }]
	)
	assert.equal(summarizeScopes('https://www.googleapis.com/auth/gmail.readonly', gServices), 'gmail (read)')
	assert.equal(summarizeScopes('https://www.googleapis.com/auth/gmail.readonly https://mail.google.com/', gServices), 'gmail (read+write)')
	assert.equal(summarizeScopes('https://www.googleapis.com/auth/gmail.readonly,https://www.googleapis.com/auth/calendar.readonly', gServices), 'calendar, gmail (read)')
	assert.equal(summarizeScopes('https://mail.google.com/ https://www.googleapis.com/auth/calendar.readonly', gServices), 'calendar (read), gmail (write)')
	assert.equal(summarizeScopes('admin:org write:packages', providers.github.services), 'packages (write), org (admin)')
	const firstFour = Object.values(gServices).slice(0, 4)
	assert.equal(summarizeScopes(firstFour.flatMap(s => s.scopes.read).join(' '), gServices), '4 (read)')
	assert.equal(summarizeScopes([...firstFour[0].scopes.write, ...firstFour[1].scopes.write, ...firstFour[2].scopes.read, ...firstFour[3].scopes.read].join(' '), gServices), '4 (2 write, 2 read)')
	assert.equal(summarizeScopes(Object.values(gServices).flatMap(s => s.scopes.read || []).join(' '), gServices), '21 (read)')
	assert.equal(summarizeScopes(Object.values(gServices).flatMap(s => s.scopes.write || []).join(' '), gServices), 'all (write)')
	const synthServices = {
		same: { id: 'same', scopes: { read: ['x'], write: ['x', 'y'] } },
		other: { id: 'other', scopes: { read: ['o.ro'], write: ['o.rw'] } }
	}
	assert.equal(summarizeScopes('x o.ro', synthServices), 'all (read)')
	assert.equal(summarizeScopes('x y o.rw', synthServices), 'all (write)')
	assert.deepEqual(parseGrantedServices('x', synthServices), [{ id: 'same', modes: ['read'] }])
	assert.deepEqual(parseGrantedServices('x y', synthServices), [{ id: 'same', modes: ['write'] }])
	const sameBoth = {
		exact: { id: 'exact', scopes: { read: ['a', 'b'], write: ['a', 'b'] } },
		second: { id: 'second', scopes: { read: ['s.ro'], write: ['s.rw'] } }
	}
	assert.deepEqual(parseGrantedServices('a', sameBoth), [{ id: 'exact', modes: ['read'] }])
	assert.deepEqual(parseGrantedServices('a b', sameBoth), [{ id: 'exact', modes: ['write'] }])
})

test('two-step /oauth/verify flow, local token fallback gating, and bootstrapLocalAdmin', async () => {
	const { user, session, app } = createTestSession({
		account: 'verify-flow@example.com',
		scopes: 'https://mail.google.com/ https://www.googleapis.com/auth/calendar.readonly'
	})
	const extraApp = db.tokens.create({ userId: user.id, provider: 'stripe', type: 'static', name: 'Extra Stripe', credentials: { bearer: 'sk_extra' } })
	const newApp = db.tokens.create({ userId: user.id, provider: 'linear', type: 'static', name: 'New Linear', credentials: { bearer: 'lin_new' } })
	const { session: otherSess, app: foreignApp } = createTestSession({ account: 'verify-other@example.com' })
	const badVerify = db.tokens.createState({ mode: 'verify', userId: null })
	assert.equal((await req('GET', `/oauth/verify?code=${badVerify}`)).status, 400)
	const wrongMode = db.tokens.createState({ mode: 'login', userId: user.id })
	assert.equal((await req('GET', `/oauth/verify?code=${wrongMode}`)).status, 400)
	const missingSessVerify = db.tokens.createState({ mode: 'verify', userId: user.id, sessionId: 'missing-session' })
	assert.equal((await req('GET', `/oauth/verify?code=${missingSessVerify}`)).status, 400)
	const crossUserSessVerify = db.tokens.createState({ mode: 'verify', userId: user.id, sessionId: otherSess.id })
	assert.equal((await req('GET', `/oauth/verify?code=${crossUserSessVerify}`)).status, 400)
	const existingSessVerify = db.tokens.createState({ mode: 'verify', userId: user.id, sessionId: session.id, admin: 1, newAppIds: [newApp.id], name: 'Linked Session' })
	const getExistingVerify = await req('GET', `/oauth/verify?code=${existingSessVerify}`)
	assert.equal(getExistingVerify.status, 200)
	assert.ok(getExistingVerify.text.includes('Test Google App · calendar (read), gmail (write)'), 'Verify page renders app scope summary')
	assert.ok(getExistingVerify.text.includes(`value="${app.id}" checked>`), 'Existing linked app is pre-checked')
	assert.ok(getExistingVerify.text.includes(`value="${newApp.id}" checked>`), 'Newly connected admin app is pre-checked')
	assert.ok(getExistingVerify.text.includes(`value="${extraApp.id}">`), 'Unlinked prior app stays unchecked')
	const postExistingBody = new URLSearchParams({ code: existingSessVerify })
	postExistingBody.append('app_id', extraApp.id)
	postExistingBody.append('app_id', foreignApp.id)
	postExistingBody.append('app_id', 'bogus-id')
	const postExistingVerify = await req('POST', '/oauth/verify', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: postExistingBody.toString()
	})
	assert.equal(postExistingVerify.status, 200)
	assert.deepEqual(db.links.listBySessionId(session.id).map(l => l.appId), [extraApp.id], 'Existing-session /oauth/verify unlinks unchecked apps and drops cross-user/invalid app_ids')
	const verifyCode = db.tokens.createState({ mode: 'verify', userId: user.id, name: 'Verify App', clientRedirectUri: 'https://antigravity.google/oauth-callback', clientState: 'st1' })
	assert.equal((await req('GET', `/oauth/verify?code=${verifyCode}`)).status, 200)
	assert.ok(db.tokens.getState(verifyCode), 'GET /oauth/verify must not consume state (scanner-safe)')
	const postVerifyBody = new URLSearchParams({ code: verifyCode })
	postVerifyBody.append('app_id', app.id)
	postVerifyBody.append('app_id', foreignApp.id)
	postVerifyBody.append('app_id', 'bogus-id')
	const postVerify = await req('POST', '/oauth/verify', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: postVerifyBody.toString(),
		redirect: 'manual'
	})
	assert.equal(postVerify.status, 302)
	assert.equal(db.tokens.getState(verifyCode), null)
	assert.equal(db.sqlite.prepare("SELECT COUNT(*) AS n FROM links WHERE app_id = ?").get(app.id).n, 0, 'Unlinked app has no links until /oauth/token exchanges auth code')
	const authCode = new URL(postVerify.headers.get('location')).searchParams.get('code')
	const tokenRes = await req('POST', '/oauth/token', { body: { grant_type: 'authorization_code', code: authCode, redirect_uri: 'https://antigravity.google/oauth-callback' } })
	assert.equal(tokenRes.status, 200)
	const verifySess = db.tokens.getByToken(tokenRes.data.access_token)
	assert.deepEqual(db.links.listBySessionId(verifySess.id).map(l => l.appId), [app.id], 'Fresh-login /oauth/verify drops cross-user/invalid app_ids')
	assert.equal((await req('PUT', '/oauth/verify')).status, 405)
	assert.equal((await req('POST', '/oauth/verify', {
		headers: { origin: 'https://evil.example.com', 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: verifyCode }).toString()
	})).status, 403)
	assert.equal((await req('POST', '/oauth/verify', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ code: verifyCode }).toString()
	})).status, 400, 'Consumed verify code cannot be replayed')
	await withEnv({ GITHUB_CLIENT_ID: 'gh-e2e-id', GITHUB_CLIENT_SECRET: 'gh-e2e-sec' }, async () => {
		const { session: ownerAdmin } = createTestSession({ account: 'e2e-link-owner@example.com', admin: true })
		const ghOwner = db.logins.resolveUser('github', 'e2e-gh-user')
		const ghMergedApp = db.tokens.create({ userId: ghOwner.id, provider: 'linear', type: 'static', name: 'GH Merged Linear', credentials: { bearer: 'lin_gh' } })
		assert.equal((await req('GET', '/oauth/authorize?code=invalid-setup-code')).status, 403)
		const linkRes = JSON.parse((await mcp(ownerAdmin.token, 'admin', { action: 'link_login', provider: 'github', merge: true })).content[0].text)
		const setupCode = new URL(linkRes.connectUrl).searchParams.get('code')
		const authPage = await req('GET', `/oauth/authorize?code=${encodeURIComponent(setupCode)}`)
		assert.equal(authPage.status, 200)
		assert.ok(authPage.text.includes('"linkMode":true') && authPage.text.includes('"mergeMode":true'))
		const consentRedirect = await req('POST', '/oauth/authorize/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: setupCode, provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(consentRedirect.status, 302)
		const ghState = new URL(consentRedirect.headers.get('location')).searchParams.get('state')
		await withMockFetch(async (input, init, origFetch) => {
			const u = typeof input === 'string' ? input : input.url
			if (u === 'https://github.com/login/oauth/access_token') return Response.json({ access_token: 'gho_e2e', token_type: 'bearer' })
			if (u === 'https://api.github.com/user') return Response.json({ login: 'e2e-gh-user' })
			return origFetch(input, init)
		}, async origFetch => {
			const cbRes = await origFetch(`${baseUrl()}/oauth/callback?code=gh_e2e&state=${ghState}`, { redirect: 'manual' })
			assert.equal(cbRes.status, 302)
			const verifyLoc = new URL(cbRes.headers.get('location'), baseUrl())
			assert.equal(verifyLoc.pathname, '/oauth/verify')
			const linkVerifyCode = verifyLoc.searchParams.get('code')
			const verifyPost = await origFetch(`${baseUrl()}/oauth/verify`, {
				method: 'POST',
				headers: { origin: baseUrl(), 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ code: linkVerifyCode, app_id: ghMergedApp.id }).toString()
			})
			assert.equal(verifyPost.status, 200)
			assert.ok(db.links.listBySessionId(ownerAdmin.id).some(l => l.appId === ghMergedApp.id))
		})
	})
	const { session: gatedAdmin } = createTestSession({ account: 'local-gated@example.com', admin: true })
	assert.equal((await req('POST', '/oauth/authorize/consent', {
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ token: gatedAdmin.token }).toString()
	})).status, 403, 'Local token sign-in rejected when OAuth providers exist')
	assert.equal(bootstrapLocalAdmin(), null, 'bootstrapLocalAdmin no-ops when OAuth providers are configured')
	await withEnv({ GOOGLE_CLIENT_ID: undefined, GITHUB_CLIENT_ID: undefined }, async () => {
		assert.deepEqual(providers.listOauthProviders('auth'), [])
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
	app = db.tokens.updateCredentials(app.id, {
		credentials: { accessToken: 'ya29.old', refreshToken: '1//old-r', account: 'reauth-owner@example.com' },
		expiresAt: Date.now() - 1000,
		scopes: 'https://mail.google.com/ https://www.googleapis.com/auth/calendar.readonly'
	})
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
		const noExpiryApp = db.tokens.updateCredentials(app.id, { credentials: { ...db.tokens.get(app.id).credentials, accessToken: 'ya29.noexp' }, expiresAt: null })
		assert.equal((await providers.google.resolveCredentials(noExpiryApp)).headers.authorization, 'Bearer ya29.noexp')
		assert.equal(refreshCalls, 1, 'OAuth token without expiresAt must not refresh on every request')
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
		const reauthHtml = await (await origFetch(`${baseUrl()}${reauthUrl.pathname}${reauthUrl.search}`)).text()
		const initMatch = reauthHtml.match(/const initData = (\{[^\n]+\})/)
		assert.ok(initMatch, 'reauth connect page embeds initData JSON')
		const initData = JSON.parse(initMatch[1])
		assert.equal(initData.params.reauth_app_id, app.id, 'reauth connect page pre-populates reauth_app_id')
		assert.equal(initData.params.services, 'calendar:read,gmail:write', 'reauth connect page pre-populates granted services')
		const overrideHtml = await (await origFetch(`${baseUrl()}${reauthUrl.pathname}${reauthUrl.search}&services=docs:write`)).text()
		const overrideData = JSON.parse(overrideHtml.match(/const initData = (\{[^\n]+\})/)[1])
		assert.equal(overrideData.params.services, 'docs:write')
		const repeatParamHtml = await (await origFetch(`${baseUrl()}${reauthUrl.pathname}${reauthUrl.search}&services=gmail&services=calendar:write`)).text()
		const repeatParamData = JSON.parse(repeatParamHtml.match(/const initData = (\{[^\n]+\})/)[1])
		assert.equal(repeatParamData.params.services, 'gmail:read,calendar:write')
		const clearParamHtml = await (await origFetch(`${baseUrl()}${reauthUrl.pathname}${reauthUrl.search}&services=`)).text()
		const clearParamData = JSON.parse(clearParamHtml.match(/const initData = (\{[^\n]+\})/)[1])
		assert.equal(clearParamData.params.services, '')
		const presetConnect = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'google', name: 'Preset Google', services: ['gmail', 'calendar:write', 'books'] })).content[0].text)
		const presetUrl = new URL(presetConnect.connectUrl)
		const presetHtml = await (await origFetch(`${baseUrl()}${presetUrl.pathname}${presetUrl.search}`)).text()
		const presetData = JSON.parse(presetHtml.match(/const initData = (\{[^\n]+\})/)[1])
		assert.equal(presetData.params.services, 'gmail:read,calendar:write,books:write', 'connect_app services preset populates connect page')
		const emptyConsentRes = await origFetch(`${baseUrl()}/providers/google/consent`, {
			method: 'POST',
			headers: { origin: baseUrl(), 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: presetUrl.searchParams.get('code'), app_name: 'Unchecked Google' }).toString(),
			redirect: 'manual'
		})
		assert.equal(emptyConsentRes.status, 302)
		const emptyConsentLoc = new URL(emptyConsentRes.headers.get('location'))
		assert.equal(emptyConsentLoc.searchParams.get('scope'), 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile')
		const reauthPresetConnect = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', appId: app.id, services: ['drive:write'] })).content[0].text)
		const reauthPresetUrl = new URL(reauthPresetConnect.connectUrl)
		const reauthPresetHtml = await (await origFetch(`${baseUrl()}${reauthPresetUrl.pathname}${reauthPresetUrl.search}`)).text()
		const reauthPresetData = JSON.parse(reauthPresetHtml.match(/const initData = (\{[^\n]+\})/)[1])
		assert.equal(reauthPresetData.params.services, 'drive:write', 'connect_app services on appId overrides existing scopes fallback')
		const connectInfo = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'google', name: 'Work Google' })).content[0].text)
		const connectUrl = new URL(connectInfo.connectUrl)
		const connectCode = connectUrl.searchParams.get('code')
		assert.ok((await (await origFetch(`${baseUrl()}${connectUrl.pathname}${connectUrl.search}`)).text()).includes('Work Google'))
		const consentRes = await origFetch(`${baseUrl()}/providers/google/consent`, {
			method: 'POST',
			headers: { origin: baseUrl(), 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: connectCode, services: 'gmail:write', app_name: 'Work Google' }).toString(),
			redirect: 'manual'
		})
		assert.equal(consentRes.status, 302)
		const consentLocation = new URL(consentRes.headers.get('location'))
		assert.ok(consentLocation.searchParams.get('scope').includes('https://mail.google.com/'))
		const consentState = consentLocation.searchParams.get('state')
		returnedEmail = 'connected-ui@example.com'
		assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${consentState}`)).status, 200)
		const createdApp = db.tokens.listByUserId(adminSess.userId).find(t => t.type === 'oauth' && t.name === 'Work Google')
		assert.equal(createdApp?.credentials?.account, 'connected-ui@example.com')
		assert.ok(db.links.listBySessionId(adminSess.id).some(l => l.appId === createdApp.id), 'connect flow auto-links new OAuth app')
	})
	await withEnv({ OAUTH_TIMEOUT_MS: '25' }, async () => {
		const expiredApp = db.tokens.updateCredentials(app.id, { credentials: { ...db.tokens.get(app.id).credentials }, expiresAt: Date.now() - 1000 })
		await withEnv({ GOOGLE_CLIENT_SECRET: undefined }, async () => {
			assert.equal((await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })).status, 500)
		})
		let refreshMode = 'slow'
		let userInfoCalls = 0
		await withMockFetch((input, init, origFetch) => {
			const u = typeof input === 'string' ? input : input.url
			if (u === 'https://oauth2.googleapis.com/token') {
				const form = new URLSearchParams(String(init?.body || ''))
				if (form.get('grant_type') === 'refresh_token') {
					if (refreshMode === 'invalid_client') return Response.json({ error: 'invalid_client' }, { status: 400 })
					if (refreshMode === 'upstream_503') return Response.json({ error: 'temporarily_unavailable' }, { status: 503 })
					if (refreshMode === 'invalid_grant') return Response.json({ error: 'invalid_grant', error_description: 'Token revoked' }, { status: 400 })
					if (refreshMode === 'missing_token_json') return Response.json({ token_type: 'Bearer', expires_in: 3600 })
					if (refreshMode === 'missing_token_text') return new Response('unexpected plain response', { status: 200 })
					if (refreshMode === 'body_stall') {
						return new Response(new ReadableStream({
							start (c) {
								init?.signal?.addEventListener('abort', () => c.error(init.signal.reason), { once: true })
							}
						}), { status: 200, headers: { 'content-type': 'application/json' } })
					}
				}
				if (refreshMode === 'exchange_missing_token') return Response.json({ access_token: '' })
				if (refreshMode === 'exchange_net_err') return Promise.reject(new Error('ECONNRESET'))
				if (refreshMode === 'exchange_userinfo_slow' && form.get('code') === 'ui-slow') {
					return Response.json({ access_token: 'ya29.ui-slow' })
				}
				if (refreshMode === 'exchange' && (form.get('code') !== 'slow' || !['http://localhost/cb', `${baseUrl()}/oauth/callback`].includes(form.get('redirect_uri')))) {
					return Response.json({ error: 'invalid_request' }, { status: 400 })
				}
				return new Promise((_, reject) => {
					init?.signal?.addEventListener('abort', () => reject(init.signal.reason), { once: true })
				})
			}
			if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') {
				userInfoCalls++
				return new Promise((_, reject) => {
					init?.signal?.addEventListener('abort', () => reject(init.signal.reason), { once: true })
				})
			}
			return origFetch(input, init)
		}, async origFetch => {
			const beforeCreds = db.tokens.get(expiredApp.id)
			assert.equal((await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })).status, 504)
			refreshMode = 'missing_token_json'
			assert.equal((await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })).status, 502)
			refreshMode = 'missing_token_text'
			assert.equal((await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })).status, 502)
			const afterCreds = db.tokens.get(expiredApp.id)
			assert.equal(afterCreds.credentials.accessToken, beforeCreds.credentials.accessToken, 'Missing access_token in 200 OK refresh response must not overwrite stored accessToken')
			assert.equal(afterCreds.expiresAt, beforeCreds.expiresAt, 'Missing access_token in 200 OK refresh response must not overwrite expiresAt')
			refreshMode = 'body_stall'
			assert.equal((await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })).status, 504)
			refreshMode = 'invalid_client'
			assert.equal((await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })).status, 502)
			refreshMode = 'upstream_503'
			assert.equal((await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })).status, 502)
			refreshMode = 'invalid_grant'
			const revokedRes = await req('GET', '/api/google/gmail/v1/users/me/profile', { token: adminSess.token, headers: { 'x-upstream-app': expiredApp.id } })
			assert.equal(revokedRes.status, 401)
			assert.match(revokedRes.data.error, /connect_app/)
			refreshMode = 'exchange_missing_token'
			await assert.rejects(() => providers.google.exchangeCode({ code: 'empty', callbackUrl: 'http://localhost/cb' }), { status: 502, message: /missing access_token/ })
			assert.equal(userInfoCalls, 0, 'Missing access_token from token endpoint must fail before querying userinfo')
			const emptyTokState = db.tokens.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=empty&state=${emptyTokState}`)).status, 502)
			refreshMode = 'exchange'
			await assert.rejects(() => providers.google.exchangeCode({ code: 'slow', callbackUrl: 'http://localhost/cb' }), { status: 504, message: /timed out/i })
			const slowCbState = db.tokens.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=slow&state=${slowCbState}`)).status, 504)
			refreshMode = 'exchange_userinfo_slow'
			const slowUiState = db.tokens.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=ui-slow&state=${slowUiState}`)).status, 504)
			refreshMode = 'exchange_net_err'
			const netErrState = db.tokens.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=net&state=${netErrState}`)).status, 502)
		})
	})
})

test('getActiveSession allows in-flight setup/verify for refreshable OAuth sessions past 1h access expiry but rejects expired non-refreshable sessions', async () => {
	const { user, app } = createTestSession({ account: 'midflow@example.com', admin: true })
	const refreshableSess = db.tokens.create({
		userId: user.id,
		provider: 'self',
		type: 'bearer',
		admin: 1,
		expiresAt: Date.now() - 1000,
		credentials: { refreshToken: 'rt_midflow' }
	})
	const hardExpiredSess = db.tokens.create({
		userId: user.id,
		provider: 'self',
		type: 'bearer',
		admin: 1,
		expiresAt: Date.now() - 1000
	})
	assert.equal(db.tokens.resolveSession(refreshableSess.token), null)
	assert.ok(db.tokens.getActiveSession(refreshableSess.id))
	assert.equal(db.tokens.getActiveSession(hardExpiredSess.id), null)
	const verifyRefreshable = db.tokens.createState({ mode: 'verify', userId: user.id, sessionId: refreshableSess.id, admin: true, newAppIds: [app.id] })
	const verifyGet = await req('GET', `/oauth/verify?code=${verifyRefreshable}`)
	assert.equal(verifyGet.status, 200)
	const verifyPost = await req('POST', '/oauth/verify', {
		headers: { 'content-type': 'application/x-www-form-urlencoded', origin: baseUrl() },
		body: `code=${encodeURIComponent(verifyRefreshable)}&app_id=${encodeURIComponent(app.id)}`
	})
	assert.equal(verifyPost.status, 200)
	assert.ok(db.links.listBySessionId(refreshableSess.id).some(l => l.appId === app.id))
	const setupState = db.tokens.createState({ mode: 'setup_link', sessionId: refreshableSess.id })
	assert.equal((await req('GET', `/oauth/authorize?code=${encodeURIComponent(setupState)}`)).status, 200)
	const verifyHardExpired = db.tokens.createState({ mode: 'verify', userId: user.id, sessionId: hardExpiredSess.id, admin: true, newAppIds: [app.id] })
	assert.equal((await req('GET', `/oauth/verify?code=${verifyHardExpired}`)).status, 400)
	const staleUpdated = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString()
	db.sqlite.prepare('UPDATE tokens SET updated = ? WHERE id = ?').run(staleUpdated, refreshableSess.id)
	assert.equal(db.tokens.getActiveSession(refreshableSess.id), null)
})

test('OAUTH_PROVIDERS separates auth and app roles across authorize, link_login, share_app, connect_app, and callback', async () => {
	const { session: adminSess } = createTestSession({ account: 'oauth-roles@example.com', admin: true })
	const stripeApp = db.tokens.create({
		userId: adminSess.userId,
		provider: 'stripe',
		type: 'static',
		credentials: { bearer: 'sk_test', baseUrl: 'https://api.stripe.com' }
	})
	const ghExistingApp = db.tokens.create({
		userId: adminSess.userId,
		provider: 'github',
		type: 'oauth',
		credentials: { accessToken: 'gho_reauth', account: 'octo-reauth' }
	})
	await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-sec', OAUTH_PROVIDERS: 'google,github:app' }, async () => {
		assert.deepEqual(providers.listOauthProviders('auth').map(p => p.id), ['google'])
		assert.deepEqual(providers.listOauthProviders('app').map(p => p.id), ['google', 'github'])
		const authPage = await req('GET', '/oauth/authorize')
		assert.equal(authPage.status, 200)
		assert.doesNotMatch(authPage.text, /"id":"github"/)
		const ghLoginConsent = await req('POST', '/oauth/authorize/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(ghLoginConsent.status, 400)
		assert.equal((await mcp(adminSess.token, 'admin', { action: 'link_login', provider: 'github' })).isError, true)
		assert.equal((await mcp(adminSess.token, 'admin', { action: 'share_app', appId: stripeApp.id, account: 'github:octo' })).isError, true)
		await withEnv({ SSO_DOMAINS: 'corp.io:github' }, async () => {
			assert.equal((await mcp(adminSess.token, 'admin', { action: 'share_app', appId: stripeApp.id, account: 'bob@corp.io' })).isError, true)
		})
		const ghConnect = await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'github' })
		assert.equal(ghConnect.isError, undefined)
		const ghConnectUrl = new URL(JSON.parse(ghConnect.content[0].text).connectUrl)
		assert.equal((await req('GET', `${ghConnectUrl.pathname}${ghConnectUrl.search}`)).status, 200)
		const toolsBoth = await req('POST', '/mcp', { token: adminSess.token, body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } })
		const bothServicesDesc = toolsBoth.data.result.tools.find(t => t.name === 'admin').inputSchema.properties.services.description
		assert.match(bothServicesDesc, /github:.*packages \[read, write, delete\]/)
		const ghConsent = await req('POST', '/providers/github/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: ghConnectUrl.searchParams.get('code') }).toString(),
			redirect: 'manual'
		})
		assert.equal(ghConsent.status, 302)
		const ghPresetConnect = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'github', name: 'Preset GitHub', services: ['packages:delete', 'org:admin'] })).content[0].text)
		const ghPresetUrl = new URL(ghPresetConnect.connectUrl)
		const ghConnectRes = await req('GET', `${ghPresetUrl.pathname}${ghPresetUrl.search}`)
		assert.equal(ghConnectRes.status, 200)
		const ghInitData = JSON.parse(ghConnectRes.text.match(/const initData = (\{[^\n]+\})/)[1])
		assert.equal(ghInitData.params.services, 'packages:delete,org:admin')
		const ghPresetConsent = await req('POST', '/providers/github/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: ghPresetUrl.searchParams.get('code'), services: 'packages:delete,org:admin', app_name: 'Preset GitHub' }).toString(),
			redirect: 'manual'
		})
		assert.equal(ghPresetConsent.status, 302)
		const ghAuthRedirect = new URL(ghPresetConsent.headers.get('location'))
		assert.deepEqual(ghAuthRedirect.searchParams.get('scope').split(' '), ['read:user', 'delete:packages', 'admin:org'])
		await withMockFetch((input, init, origFetch) => {
			const u = typeof input === 'string' ? input : input.url
			if (u === 'https://github.com/login/oauth/access_token') return Response.json({ access_token: 'gho_ui', token_type: 'bearer', scope: 'read:user,delete:packages,admin:org' })
			if (u === 'https://api.github.com/user') return Response.json({ login: 'octo-ui' })
			return origFetch(input, init)
		}, async origFetch => {
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${ghAuthRedirect.searchParams.get('state')}`)).status, 200)
		})
		const createdGh = db.tokens.listByUserId(adminSess.userId).find(t => t.provider === 'github' && t.name === 'Preset GitHub')
		assert.equal(createdGh?.scopes, 'read:user,delete:packages,admin:org')
		const clearedNameCode = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSess.id, provider: 'github', name: 'Temporary Label' })
		const clearedConsent = await req('POST', '/providers/github/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: clearedNameCode, app_name: '' }).toString(),
			redirect: 'manual'
		})
		assert.equal(clearedConsent.status, 302)
		const clearedState = new URL(clearedConsent.headers.get('location')).searchParams.get('state')
		assert.equal(db.tokens.getState(clearedState).name, null, 'Clearing app_name to "" overrides preset setup.name')
		const ghReauthConnect = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', appId: createdGh.id })).content[0].text)
		const ghReauthUrl = new URL(ghReauthConnect.connectUrl)
		const ghReauthHtml = await req('GET', `${ghReauthUrl.pathname}${ghReauthUrl.search}`)
		assert.equal(JSON.parse(ghReauthHtml.text.match(/const initData = (\{[^\n]+\})/)[1]).params.services, 'packages:delete,org:admin')
		const loginCbState = db.tokens.createState({ mode: 'login', provider: 'github' })
		assert.equal((await req('GET', `/oauth/callback?code=c&state=${loginCbState}`)).status, 403)
		const linkCbState = db.tokens.createState({ mode: 'auth', sessionId: adminSess.id, provider: 'github' })
		assert.equal((await req('GET', `/oauth/callback?code=c&state=${linkCbState}`)).status, 403)
	})
	await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-sec', OAUTH_PROVIDERS: 'google,github:auth' }, async () => {
		assert.deepEqual(providers.listOauthProviders('auth').map(p => p.id), ['google', 'github'])
		assert.deepEqual(providers.listOauthProviders('app').map(p => p.id), ['google'])
		const ghLoginConsent = await req('POST', '/oauth/authorize/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ provider: 'github' }).toString(),
			redirect: 'manual'
		})
		assert.equal(ghLoginConsent.status, 302)
		assert.equal((await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'github' })).isError, true)
		assert.equal((await mcp(adminSess.token, 'admin', { action: 'connect_app', appId: ghExistingApp.id })).isError, true)
		assert.equal((await req('GET', '/providers/github/connect')).status, 404)
		assert.equal((await req('POST', '/providers/github/consent')).status, 404)
		const connectCbState = db.tokens.createState({ mode: 'connect', sessionId: adminSess.id, provider: 'github' })
		assert.equal((await req('GET', `/oauth/callback?code=c&state=${connectCbState}`)).status, 403)
		const legacyCbState = db.tokens.createState({ mode: null, sessionId: adminSess.id, provider: 'github' })
		assert.equal((await req('GET', `/oauth/callback?code=c&state=${legacyCbState}`)).status, 403)
		const staticGh = await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'github', credentials: 'ghp_static_pat' })
		assert.equal(staticGh.isError, undefined)
		assert.equal(JSON.parse(staticGh.content[0].text).app.type, 'static')
		const toolsGoogleOnly = await req('POST', '/mcp', { token: adminSess.token, body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} } })
		const googleOnlyDesc = toolsGoogleOnly.data.result.tools.find(t => t.name === 'admin').inputSchema.properties.services.description
		assert.match(googleOnlyDesc, /google: /)
		assert.doesNotMatch(googleOnlyDesc, /github: /)
	})
	await withEnv({ OAUTH_PROVIDERS: 'google:app' }, async () => {
		assert.deepEqual(providers.listOauthProviders('auth'), [])
		assert.deepEqual(providers.listOauthProviders('app').map(p => p.id), ['google'])
		const authPage = await req('GET', '/oauth/authorize')
		assert.equal(authPage.status, 200)
		assert.match(authPage.text, /"localAuth":true/)
		const localConsent = await req('POST', '/oauth/authorize/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ token: adminSess.token, session_name: 'App-Only Local' }).toString(),
			redirect: 'manual'
		})
		assert.equal(localConsent.status, 302)
		assert.match(localConsent.headers.get('location'), /^https?:\/\/[^/]+\/oauth\/verify\?code=/)
		assert.equal((await mcp(adminSess.token, 'admin', { action: 'link_login' })).isError, true)
		db.sqlite.exec("DELETE FROM tokens WHERE provider = 'self'")
		const bootstrapped = bootstrapLocalAdmin()
		assert.ok(bootstrapped?.admin)
	})
})

test('static app browser connect flow supports pre-filled metadata, custom providers, OAuth-provider static tokens, JSON credentials, and credential rotation without exposing keys to agents', async () => {
	const parseInit = html => JSON.parse(html.match(/const initData = (\{[^\n]+\})/)[1])
	const { session: adminSess } = createTestSession({ account: 'static-ui@example.com', admin: true })
	const nonAdmin = db.tokens.create({ userId: adminSess.userId, provider: 'self', admin: 0 })
	const toolsRes = await req('POST', '/mcp', { token: adminSess.token, body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } })
	const adminSchema = toolsRes.data.result.tools.find(t => t.name === 'admin').inputSchema
	assert.deepEqual(adminSchema.properties.type.enum, ['oauth', 'static'])
	const startRes = JSON.parse((await mcp(adminSess.token, 'admin', {
		action: 'connect_app',
		provider: 'stripe',
		name: 'Billing Prod',
		baseUrl: 'https://api.stripe.com'
	})).content[0].text)
	assert.equal(startRes.actionRequired, 'browser_flow')
	assert.match(startRes.connectUrl, /^https?:\/\/[^/]+\/apps\/connect\?code=/)
	const setupCode = new URL(startRes.connectUrl).searchParams.get('code')
	assert.equal((await req('GET', '/apps/connect')).status, 403)
	assert.equal((await req('GET', '/apps/connect?code=bogus')).status, 403)
	assert.equal((await req('PUT', `/apps/connect?code=${encodeURIComponent(setupCode)}`)).status, 405)
	const oauthSetupCode = db.tokens.createState({ mode: 'setup_connect', sessionId: adminSess.id, provider: 'google' })
	assert.equal((await req('GET', `/apps/connect?code=${encodeURIComponent(oauthSetupCode)}`)).status, 403)
	assert.equal((await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: { code: oauthSetupCode, provider: 'stripe', baseUrl: 'https://api.stripe.com', credentials: 'sk_wrong_mode' }
	})).status, 403)
	assert.ok(db.tokens.getState(oauthSetupCode), 'POST /apps/connect must not consume wrong-mode setup code')
	const foreignUser = db.users.create()
	const foreignStatic = db.tokens.create({ userId: foreignUser.id, provider: 'stripe', type: 'static', credentials: { headers: { authorization: 'Bearer sk_foreign' }, baseUrl: 'https://api.stripe.com' } })
	const ownOauth = db.tokens.create({ userId: adminSess.userId, provider: 'google', type: 'oauth', credentials: { accessToken: 'ya29.own', account: 'own@example.com' } })
	for (const badReauth of [foreignStatic, ownOauth]) {
		const badReauthCode = db.tokens.createState({ mode: 'setup_static', sessionId: adminSess.id, provider: badReauth.provider, reauthAppId: badReauth.id })
		assert.equal((await req('GET', `/apps/connect?code=${encodeURIComponent(badReauthCode)}`)).status, 403)
		assert.equal((await req('POST', '/apps/connect', {
			headers: { 'content-type': 'application/json', origin: baseUrl() },
			body: { code: badReauthCode, baseUrl: 'https://api.stripe.com', credentials: 'sk_hijack' }
		})).status, 403)
	}
	assert.equal(db.tokens.get(foreignStatic.id).credentials.headers.authorization, 'Bearer sk_foreign')
	assert.equal((await req('GET', `/providers/google/connect?code=${encodeURIComponent(setupCode)}`)).status, 403)
	const wrongConsentRes = await req('POST', '/providers/google/consent', {
		headers: { 'content-type': 'application/x-www-form-urlencoded', origin: baseUrl() },
		body: new URLSearchParams({ code: setupCode }).toString()
	})
	assert.equal(wrongConsentRes.status, 403)
	assert.ok(db.tokens.getState(setupCode), 'POST /providers/:provider/consent must not consume wrong-mode setup code')
	const wrongVerifyRes = await req('POST', '/oauth/verify', {
		headers: { 'content-type': 'application/x-www-form-urlencoded', origin: baseUrl() },
		body: new URLSearchParams({ code: setupCode }).toString()
	})
	assert.equal(wrongVerifyRes.status, 400)
	assert.ok(db.tokens.getState(setupCode), 'POST /oauth/verify must not consume wrong-mode setup code')
	const nonAdminStatic = db.tokens.createState({ mode: 'setup_static', sessionId: nonAdmin.id, provider: 'stripe' })
	assert.equal((await req('GET', `/apps/connect?code=${encodeURIComponent(nonAdminStatic)}`)).status, 403)
	const pageRes = await req('GET', `/apps/connect?code=${encodeURIComponent(setupCode)}`)
	assert.equal(pageRes.status, 200)
	assert.equal(pageRes.headers.get('cache-control'), 'no-store')
	assert.equal(pageRes.headers.get('x-frame-options'), 'DENY')
	assert.equal(pageRes.text.includes('name="account"'), false, 'Static connect UI must not render an account input')
	const initData = parseInit(pageRes.text)
	assert.deepEqual(initData, {
		code: setupCode,
		updateMode: false,
		provider: 'stripe',
		name: 'Billing Prod',
		baseUrl: 'https://api.stripe.com'
	})
	const crossOriginRes = await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
		body: { code: setupCode, provider: 'stripe', baseUrl: 'https://api.stripe.com', credentials: 'sk_live_secret' }
	})
	assert.equal(crossOriginRes.status, 403)
	for (const extraBody of [
		{ code: setupCode, provider: 'stripe', baseUrl: 'https://api.stripe.com', account: 'acct_prod', credentials: 'sk_live_secret' },
		{ code: setupCode, provider: 'stripe', base_url: 'https://api.stripe.com', credentials: 'sk_live_secret' }
	]) {
		assert.equal((await req('POST', '/apps/connect', {
			headers: { 'content-type': 'application/json', origin: baseUrl() },
			body: extraBody
		})).status, 400)
	}
	const badSubmit = await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: { code: setupCode, provider: 'stripe', baseUrl: 'http://insecure.example.com', credentials: 'sk_live_secret' }
	})
	assert.equal(badSubmit.status, 400)
	assert.match(badSubmit.data.error, /Valid https:\/\/ baseUrl/)
	const okSubmit = await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: {
			code: setupCode,
			provider: 'stripe',
			name: 'Billing Prod',
			baseUrl: 'https://api.stripe.com',
			credentials: 'sk_live_browser_secret'
		}
	})
	assert.equal(okSubmit.status, 200)
	assert.equal(okSubmit.data.connected, true)
	assert.equal(okSubmit.data.updated, false)
	assert.equal(JSON.stringify(okSubmit.data).includes('sk_live_browser_secret'), false)
	const createdStripe = db.tokens.get(okSubmit.data.appId)
	assert.equal(createdStripe.type, 'static')
	assert.equal(createdStripe.provider, 'stripe')
	assert.equal(createdStripe.name, 'Billing Prod')
	assert.equal(createdStripe.credentials.baseUrl, 'https://api.stripe.com')
	assert.equal(createdStripe.credentials.account, undefined)
	assert.equal(createdStripe.credentials.headers.authorization, 'Bearer sk_live_browser_secret')
	assert.ok(db.links.listBySessionId(adminSess.id).some(l => l.appId === createdStripe.id), 'static browser connect auto-links new app to requesting session')
	assert.equal((await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: { code: setupCode, provider: 'stripe', baseUrl: 'https://api.stripe.com', credentials: 'sk_replay' }
	})).status, 403)
	const rotateStart = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', appId: createdStripe.id })).content[0].text)
	assert.equal(rotateStart.actionRequired, 'browser_flow')
	const rotateCode = new URL(rotateStart.connectUrl).searchParams.get('code')
	const rotatePage = await req('GET', `/apps/connect?code=${encodeURIComponent(rotateCode)}`)
	assert.equal(rotatePage.status, 200)
	assert.equal(rotatePage.text.includes('sk_live_browser_secret'), false, 'existing static secrets must never be sent to browser UI')
	const rotateInit = parseInit(rotatePage.text)
	assert.deepEqual(rotateInit, {
		code: rotateCode,
		updateMode: true,
		provider: 'stripe',
		name: 'Billing Prod',
		baseUrl: 'https://api.stripe.com'
	})
	const changeProviderErr = await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: { code: rotateCode, provider: 'anthropic', baseUrl: 'https://api.anthropic.com', credentials: 'sk_new' }
	})
	assert.equal(changeProviderErr.status, 400)
	const rotatePreserve = await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: { code: rotateCode, credentials: 'sk_rotated_preserve' }
	})
	assert.equal(rotatePreserve.status, 200)
	assert.equal(rotatePreserve.data.updated, true)
	assert.equal(rotatePreserve.data.appId, createdStripe.id)
	assert.equal(db.tokens.get(createdStripe.id).name, 'Billing Prod', 'Omitting name on rotation preserves existing app name')
	assert.equal(db.tokens.get(createdStripe.id).credentials.baseUrl, 'https://api.stripe.com', 'Omitting baseUrl on rotation preserves existing baseUrl')
	const rotateClearStart = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', appId: createdStripe.id })).content[0].text)
	const rotateClearCode = new URL(rotateClearStart.connectUrl).searchParams.get('code')
	const rotateSubmit = await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: {
			code: rotateClearCode,
			provider: 'stripe',
			name: '',
			baseUrl: 'https://api.stripe.com/v2',
			credentials: { headers: { 'x-api-key': 'sk_rotated' }, query: { api_version: '2026-01-01' } }
		}
	})
	assert.equal(rotateSubmit.status, 200)
	assert.equal(rotateSubmit.data.updated, true)
	assert.equal(rotateSubmit.data.appId, createdStripe.id)
	const updatedStripe = db.tokens.get(createdStripe.id)
	assert.equal(updatedStripe.name, 'Stripe', 'Explicit empty name resets app name to provider default')
	assert.equal(updatedStripe.credentials.baseUrl, 'https://api.stripe.com/v2')
	assert.equal(updatedStripe.credentials.account, undefined)
	assert.equal(updatedStripe.credentials.headers['x-api-key'], 'sk_rotated')
	assert.equal(updatedStripe.credentials.headers.authorization, undefined)
	assert.equal(updatedStripe.credentials.query.api_version, '2026-01-01')
	const listedApps = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'list_apps' })).content[0].text).apps
	const listedStripe = listedApps.find(a => a.id === createdStripe.id)
	assert.equal('account' in listedStripe, false, 'list_apps must omit account on static apps')
	const blankStart = await req('POST', '/api/apps', { token: adminSess.token, body: { type: 'static' } })
	assert.equal(blankStart.status, 201)
	assert.equal(blankStart.data.actionRequired, 'browser_flow')
	for (const emptyBase of ['', null]) {
		const emptyBaseStart = await req('POST', '/api/apps', { token: adminSess.token, body: { type: 'static', baseUrl: emptyBase } })
		assert.equal(emptyBaseStart.status, 201)
		const emptyCode = new URL(emptyBaseStart.data.connectUrl).searchParams.get('code')
		assert.equal(parseInit((await req('GET', `/apps/connect?code=${encodeURIComponent(emptyCode)}`)).text).baseUrl, '')
	}
	assert.equal((await req('POST', '/api/apps', { token: adminSess.token, body: { type: 'static', baseUrl: 'http://insecure.example' } })).status, 400)
	const blankCode = new URL(blankStart.data.connectUrl).searchParams.get('code')
	const blankInit = parseInit((await req('GET', `/apps/connect?code=${encodeURIComponent(blankCode)}`)).text)
	assert.equal(blankInit.provider, '')
	const blankSubmit = await req('POST', '/apps/connect', {
		headers: { 'content-type': 'application/json', origin: baseUrl() },
		body: {
			code: blankCode,
			provider: 'anthropic',
			baseUrl: 'https://api.anthropic.com',
			credentials: { headers: { 'x-api-key': 'sk-ant-123', 'anthropic-version': '2023-06-01' } }
		}
	})
	assert.equal(blankSubmit.status, 200)
	const createdAnthropic = db.tokens.get(blankSubmit.data.appId)
	assert.equal(createdAnthropic.provider, 'anthropic')
	assert.equal(createdAnthropic.credentials.headers['anthropic-version'], '2023-06-01')
	await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-sec' }, async () => {
		const ghStaticStart = JSON.parse((await mcp(adminSess.token, 'admin', { action: 'connect_app', provider: 'github', type: 'static', name: 'GitHub PAT' })).content[0].text)
		assert.equal(ghStaticStart.actionRequired, 'browser_flow')
		const ghStaticCode = new URL(ghStaticStart.connectUrl).searchParams.get('code')
		const ghInit = parseInit((await req('GET', `/apps/connect?code=${encodeURIComponent(ghStaticCode)}`)).text)
		assert.equal(ghInit.provider, 'github')
		assert.equal(ghInit.baseUrl, 'https://api.github.com')
		const nonJsonSubmit = await req('POST', '/apps/connect', {
			headers: { 'content-type': 'application/x-www-form-urlencoded', origin: baseUrl() },
			body: new URLSearchParams({ code: ghStaticCode, provider: 'github', credentials: 'ghp_form_secret' }).toString()
		})
		assert.equal(nonJsonSubmit.status, 415)
		assert.ok(db.tokens.getState(ghStaticCode), 'Non-JSON submission must not consume setupCode')
		const ghJsonSubmit = await req('POST', '/apps/connect', {
			headers: { 'content-type': 'application/json', origin: baseUrl() },
			body: {
				code: ghStaticCode,
				provider: 'github',
				name: 'GitHub PAT',
				baseUrl: '',
				credentials: 'ghp_form_secret'
			}
		})
		assert.equal(ghJsonSubmit.status, 200)
		assert.equal(ghJsonSubmit.data.title, 'GitHub Connected')
		assert.equal(ghJsonSubmit.data.subtitle, 'Connected GitHub PAT')
		assert.equal(JSON.stringify(ghJsonSubmit.data).includes('ghp_form_secret'), false)
		const createdGhStatic = db.tokens.listByUserId(adminSess.userId).find(t => t.provider === 'github' && t.type === 'static' && t.name === 'GitHub PAT')
		assert.equal(createdGhStatic.credentials.baseUrl, 'https://api.github.com')
		assert.equal(createdGhStatic.credentials.headers.authorization, 'Bearer ghp_form_secret')
	})
	for (const modeCase of [
		{
			tag: 'basic',
			credentials: { basic: 'key_id:sec ' },
			verify: creds => assert.equal(creds.headers.authorization, `Basic ${Buffer.from('key_id:sec ').toString('base64')}`)
		},
		{
			tag: 'headers',
			credentials: { headers: { 'X-Api-Key': 'hdr_secret' } },
			verify: creds => assert.equal(creds.headers['x-api-key'], 'hdr_secret')
		},
		{
			tag: 'query',
			credentials: { query: { api_key: 'q_secret' } },
			verify: creds => assert.equal(creds.query.api_key, 'q_secret')
		},
		{
			tag: 'mixed',
			credentials: { headers: { authorization: 'Bearer j_tok' }, query: { v: '2' } },
			verify: creds => {
				assert.equal(creds.headers.authorization, 'Bearer j_tok')
				assert.equal(creds.query.v, '2')
			}
		}
	]) {
		const modeProv = `custom_${modeCase.tag}`
		const modeCode = db.tokens.createState({ mode: 'setup_static', sessionId: adminSess.id, provider: modeProv, baseUrl: 'https://api.example.com' })
		const modeRes = await req('POST', '/apps/connect', {
			headers: { 'content-type': 'application/json', origin: baseUrl() },
			body: { code: modeCode, provider: modeProv, baseUrl: 'https://api.example.com', credentials: modeCase.credentials }
		})
		assert.equal(modeRes.status, 200)
		const stored = db.tokens.listByUserId(adminSess.userId).find(t => t.provider === modeProv)
		modeCase.verify(stored.credentials)
	}
})

test('buildAuthUrl deduplicates implied weaker scopes without dropping distinct read scopes', async () => {
	await withEnv({ GOOGLE_CLIENT_ID: 'g-cid', GOOGLE_CLIENT_SECRET: 'g-sec', GITHUB_CLIENT_ID: 'gh-cid', GITHUB_CLIENT_SECRET: 'gh-sec' }, async () => {
		const googleUrl = new URL(providers.google.buildAuthUrl({
			state: 'st-g',
			callbackUrl: 'https://jump.example.com/oauth/callback',
			services: ['drive:read', 'drive:write', 'gmail:read', 'gmail:write', 'youtube:read', 'youtube:write', 'photos:read', 'photos:write', 'meet:read', 'meet:write', 'apps_script:read', 'apps_script:write', 'admin:read', 'admin:write']
		}))
		const gScopes = googleUrl.searchParams.get('scope').split(' ')
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/drive'))
		assert.ok(!gScopes.includes('https://www.googleapis.com/auth/drive.readonly'))
		assert.ok(!gScopes.includes('https://www.googleapis.com/auth/drive.activity.readonly'))
		assert.ok(gScopes.includes('https://mail.google.com/'))
		assert.ok(!gScopes.includes('https://www.googleapis.com/auth/gmail.readonly'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/youtube'))
		assert.ok(!gScopes.includes('https://www.googleapis.com/auth/youtube.readonly'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/yt-analytics.readonly'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/photoslibrary.appendonly'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/meetings.space.readonly'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/meetings.space.created'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/script.metrics'))
		assert.ok(!gScopes.includes('https://www.googleapis.com/auth/script.projects.readonly'))
		assert.ok(gScopes.includes('https://www.googleapis.com/auth/admin.reports.audit.readonly'))
		assert.ok(!gScopes.includes('https://www.googleapis.com/auth/admin.directory.user.readonly'))
		const readOnlyUrl = new URL(providers.google.buildAuthUrl({
			state: 'st-g-ro',
			callbackUrl: 'https://jump.example.com/oauth/callback',
			services: ['drive:read', 'gmail:read']
		}))
		const roScopes = readOnlyUrl.searchParams.get('scope').split(' ')
		assert.ok(roScopes.includes('https://www.googleapis.com/auth/drive.readonly'))
		assert.ok(roScopes.includes('https://www.googleapis.com/auth/gmail.readonly'))
		const ghUrl = new URL(providers.github.buildAuthUrl({
			state: 'st-gh',
			callbackUrl: 'https://jump.example.com/oauth/callback',
			services: ['repo:read', 'repo:write', 'org:read', 'org:admin', 'user:write', 'packages:read', 'packages:write']
		}))
		const ghScopes = ghUrl.searchParams.get('scope').split(' ')
		assert.deepEqual(ghScopes, ['repo', 'admin:org', 'user', 'read:packages', 'write:packages'])
	})
})

test('OAuth connect redirect and error responses emit safe [oauth] diagnostic logs without secrets', async () => {
	const { session } = createTestSession({ account: 'log-owner@example.com', admin: 1 })
	const app = db.tokens.create({
		userId: session.userId,
		provider: 'google',
		type: 'oauth',
		name: 'Google App',
		credentials: { accessToken: 'tok', account: 'secret-email@example.com' }
	})
	const logs = []
	const warns = []
	const origLog = console.log
	const origWarn = console.warn
	console.log = (...args) => logs.push(args.join(' '))
	console.warn = (...args) => warns.push(args.join(' '))
	try {
		await withEnv({ GOOGLE_CLIENT_ID: 'cid-123', GOOGLE_CLIENT_SECRET: 'csec-456' }, async () => {
			const connectInfo = JSON.parse((await mcp(session.token, 'admin', { action: 'connect_app', appId: app.id })).content[0].text)
			const setupCode = new URL(connectInfo.connectUrl).searchParams.get('code')
			const consentRes = await fetch(`${baseUrl()}/providers/google/consent`, {
				method: 'POST',
				headers: { origin: baseUrl(), 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ code: setupCode, services: 'gmail:write,calendar' }).toString(),
				redirect: 'manual'
			})
			assert.equal(consentRes.status, 302)
			const locationUrl = consentRes.headers.get('location')
			assert.ok(logs.some(line =>
				line.includes('[oauth] Redirecting provider=google flow=connect') &&
				line.includes(`reauth=${app.id}`) &&
				line.includes(`redirectUri=${baseUrl()}/oauth/callback`) &&
				line.includes('services=gmail:write,calendar:read') &&
				line.includes(`urlLength=${locationUrl.length}`) &&
				line.includes('loginHint=true') &&
				!line.includes('secret-email@example.com') &&
				!line.includes(setupCode)
			), `Expected safe consent redirect log, got: ${logs.join('\n')}`)
			assert.equal((await req('GET', `/providers/google/connect?code=${setupCode}`)).status, 403)
			assert.ok(warns.some(line => line.includes('[oauth] GET /providers/google/connect rejected: invalid or expired setup code')))
			assert.equal((await req('GET', '/oauth/callback?error=invalid_scope&error_description=Bad+scope')).status, 400)
			assert.ok(warns.some(line => line.includes('[oauth] GET /oauth/callback failed: upstream error=invalid_scope (Bad scope)')))
			assert.equal((await req('GET', '/oauth/callback?code=c&state=missing-state')).status, 403)
			assert.ok(warns.some(line => line.includes('[oauth] GET /oauth/callback rejected: invalid or expired OAuth state')))
			createTestSession({ account: 'conflict-email@example.com' })
			const conflictState = db.tokens.createState({ mode: 'auth', sessionId: session.id, provider: 'google', merge: false })
			await withMockFetch(async (input, init, origFetch) => {
				const u = typeof input === 'string' ? input : input.url
				if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'tok', expires_in: 3600 })
				if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') return Response.json({ email: 'conflict-email@example.com', verified_email: true })
				return origFetch(input, init)
			}, async origFetch => {
				const conflictRes = await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${conflictState}`)
				assert.equal(conflictRes.status, 409)
				assert.ok(warns.some(line =>
					line.includes('[oauth] GET /oauth/callback (google auth) conflict: account already registered to another user') &&
					!line.includes('conflict-email@example.com')
				))
			})
		})
	} finally {
		console.log = origLog
		console.warn = origWarn
	}
})
