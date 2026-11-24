import test from 'node:test'
import assert from 'node:assert/strict'
import { useServer, createTestSession, withMockFetch, withEnv, db, providers } from './helpers.js'

useServer()

test('provider-specific hooks: google and github buildAuthUrl, extractAccount, and revokeToken', async () => {
	const googleConnectUrl = new URL(providers.google.buildAuthUrl({ state: 'st-g', callbackUrl: 'https://jump.test/oauth/callback', services: ['gmail'], write: [], loginHint: 'Alice@Example.com' }))
	assert.equal(googleConnectUrl.searchParams.get('access_type'), 'offline')
	assert.equal(googleConnectUrl.searchParams.get('prompt'), 'consent')
	assert.equal(googleConnectUrl.searchParams.get('login_hint'), 'Alice@Example.com')
	const googleLoginUrl = new URL(providers.google.buildAuthUrl({ state: 'st-g2', callbackUrl: 'https://jump.test/oauth/callback', login: true }))
	assert.equal(googleLoginUrl.searchParams.get('access_type'), null)
	assert.equal(googleLoginUrl.searchParams.get('prompt'), null)
	await withEnv({ GITHUB_CLIENT_ID: 'gh_id', GITHUB_CLIENT_SECRET: 'gh_sec' }, async () => {
		const ghAuthUrl = new URL(providers.github.buildAuthUrl({ state: 'st-gh', callbackUrl: 'https://jump.test/oauth/callback', services: ['repo'], write: ['repo'], loginHint: 'octocat' }))
		assert.equal(ghAuthUrl.searchParams.get('login'), 'octocat')
		assert.deepEqual(ghAuthUrl.searchParams.get('scope').split(' '), ['read:user', 'repo'])
	})
	const { session } = createTestSession({ account: 'provider-hooks@example.com', admin: true })
	const googleApp = db.tokens.create({ userId: session.userId, provider: 'google', type: 'oauth', credentials: { accessToken: 'ya29.rev', refreshToken: '1//rev', account: 'provider-hooks@example.com' } })
	const ghApp = db.tokens.create({ userId: session.userId, provider: 'github', type: 'oauth', credentials: { accessToken: 'gho_rev', account: 'octo' } })
	let googleRevokeReq = null
	const ghRevokeReqs = []
	let ghMissingLogin = true
	await withMockFetch((input, init, origFetch) => {
		const u = typeof input === 'string' ? input : input.url
		if (u === 'https://github.com/login/oauth/access_token') {
			return Response.json({ access_token: 'gho_cb', token_type: 'bearer' })
		}
		if (u === 'https://api.github.com/user') {
			return Response.json(ghMissingLogin ? { id: 1 } : { login: 'OctoCat' })
		}
		if (u === 'https://oauth2.googleapis.com/revoke') {
			googleRevokeReq = { method: init?.method, ua: init?.headers?.['user-agent'], contentType: init?.headers?.['content-type'], body: init?.body }
			return new Response(null, { status: 200 })
		}
		if (u.startsWith('https://api.github.com/applications/')) {
			ghRevokeReqs.push({ url: u, method: init?.method, auth: init?.headers?.authorization, ua: init?.headers?.['user-agent'], body: init?.body })
			if (ghRevokeReqs.length > 1) return Promise.reject(new Error('network down'))
			return new Response(null, { status: 204 })
		}
		return origFetch(input, init)
	}, async () => {
		await withEnv({ GITHUB_CLIENT_ID: undefined, GITHUB_CLIENT_SECRET: undefined }, async () => {
			await providers.github.revokeToken(ghApp)
		})
		assert.equal(ghRevokeReqs.length, 0, 'GitHub revoke is a no-op without client credentials')
		await withEnv({ GITHUB_CLIENT_ID: 'gh_id', GITHUB_CLIENT_SECRET: 'gh_sec' }, async () => {
			await assert.rejects(() => providers.github.exchangeCode({ code: 'gh-code', callbackUrl: 'https://jump.test/oauth/callback' }), /Could not retrieve account identifier/)
			ghMissingLogin = false
			const ghExchanged = await providers.github.exchangeCode({ code: 'gh-code', callbackUrl: 'https://jump.test/oauth/callback' })
			assert.equal(ghExchanged.account, 'OctoCat')
			await providers.github.revokeToken(ghApp)
			assert.equal(ghRevokeReqs.length, 1)
			assert.equal(ghRevokeReqs[0].url, 'https://api.github.com/applications/gh_id/token')
			assert.equal(ghRevokeReqs[0].method, 'DELETE')
			assert.equal(ghRevokeReqs[0].ua, 'jump-test')
			assert.equal(ghRevokeReqs[0].auth, `Basic ${Buffer.from('gh_id:gh_sec').toString('base64')}`)
			assert.deepEqual(JSON.parse(ghRevokeReqs[0].body), { access_token: 'gho_rev' })
			await providers.github.revokeToken(ghApp)
			assert.equal(ghRevokeReqs.length, 2, 'GitHub revoke swallows upstream errors without throwing')
		})
		await providers.google.revokeToken(googleApp)
		assert.equal(googleRevokeReq?.method, 'POST')
		assert.equal(googleRevokeReq?.ua, 'jump-test')
		assert.equal(googleRevokeReq?.contentType, 'application/x-www-form-urlencoded')
		assert.equal(new URLSearchParams(googleRevokeReq?.body).get('token'), '1//rev')
	})
})

test('fetchOauth and fetchOauthJson normalize mixed-case and Headers overrides without colliding', async () => {
	const seen = []
	await withMockFetch((input, init) => {
		seen.push({ method: init.method, headers: init.headers, body: init.body })
		return Response.json({ ok: true })
	}, async () => {
		await providers.fetchOauth('https://oauth.example/token', {
			headers: { 'User-Agent': 'custom-ua', 'Content-Type': 'text/plain; charset=utf-8' },
			form: { a: '1' }
		})
		await providers.fetchOauthJson('https://oauth.example/info', {
			headers: new Headers({ Accept: 'application/vnd.github+json', 'X-Extra': 'yes' })
		})
	})
	assert.equal(seen[0].method, 'POST')
	assert.deepEqual(seen[0].headers, {
		'user-agent': 'custom-ua',
		'content-type': 'text/plain; charset=utf-8'
	})
	assert.equal(seen[0].body, 'a=1')
	assert.equal(seen[1].method, 'GET')
	assert.deepEqual(seen[1].headers, {
		accept: 'application/vnd.github+json',
		'x-extra': 'yes',
		'user-agent': 'jump-test'
	})
})

test('provider capability inference and parseOauthProviders validation', () => {
	const okta = providers.createProvider({
		id: 'okta',
		name: 'Okta',
		oauth: {
			authUrl: 'https://okta.example/authorize',
			tokenUrl: 'https://okta.example/token',
			userInfoUrl: 'https://okta.example/userinfo',
			extractAccount: u => u.email || null,
			baseScopes: ['openid', 'email']
		}
	})
	const customStatic = providers.createProvider('stripe')
	assert.equal(providers.google.supportsAuth, true)
	assert.equal(providers.google.supportsApp, true)
	assert.equal(okta.supportsAuth, true)
	assert.equal(okta.supportsApp, false)
	assert.equal(customStatic.supportsAuth, false)
	assert.equal(customStatic.supportsApp, true)
	const registry = { google: providers.google, github: providers.github, okta, stripe: customStatic }
	assert.equal(providers.parseOauthProviders('', registry), null)
	assert.equal(providers.parseOauthProviders('   ', registry), null)
	const parsed = providers.parseOauthProviders('google, github:app, okta', registry)
	assert.deepEqual(parsed.get('google'), { auth: true, app: true })
	assert.deepEqual(parsed.get('github'), { auth: false, app: true })
	assert.deepEqual(parsed.get('okta'), { auth: true, app: false })
	assert.throws(() => providers.parseOauthProviders('okta:app', registry), /does not support "app"/)
	assert.throws(() => providers.parseOauthProviders('stripe', registry), /Invalid OAUTH_PROVIDERS provider/)
	assert.throws(() => providers.parseOauthProviders('google:login', registry), /Invalid OAUTH_PROVIDERS role/)
	assert.throws(() => providers.parseOauthProviders('google,google:auth', registry), /Duplicate provider/)
	assert.throws(() => providers.parseOauthProviders('google:auth:extra', registry), /Invalid OAUTH_PROVIDERS entry/)
	assert.throws(() => providers.parseOauthProviders('google:', registry), /Invalid OAUTH_PROVIDERS role/)
	assert.throws(() => providers.parseOauthProviders(':auth', registry), /Invalid OAUTH_PROVIDERS provider/)
	assert.throws(() => providers.parseOauthProviders('google,,github', registry), /Invalid OAUTH_PROVIDERS entry/)
	assert.throws(() => providers.parseOauthProviders(',', registry), /Invalid OAUTH_PROVIDERS entry/)
	assert.throws(() => providers.parseOauthProviders(123, registry), /Invalid OAUTH_PROVIDERS value/)
	assert.throws(() => providers.isOauthProviderAllowed(providers.google, 'bogus'), /Invalid OAuth role/)
	assert.throws(() => providers.listOauthProviders('bogus'), /Invalid OAuth role/)
	assert.throws(() => providers.requireOauthProvider('google', 'bogus'), /Invalid OAuth role/)
})
