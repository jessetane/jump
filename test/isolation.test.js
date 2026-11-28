import test from 'node:test'
import assert from 'node:assert/strict'
import { useServer, baseUrl, createTestSession, withUpstream, withMockFetch, withEnv, mcp, req, db, providers, ssoMod } from './helpers.js'

useServer()

test('admin vs non-admin tool filtering, capability gates, and non-escalation', async () => {
	const user = db.logins.resolveUser('google', 'roles@example.com')
	const admin = db.sessions.create({ userId: user.id, admin: 1 })
	const worker = db.sessions.create({ userId: user.id, admin: 0 })
	const app = db.apps.create({ userId: user.id, provider: 'google', type: 'oauth', name: 'G', expiresAt: Date.now() + 3600000 })
	db.links.create({ sessionId: admin.id, appId: app.id })
	db.links.create({ sessionId: worker.id, appId: app.id })
	const adminTools = (await req('POST', '/mcp', { token: admin.token, body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } })).data.result.tools.map(t => t.name)
	const workerTools = (await req('POST', '/mcp', { token: worker.token, body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} } })).data.result.tools.map(t => t.name)
	assert.deepEqual(adminTools, ['admin', 'google_api'])
	assert.deepEqual(workerTools, ['google_api'])
	for (const args of [
		{ action: 'list_sessions' },
		{ action: 'get_session', sessionId: admin.id },
		{ action: 'revoke_session', sessionId: admin.id },
		{ action: 'revoke_session', allOthers: true },
		{ action: 'update_session', admin: true },
		{ action: 'update_app', appId: app.id, name: 'X' },
		{ action: 'link_login', provider: 'google' },
		{ action: 'unlink_login', provider: 'google' },
		{ action: 'share_app', appId: app.id, account: 'other@example.com' },
		{ action: 'list_logs', sessionId: admin.id }
	]) {
		const res = await mcp(worker.token, 'admin', args)
		assert.equal(res.isError, true, `Non-admin must be blocked from ${args.action}`)
		assert.match(res.content[0].text, /requires admin privileges/)
	}
	assert.equal((await mcp(worker.token, 'admin', { action: 'update_session', name: 'Renamed Self' })).isError, undefined)
	assert.equal((await mcp(worker.token, 'admin', { action: 'get_session', sessionId: worker.id })).isError, undefined)
	assert.equal((await mcp(worker.token, 'admin', { action: 'revoke_session', sessionId: worker.id })).isError, undefined)
	assert.equal(db.sessions.get(worker.id), null)
})

test('cross-tenant isolation blocks access to other users sessions, apps, links, and shares', async () => {
	const tenantA = createTestSession({ account: 'tenant-a@example.com', admin: true })
	const tenantB = createTestSession({ account: 'tenant-b@example.com', admin: true })
	const childA = JSON.parse((await mcp(tenantA.session.token, 'admin', { action: 'create_session', name: 'Worker A', linkAppIds: [tenantA.app.id] })).content[0].text).session
	assert.equal((await mcp(tenantB.session.token, 'admin', { action: 'get_session', sessionId: tenantA.session.id })).isError, true)
	assert.equal((await mcp(tenantB.session.token, 'admin', { action: 'unlink_app', sessionId: childA.id, appId: tenantA.app.id })).isError, true)
	assert.equal((await mcp(tenantA.session.token, 'admin', { action: 'unlink_app', sessionId: childA.id, appId: tenantB.app.id })).isError, true)
	assert.equal((await mcp(tenantB.session.token, 'admin', { action: 'update_app', appId: tenantA.app.id, name: 'Hijack' })).isError, true)
	assert.equal((await mcp(tenantB.session.token, 'admin', { action: 'share_app', appId: tenantA.app.id, account: 'eve@example.com' })).isError, true)
	assert.equal((await mcp(tenantB.session.token, 'google_api', { url: 'https://www.googleapis.com/drive/v3/files', app: tenantA.app.id })).isError, true)
	assert.equal(db.links.listBySessionId(childA.id).length, 1)
})

test('shared apps: pending shares without stub users, ceiling policy intersection, cascade cleanup, and cross-user privacy', async () => {
	await withUpstream((upReq, res) => {
		res.writeHead(200, { 'content-type': 'application/json' })
		res.end(JSON.stringify({ ok: true, path: upReq.url }))
	}, async ({ url: upstreamUrl }) => {
		const sarah = createTestSession({ account: 'sarah-share@acme.com', admin: true, withApp: false })
		const sarahApp = JSON.parse((await mcp(sarah.session.token, 'admin', {
			action: 'connect_app',
			provider: 'stripe',
			name: 'Acme Stripe',
			credentials: 'sk_live_sarah_secret',
			baseUrl: upstreamUrl
		})).content[0].text).app
		assert.equal('account' in sarahApp, false)
		const usersBefore = db.sqlite.prepare('SELECT COUNT(*) AS n FROM users').get().n
		const shareRes = JSON.parse((await mcp(sarah.session.token, 'admin', {
			action: 'share_app',
			appId: sarahApp.id,
			account: 'dan-share@acme.com',
			policy: [
				{ action: 'allow', methods: ['GET'], path: '/v1/customers/**' },
				{ action: 'allow', methods: ['GET'], path: '/v1/invoices/**' }
			]
		})).content[0].text)
		assert.equal(shareRes.userId, null)
		assert.equal(db.sqlite.prepare('SELECT COUNT(*) AS n FROM users').get().n, usersBefore, 'Pending share must never create stub users')
		const dan = db.logins.resolveUser('google', 'dan-share@acme.com', { allowUnscoped: true })
		const danAdmin = db.sessions.create({ userId: dan.id, admin: 1 })
		const danListed = JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'list_apps' })).content[0].text).apps
		assert.equal(danListed.length, 1)
		assert.equal(danListed[0].id, shareRes.shareId)
		assert.equal(JSON.stringify(danListed[0]).includes('sk_live_sarah_secret'), false)
		for (const forbidden of [
			{ action: 'update_app', appId: shareRes.shareId, name: 'Hijacked' },
			{ action: 'share_app', appId: shareRes.shareId, account: 'eve@acme.com' },
			{ action: 'connect_app', appId: shareRes.shareId }
		]) {
			assert.equal((await mcp(danAdmin.token, 'admin', forbidden)).isError, true, `Recipient must not perform ${forbidden.action} on shared app`)
		}
		const danAgent = JSON.parse((await mcp(danAdmin.token, 'admin', {
			action: 'create_session',
			name: 'Dan Agent',
			linkAppIds: [shareRes.shareId],
			policy: [
				{ action: 'allow', methods: ['GET'], path: '/v1/customers/**' },
				{ action: 'allow', methods: ['POST'], path: '/v1/invoices/**' }
			]
		})).content[0].text).session
		const danAgentTools = (await req('POST', '/mcp', { token: danAgent.token, body: { jsonrpc: '2.0', id: 20, method: 'tools/list', params: {} } })).data.result.tools
		const danStripeTool = danAgentTools.find(t => t.name === 'stripe_api')
		assert.ok(danStripeTool.description.includes(`id=${shareRes.shareId}`), 'Shared app tools/list exposes shareId')
		assert.equal(danStripeTool.description.includes(sarahApp.id), false, 'Shared app tools/list must never leak owner upstream appId')
		assert.equal((await mcp(danAgent.token, 'stripe_api', { url: '/v1/customers/c1' })).isError, undefined)
		assert.equal((await mcp(danAgent.token, 'stripe_api', { url: '/v1/invoices/i1', method: 'POST' })).isError, true, 'Owner ceiling denies POST even if session allows it')
		assert.equal((await mcp(danAgent.token, 'stripe_api', { url: '/v1/invoices/i1', method: 'GET' })).isError, true, 'Session policy denies GET /invoices even if owner ceiling allows it')
		const danLogs = JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'list_logs' })).content[0].text).logs
		assert.ok(danLogs.every(l => l.appId === shareRes.shareId), 'Recipient logs expose shareId and never owner appId')
		assert.equal(JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'list_logs', appId: sarahApp.id })).content[0].text).logs.length, 0)
		assert.equal((await mcp(danAgent.token, 'stripe_api', { url: '/v1/customers/c1', app: sarahApp.id })).isError, true, 'Owner upstream appId must be rejected on shared app proxy')
		assert.equal((await req('GET', '/api/stripe/v1/customers/c1', { token: danAgent.token, headers: { 'x-upstream-app': sarahApp.id } })).status, 404)
		db.logins.upsert({ userId: dan.id, provider: 'github', account: 'dan-public-handle' })
		const privApp = JSON.parse((await mcp(sarah.session.token, 'admin', {
			action: 'connect_app',
			provider: 'stripe',
			credentials: 'sk_priv',
			baseUrl: upstreamUrl
		})).content[0].text).app
		await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-sec' }, async () => {
			const privShare = JSON.parse((await mcp(sarah.session.token, 'admin', {
				action: 'share_app',
				appId: privApp.id,
				account: 'github:dan-public-handle',
				policy: [{ action: 'allow', methods: ['GET'] }]
			})).content[0].text)
			const danPubSess = JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'create_session', linkAppIds: [privShare.shareId] })).content[0].text).session
			await mcp(danPubSess.token, 'stripe_api', { url: '/v1/customers/priv' })
			const danMultiSess = JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'create_session', linkAppIds: [privShare.shareId, shareRes.shareId] })).content[0].text).session
			const multiShareErr = await mcp(danMultiSess.token, 'stripe_api', { url: '/v1/customers/priv' })
			assert.equal(multiShareErr.isError, true)
			assert.ok(multiShareErr.content[0].text.includes(`id=${privShare.shareId}`) && multiShareErr.content[0].text.includes(`id=${shareRes.shareId}`))
			assert.equal(multiShareErr.content[0].text.includes(privApp.id) || multiShareErr.content[0].text.includes(sarahApp.id), false, 'Multi-share ambiguity error must never leak owner appIds')
			assert.equal((await mcp(danMultiSess.token, 'stripe_api', { url: '/v1/customers/priv', app: privShare.shareId })).isError, undefined)
			db.sessions.remove(danMultiSess.id)
			const ownerPrivLogs = (await mcp(sarah.session.token, 'admin', { action: 'list_logs', appId: privApp.id })).content[0].text
			assert.equal(ownerPrivLogs.includes('dan-share@acme.com'), false, 'Owner audit logs must not deanonymize recipient primary email across secondary handles')
			assert.equal(JSON.parse((await mcp(sarah.session.token, 'admin', { action: 'unshare_app', appId: privApp.id, account: 'github:dan-public-handle' })).content[0].text).unshared, true)
			const ownerLogsPostUnshare = (await mcp(sarah.session.token, 'admin', { action: 'list_logs', appId: privApp.id })).content[0].text
			assert.equal(ownerLogsPostUnshare.includes('dan-share@acme.com'), false, 'Historical owner logs after unshare must never fall back to recipient primary email')
			assert.equal(db.shares.get(privShare.shareId), null)
			assert.equal(db.links.listBySessionId(danPubSess.id).length, 0, 'Unshare cascade-deletes recipient session links')
			const danLogsPostUnshare = JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'list_logs' })).content[0].text).logs
			const unsharedEntry = danLogsPostUnshare.find(l => l.sessionId === danPubSess.id)
			assert.ok(unsharedEntry)
			assert.equal(unsharedEntry.appId, null, 'Recipient logs after unshare must resolve appId to null instead of owner appId')
			assert.equal(JSON.stringify(danLogsPostUnshare).includes(privApp.id), false)
		})
		const selfPending = db.shares.upsert({ userId: null, account: 'sarah-self-gh', authProvider: 'github', appId: sarahApp.id })
		assert.ok(db.shares.get(selfPending.id))
		db.logins.upsert({ userId: sarah.user.id, provider: 'github', account: 'sarah-self-gh' })
		assert.equal(db.shares.get(selfPending.id), null, 'Linking a login matching an own pending share removes the self-share')
		await mcp(sarah.session.token, 'admin', { action: 'disconnect_app', appId: sarahApp.id, revoke: false })
		assert.equal(db.shares.get(shareRes.shareId), null, 'Deleting upstream app cascade-deletes downstream shares')
		assert.equal(db.links.listBySessionId(danAgent.id).length, 0)
		const expiredG = db.apps.create({ userId: sarah.user.id, provider: 'google', type: 'oauth', name: 'Expired G', account: 'sarah-share@acme.com', credentials: { accessToken: 'ya29.exp', refreshToken: '1//bad' }, expiresAt: Date.now() - 1000 })
		const gShare = JSON.parse((await mcp(sarah.session.token, 'admin', { action: 'share_app', appId: expiredG.id, account: 'dan-share@acme.com' })).content[0].text)
		await mcp(danAdmin.token, 'admin', { action: 'link_app', sessionId: danAgent.id, appId: gShare.shareId })
		await withMockFetch(() => Response.json({ error: 'invalid_grant' }, { status: 400 }), async () => {
			const failRes = await mcp(danAgent.token, 'google_api', { url: 'https://www.googleapis.com/drive/v3/files' })
			assert.equal(failRes.isError, true)
			assert.equal(failRes.content[0].text.includes(expiredG.id), false, 'Shared refresh error never exposes owner upstreamApp.id')
			assert.doesNotMatch(failRes.content[0].text, /reauth_app_id/)
		})
		await mcp(danAdmin.token, 'admin', { action: 'disconnect_app', appId: gShare.shareId })
		assert.equal(db.shares.get(gShare.shareId), null)
		assert.ok(db.apps.get(expiredG.id), 'Recipient disconnecting share never deletes owner upstream app')
	})
})

test('SSO_DOMAINS pinning prevents wrong-IdP login/linking, claim hijacking, and strict cross-provider sharing', async () => {
	assert.throws(() => ssoMod.parseSsoDomains('acme.com'), /Invalid SSO_DOMAINS entry/)
	assert.throws(() => ssoMod.parseSsoDomains('acme.com:google,acme.com:github'), /Duplicate domain/)
	await withEnv({ SSO_DOMAINS: 'corp.com:google, strictcorp.com:google:strict, partner.io:github', GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-sec' }, async () => {
		let gEmail = 'alice@corp.com'
		let ghLogin = 'alice@corp.com'
		await withMockFetch(async (input, init, origFetch) => {
			const u = typeof input === 'string' ? input : input.url
			if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'ya29.sso', token_type: 'Bearer' })
			if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') return Response.json({ email: gEmail, verified_email: true })
			if (u === 'https://github.com/login/oauth/access_token') return Response.json({ access_token: 'gho_sso', token_type: 'bearer' })
			if (u === 'https://api.github.com/user') return Response.json({ login: ghLogin })
			return origFetch(input, init)
		}, async origFetch => {
			const wrongState = db.states.createState({ mode: 'login', provider: 'github' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${wrongState}`)).status, 403)
			assert.equal(db.logins.findUserByAccount('alice@corp.com', 'github'), null)
			const okState = db.states.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${okState}`)).status, 200)
			const corpUser = db.logins.findUserByAccount('alice@corp.com', 'google')
			const corpAdmin = db.sessions.create({ userId: corpUser.id, admin: 1 })
			assert.equal((await mcp(corpAdmin.token, 'admin', { action: 'link_login', provider: 'github' })).isError, true)
			const ssoBlockedSetup = db.states.createState({ mode: 'setup_link', sessionId: corpAdmin.id, provider: 'github' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/authorize?code=${ssoBlockedSetup}`)).status, 403)
			const unconstrainedSetup = db.states.createState({ mode: 'setup_link', sessionId: corpAdmin.id })
			const unconstrainedPage = await origFetch(`${baseUrl()}/oauth/authorize?code=${unconstrainedSetup}`)
			assert.equal(unconstrainedPage.status, 200)
			const unconstrainedData = JSON.parse((await unconstrainedPage.text()).match(/const initData = (\{[^\n]+\})/)[1])
			assert.deepEqual(unconstrainedData.providers.map(p => p.id), ['google'], 'Unconstrained setup_link filters SSO-disallowed providers')
			assert.equal((await origFetch(`${baseUrl()}/oauth/authorize/consent`, {
				method: 'POST',
				headers: { origin: baseUrl(), 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ code: unconstrainedSetup, provider: 'github' }).toString()
			})).status, 403)
			const pinnedSetup = db.states.createState({ mode: 'setup_link', sessionId: corpAdmin.id, provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/authorize/consent`, {
				method: 'POST',
				headers: { origin: baseUrl(), 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ code: pinnedSetup, provider: 'github' }).toString()
			})).status, 403)
			assert.ok(db.states.getState(pinnedSetup), 'Provider mismatch on consent does not consume setup code')
			const badSsoCode = db.states.createState({ mode: 'setup_link', sessionId: corpAdmin.id })
			await withEnv({ SSO_DOMAINS: 'invalid-entry' }, async () => {
				assert.equal((await req('GET', `/oauth/authorize?code=${badSsoCode}`)).status, 500, 'authorize propagates invalid SSO_DOMAINS instead of swallowing')
			})
			const contractor = db.logins.resolveUser('github', 'contractor-gh')
			const contractorAdmin = db.sessions.create({ userId: contractor.id, admin: 1 })
			gEmail = 'bob@corp.com'
			const linkPinnedOntoOther = db.states.createState({ mode: 'auth', sessionId: contractorAdmin.id, provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${linkPinnedOntoOther}`)).status, 403)
			const appOwner = createTestSession({ account: 'flex@example.com', admin: true, withApp: false })
			const flexApp = db.apps.create({ userId: appOwner.user.id, provider: 'stripe', type: 'static', baseUrl: 'https://api.stripe.com', credentials: { headers: { authorization: 'Bearer sk' } } })
			const unscopedPending = db.shares.upsert({ userId: null, account: 'member@partner.io', authProvider: null, appId: flexApp.id })
			gEmail = 'member@partner.io'
			const wrongIdpClaim = db.states.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${wrongIdpClaim}`)).status, 403, 'Verified-email provider cannot claim unscoped share on domain pinned to another IdP')
			assert.equal(db.shares.get(unscopedPending.id).userId, null)
			ghLogin = 'member@partner.io'
			const rightIdpClaim = db.states.createState({ mode: 'login', provider: 'github' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${rightIdpClaim}`, { redirect: 'manual' })).status, 302)
			assert.equal(db.shares.listByUserId(db.logins.findUserByAccount('member@partner.io', 'github').id).length, 1)
			const strictUser = db.logins.resolveUser('google', 'boss@strictcorp.com')
			const strictAdmin = db.sessions.create({ userId: strictUser.id, admin: 1 })
			const strictApp = db.apps.create({ userId: strictUser.id, provider: 'stripe', type: 'static', baseUrl: 'https://api.stripe.com', credentials: { headers: { authorization: 'Bearer sk' } } })
			assert.equal((await mcp(strictAdmin.token, 'admin', { action: 'share_app', appId: strictApp.id, account: 'ext', provider: 'github' })).isError, true)
			assert.equal((await mcp(strictAdmin.token, 'admin', { action: 'share_app', appId: strictApp.id, account: 'ally@partner.io' })).isError, true)
		})
	})
})

test('login-key lifecycle, lockout guard, verified-email pending claim guard, and atomic mergeUsers under SSO_DOMAINS', async () => {
	const sole = createTestSession({ account: 'sole-lock@example.com', admin: true })
	const soleLogin = db.logins.listByUserId(sole.user.id)[0]
	assert.equal((await req('DELETE', `/api/logins/${encodeURIComponent(soleLogin.id)}`, { token: sole.session.token })).status, 400, 'Cannot unlink sole remaining login key')
	const secondLogin = db.logins.upsert({ userId: sole.user.id, provider: 'github', account: 'sole-second-gh' })
	assert.equal((await req('DELETE', `/api/logins/${encodeURIComponent(secondLogin.id)}`, { token: sole.session.token })).status, 200)
	assert.equal(db.logins.listByUserId(sole.user.id).length, 1)
	const shay = createTestSession({ account: 'shay-claim@example.com', admin: true, withApp: false })
	const shayLogin = db.logins.listByUserId(shay.user.id)[0]
	assert.equal((await req('DELETE', `/api/logins/${encodeURIComponent(shayLogin.id)}`, { token: sole.session.token })).status, 404, 'Cannot unlink foreign user login')
	const shayApp = db.apps.create({ userId: shay.user.id, provider: 'stripe', type: 'static', baseUrl: 'https://api.stripe.com', credentials: { headers: { authorization: 'Bearer sk_claim' } } })
	db.shares.upsert({ userId: null, account: 'prec-claim@acme.com', authProvider: null, appId: shayApp.id, policy: [{ action: 'allow', path: '/v1/unscoped' }] })
	const unverifiedUser = db.logins.resolveUser('custom_unverified_idp', 'prec-claim@acme.com')
	assert.equal(db.shares.listByUserId(unverifiedUser.id).length, 0, 'Unverified-email provider never claims unscoped pending email shares')
	await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-sec' }, async () => {
		const soleWorker = db.sessions.create({ userId: sole.user.id, admin: 0 })
		assert.equal((await req('POST', '/api/logins', { token: soleWorker.token, body: { provider: 'github' } })).status, 403)
		const linkLoginRes = await req('POST', '/api/logins', { token: sole.session.token, body: { provider: 'github' } })
		assert.equal(linkLoginRes.status, 201)
		assert.match(linkLoginRes.data.connectUrl, /\/oauth\/authorize\?code=/)
		assert.equal((await req('POST', '/api/shares', { token: soleWorker.token, body: { appId: shayApp.id, account: 'rest-share@example.com' } })).status, 403)
		const shareRest = await req('POST', '/api/shares', { token: shay.session.token, body: { appId: shayApp.id, account: 'rest-share@example.com', policy: [{ action: 'allow', path: '/v1/*' }] } })
		assert.equal(shareRest.status, 201)
		assert.ok(db.shares.get(shareRest.data.shareId))
		assert.equal((await req('DELETE', `/api/shares?appId=${shayApp.id}&account=rest-share@example.com`, { token: soleWorker.token })).status, 403)
		assert.equal((await req('DELETE', `/api/shares?appId=${shayApp.id}&account=rest-share@example.com`, { token: shay.session.token })).status, 200)
		assert.equal(db.shares.get(shareRest.data.shareId), null)
		let gEmail = 'primary-owner@example.com'
		let ghLogin = 'accidental-new-gh'
		await withMockFetch(async (input, init, origFetch) => {
			const u = typeof input === 'string' ? input : input.url
			if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'ya29.m', token_type: 'Bearer' })
			if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') return Response.json({ email: gEmail, verified_email: true })
			if (u === 'https://github.com/login/oauth/access_token') return Response.json({ access_token: 'gho_m', token_type: 'bearer' })
			if (u === 'https://api.github.com/user') return Response.json({ login: ghLogin })
			return origFetch(input, init)
		}, async origFetch => {
			const older = db.logins.resolveUser('google', 'primary-owner@example.com')
			db.sqlite.prepare('UPDATE users SET created = ? WHERE id = ?').run('2026-01-01T00:00:00.000Z', older.id)
			const olderSess = db.sessions.create({ userId: older.id, admin: 1 })
			const olderApp = db.apps.create({ userId: older.id, provider: 'stripe', type: 'static', name: 'Older Stripe', baseUrl: 'https://api.stripe.com', credentials: { headers: { authorization: 'Bearer sk_old' } } })
			db.links.create({ sessionId: olderSess.id, appId: olderApp.id })
			const newer = db.logins.resolveUser('github', 'accidental-new-gh')
			const newerSess = db.sessions.create({ userId: newer.id, admin: 1 })
			const absorbedApp = db.apps.create({ userId: newer.id, provider: 'linear', type: 'static', baseUrl: 'https://api.linear.app', credentials: { headers: { authorization: 'lin_absorbed' } } })
			await mcp(olderSess.token, 'admin', { action: 'share_app', appId: olderApp.id, account: 'github:accidental-new-gh' })
			const looserShare = db.shares.upsert({ userId: newer.id, account: 'accidental-new-gh', authProvider: 'github', appId: shayApp.id, policy: [{ action: 'allow', path: '/v1/*' }] })
			const stricterShare = db.shares.upsert({ userId: older.id, account: 'primary-owner@example.com', authProvider: 'google', appId: shayApp.id, policy: [{ action: 'allow', methods: ['GET'], path: '/v1/charges' }] })
			const olderWorker = db.sessions.create({ userId: older.id, admin: 0 })
			db.links.create({ sessionId: olderWorker.id, appId: stricterShare.appId, shareId: stricterShare.id })
			const conflictState = db.states.createState({ mode: 'auth', sessionId: newerSess.id, provider: 'google', merge: false })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=g&state=${conflictState}`)).status, 409)
			assert.ok(db.users.get(newer.id), '409 conflict leaves target user untouched')
			const mergeState = db.states.createState({ mode: 'auth', sessionId: newerSess.id, provider: 'google', merge: true })
			const mergeCb = await origFetch(`${baseUrl()}/oauth/callback?code=g&state=${mergeState}`, { redirect: 'manual' })
			assert.equal(mergeCb.status, 302)
			const verifyCode = new URL(mergeCb.headers.get('location'), baseUrl()).searchParams.get('code')
			const postVerify = await origFetch(`${baseUrl()}/oauth/verify`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({ code: verifyCode, app_id: olderApp.id }).toString()
			})
			assert.equal(postVerify.status, 200)
			assert.equal(db.users.get(newer.id), null)
			assert.equal(db.apps.get(absorbedApp.id).userId, older.id)
			assert.deepEqual(db.apps.get(absorbedApp.id).credentials.headers, { authorization: 'lin_absorbed' }, 'Re-parented app decrypts cleanly')
			const mergedApps = JSON.parse((await mcp(newerSess.token, 'admin', { action: 'list_apps' })).content[0].text).apps
			assert.equal(mergedApps.some(a => a.type === 'share' && a.name === 'Older Stripe'), false, 'Self-shares cleaned up on merge')
			assert.ok(db.shares.get(looserShare.id) && !db.shares.get(stricterShare.id))
			assert.deepEqual(db.links.listBySessionId(olderWorker.id), [], 'Conflicting share link with different policy drops fail-closed on merge')
			const revOwner = createTestSession({ account: 'rev-owner@example.com', admin: true, withApp: true })
			const earlierUser = db.logins.resolveUser('google', 'earlier-merge@example.com')
			db.sqlite.prepare('UPDATE users SET created = ? WHERE id = ?').run('2026-01-01T00:00:00.000Z', earlierUser.id)
			const laterUser = db.logins.resolveUser('github', 'later-merge-gh')
			const revStrictEarlier = db.shares.upsert({ userId: earlierUser.id, account: 'earlier-merge@example.com', authProvider: 'google', appId: revOwner.app.id, policy: [{ action: 'allow', methods: ['GET'], path: '/strict/**' }] })
			db.sqlite.prepare('UPDATE shares SET created = ? WHERE id = ?').run('2026-01-02T00:00:00.000Z', revStrictEarlier.id)
			const revLooseLater = db.shares.upsert({ userId: laterUser.id, account: 'later-merge-gh', authProvider: 'github', appId: revOwner.app.id, policy: [{ action: 'allow', path: '/**' }] })
			const laterWorker = db.sessions.create({ userId: laterUser.id, admin: 0 })
			db.links.create({ sessionId: laterWorker.id, appId: revLooseLater.appId, shareId: revLooseLater.id })
			const sameExtApp = db.apps.create({ userId: revOwner.user.id, provider: 'stripe', type: 'static', baseUrl: 'https://api.stripe.com', credentials: { headers: { authorization: 'Bearer sk_same' } } })
			const samePolicy = [{ action: 'allow', path: '/v1/charges' }]
			const earlierSame = db.shares.upsert({ userId: earlierUser.id, account: 'earlier-merge@example.com', authProvider: 'google', appId: sameExtApp.id, policy: samePolicy })
			db.sqlite.prepare('UPDATE shares SET created = ? WHERE id = ?').run('2026-01-02T00:00:00.000Z', earlierSame.id)
			const laterSame = db.shares.upsert({ userId: laterUser.id, account: 'later-merge-gh', authProvider: 'github', appId: sameExtApp.id, policy: samePolicy })
			db.links.create({ sessionId: laterWorker.id, appId: laterSame.appId, shareId: laterSame.id })
			db.logins.upsert({ userId: earlierUser.id, provider: 'github', account: 'later-merge-gh', merge: true })
			assert.ok(db.shares.get(revStrictEarlier.id) && !db.shares.get(revLooseLater.id), 'Earliest-created share survives even when stricter')
			const survivingLinks = db.links.listBySessionId(laterWorker.id).map(l => l.targetId)
			assert.deepEqual(survivingLinks, [earlierSame.id], 'Conflicting looser share drops fail-closed while identical-policy share migrates link onto earliest share')
			await withEnv({ SSO_DOMAINS: 'isolated.corp:google' }, async () => {
				const pinned = db.logins.resolveUser('google', 'staff@isolated.corp')
				db.logins.upsert({ userId: pinned.id, provider: 'github', account: 'sso-bridge-gh' })
				const outsider = db.logins.resolveUser('google', 'outsider@gmail.com')
				const outsiderSess = db.sessions.create({ userId: outsider.id, admin: 1 })
				ghLogin = 'sso-bridge-gh'
				const ssoMergeState = db.states.createState({ mode: 'auth', sessionId: outsiderSess.id, provider: 'github', merge: true })
				assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=gh&state=${ssoMergeState}`)).status, 403, 'Merge rejects absorbing logins violating SSO_DOMAINS')
				assert.ok(db.users.get(pinned.id))
			})
			assert.throws(() => db.logins.upsert({ userId: 'nonexistent-user', provider: 'google', account: 'primary-owner@example.com', merge: true }), { status: 404, message: 'User not found' })
		})
	})
})

test('app-level policies compose across connect_app, update_app, shares, and links with full visibility', async () => {
	const received = []
	await withUpstream(async (r, upstreamRes) => {
		const chunks = []
		for await (const c of r) chunks.push(c)
		received.push({ method: r.method, url: r.url, body: Buffer.concat(chunks).toString('utf8') })
		upstreamRes.writeHead(200, { 'content-type': 'application/json' })
		upstreamRes.end(JSON.stringify({ ok: true }))
	}, async ({ url: upstreamUrl }) => {
		const owner = createTestSession({ account: 'app-policy-owner@example.com', admin: true, withApp: false })
		const recip = createTestSession({ account: 'app-policy-recip@example.com', admin: true, withApp: false })
		const appPolicy = [
			{ action: 'deny', methods: ['DELETE'], description: 'Deletes blocked on app' },
			{ action: 'deny', methods: ['POST'], body: { dangerous: true }, description: 'Dangerous payload blocked on app' },
			{ action: 'allow', path: '/v1/**' }
		]
		const inlineStatic = JSON.parse((await mcp(owner.session.token, 'admin', {
			action: 'connect_app',
			provider: 'stripe',
			name: 'Guarded Stripe',
			credentials: 'sk_app_pol',
			baseUrl: upstreamUrl,
			policy: appPolicy
		})).content[0].text).app
		assert.deepEqual(inlineStatic.policy, appPolicy)
		await mcp(owner.session.token, 'admin', { action: 'link_app', sessionId: owner.session.id, appId: inlineStatic.id })
		const worker = JSON.parse((await mcp(owner.session.token, 'admin', {
			action: 'create_session',
			name: 'Unrestricted Link Worker',
			linkAppIds: [inlineStatic.id]
		})).content[0].text).session
		const sharePolicy = [{ action: 'allow', methods: ['GET', 'POST', 'DELETE'], path: '/v1/customers/**' }]
		const share = JSON.parse((await mcp(owner.session.token, 'admin', {
			action: 'share_app',
			appId: inlineStatic.id,
			account: 'app-policy-recip@example.com',
			policy: sharePolicy
		})).content[0].text)
		const recipWorker = JSON.parse((await mcp(recip.session.token, 'admin', {
			action: 'create_session',
			name: 'Recip 3-Layer Worker',
			linkAppIds: [share.shareId],
			policy: [
				{ action: 'deny', path: '/v1/customers/secret/**' },
				{ action: 'allow', methods: ['POST', 'GET', 'DELETE'], path: '/v1/**' }
			]
		})).content[0].text).session
		assert.equal((await mcp(worker.token, 'stripe_api', { url: '/v1/charges' })).isError, undefined)
		const appDeniedDel = await mcp(worker.token, 'stripe_api', { url: '/v1/charges/ch_1', method: 'DELETE' })
		assert.equal(appDeniedDel.isError, true)
		assert.match(appDeniedDel.content[0].text, /Deletes blocked on app/)
		const appDeniedHttpBody = await req('POST', '/api/stripe/v1/customers', {
			token: worker.token,
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ dangerous: true })
		})
		assert.equal(appDeniedHttpBody.status, 403)
		const appDeniedOutside = await mcp(worker.token, 'stripe_api', { url: '/v2/other' })
		assert.equal(appDeniedOutside.isError, true)
		assert.equal((await mcp(recipWorker.token, 'stripe_api', { url: '/v1/customers/c_1', method: 'POST', body: { dangerous: false } })).isError, undefined)
		assert.equal((await mcp(recipWorker.token, 'stripe_api', { url: '/v1/customers/c_1', method: 'POST', body: { dangerous: true } })).isError, true, 'App policy blocks body even when share and link allow')
		assert.equal((await mcp(recipWorker.token, 'stripe_api', { url: '/v1/customers/c_1', method: 'DELETE' })).isError, true, 'App policy blocks DELETE even when share and link allow')
		assert.equal((await mcp(recipWorker.token, 'stripe_api', { url: '/v1/charges', method: 'GET' })).isError, true, 'Share policy still blocks /v1/charges even when app allows')
		assert.equal((await mcp(recipWorker.token, 'stripe_api', { url: '/v1/customers/secret/1', method: 'GET' })).isError, true, 'Link policy still blocks /v1/customers/secret/**')
		const ownerApps = JSON.parse((await mcp(owner.session.token, 'admin', { action: 'list_apps' })).content[0].text).apps
		assert.deepEqual(ownerApps.find(a => a.id === inlineStatic.id).policy, appPolicy)
		const recipApps = JSON.parse((await mcp(recip.session.token, 'admin', { action: 'list_apps' })).content[0].text).apps
		const recipShareEntry = recipApps.find(a => a.id === share.shareId)
		assert.deepEqual(recipShareEntry.appPolicy, appPolicy)
		assert.deepEqual(recipShareEntry.policy, sharePolicy)
		const recipSessionInfo = JSON.parse((await mcp(recip.session.token, 'admin', { action: 'get_session', sessionId: recipWorker.id })).content[0].text).session
		const recipLinkEntry = recipSessionInfo.apps[0]
		assert.deepEqual(recipLinkEntry.appPolicy, appPolicy)
		assert.deepEqual(recipLinkEntry.sharePolicy, sharePolicy)
		assert.equal(recipLinkEntry.policy.length, 2)
		const ownerWhoami = JSON.parse((await mcp(owner.session.token, 'admin', { action: 'whoami' })).content[0].text).session
		assert.deepEqual(ownerWhoami.apps[0].appPolicy, appPolicy)
		assert.equal(ownerWhoami.apps[0].policy, null)
		const browserStaticStart = JSON.parse((await mcp(owner.session.token, 'admin', {
			action: 'connect_app',
			provider: 'notion',
			name: 'Browser Notion',
			baseUrl: upstreamUrl,
			policy: [{ action: 'allow', methods: ['GET'] }]
		})).content[0].text)
		const browserSubmit = await req('POST', '/apps/connect', {
			headers: { 'content-type': 'application/json', origin: baseUrl() },
			body: { code: new URL(browserStaticStart.connectUrl).searchParams.get('code'), credentials: 'secret_notion' }
		})
		assert.equal(browserSubmit.status, 200)
		assert.deepEqual(JSON.parse(db.apps.get(browserSubmit.data.appId).policy), [{ action: 'allow', methods: ['GET'] }])
		const rotateStart = JSON.parse((await mcp(owner.session.token, 'admin', { action: 'connect_app', appId: browserSubmit.data.appId })).content[0].text)
		await req('POST', '/apps/connect', {
			headers: { 'content-type': 'application/json', origin: baseUrl() },
			body: { code: new URL(rotateStart.connectUrl).searchParams.get('code'), credentials: 'secret_notion_v2' }
		})
		assert.deepEqual(JSON.parse(db.apps.get(browserSubmit.data.appId).policy), [{ action: 'allow', methods: ['GET'] }], 'Rotating static credentials preserves app policy')
		const cleared = await req('PATCH', `/api/apps/${inlineStatic.id}`, { token: owner.session.token, body: { policy: null } })
		assert.equal(cleared.status, 200)
		assert.equal(cleared.data.app.policy, null)
		assert.equal((await mcp(worker.token, 'stripe_api', { url: '/v1/charges/ch_1', method: 'DELETE' })).isError, undefined, 'Clearing app policy lifts block immediately')
		const oauthPolicy = [{ action: 'allow', methods: ['GET'], origin: 'https://www.googleapis.com', path: '/drive/**' }]
		const oauthConnect = JSON.parse((await mcp(owner.session.token, 'admin', {
			action: 'connect_app',
			provider: 'google',
			name: 'Policy Google',
			policy: oauthPolicy
		})).content[0].text)
		const consentRes = await req('POST', '/providers/google/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: new URL(oauthConnect.connectUrl).searchParams.get('code') }).toString(),
			redirect: 'manual'
		})
		const gState = new URL(consentRes.headers.get('location')).searchParams.get('state')
		await withMockFetch(async (input, init, origFetch) => {
			const u = typeof input === 'string' ? input : input.url
			if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'ya29.pol', refresh_token: '1//pol', expires_in: 3600 })
			if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') return Response.json({ email: 'app-policy-owner@example.com', verified_email: true })
			return origFetch(input, init)
		}, async origFetch => {
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${gState}`)).status, 200)
		})
		const gApp = db.apps.listByUserId(owner.user.id).find(a => a.name === 'Policy Google')
		assert.deepEqual(JSON.parse(gApp.policy), oauthPolicy, 'OAuth connect_app carries app policy through state and callback')
		const gUpdated = await req('PATCH', `/api/apps/${gApp.id}`, { token: owner.session.token, body: { policy: [{ action: 'allow', methods: ['GET'], origin: 'https://www.googleapis.com', path: '/calendar/**' }] } })
		assert.equal(gUpdated.status, 200, 'update_app allows changing policy on OAuth apps')
		assert.equal(gUpdated.data.app.policy[0].path, '/calendar/**')
		const gReauth = JSON.parse((await mcp(owner.session.token, 'admin', { action: 'connect_app', appId: gApp.id })).content[0].text)
		const reauthConsent = await req('POST', '/providers/google/consent', {
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: new URL(gReauth.connectUrl).searchParams.get('code') }).toString(),
			redirect: 'manual'
		})
		const reauthState = new URL(reauthConsent.headers.get('location')).searchParams.get('state')
		await withEnv({ GOOGLE_CLIENT_ID: 'g-cid', GOOGLE_CLIENT_SECRET: 'g-sec' }, async () => {
			await withMockFetch(async (input, init, origFetch) => {
				const u = typeof input === 'string' ? input : input.url
				if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'ya29.reauth', refresh_token: '1//reauth', expires_in: 3600 })
				if (u === 'https://www.googleapis.com/oauth2/v2/userinfo') return Response.json({ email: 'app-policy-owner@example.com', verified_email: true })
				return origFetch(input, init)
			}, async origFetch => {
				assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c2&state=${reauthState}`)).status, 200)
			})
			assert.deepEqual(JSON.parse(db.apps.get(gApp.id).policy), gUpdated.data.app.policy, 'OAuth re-auth preserves app policy')
			db.apps.update(gApp.id, { expiresAt: Date.now() - 1000 })
			await withMockFetch(async (input, init, origFetch) => {
				const u = typeof input === 'string' ? input : input.url
				if (u === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'ya29.refreshed', expires_in: 3600 })
				return origFetch(input, init)
			}, async () => {
				const refreshedCreds = await providers.google.resolveCredentials(db.apps.get(gApp.id))
				assert.equal(refreshedCreds.headers.authorization, 'Bearer ya29.refreshed')
			})
			assert.deepEqual(JSON.parse(db.apps.get(gApp.id).policy), gUpdated.data.app.policy, 'OAuth token refresh preserves app policy')
		})
		const clearedShare = JSON.parse((await mcp(owner.session.token, 'admin', {
			action: 'share_app',
			appId: inlineStatic.id,
			account: 'app-policy-recip@example.com',
			policy: null
		})).content[0].text)
		assert.equal(clearedShare.policy, null, 'share_app supports clearing share policy with null')
		const clearedShareSession = JSON.parse((await mcp(recip.session.token, 'admin', { action: 'get_session', sessionId: recipWorker.id })).content[0].text).session
		assert.equal('sharePolicy' in clearedShareSession.apps[0], false)
		assert.equal((await mcp(recipWorker.token, 'stripe_api', { url: '/v1/charges', method: 'GET' })).isError, undefined, 'Clearing share policy lifts share block immediately while app and link allow')
	})
})
