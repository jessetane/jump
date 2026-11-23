import test from 'node:test'
import assert from 'node:assert/strict'
import { useServer, baseUrl, createTestSession, withUpstream, withMockFetch, withEnv, mcp, req, db, ssoMod } from './helpers.js'

useServer()

test('admin vs non-admin tool filtering, capability gates, and non-escalation', async () => {
	const user = db.logins.resolveUser('google', 'roles@example.com')
	const admin = db.tokens.create({ userId: user.id, provider: 'self', admin: 1 })
	const worker = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
	const app = db.tokens.create({ userId: user.id, provider: 'google', type: 'oauth', name: 'G', expiresAt: Date.now() + 3600000 })
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
	assert.equal(db.tokens.get(worker.id), null)
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
			account: 'acct_acme',
			credentials: 'sk_live_sarah_secret',
			baseUrl: upstreamUrl
		})).content[0].text).app
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
		const danAdmin = db.tokens.create({ userId: dan.id, provider: 'self', admin: 1 })
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
		assert.equal((await mcp(danAgent.token, 'stripe_api', { url: '/v1/customers/c1' })).isError, undefined)
		assert.equal((await mcp(danAgent.token, 'stripe_api', { url: '/v1/invoices/i1', method: 'POST' })).isError, true, 'Owner ceiling denies POST even if session allows it')
		assert.equal((await mcp(danAgent.token, 'stripe_api', { url: '/v1/invoices/i1', method: 'GET' })).isError, true, 'Session policy denies GET /invoices even if owner ceiling allows it')
		const danLogs = JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'list_logs' })).content[0].text).logs
		assert.ok(danLogs.every(l => l.appId === shareRes.shareId), 'Recipient logs expose shareId and never owner appId')
		assert.equal(JSON.parse((await mcp(danAdmin.token, 'admin', { action: 'list_logs', appId: sarahApp.id })).content[0].text).logs.length, 0)
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
			const ownerPrivLogs = (await mcp(sarah.session.token, 'admin', { action: 'list_logs', appId: privApp.id })).content[0].text
			assert.equal(ownerPrivLogs.includes('dan-share@acme.com'), false, 'Owner audit logs must not deanonymize recipient primary email across secondary handles')
			assert.equal(JSON.parse((await mcp(sarah.session.token, 'admin', { action: 'unshare_app', appId: privApp.id, account: 'github:dan-public-handle' })).content[0].text).unshared, true)
			const ownerLogsPostUnshare = (await mcp(sarah.session.token, 'admin', { action: 'list_logs', appId: privApp.id })).content[0].text
			assert.equal(ownerLogsPostUnshare.includes('dan-share@acme.com'), false, 'Historical owner logs after unshare must never fall back to recipient primary email')
			assert.equal(db.tokens.get(privShare.shareId), null)
			assert.equal(db.links.listBySessionId(danPubSess.id).length, 0, 'Unshare cascade-deletes recipient session links')
		})
		await mcp(sarah.session.token, 'admin', { action: 'disconnect_app', appId: sarahApp.id, revoke: false })
		assert.equal(db.tokens.get(shareRes.shareId), null, 'Deleting upstream app cascade-deletes downstream shares')
		assert.equal(db.links.listBySessionId(danAgent.id).length, 0)
		const expiredG = db.tokens.create({ userId: sarah.user.id, provider: 'google', type: 'oauth', name: 'Expired G', credentials: { accessToken: 'ya29.exp', refreshToken: '1//bad', account: 'sarah-share@acme.com' }, expiresAt: Date.now() - 1000 })
		const gShare = JSON.parse((await mcp(sarah.session.token, 'admin', { action: 'share_app', appId: expiredG.id, account: 'dan-share@acme.com' })).content[0].text)
		await mcp(danAdmin.token, 'admin', { action: 'link_app', sessionId: danAgent.id, appId: gShare.shareId })
		await withMockFetch(() => Response.json({ error: 'invalid_grant' }, { status: 400 }), async () => {
			const failRes = await mcp(danAgent.token, 'google_api', { url: 'https://www.googleapis.com/drive/v3/files' })
			assert.equal(failRes.isError, true)
			assert.equal(failRes.content[0].text.includes(expiredG.id), false, 'Shared refresh error never exposes owner upstreamApp.id')
			assert.doesNotMatch(failRes.content[0].text, /reauth_app_id/)
		})
		await mcp(danAdmin.token, 'admin', { action: 'disconnect_app', appId: gShare.shareId })
		assert.equal(db.tokens.get(gShare.shareId), null)
		assert.ok(db.tokens.get(expiredG.id), 'Recipient disconnecting share never deletes owner upstream app')
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
			const wrongState = db.tokens.createState({ mode: 'login', provider: 'github' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${wrongState}`)).status, 403)
			assert.equal(db.logins.findUserByAccount('alice@corp.com', 'github'), null)
			const okState = db.tokens.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${okState}`)).status, 200)
			const corpUser = db.logins.findUserByAccount('alice@corp.com', 'google')
			const corpAdmin = db.tokens.create({ userId: corpUser.id, provider: 'self', admin: 1 })
			assert.equal((await mcp(corpAdmin.token, 'admin', { action: 'link_login', provider: 'github' })).isError, true)
			const badSsoCode = db.tokens.createState({ mode: 'setup_link', sessionId: corpAdmin.id })
			await withEnv({ SSO_DOMAINS: 'invalid-entry' }, async () => {
				assert.equal((await req('GET', `/oauth/authorize?code=${badSsoCode}`)).status, 500, 'authorize propagates invalid SSO_DOMAINS instead of swallowing')
			})
			const contractor = db.logins.resolveUser('github', 'contractor-gh')
			const contractorAdmin = db.tokens.create({ userId: contractor.id, provider: 'self', admin: 1 })
			gEmail = 'bob@corp.com'
			const linkPinnedOntoOther = db.tokens.createState({ mode: 'auth', sessionId: contractorAdmin.id, provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${linkPinnedOntoOther}`)).status, 403)
			const appOwner = createTestSession({ account: 'flex@example.com', admin: true, withApp: false })
			const flexApp = db.tokens.create({ userId: appOwner.user.id, provider: 'stripe', type: 'static', credentials: { headers: { authorization: 'Bearer sk' }, baseUrl: 'https://api.stripe.com' } })
			const unscopedPending = db.tokens.upsertShare({ userId: null, account: 'member@partner.io', authProvider: null, appId: flexApp.id, provider: 'stripe' })
			gEmail = 'member@partner.io'
			const wrongIdpClaim = db.tokens.createState({ mode: 'login', provider: 'google' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${wrongIdpClaim}`)).status, 403, 'Verified-email provider cannot claim unscoped share on domain pinned to another IdP')
			assert.equal(db.tokens.get(unscopedPending.id).userId, null)
			ghLogin = 'member@partner.io'
			const rightIdpClaim = db.tokens.createState({ mode: 'login', provider: 'github' })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=c&state=${rightIdpClaim}`, { redirect: 'manual' })).status, 302)
			assert.equal(db.tokens.listByUserId(db.logins.findUserByAccount('member@partner.io', 'github').id).filter(t => t.type === 'share').length, 1)
			const strictUser = db.logins.resolveUser('google', 'boss@strictcorp.com')
			const strictAdmin = db.tokens.create({ userId: strictUser.id, provider: 'self', admin: 1 })
			const strictApp = db.tokens.create({ userId: strictUser.id, provider: 'stripe', type: 'static', credentials: { headers: { authorization: 'Bearer sk' }, baseUrl: 'https://api.stripe.com' } })
			assert.equal((await mcp(strictAdmin.token, 'admin', { action: 'share_app', appId: strictApp.id, account: 'ext', provider: 'github' })).isError, true)
			assert.equal((await mcp(strictAdmin.token, 'admin', { action: 'share_app', appId: strictApp.id, account: 'ally@partner.io' })).isError, true)
		})
	})
})

test('login-key lifecycle, lockout guard, verified-email pending claim guard, and atomic mergeUsers under SSO_DOMAINS', async () => {
	const sole = createTestSession({ account: 'sole-lock@example.com', admin: true })
	const soleLogin = db.logins.listByUserId(sole.user.id)[0]
	assert.equal((await req('DELETE', `/api/logins/${encodeURIComponent(soleLogin.id)}`, { token: sole.session.token })).status, 400, 'Cannot unlink sole remaining login key')
	const shay = createTestSession({ account: 'shay-claim@example.com', admin: true, withApp: false })
	const shayApp = db.tokens.create({ userId: shay.user.id, provider: 'stripe', type: 'static', credentials: { headers: { authorization: 'Bearer sk_claim' }, baseUrl: 'https://api.stripe.com' } })
	db.tokens.upsertShare({ userId: null, account: 'prec-claim@acme.com', authProvider: null, appId: shayApp.id, provider: 'stripe', policy: [{ action: 'allow', path: '/v1/unscoped' }] })
	const unverifiedUser = db.logins.resolveUser('custom_unverified_idp', 'prec-claim@acme.com')
	assert.equal(db.tokens.listByUserId(unverifiedUser.id).filter(t => t.type === 'share').length, 0, 'Unverified-email provider never claims unscoped pending email shares')
	await withEnv({ GITHUB_CLIENT_ID: 'gh-id', GITHUB_CLIENT_SECRET: 'gh-sec' }, async () => {
		const soleWorker = db.tokens.create({ userId: sole.user.id, provider: 'self', admin: 0 })
		assert.equal((await req('POST', '/api/logins', { token: soleWorker.token, body: { provider: 'github' } })).status, 403)
		const linkLoginRes = await req('POST', '/api/logins', { token: sole.session.token, body: { provider: 'github' } })
		assert.equal(linkLoginRes.status, 200)
		assert.match(linkLoginRes.data.connectUrl, /\/oauth\/authorize\?code=/)
		assert.equal((await req('POST', '/api/shares', { token: soleWorker.token, body: { appId: shayApp.id, account: 'rest-share@example.com' } })).status, 403)
		const shareRest = await req('POST', '/api/shares', { token: shay.session.token, body: { appId: shayApp.id, account: 'rest-share@example.com', policy: [{ action: 'allow', path: '/v1/*' }] } })
		assert.equal(shareRest.status, 201)
		assert.ok(db.tokens.get(shareRest.data.shareId))
		assert.equal((await req('DELETE', `/api/shares?appId=${shayApp.id}&account=rest-share@example.com`, { token: soleWorker.token })).status, 403)
		assert.equal((await req('DELETE', `/api/shares?appId=${shayApp.id}&account=rest-share@example.com`, { token: shay.session.token })).status, 200)
		assert.equal(db.tokens.get(shareRest.data.shareId), null)
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
			const olderSess = db.tokens.create({ userId: older.id, provider: 'self', admin: 1 })
			const olderApp = db.tokens.create({ userId: older.id, provider: 'stripe', type: 'static', name: 'Older Stripe', credentials: { headers: { authorization: 'Bearer sk_old' }, baseUrl: 'https://api.stripe.com' } })
			db.links.create({ sessionId: olderSess.id, appId: olderApp.id })
			const newer = db.logins.resolveUser('github', 'accidental-new-gh')
			const newerSess = db.tokens.create({ userId: newer.id, provider: 'self', admin: 1 })
			const absorbedApp = db.tokens.create({ userId: newer.id, provider: 'linear', type: 'static', credentials: { headers: { authorization: 'lin_absorbed' }, baseUrl: 'https://api.linear.app' } })
			await mcp(olderSess.token, 'admin', { action: 'share_app', appId: olderApp.id, account: 'github:accidental-new-gh' })
			const looserShare = db.tokens.upsertShare({ userId: newer.id, account: 'accidental-new-gh', authProvider: 'github', appId: shayApp.id, provider: 'stripe', policy: [{ action: 'allow', path: '/v1/*' }] })
			const stricterShare = db.tokens.upsertShare({ userId: older.id, account: 'primary-owner@example.com', authProvider: 'google', appId: shayApp.id, provider: 'stripe', policy: [{ action: 'allow', methods: ['GET'], path: '/v1/charges' }] })
			const olderWorker = db.tokens.create({ userId: older.id, provider: 'self', admin: 0 })
			db.links.create({ sessionId: olderWorker.id, appId: stricterShare.id })
			const conflictState = db.tokens.createState({ mode: 'auth', sessionId: newerSess.id, provider: 'google', merge: false })
			assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=g&state=${conflictState}`)).status, 409)
			assert.ok(db.users.get(newer.id), '409 conflict leaves target user untouched')
			const mergeState = db.tokens.createState({ mode: 'auth', sessionId: newerSess.id, provider: 'google', merge: true })
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
			assert.equal(db.tokens.get(absorbedApp.id).userId, older.id)
			assert.deepEqual(db.tokens.get(absorbedApp.id).credentials.headers, { authorization: 'lin_absorbed' }, 'Re-parented app decrypts cleanly')
			const mergedApps = JSON.parse((await mcp(newerSess.token, 'admin', { action: 'list_apps' })).content[0].text).apps
			assert.equal(mergedApps.some(a => a.type === 'share' && a.name === 'Older Stripe'), false, 'Self-shares cleaned up on merge')
			assert.ok(db.tokens.get(looserShare.id) && !db.tokens.get(stricterShare.id))
			assert.deepEqual(db.links.listBySessionId(olderWorker.id), [], 'Conflicting share link with different policy drops fail-closed on merge')
			await withEnv({ SSO_DOMAINS: 'isolated.corp:google' }, async () => {
				const pinned = db.logins.resolveUser('google', 'staff@isolated.corp')
				db.logins.upsert({ userId: pinned.id, provider: 'github', account: 'sso-bridge-gh' })
				const outsider = db.logins.resolveUser('google', 'outsider@gmail.com')
				const outsiderSess = db.tokens.create({ userId: outsider.id, provider: 'self', admin: 1 })
				ghLogin = 'sso-bridge-gh'
				const ssoMergeState = db.tokens.createState({ mode: 'auth', sessionId: outsiderSess.id, provider: 'github', merge: true })
				assert.equal((await origFetch(`${baseUrl()}/oauth/callback?code=gh&state=${ssoMergeState}`)).status, 403, 'Merge rejects absorbing logins violating SSO_DOMAINS')
				assert.ok(db.users.get(pinned.id))
			})
			assert.throws(() => db.logins.upsert({ userId: 'nonexistent-user', provider: 'google', account: 'primary-owner@example.com', merge: true }), { status: 404, message: 'User not found' })
		})
	})
})
