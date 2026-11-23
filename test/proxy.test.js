import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import { PassThrough, Readable } from 'node:stream'
import zlib from 'node:zlib'
import { VIRTUAL_UPSTREAM_IP, useServer, baseUrl, testDbPath, createTestSession, withUpstream, withDnsTest, withEnv, mcp, req, db, providers, proxy, utilMod } from './helpers.js'

useServer()

test('provider URL allowlists, target resolution, path traversal, and SSRF IP/hostname blocklist', async () => {
	assert.equal(providers.google.isAllowedUrl('https://www.googleapis.com/drive/v3/files').allowed, true)
	assert.equal(providers.google.isAllowedUrl('http://www.googleapis.com/drive/v3/files').allowed, false)
	assert.equal(providers.google.isAllowedUrl('https://evilgoogleapis.com/x').allowed, false)
	assert.equal(providers.google.isAllowedUrl('https://user:pass@www.googleapis.com/drive/v3/files').allowed, false)
	assert.equal(providers.github.isAllowedUrl('https://api.github.com/repos/jessetane/jump').allowed, true)
	assert.equal(providers.github.isAllowedUrl('https://evil.com/repos').allowed, false)
	const customProv = providers.createProvider({ id: 'scoped_prov', baseUrl: 'https://api.custom.dev/v2/tenant-a' })
	assert.equal(customProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/items').allowed, true)
	assert.equal(customProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/%2e%2e/tenant-b').allowed, false)
	assert.equal(customProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/..;/tenant-b').allowed, false, 'Matrix-param ..; traversal must not escape baseUrl prefix')
	assert.equal(customProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a/%2e%2e%3bfoo=1/tenant-b').allowed, false)
	assert.equal(customProv.isAllowedUrl('https://api.custom.dev/v2/tenant-a\\..\\tenant-b').allowed, false)
	assert.equal(utilMod.hasPathTraversal('/v1/public/%252e%252e/admin'), true)
	assert.equal(utilMod.hasPathTraversal('/v1/public%5cadmin'), true)
	assert.equal(utilMod.hasPathTraversal('/v1/items;v=2'), false)
	assert.equal(utilMod.hasPathTraversal('/v1/foo..bar/items'), false)
	assert.equal(utilMod.hasPathTraversal('/storage/v1/b/my-bucket/o/folder%2Ffile.pdf'), false)
	assert.equal(utilMod.resolveTargetUrl('https:/api.example.com/v1/items'), 'https://api.example.com/v1/items')
	assert.equal(utilMod.resolveTargetUrl('HTTPS:/api.example.com/v1/items'), 'https://api.example.com/v1/items')
	assert.equal(utilMod.resolveTargetUrl('HTTPS://www.googleapis.com/drive/v3/files', 'https://www.googleapis.com'), 'HTTPS://www.googleapis.com/drive/v3/files')
	assert.equal(utilMod.resolveTargetUrl('ftp://evil.com/file', 'https://api.example.com'), 'ftp://evil.com/file')
	assert.equal(providers.google.normalizeTargetUrl('HTTPS://www.googleapis.com/drive/v3/files'), 'HTTPS://www.googleapis.com/drive/v3/files')
	assert.equal(providers.google.isAllowedUrl('HTTP://www.googleapis.com/drive/v3/files').allowed, false)
	assert.equal(utilMod.resolveTargetUrl('/v1/items', 'https://api.example.com/base/'), 'https://api.example.com/base/v1/items')
	await assert.rejects(() => proxy.sendUpstreamHop('ftp://8.8.8.8/file', { method: 'GET', headers: {}, timeoutMs: 1000 }), err => err.status === 400)
	await assert.rejects(() => proxy.sendUpstreamHop('http://8.8.8.8/file', { method: 'GET', headers: {}, timeoutMs: 1000 }), err => err.status === 400)
	for (const blocked of [
		'https://user:pass@fcc.gov/api',
		'http://fcc.gov/api',
		'https://localhost',
		'https://localhost.',
		'https://localhost..',
		'https://metadata.google.internal',
		'https://127.0.0.1',
		'https://169.254.169.254',
		'https://10.0.0.1',
		'https://192.168.1.1',
		'https://172.16.0.5',
		'https://100.64.0.1',
		'https://192.0.2.1',
		'https://[::ffff:127.0.0.1]',
		'https://[::ffff:1.1.1.1]',
		'https://[fc0::1]',
		'https://[fd1::1]',
		'https://[fe80::1]',
		'https://[64:ff9b::a9fe:a9fe]',
		'https://[2002:a9fe:a9fe::]'
	]) {
		assert.equal(utilMod.validateBaseUrl(blocked), null, `Must block unsafe baseUrl: ${blocked}`)
	}
	for (const allowed of ['https://fcc.gov/api/v1/', 'https://1.1.1.1', 'https://100.128.0.1', 'https://[2606:4700:4700::1111]']) {
		assert.ok(utilMod.validateBaseUrl(allowed), `Must allow public baseUrl: ${allowed}`)
	}
})

test('socket-pinned single-lookup DNS resolution blocks private answers and defeats DNS rebinding', async () => {
	const tlsReceived = []
	let loopbackTrapHits = 0
	let tlsPort = 0
	const dnsFixtures = {
		'loopback-v4.example.test': [{ address: '127.0.0.1', family: 4 }],
		'loopback-v6.example.test': [{ address: '::1', family: 6 }],
		'rfc1918.example.test': [{ address: '10.0.0.5', family: 4 }],
		'rfc6598.example.test': [{ address: '100.64.1.20', family: 4 }],
		'nat64.example.test': [{ address: '64:ff9b::a9fe:a9fe', family: 6 }],
		'ula.example.test': [{ address: 'fd00:ec2::254', family: 6 }],
		'mixed.example.test': [{ address: VIRTUAL_UPSTREAM_IP, family: 4 }, { address: '192.168.1.10', family: 4 }],
		'public.example.test': [{ address: VIRTUAL_UPSTREAM_IP, family: 4 }]
	}
	const lookupCounts = new Map()
	const dialedIps = []
	let rebindAttempt = 0
	await withUpstream({ host: 'public.example.test' }, (upReq, res) => {
		tlsReceived.push({ sni: upReq.socket.servername, host: upReq.headers.host, url: upReq.url })
		if (upReq.url === '/bounce-to-cgnat') {
			res.writeHead(302, { location: `https://rfc6598.example.test:${tlsPort}/internal` })
			res.end()
			return
		}
		if (upReq.url === '/v1/first') res.setHeader('connection', 'close')
		res.writeHead(200, { 'content-type': 'application/json' })
		res.end(JSON.stringify({ ok: true, sni: upReq.socket.servername, host: upReq.headers.host, te: upReq.headers['transfer-encoding'] || null }))
	}, async ({ port }) => {
		tlsPort = port
		await withUpstream({ host: 'trap.example.test' }, (upReq, res) => {
			loopbackTrapHits++
			res.writeHead(200, { 'content-type': 'application/json' })
			res.end(JSON.stringify({ leaked: true }))
		}, async () => {
			await withDnsTest({
				lookup: async (host, opts, orig) => {
					lookupCounts.set(host, (lookupCounts.get(host) || 0) + 1)
					if (host === 'rebind.example.test') {
						rebindAttempt++
						return rebindAttempt === 1 ? [{ address: VIRTUAL_UPSTREAM_IP, family: 4 }] : [{ address: '127.0.0.1', family: 4 }]
					}
					if (Object.hasOwn(dnsFixtures, host)) return dnsFixtures[host]
					return orig(host, opts)
				},
				onDial: ip => dialedIps.push(ip)
			}, async () => {
				const { user, session } = createTestSession({ account: 'dns-ssrf@example.com', admin: true, withApp: false })
				for (const [idx, host] of Object.keys(dnsFixtures).filter(h => h !== 'public.example.test').entries()) {
					const provider = `ssrf_${idx}`
					const app = db.tokens.create({ userId: user.id, provider, type: 'static', credentials: { headers: { authorization: 'Bearer sk' }, baseUrl: `https://${host}:${tlsPort}` } })
					db.links.create({ sessionId: session.id, appId: app.id })
					assert.equal((await mcp(session.token, `${provider}_api`, { url: '/v1/data' })).isError, true)
					assert.equal((await req('GET', `/api/${provider}/v1/data`, { token: session.token })).status, 403)
				}
				assert.deepEqual(dialedIps, [], 'No TCP socket may dial on blocked DNS answers')
				assert.deepEqual(tlsReceived, [])
				const pubApp = db.tokens.create({ userId: user.id, provider: 'ssrf_pub', type: 'static', credentials: { headers: { authorization: 'Bearer sk_pub' }, baseUrl: `https://public.example.test:${tlsPort}` } })
				db.links.create({ sessionId: session.id, appId: pubApp.id })
				lookupCounts.clear()
				const okPubRes = await mcp(session.token, 'ssrf_pub_api', { url: '/v1/ok', headers: { host: 'evil.com', 'transfer-encoding': 'chunked' } })
				assert.equal(okPubRes.isError, undefined)
				assert.deepEqual(JSON.parse(okPubRes.content[0].text), { ok: true, sni: 'public.example.test', host: `public.example.test:${tlsPort}`, te: null })
				assert.equal(lookupCounts.get('public.example.test'), 1)
				assert.equal((await mcp(session.token, 'ssrf_pub_api', { url: '/bounce-to-cgnat' })).isError, true)
				const ip4App = db.tokens.create({ userId: user.id, provider: 'ssrf_ip4', type: 'static', credentials: { headers: { authorization: 'Bearer sk_ip4' }, baseUrl: `https://${VIRTUAL_UPSTREAM_IP}:${tlsPort}` } })
				db.links.create({ sessionId: session.id, appId: ip4App.id })
				dialedIps.length = 0
				assert.equal((await mcp(session.token, 'ssrf_ip4_api', { url: '/v1/ip4' })).isError, undefined)
				assert.deepEqual(dialedIps, [VIRTUAL_UPSTREAM_IP])
				const rebindApp = db.tokens.create({ userId: user.id, provider: 'ssrf_rebind', type: 'static', credentials: { headers: { authorization: 'Bearer sk_rebind' }, baseUrl: `https://rebind.example.test:${tlsPort}` } })
				db.links.create({ sessionId: session.id, appId: rebindApp.id })
				dialedIps.length = 0
				assert.equal((await mcp(session.token, 'ssrf_rebind_api', { url: '/v1/first' })).isError, undefined)
				assert.equal(lookupCounts.get('rebind.example.test'), 1, 'Exact 1 lookup on first request prevents 2nd-lookup TOCTOU')
				assert.equal((await mcp(session.token, 'ssrf_rebind_api', { url: '/v1/second' })).isError, true)
				assert.equal(loopbackTrapHits, 0)
			})
		})
	})
})

test('upstream redirects validate targets, strip headers/query secrets cross-origin and on bounce-back, and downgrade 303', async () => {
	const cdnReceived = []
	let apiPort = 0
	const qSecret = 'SUPER_SECRET_QUERY_KEY_998877'
	await withUpstream({ host: 'cdn.example.test' }, (upReq, res) => {
		cdnReceived.push({ method: upReq.method, url: upReq.url, headers: upReq.headers })
		if (upReq.url === '/bounce-to-api') {
			res.writeHead(302, { location: `https://api.example.test:${apiPort}/echo-auth` })
			res.end()
			return
		}
		if (upReq.url === '/bounce-to-qauth') {
			res.writeHead(302, { location: `https://api.example.test:${apiPort}/qauth/dest?page=9` })
			res.end()
			return
		}
		res.writeHead(200, { 'content-type': 'application/octet-stream' })
		res.end(Buffer.from('archive-bytes'))
	}, async ({ url: cdnUrl }) => {
		await withUpstream({ host: 'api.example.test' }, (upReq, res) => {
			if (upReq.url === '/repos/acme/tarball') {
				res.writeHead(302, { location: `${cdnUrl}/dl/tarball.gz?sig=1` })
				res.end()
				return
			}
			if (upReq.url === '/bounce-back-auth') {
				res.writeHead(302, { location: `${cdnUrl}/bounce-to-api` })
				res.end()
				return
			}
			if (upReq.url === '/echo-auth') {
				res.writeHead(200, { 'content-type': 'application/json' })
				res.end(JSON.stringify({ auth: upReq.headers.authorization || null }))
				return
			}
			if (upReq.url === '/public/bounce-admin') {
				res.writeHead(302, { location: '/admin/secrets' })
				res.end()
				return
			}
			if (upReq.url === '/admin/secrets') {
				res.writeHead(200)
				res.end('secret')
				return
			}
			if (upReq.url === '/post-303') {
				res.writeHead(303, { location: `${cdnUrl}/after-post` })
				res.end()
				return
			}
			if (upReq.url === '/ssrf-meta') {
				res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
				res.end()
				return
			}
			if (upReq.url === '/userinfo-hop') {
				res.writeHead(302, { location: `https://user:secret@${new URL(cdnUrl).host}/after` })
				res.end()
				return
			}
			if (upReq.url === '/loop') {
				res.writeHead(302, { location: '/loop' })
				res.end()
				return
			}
			if (upReq.url.startsWith('/qauth/start')) {
				res.writeHead(302, { location: '/qauth/dest?page=2' })
				res.end()
				return
			}
			if (upReq.url.startsWith('/qauth/bounce')) {
				res.writeHead(302, { location: `${cdnUrl}/bounce-to-qauth` })
				res.end()
				return
			}
			if (upReq.url.startsWith('/qauth/cdn')) {
				res.writeHead(302, { location: `${cdnUrl}/cdn?ApiKey=override&asset=1` })
				res.end()
				return
			}
			if (upReq.url.startsWith('/qauth/raw-rel')) {
				res.writeHead(302, { location: `/v2/next?apikey=${qSecret}&ok=1#sec` })
				res.end()
				return
			}
			if (upReq.url.startsWith('/qauth/raw-bad-loc')) {
				res.writeHead(302, { location: `http://[::1:bad/?ApiKey=${qSecret}` })
				res.end()
				return
			}
			if (upReq.url.startsWith('/qauth/dest')) {
				res.writeHead(200, { 'content-type': 'application/json' })
				res.end(JSON.stringify({ url: upReq.url }))
				return
			}
			res.writeHead(404)
			res.end()
		}, async ({ url: apiUrl, port }) => {
			apiPort = port
			const { user, session } = createTestSession({ account: 'redirects@example.com', admin: true, withApp: false })
			const ghApp = db.tokens.create({
				userId: user.id,
				provider: 'github',
				type: 'static',
				credentials: { headers: { authorization: 'Bearer ghp_secret', 'x-tenant': 'acme' }, baseUrl: apiUrl }
			})
			db.links.create({ sessionId: session.id, appId: ghApp.id, policy: [{ action: 'deny', path: '/admin/**' }, { action: 'allow', path: '/**' }] })
			const qApp = db.tokens.create({
				userId: user.id,
				provider: 'namecheap',
				type: 'static',
				credentials: { query: { ApiKey: qSecret }, baseUrl: apiUrl }
			})
			db.links.create({ sessionId: session.id, appId: qApp.id, policy: [{ action: 'allow', path: '/qauth/**' }] })
			const okDl = await mcp(session.token, 'github_api', { url: '/repos/acme/tarball' })
			assert.equal(Buffer.from(JSON.parse(okDl.content[0].text).data, 'base64').toString('utf8'), 'archive-bytes')
			assert.equal(cdnReceived[0].headers.authorization, undefined)
			assert.equal(cdnReceived[0].headers['x-tenant'], undefined)
			const restRedirect = await req('GET', '/api/github/repos/acme/tarball', { token: session.token, redirect: 'manual' })
			assert.equal(restRedirect.status, 302)
			assert.equal((await mcp(session.token, 'github_api', { url: '/public/bounce-admin' })).isError, true, 'Same-origin redirect re-checks policy')
			assert.equal(JSON.parse((await mcp(session.token, 'github_api', { url: '/bounce-back-auth' })).content[0].text).auth, null, 'Off-origin then back-origin redirect must not re-attach auth')
			cdnReceived.length = 0
			assert.equal((await mcp(session.token, 'github_api', { url: '/post-303', method: 'POST', body: { a: 1 } })).isError, undefined)
			assert.equal(cdnReceived[0].method, 'GET')
			assert.equal(cdnReceived[0].headers['content-type'], undefined)
			assert.equal((await mcp(session.token, 'github_api', { url: '/ssrf-meta' })).isError, true)
			const userinfoRes = await mcp(session.token, 'github_api', { url: '/userinfo-hop' })
			assert.equal(userinfoRes.isError, true)
			assert.equal(userinfoRes.content[0].text.includes('secret'), false)
			assert.equal((await mcp(session.token, 'github_api', { url: '/loop' })).isError, true)
			assert.equal(JSON.parse((await mcp(session.token, 'namecheap_api', { url: '/qauth/start' })).content[0].text).url, `/qauth/dest?page=2&ApiKey=${qSecret}`)
			cdnReceived.length = 0
			assert.equal((await mcp(session.token, 'namecheap_api', { url: '/qauth/cdn' })).isError, undefined)
			assert.equal(cdnReceived[0].url.includes(qSecret), false)
			assert.equal(JSON.parse((await mcp(session.token, 'namecheap_api', { url: '/qauth/bounce' })).content[0].text).url, '/qauth/dest?page=9')
			const rawRel = await req('GET', '/api/namecheap/qauth/raw-rel', { token: session.token, redirect: 'manual' })
			assert.equal(rawRel.status, 302)
			assert.equal(rawRel.headers.get('location'), '/v2/next?ok=1#sec')
			const origConsoleError = console.error
			let errLogs = ''
			console.error = (...args) => { errLogs += args.map(String).join(' ') }
			let rawBadLoc
			try {
				rawBadLoc = await req('GET', '/api/namecheap/qauth/raw-bad-loc', { token: session.token, redirect: 'manual' })
			} finally {
				console.error = origConsoleError
			}
			assert.equal(rawBadLoc.status, 502)
			assert.equal(errLogs.includes(qSecret), false)
			assert.equal(rawBadLoc.text.includes(qSecret), false)
			db.sqlite.exec('PRAGMA wal_checkpoint(FULL);')
			assert.equal(fs.readFileSync(testDbPath).includes(qSecret), false)
		})
	})
})

test('MCP buffered decompression/limits vs REST streaming, body-inspection guards, timeouts, and teardown', async () => {
	await assert.rejects(() => proxy.readResponseBody(Readable.from([Buffer.alloc(500), Buffer.alloc(600)]), 1000), err => err.status === 413)
	const gzBr = zlib.brotliCompressSync(zlib.gzipSync(Buffer.from('stacked-ok')))
	assert.equal((await proxy.readResponseBody(Object.assign(Readable.from([gzBr]), { headers: { 'content-encoding': 'gzip, br' } }), 1000)).toString('utf8'), 'stacked-ok')
	await assert.rejects(() => proxy.readResponseBody(Object.assign(Readable.from([gzBr]), { headers: { 'content-encoding': 'gzip, bogus' } }), 1000), err => err.status === 502)
	const bodilessErr = new PassThrough()
	proxy.drainSilently(bodilessErr)
	assert.doesNotThrow(() => bodilessErr.destroy(new Error('reset')))
	let lastAcceptEnc = null
	let uploadAborted = false
	let uploadHits = 0
	let lastUploadBody = ''
	let lastUploadContentLength = null
	let early200Bytes = 0
	let early413Bytes = 0
	await withUpstream(async (upReq, res) => {
		lastAcceptEnc = upReq.headers['accept-encoding'] || null
		if (upReq.url === '/gzip') {
			res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' })
			res.end(zlib.gzipSync(Buffer.from(JSON.stringify({ ok: 'gz' }))))
			return
		}
		if (upReq.url === '/zstd') {
			res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'zstd' })
			res.end(zlib.zstdCompressSync(Buffer.from(JSON.stringify({ ok: 'zstd' }))))
			return
		}
		if (upReq.url === '/empty-204-gzip') {
			res.writeHead(204, { 'content-encoding': 'gzip' })
			res.end()
			return
		}
		if (upReq.url === '/image-png') {
			res.writeHead(200, { 'content-type': 'image/png' })
			res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
			return
		}
		if (upReq.url === '/latin1') {
			res.writeHead(200, { 'content-type': 'text/plain; charset=latin1' })
			res.end(Buffer.from([0x43, 0x61, 0x66, 0xe9]))
			return
		}
		if (upReq.url === '/bomb') {
			res.writeHead(200, { 'content-type': 'text/plain', 'content-encoding': 'gzip' })
			res.end(zlib.gzipSync(Buffer.alloc(2 * 1024 * 1024, 0x41)))
			return
		}
		if (upReq.url === '/large-stream') {
			res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(1536 * 1024), 'set-cookie': 'bad=1', 'x-content-type-options': 'bogus' })
			if (upReq.method !== 'HEAD') res.write(Buffer.alloc(1536 * 1024, 0x5a))
			res.end()
			return
		}
		if (upReq.url === '/upload-stream') {
			uploadHits++
			const chunks = []
			let bytes = 0
			for await (const c of upReq) {
				bytes += c.byteLength
				if (bytes <= 4096) chunks.push(c)
			}
			lastUploadBody = bytes <= 4096 ? Buffer.concat(chunks).toString('utf8') : ''
			lastUploadContentLength = upReq.headers['content-length'] || null
			res.writeHead(200, { 'content-type': 'application/json' })
			res.end(JSON.stringify({ bytes }))
			return
		}
		if (upReq.url === '/pre-byte-reset') {
			res.writeHead(200, { 'content-encoding': 'gzip', 'content-length': '5000000', location: '/leak' })
			res.flushHeaders()
			setTimeout(() => res.socket?.destroy(), 10)
			return
		}
		if (upReq.url === '/upload-abort') {
			upReq.on('error', () => {})
			upReq.on('close', () => { if (!upReq.complete) uploadAborted = true })
			upReq.resume()
			return
		}
		if (upReq.url === '/early-413' || upReq.url === '/early-200') {
			const is200 = upReq.url === '/early-200'
			upReq.on('error', () => {})
			upReq.on('data', chunk => {
				if (is200) early200Bytes += chunk.byteLength
				else early413Bytes += chunk.byteLength
				if (!res.headersSent) {
					res.writeHead(is200 ? 200 : 413, { 'content-type': 'application/json' })
					setTimeout(() => res.end(JSON.stringify({ early: is200 ? 200 : 413 })), 15)
				}
			})
			return
		}
		if (upReq.url === '/active-trickle') {
			res.writeHead(200, { 'content-type': 'text/plain' })
			for (let i = 0; i < 4; i++) {
				await new Promise(r => setTimeout(r, 60))
				res.write(`p${i};`)
			}
			res.end()
			return
		}
		if (upReq.url === '/hung-silence') {
			res.writeHead(200, { 'content-type': 'text/plain' })
			res.write('start;')
			return
		}
		if (upReq.url === '/ws-upgrade') {
			res.writeHead(101, { Connection: 'Upgrade', Upgrade: 'websocket' })
			res.end()
			return
		}
		res.writeHead(200, { 'content-type': 'application/json' })
		res.end(JSON.stringify({ method: upReq.method }))
	}, async ({ url: upstreamUrl }) => {
		await withEnv({ MAX_FILE_SIZE_MB: '1' }, async () => {
			const { user, session } = createTestSession({ account: 'stream@example.com', admin: true, withApp: false })
			const app = db.tokens.create({ userId: user.id, provider: 'comp', type: 'static', credentials: { headers: { authorization: 'Bearer sk_comp' }, baseUrl: upstreamUrl } })
			db.links.create({ sessionId: session.id, appId: app.id })
			assert.deepEqual(JSON.parse((await mcp(session.token, 'comp_api', { url: '/gzip', headers: { 'accept-encoding': 'bogus' } })).content[0].text), { ok: 'gz' })
			assert.equal(lastAcceptEnc, 'gzip, br, zstd')
			assert.deepEqual(JSON.parse((await mcp(session.token, 'comp_api', { url: '/zstd' })).content[0].text), { ok: 'zstd' })
			assert.equal((await mcp(session.token, 'comp_api', { url: '/empty-204-gzip', method: 'DELETE' })).isError, undefined)
			const imgRes = await mcp(session.token, 'comp_api', { url: '/image-png' })
			assert.deepEqual(imgRes.content[0], { type: 'image', mimeType: 'image/png', data: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).toString('base64') })
			assert.equal((await mcp(session.token, 'comp_api', { url: '/latin1' })).content[0].text, 'Café')
			assert.equal((await mcp(session.token, 'comp_api', { url: '/bomb' })).isError, true)
			assert.equal((await mcp(session.token, 'comp_api', { url: '/ws-upgrade' })).isError, true)
			assert.equal((await mcp(session.token, 'comp_api', { url: '/gzip', method: 'CONNECT' })).isError, true)
			const restLarge = await fetch(`${baseUrl()}/api/comp/large-stream`, { headers: { authorization: `Bearer ${session.token}` } })
			assert.equal(restLarge.status, 200)
			assert.equal((await restLarge.arrayBuffer()).byteLength, 1536 * 1024)
			assert.equal(restLarge.headers.get('set-cookie'), null)
			assert.equal(restLarge.headers.get('x-content-type-options'), 'nosniff')
			assert.equal(restLarge.headers.get('content-security-policy'), 'sandbox')
			assert.equal((await req('HEAD', '/api/comp/large-stream', { token: session.token })).status, 200)
			assert.equal((await mcp(session.token, 'comp_api', { url: '/large-stream', method: 'HEAD' })).isError, undefined)
			assert.equal((await mcp(session.token, 'comp_api', { url: '/large-stream', method: 'GET' })).isError, true)
			const resetRes = await req('GET', '/api/comp/pre-byte-reset', { token: session.token })
			assert.equal(resetRes.status, 502)
			assert.equal(resetRes.headers.get('content-encoding'), null)
			assert.equal(resetRes.headers.get('location'), null)
			const restUp = await req('POST', '/api/comp/upload-stream', { token: session.token, headers: { 'content-type': 'application/octet-stream' }, body: Buffer.alloc(1536 * 1024, 0x42) })
			assert.equal(restUp.data.bytes, 1536 * 1024)
			const inspectedSess = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
			db.links.create({ sessionId: inspectedSess.id, appId: app.id, policy: [{ action: 'deny', methods: ['POST'], body: '*secret*' }, { action: 'allow', methods: ['POST'], path: '/upload-stream' }] })
			const gzDenied = await req('POST', '/api/comp/upload-stream', {
				token: inspectedSess.token,
				headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
				body: zlib.gzipSync(Buffer.from(JSON.stringify({ msg: 'secret' })))
			})
			assert.equal(gzDenied.status, 415, 'Body-inspected REST requests reject Content-Encoding with 415')
			const hitsBefore = uploadHits
			const allowedRestBody = JSON.stringify({ msg: 'hello-rest' })
			const allowedRest = await req('POST', '/api/comp/upload-stream', {
				token: inspectedSess.token,
				headers: { 'content-type': 'application/json' },
				body: allowedRestBody
			})
			assert.equal(allowedRest.status, 200)
			assert.equal(lastUploadBody, allowedRestBody)
			assert.equal(lastUploadContentLength, String(Buffer.byteLength(allowedRestBody)))
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: inspectedSess.token,
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ msg: 'contains secret here' })
			})).status, 403)
			assert.equal(uploadHits, hitsBefore + 1, 'Denied REST body never reaches upstream')
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: inspectedSess.token,
				headers: { 'content-type': 'application/octet-stream' },
				body: Buffer.alloc(1024 * 1024 + 1, 0x61)
			})).status, 413, 'Inspected REST request body enforces 1 MB getRawBody limit')
			const jsonPolicySess = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
			db.links.create({
				sessionId: jsonPolicySess.id,
				appId: app.id,
				policy: [
					{ action: 'deny', methods: ['POST'], body: { role: 'admin' } },
					{ action: 'allow', methods: ['POST'], path: '/upload-stream' }
				]
			})
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: jsonPolicySess.token,
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ role: 'user' })
			})).status, 200)
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: jsonPolicySess.token,
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ role: 'admin' })
			})).status, 403)
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: jsonPolicySess.token,
				headers: { 'content-type': 'application/json' },
				body: '{malformed'
			})).status, 403, 'Malformed JSON under inspecting REST policy fails closed')
			const formPolicySess = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
			db.links.create({
				sessionId: formPolicySess.id,
				appId: app.id,
				policy: [
					{ action: 'deny', methods: ['POST'], body: { tag: 'evil' }, bodyType: 'form' },
					{ action: 'allow', methods: ['POST'], path: '/upload-stream' }
				]
			})
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: formPolicySess.token,
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: 'tag=ok'
			})).status, 200)
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: formPolicySess.token,
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: 'tag=evil'
			})).status, 403)
			assert.equal(uploadHits, hitsBefore + 3, 'Only allowed inspected requests reach upstream')
			const uninspectedSess = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
			db.links.create({ sessionId: uninspectedSess.id, appId: app.id, policy: [{ action: 'allow', methods: ['POST'], path: '/upload-stream' }] })
			assert.equal((await req('POST', '/api/comp/upload-stream', {
				token: uninspectedSess.token,
				headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
				body: zlib.gzipSync(Buffer.from(JSON.stringify({ ok: 1 })))
			})).status, 200, 'Compressed uploads pass through when no body policy inspects body')
			const port = new URL(baseUrl()).port
			await new Promise((resolve, reject) => {
				const sock = net.createConnection({ host: '127.0.0.1', port }, () => {
					sock.write(`POST /api/comp/upload-abort HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${session.token}\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\npartial`)
					setTimeout(() => { sock.end(); resolve() }, 20)
				})
				sock.on('error', reject)
			})
			for (let i = 0; i < 40 && !uploadAborted; i++) await new Promise(r => setTimeout(r, 10))
			assert.equal(uploadAborted, true)
			const runEarly = p => new Promise((resolve, reject) => {
				let settled = false
				let gotRes = false
				const r = http.request(`${baseUrl()}${p}`, {
					method: 'POST',
					headers: { authorization: `Bearer ${session.token}`, 'content-type': 'application/octet-stream', 'content-length': String(2 * 1024 * 1024) }
				}, res => {
					gotRes = true
					const chunks = []
					res.on('data', c => chunks.push(c))
					res.on('end', () => { settled = true; resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }) })
				})
				r.on('error', err => { if (!settled && err.code !== 'EPIPE' && err.code !== 'ECONNRESET') reject(err) })
				const pump = async () => {
					const chunk = Buffer.alloc(64 * 1024, 0x44)
					for (let i = 0; i < 32 && !gotRes && !settled && !r.destroyed; i++) {
						r.write(chunk)
						await new Promise(done => setTimeout(done, 15))
					}
					if (!gotRes && !settled && !r.destroyed) r.end()
				}
				pump()
			})
			const e413 = await runEarly('/api/comp/early-413')
			assert.equal(e413.status, 413)
			assert.equal(e413.headers.connection, 'close')
			assert.ok(early413Bytes < 1024 * 1024)
			const e200 = await runEarly('/api/comp/early-200')
			assert.equal(e200.status, 200)
			assert.equal(e200.headers.connection, 'close')
			assert.ok(early200Bytes < 1024 * 1024)
			await withEnv({ UPSTREAM_TIMEOUT_MS: '180' }, async () => {
				const trickle = await req('GET', '/api/comp/active-trickle', { token: session.token })
				assert.equal(trickle.status, 200)
				assert.equal(trickle.text, 'p0;p1;p2;p3;')
				assert.equal((await mcp(session.token, 'comp_api', { url: '/hung-silence' })).isError, true)
			})
		})
	})
})

test('structured credentials attachment, header hygiene, unit replacement, and app disambiguation', async () => {
	const captured = []
	await withUpstream((upReq, res) => {
		const chunks = []
		upReq.on('data', c => chunks.push(c))
		upReq.on('end', () => {
			captured.push({ method: upReq.method, url: upReq.url, headers: upReq.headers, body: Buffer.concat(chunks).toString('utf8') })
			res.writeHead(200, { 'content-type': 'application/json' })
			res.end(JSON.stringify({ ok: true, url: upReq.url, auth: upReq.headers.authorization || null, body: captured.at(-1).body }))
		})
	}, async ({ url: upstreamUrl }) => {
		const { user, session } = createTestSession({ account: 'creds-proxy@example.com', admin: true, withApp: false })
		const basicApp = JSON.parse((await mcp(session.token, 'admin', { action: 'connect_app', provider: 'mailgun', credentials: { basic: 'api:key-mg' }, baseUrl: upstreamUrl })).content[0].text).app
		await mcp(session.token, 'admin', { action: 'link_app', sessionId: session.id, appId: basicApp.id })
		await mcp(session.token, 'mailgun_api', {
			url: '/v3/messages',
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Bearer spoof' },
			body: { from: 'a@b.com', tag: ['x', 'y'], vars: { plan: 'pro' } }
		})
		assert.equal(captured.at(-1).headers.authorization, `Basic ${Buffer.from('api:key-mg').toString('base64')}`)
		assert.equal(captured.at(-1).body, 'from=a%40b.com&tag=x&tag=y&vars=%7B%22plan%22%3A%22pro%22%7D')
		const scopedCt = db.tokens.create({ userId: user.id, provider: 'self', admin: 0 })
		db.links.create({ sessionId: scopedCt.id, appId: basicApp.id, policy: [{ action: 'deny', methods: ['POST'], body: { tag: 'evil' }, bodyType: 'form' }, { action: 'allow', methods: ['POST'], path: '/v3/messages' }] })
		const ctDiffBlocked = await mcp(scopedCt.token, 'mailgun_api', {
			url: '/v3/messages',
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
			body: { tag: 'evil' }
		})
		assert.equal(ctDiffBlocked.isError, true, 'Mixed-case Content-Type cannot bypass form body policy')
		await mcp(session.token, 'mailgun_api', { url: '/v3/get-strip', method: 'GET', body: { unwanted: 1 } })
		assert.equal(captured.at(-1).body, '', 'GET strips body')
		assert.equal(captured.at(-1).headers['content-type'], undefined)
		const notionConnect = await mcp(session.token, 'admin', {
			action: 'connect_app',
			provider: 'notion',
			credentials: {
				bearer: 'Bearer secret_notion',
				headers: { 'Notion-Version': '2022-06-28', constructor: 'ctor_val' },
				query: { workspace: 'ws_1', ApiKey: 'k_1' }
			},
			baseUrl: upstreamUrl
		})
		assert.equal(notionConnect.isError, undefined, notionConnect.content[0].text)
		const notionApp = JSON.parse(notionConnect.content[0].text).app
		await mcp(session.token, 'admin', { action: 'link_app', sessionId: session.id, appId: notionApp.id })
		const notionMcp = await mcp(session.token, 'notion_api', {
			url: '/v1/pages?WORKspace=spoof&apikey=spoof&page=1',
			headers: { 'notion-version': '1999', authorization: 'Bearer spoof' }
		})
		assert.equal(notionMcp.isError, undefined)
		assert.equal(captured.at(-1).headers.authorization, 'Bearer secret_notion')
		assert.equal(captured.at(-1).headers['notion-version'], '2022-06-28')
		const notionRest = await req('POST', '/api/notion/v1/pages?WORKspace=spoof&apikey=spoof&page=1', {
			token: session.token,
			headers: { 'notion-version': '1999', cookie: 'sid=1', 'x-api-key': 'jump_key', 'x-safe': 'keep' },
			body: Buffer.from('raw')
		})
		assert.equal(notionRest.status, 200, notionRest.text)
		assert.equal(captured.at(-1).headers.authorization, 'Bearer secret_notion')
		assert.equal(captured.at(-1).headers['notion-version'], '2022-06-28')
		assert.equal(captured.at(-1).headers.constructor, 'ctor_val')
		assert.equal(captured.at(-1).headers.cookie, undefined)
		assert.equal(captured.at(-1).headers['x-api-key'], undefined)
		assert.equal(captured.at(-1).headers['x-safe'], 'keep')
		const qUrl = new URL(captured.at(-1).url, upstreamUrl)
		assert.equal(qUrl.searchParams.get('workspace'), 'ws_1')
		assert.equal(qUrl.searchParams.get('WORKspace'), null)
		assert.equal(qUrl.searchParams.get('ApiKey'), 'k_1')
		assert.equal(qUrl.searchParams.get('apikey'), null)
		await mcp(session.token, 'admin', { action: 'update_app', appId: notionApp.id, credentials: { query: { api_key: 'replaced_only' } } })
		assert.equal(db.tokens.get(notionApp.id).credentials.headers, undefined, 'Unit credential replacement removes stale headers')
		assert.deepEqual(db.tokens.get(notionApp.id).credentials.query, { api_key: 'replaced_only' })
		const colonBearer = JSON.parse((await mcp(session.token, 'admin', { action: 'connect_app', provider: 'colon_b', credentials: 'part1:part2', baseUrl: upstreamUrl })).content[0].text).app
		db.links.create({ sessionId: session.id, appId: colonBearer.id })
		await mcp(session.token, 'colon_b_api', { url: '/c' })
		assert.equal(captured.at(-1).headers.authorization, 'Bearer part1:part2', 'String credentials with colon stay Bearer')
		const m1 = db.tokens.create({ userId: session.userId, provider: 'stripe', type: 'static', name: 'Personal', credentials: { account: 'p@example.com', headers: { authorization: 'Bearer sk_1' }, baseUrl: upstreamUrl } })
		const m2 = db.tokens.create({ userId: session.userId, provider: 'stripe', type: 'static', name: 'Work', credentials: { account: 'w@example.com', headers: { authorization: 'Bearer sk_2' }, baseUrl: upstreamUrl } })
		const m3 = db.tokens.create({ userId: session.userId, provider: 'stripe', type: 'static', name: 'Billing', credentials: { account: 'w@example.com', headers: { authorization: 'Bearer sk_3' }, baseUrl: upstreamUrl } })
		db.links.create({ sessionId: session.id, appId: m1.id, policy: [{ action: 'allow', path: '/p/**' }] })
		db.links.create({ sessionId: session.id, appId: m2.id, policy: [{ action: 'allow', path: '/w/**' }] })
		db.links.create({ sessionId: session.id, appId: m3.id, policy: [{ action: 'allow', path: '/b/**' }] })
		assert.equal((await mcp(session.token, 'stripe_api', { url: '/p/1' })).isError, true, 'Multiple linked apps without app param fails')
		assert.equal((await mcp(session.token, 'stripe_api', { url: '/w/1', app: 'w@example.com' })).isError, true, 'Ambiguous shared account fails')
		assert.equal((await mcp(session.token, 'stripe_api', { url: '/b/1', app: 'billing' })).isError, undefined)
		assert.equal(captured.at(-1).headers.authorization, 'Bearer sk_3')
		assert.equal((await mcp(session.token, 'stripe_api', { url: '/p/1', app: 'P@example.com' })).isError, undefined)
		assert.equal(captured.at(-1).headers.authorization, 'Bearer sk_1')
		assert.equal((await mcp(session.token, 'stripe_api', { url: '/p/1', app: m1.id })).isError, undefined)
		assert.equal((await mcp(session.token, 'stripe_api', { url: '/p/1', app: 'non-existent' })).isError, true)
		assert.equal((await req('GET', '/api/stripe/p/1', { token: session.token })).status, 400)
		assert.equal((await req('GET', '/api/stripe/p/1', { token: session.token, headers: { 'x-upstream-app': 'non-existent' } })).status, 404)
		const restSelId = await req('GET', '/api/stripe/p/1?app=upstream-app&other=1', { token: session.token, headers: { 'x-upstream-app': m1.id } })
		assert.equal(restSelId.status, 200)
		assert.equal(captured.at(-1).headers.authorization, 'Bearer sk_1')
		assert.equal(captured.at(-1).headers['x-upstream-app'], undefined)
		assert.equal(captured.at(-1).url, '/p/1?app=upstream-app&other=1')
		const restSelName = await req('GET', '/api/stripe/b/1?other=2', { token: session.token, headers: { 'x-upstream-app': 'billing' } })
		assert.equal(restSelName.status, 200)
		assert.equal(captured.at(-1).headers.authorization, 'Bearer sk_3')
		assert.equal(captured.at(-1).url, '/b/1?other=2')
	})
})
