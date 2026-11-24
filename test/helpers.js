import { before, after } from 'node:test'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import dns from 'node:dns'
import fs from 'node:fs'
import https from 'node:https'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import tls from 'node:tls'

const testDbPath = path.join(os.tmpdir(), `jump-test-${process.pid}-${randomUUID()}.db`)
process.env.DB_PATH = testDbPath
console.log = () => {}
process.env.APP_URL = ''
process.env.GOOGLE_CLIENT_ID = 'test-client-id'
process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret'
process.env.ALLOWED_REDIRECT_DOMAINS = 'chatgpt.com,*.antigravity.google,antigravity,cursor,vscode'
process.env.OAUTH_RATE_LIMIT = '10000'
process.env.USER_AGENT = 'jump-test'

const { server, bootstrapLocalAdmin } = await import('../server.js')
const db = await import('../db/index.js')
const providers = await import('../providers/index.js')
const api = await import('../api/index.js')
const proxy = await import('../api/proxy.js')
const mcpMod = await import('../mcp.js')
const oauthMod = await import('../oauth.js')
const policyMod = await import('../policy.js')
const ssoMod = await import('../sso.js')
const utilMod = await import('../util.js')
const cryptoMod = await import('../crypto.js')

function cleanupDbFiles (dbPath) {
	for (const suffix of ['', '-wal', '-shm', '.key', '.key.old']) {
		fs.rmSync(`${dbPath}${suffix}`, { force: true })
	}
}

function baseUrl () {
	return `http://127.0.0.1:${server.address().port}`
}

function useServer () {
	before((t, done) => {
		server.listen(0, '127.0.0.1', done)
	})
	after((t, done) => {
		server.close(() => {
			try {
				db.sqlite.close()
			} catch {}
			cleanupDbFiles(testDbPath)
			done()
		})
	})
	return baseUrl
}

function createTestSession (opts = {}) {
	const {
		account = `user-${randomUUID()}@example.com`,
		provider = 'google',
		admin = false,
		accessToken = 'ya29.fake-token',
		refreshToken = '1//fake-refresh',
		expiresAt = Date.now() + 3600000,
		scopes = null,
		policy = null,
		withApp = true,
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
	if (!withApp) return { user, session, app: null }
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

const VIRTUAL_UPSTREAM_IP = '93.184.216.34'
const localUpstreamPorts = new Set()
let testCertPem = null
let defaultCas = null
let shimDepth = 0
let origLookup = null
let origConnect = null
let customLookup = null
let dialObserver = null

function ensureTestCert () {
	if (testCertPem) return testCertPem
	testCertPem = execFileSync('openssl', [
		'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
		'-keyout', '/dev/stdout', '-out', '/dev/stdout',
		'-days', '1', '-nodes', '-subj', '/CN=*.example.test',
		'-addext', `subjectAltName=DNS:*.example.test,DNS:example.test,IP:${VIRTUAL_UPSTREAM_IP}`
	], { encoding: 'utf8' })
	defaultCas = tls.getCACertificates('default')
	tls.setDefaultCACertificates([...defaultCas, testCertPem])
	return testCertPem
}

function acquireNetworkShim () {
	ensureTestCert()
	if (shimDepth++ > 0) return
	origLookup = dns.promises.lookup
	origConnect = net.Socket.prototype.connect
	dns.promises.lookup = async (host, opts) => {
		if (customLookup) return customLookup(host, opts, origLookup)
		if (host.endsWith('.example.test')) return [{ address: VIRTUAL_UPSTREAM_IP, family: 4 }]
		return origLookup(host, opts)
	}
	net.Socket.prototype.connect = function (...args) {
		const opts = args[0]
		if (opts && typeof opts === 'object' && localUpstreamPorts.has(Number(opts.port))) {
			if (opts.host === VIRTUAL_UPSTREAM_IP) {
				dialObserver?.(opts.host)
				args[0] = { ...opts, host: '127.0.0.1' }
			} else if (typeof opts.lookup === 'function') {
				const realLookup = opts.lookup
				args[0] = {
					...opts,
					lookup (hostname, lookupOpts, cb) {
						realLookup(hostname, lookupOpts, (err, res, fam) => {
							if (err) return cb(err)
							if (Array.isArray(res)) {
								for (const r of res) dialObserver?.(r.address)
								return cb(null, res.map(r => r.address === VIRTUAL_UPSTREAM_IP ? { address: '127.0.0.1', family: 4 } : r))
							}
							dialObserver?.(res)
							cb(null, res === VIRTUAL_UPSTREAM_IP ? '127.0.0.1' : res, fam)
						})
					}
				}
			}
		}
		return origConnect.apply(this, args)
	}
}

function releaseNetworkShim () {
	if (--shimDepth > 0) return
	dns.promises.lookup = origLookup
	net.Socket.prototype.connect = origConnect
	https.globalAgent.destroy()
}

async function withDnsTest ({ lookup, onDial }, fn) {
	const prevLookup = customLookup
	const prevDial = dialObserver
	customLookup = lookup || null
	dialObserver = onDial || null
	acquireNetworkShim()
	try {
		return await fn()
	} finally {
		customLookup = prevLookup
		dialObserver = prevDial
		releaseNetworkShim()
	}
}

async function withUpstream (optsOrHandler, handlerOrFn, maybeFn) {
	const hasOpts = typeof optsOrHandler === 'object' && optsOrHandler !== null
	const host = hasOpts ? (optsOrHandler.host || 'api.example.test') : 'api.example.test'
	const handler = hasOpts ? handlerOrFn : optsOrHandler
	const fn = hasOpts ? maybeFn : handlerOrFn
	const pem = ensureTestCert()
	const upstream = https.createServer({ key: pem, cert: pem }, handler)
	await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve))
	const port = upstream.address().port
	const url = `https://${host}:${port}`
	localUpstreamPorts.add(port)
	acquireNetworkShim()
	try {
		return await fn({ url, host, port, server: upstream })
	} finally {
		https.globalAgent.destroy()
		upstream.closeAllConnections?.()
		await new Promise(resolve => upstream.close(resolve))
		localUpstreamPorts.delete(port)
		releaseNetworkShim()
	}
}

async function withMockFetch (handler, fn) {
	const origFetch = globalThis.fetch
	globalThis.fetch = (input, init) => handler(input, init, origFetch)
	try {
		return await fn(origFetch)
	} finally {
		globalThis.fetch = origFetch
	}
}

async function withEnv (vars, fn) {
	const saved = new Map()
	for (const [k, v] of Object.entries(vars)) {
		saved.set(k, process.env[k])
		if (v === undefined) delete process.env[k]
		else process.env[k] = v
	}
	try {
		return await fn()
	} finally {
		for (const [k, v] of saved) {
			if (v === undefined) delete process.env[k]
			else process.env[k] = v
		}
	}
}

function mcp (token, name, args, customBaseUrl) {
	return mcpMod.executeTool(name, args, token, customBaseUrl)
}

async function req (method, urlPath, opts = {}) {
	const { token, body, headers = {}, redirect } = opts
	const reqHeaders = { ...headers }
	if (token && !reqHeaders.authorization) reqHeaders.authorization = `Bearer ${token}`
	let reqBody = body
	if (body && typeof body === 'object' && !Buffer.isBuffer(body)) {
		if (!reqHeaders['content-type']) reqHeaders['content-type'] = 'application/json'
		reqBody = JSON.stringify(body)
	}
	const target = urlPath.startsWith('http://') || urlPath.startsWith('https://')
		? urlPath
		: `${baseUrl()}${urlPath}`
	const fetchOpts = { method, headers: reqHeaders }
	if (reqBody !== undefined) fetchOpts.body = reqBody
	if (redirect) fetchOpts.redirect = redirect
	const res = await fetch(target, fetchOpts)
	const text = await res.text()
	let data = null
	if (text && (res.headers.get('content-type') || '').includes('json')) {
		try {
			data = JSON.parse(text)
		} catch {}
	}
	return { status: res.status, headers: res.headers, text, data, res }
}

export {
	VIRTUAL_UPSTREAM_IP,
	testDbPath,
	cleanupDbFiles,
	baseUrl,
	useServer,
	createTestSession,
	withUpstream,
	withDnsTest,
	withMockFetch,
	withEnv,
	mcp,
	req,
	server,
	bootstrapLocalAdmin,
	db,
	providers,
	api,
	proxy,
	mcpMod,
	oauthMod,
	policyMod,
	ssoMod,
	utilMod,
	cryptoMod
}
