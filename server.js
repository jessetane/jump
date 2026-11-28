import http from 'node:http'
import fs from 'node:fs'
import { handleOauth } from './oauth.js'
import { handleMcp } from './mcp.js'
import { handleRest } from './rest.js'
import { listOauthProviders, parseOauthProviders } from './providers/index.js'
import * as db from './db/index.js'
import { parseSsoDomains } from './sso.js'
import { APP_NAME, escapeHtml, getBaseUrl, getClientIp, getUserAgent, httpError, positiveNumberEnv, searchParamsToObject, sendJson, sendHtml } from './util.js'

export { server, bootstrapLocalAdmin }

const INDEX_HTML = fs.readFileSync(new URL('./public/index.html', import.meta.url), 'utf8')
const STYLE_CSS = fs.readFileSync(new URL('./public/style.css', import.meta.url), 'utf8')
const OAUTH_SCOPES_JS = fs.readFileSync(new URL('./public/oauth-scopes.js', import.meta.url), 'utf8')
const STATIC_ASSETS = new Map([
	['/style.css', { type: 'text/css; charset=utf-8', body: STYLE_CSS }],
	['/oauth-scopes.js', { type: 'application/javascript; charset=utf-8', body: OAUTH_SCOPES_JS }]
])
const corsOrigin = process.env.CORS_ORIGIN || '*'

const CORS_OAUTH_PATHS = new Set(['/oauth/token', '/oauth/register', '/oauth/revoke'])
const RATE_WINDOW_MS = 60000
const MAX_RATE_BUCKETS = 10000
const oauthRateBuckets = new Map()

function parseOauthRateLimit () {
	const raw = process.env.OAUTH_RATE_LIMIT
	if (raw === undefined || raw.trim() === '') return 60
	const n = Number(raw)
	if (!Number.isFinite(n)) {
		throw new Error(`Invalid OAUTH_RATE_LIMIT: ${raw}`)
	}
	return n
}

function checkOauthRateLimit (req, res) {
	const limit = parseOauthRateLimit()
	if (limit <= 0) return true
	const ip = getClientIp(req) || 'unknown'
	const now = Date.now()
	let entry = oauthRateBuckets.get(ip)
	if (!entry || entry.resetAt <= now) {
		if (!entry && oauthRateBuckets.size >= MAX_RATE_BUCKETS) {
			for (const [k, v] of oauthRateBuckets) {
				if (v.resetAt <= now) oauthRateBuckets.delete(k)
			}
			if (oauthRateBuckets.size >= MAX_RATE_BUCKETS) {
				oauthRateBuckets.delete(oauthRateBuckets.keys().next().value)
			}
		}
		entry = { count: 0, resetAt: now + RATE_WINDOW_MS }
		oauthRateBuckets.set(ip, entry)
	}
	entry.count++
	if (entry.count <= limit) return true
	const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000))
	sendJson(res, { error: 'Too many requests' }, 429, { 'retry-after': String(retryAfter) })
	return false
}

function isCorsRoute (pathname, method) {
	if (pathname === '/') return method === 'POST' || method === 'OPTIONS'
	if (pathname === '/mcp' || pathname.startsWith('/mcp/')) return true
	if (pathname.startsWith('/api/') || pathname.startsWith('/.well-known/')) return true
	return CORS_OAUTH_PATHS.has(pathname)
}

function resolveToken (req) {
	const auth = req.headers.authorization || ''
	return auth.replace(/^Bearer\s+/i, '').trim() || req.headers['x-api-key'] || null
}

const server = http.createServer(async (req, res) => {
	const start = Date.now()
	let rawPathname = '(invalid)'
	res.setHeader('x-content-type-options', 'nosniff')
	res.on('finish', () => {
		const duration = Date.now() - start
		console.log(`[${res.statusCode}] ${req.method} ${rawPathname} (${duration}ms)`)
	})
	try {
		let url
		try {
			url = new URL(req.url, 'http://localhost')
		} catch {
			throw httpError(400, 'Invalid request URL')
		}
		rawPathname = url.pathname
		const pathname = rawPathname.replace(/\/+$/, '') || '/'
		const query = searchParamsToObject(url.searchParams)
		const token = resolveToken(req)
		const isProxyOptions = req.method === 'OPTIONS' && pathname.startsWith('/api/') && Boolean(token) && !req.headers['access-control-request-method']
		if (isCorsRoute(pathname, req.method)) {
			res.setHeader('access-control-allow-origin', corsOrigin)
			res.setHeader('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS')
			res.setHeader('access-control-allow-headers', 'authorization, content-type, mcp-session-id, mcp-protocol-version, last-event-id, x-api-key, x-upstream-app, accept')
			res.setHeader('access-control-expose-headers', 'WWW-Authenticate, Mcp-Session-Id, MCP-Protocol-Version')
			if (req.method === 'OPTIONS' && !isProxyOptions) {
				res.statusCode = 204
				res.end()
				return
			}
		}
		if (pathname === '/') {
			if (req.method === 'POST') {
				await handleMcp(req, res, token)
				return
			}
			if (req.method === 'GET' || req.method === 'HEAD') {
				sendHtml(res, INDEX_HTML.replaceAll('{{APP_NAME}}', () => escapeHtml(APP_NAME)).replaceAll('{{APP_URL}}', () => escapeHtml(getBaseUrl(req))))
				return
			}
			throw httpError(405, 'Method Not Allowed')
		}
		const staticAsset = STATIC_ASSETS.get(pathname)
		if (staticAsset && (req.method === 'GET' || req.method === 'HEAD')) {
			res.statusCode = 200
			res.setHeader('content-type', staticAsset.type)
			res.end(req.method === 'HEAD' ? undefined : staticAsset.body)
			return
		}
		if (pathname.startsWith('/api/')) {
			await handleRest(req, res, { pathname: rawPathname, url, query, token })
			return
		}
		if (pathname === '/mcp' || pathname.startsWith('/mcp/')) {
			await handleMcp(req, res, token)
			return
		}
		if (pathname.startsWith('/oauth/') || pathname.startsWith('/providers/') || pathname === '/apps/connect') {
			if (!checkOauthRateLimit(req, res)) return
			await handleOauth(req, res, { pathname, url, query })
			return
		}
		if (pathname.startsWith('/.well-known/')) {
			await handleOauth(req, res, { pathname, url, query })
			return
		}
		throw httpError(404, 'not found')
	} catch (err) {
		const statusCode = err.status || 500
		let message = err.message
		if (statusCode >= 500) {
			console.error(err)
			message = 'Internal Server Error'
		}
		if (!res.headersSent && !res.writableEnded && !res.destroyed) {
			const headers = statusCode === 401 && message === 'Authentication required'
				? { 'www-authenticate': `Bearer authorization_uri="${getBaseUrl(req)}/oauth/authorize"` }
				: {}
			if (!req.readableEnded) {
				headers.connection = 'close'
			}
			sendJson(res, { error: message }, statusCode, headers)
		}
	}
})
const upstreamTimeoutMs = positiveNumberEnv('UPSTREAM_TIMEOUT_MS', 60000)
positiveNumberEnv('OAUTH_TIMEOUT_MS', 30000)
positiveNumberEnv('MAX_FILE_SIZE_MB', 10)
parseOauthRateLimit()
parseSsoDomains()
parseOauthProviders()
getUserAgent()
server.headersTimeout = 15000
server.requestTimeout = 0
server.timeout = Math.max(60000, upstreamTimeoutMs + 15000)
server.keepAliveTimeout = 125000

function bootstrapLocalAdmin () {
	if (listOauthProviders('auth').length > 0) return null
	if (db.sessions.hasActiveAdmin()) return null
	const user = db.users.create()
	const session = db.sessions.create({
		userId: user.id,
		name: 'Local Admin',
		admin: 1
	})
	return session
}
