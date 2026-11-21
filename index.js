#!/usr/bin/env node

import './env.js'
import http from 'node:http'
import fs from 'node:fs'
import { handleOauth } from './oauth.js'
import { handleMcp } from './mcp.js'
import { handleRest } from './rest.js'
import { listAuthProviders } from './providers/index.js'
import * as db from './db/index.js'
import { getBaseUrl, getClientIp, sendJson, sendHtml } from './util.js'

export { server, bootstrapLocalAdmin }

const INDEX_HTML = fs.readFileSync(new URL('./public/index.html', import.meta.url), 'utf8')
const STYLE_CSS = fs.readFileSync(new URL('./public/style.css', import.meta.url), 'utf8')
const host = process.env.HOST || '127.0.0.1'
const port = process.env.PORT || '8080'
const corsOrigin = process.env.CORS_ORIGIN || '*'

const CORS_OAUTH_PATHS = new Set(['/oauth/token', '/oauth/register', '/oauth/revoke'])
const RATE_WINDOW_MS = 60000
const MAX_RATE_BUCKETS = 10000
const oauthRateBuckets = new Map()

function checkOauthRateLimit (req, res) {
	const rawLimit = process.env.OAUTH_RATE_LIMIT
	const parsedLimit = rawLimit === undefined || rawLimit.trim() === '' ? 60 : Number(rawLimit)
	if (parsedLimit <= 0) return true
	const limit = Number.isFinite(parsedLimit) ? parsedLimit : 60
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
	let pathname = '(invalid)'
	res.setHeader('x-content-type-options', 'nosniff')
	res.on('finish', () => {
		if (process.env.NODE_ENV !== 'test') {
			const duration = Date.now() - start
			console.log(`[${res.statusCode}] ${req.method} ${pathname} (${duration}ms)`)
		}
	})
	try {
		let url
		try {
			url = new URL(req.url, 'http://localhost')
		} catch {
			const err = new Error('Invalid request URL')
			err.status = 400
			throw err
		}
		pathname = url.pathname.replace(/\/+$/, '') || '/'
		if (isCorsRoute(pathname, req.method)) {
			res.setHeader('access-control-allow-origin', corsOrigin)
			res.setHeader('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
			res.setHeader('access-control-allow-headers', 'authorization, content-type, mcp-session-id, mcp-protocol-version, last-event-id, x-api-key, accept')
			res.setHeader('access-control-expose-headers', 'WWW-Authenticate, Mcp-Session-Id, MCP-Protocol-Version')
			if (req.method === 'OPTIONS') {
				res.statusCode = 204
				res.end()
				return
			}
		}
		const query = Object.fromEntries(url.searchParams)
		const token = resolveToken(req)
		if (pathname === '/') {
			if (req.method === 'POST') {
				await handleMcp(req, res, token)
				return
			}
			if (req.method === 'GET' || req.method === 'HEAD') {
				sendHtml(res, INDEX_HTML.replaceAll('{{APP_URL}}', getBaseUrl(req)))
				return
			}
			const err = new Error('Method Not Allowed')
			err.status = 405
			throw err
		}
		if (pathname === '/style.css' && (req.method === 'GET' || req.method === 'HEAD')) {
			res.statusCode = 200
			res.setHeader('content-type', 'text/css; charset=utf-8')
			res.end(req.method === 'HEAD' ? undefined : STYLE_CSS)
			return
		}
		if (pathname.startsWith('/api/')) {
			await handleRest(req, res, { pathname, url, query, token })
			return
		}
		if (pathname === '/mcp' || pathname.startsWith('/mcp/')) {
			await handleMcp(req, res, token)
			return
		}
		if (pathname.startsWith('/oauth/') || pathname.startsWith('/providers/')) {
			if (!checkOauthRateLimit(req, res)) return
			await handleOauth(req, res, { pathname, url, query })
			return
		}
		if (pathname.startsWith('/.well-known/')) {
			await handleOauth(req, res, { pathname, url, query })
			return
		}
		const err = new Error('not found')
		err.status = 404
		throw err
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
const upstreamTimeoutMs = Number(process.env.UPSTREAM_TIMEOUT_MS) || 60000
server.headersTimeout = 15000
server.requestTimeout = 0
server.timeout = Math.max(60000, upstreamTimeoutMs + 15000)
server.keepAliveTimeout = 125000

function bootstrapLocalAdmin () {
	if (listAuthProviders().length > 0) return null
	if (db.tokens.hasActiveAdmin()) return null
	const user = db.users.create()
	const session = db.tokens.create({
		userId: user.id,
		provider: 'self',
		type: 'bearer',
		name: 'Local Admin',
		admin: 1
	})
	return session
}

if (process.env.NODE_ENV !== 'test') {
	const bootstrapped = bootstrapLocalAdmin()
	if (bootstrapped) {
		console.log(`[bootstrap] Admin session created for localhost: ${bootstrapped.token}`)
	}
	server.listen(port, host, () => {
		console.log(`jump listening on ${host}:${port}`)
	})
	let shuttingDown = false
	function shutdown () {
		if (shuttingDown) return
		shuttingDown = true
		server.close(() => {
			db.sqlite.close()
			process.exit(0)
		})
		server.closeIdleConnections()
	}
	process.on('SIGINT', shutdown)
	process.on('SIGTERM', shutdown)
}
