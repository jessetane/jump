#!/usr/bin/env node

import 'dotenv/config'
import http from 'node:http'
import fs from 'node:fs'
import { handleOauth } from './oauth.js'
import { handleMcp } from './mcp.js'
import { handleRest } from './rest.js'
import { listAuthProviders } from './providers/index.js'
import * as db from './db/index.js'
import { getBaseUrl, sendJson, sendHtml } from './util.js'

export { server, bootstrapLocalAdmin }

const INDEX_HTML = fs.readFileSync(new URL('./public/index.html', import.meta.url), 'utf8')
const STYLE_CSS = fs.readFileSync(new URL('./public/style.css', import.meta.url), 'utf8')
const host = process.env.HOST || '::1'
const port = process.env.PORT || '8080'
const corsOrigin = process.env.CORS_ORIGIN || '*'

function resolveToken (req) {
	const auth = req.headers.authorization || ''
	return auth.replace(/^Bearer\s+/i, '').trim() || req.headers['x-api-key'] || null
}

const server = http.createServer(async (req, res) => {
	const start = Date.now()
	res.on('finish', () => {
		if (process.env.NODE_ENV !== 'test') {
			const duration = Date.now() - start
			console.log(`[${res.statusCode}] ${req.method} ${req.url} (${duration}ms)`)
		}
	})
	res.setHeader('access-control-allow-origin', corsOrigin)
	res.setHeader('access-control-allow-methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
	res.setHeader('access-control-allow-headers', 'authorization, content-type, mcp-session-id, mcp-protocol-version, last-event-id, x-api-key, accept')
	res.setHeader('access-control-expose-headers', 'WWW-Authenticate, Mcp-Session-Id, MCP-Protocol-Version')
	if (req.method === 'OPTIONS') {
		res.statusCode = 204
		res.end()
		return
	}
	const url = new URL(req.url, 'http://localhost')
	const pathname = url.pathname.replace(/\/+$/, '') || '/'
	const query = Object.fromEntries(url.searchParams)
	const token = resolveToken(req)
	try {
		if (pathname === '/') {
			if (req.method === 'POST') {
				await handleMcp(req, res, token)
				return
			}
			sendHtml(res, INDEX_HTML.replaceAll('{{APP_URL}}', getBaseUrl(req)))
			return
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
		if (pathname.startsWith('/oauth/') || pathname.startsWith('/providers/') || pathname.startsWith('/.well-known/')) {
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
		if (!res.headersSent && !res.writableEnded) {
			sendJson(res, { error: message }, statusCode)
		}
	}
})

function bootstrapLocalAdmin () {
	if (listAuthProviders().length > 0) return null
	const existing = db.sqlite.prepare("SELECT COUNT(*) AS count FROM tokens WHERE provider = 'self' AND type = 'bearer' AND admin = 1 AND (expires_at IS NULL OR expires_at > ?)").get(Date.now())
	if (existing?.count > 0) return null
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
	const shutdown = () => {
		server.close(() => {
			db.sqlite.close()
			process.exit(0)
		})
	}
	process.on('SIGINT', shutdown)
	process.on('SIGTERM', shutdown)
}
