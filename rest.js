import * as api from './api/index.js'
import { HOP_BY_HOP_HEADERS, assertKeys, getRawBody, getBody, getBaseUrl, isPlainObject, sendJson, sendText } from './util.js'

export {
	handleRest
}

const STRIPPED_REQUEST_HEADERS = new Set([
	...HOP_BY_HOP_HEADERS,
	'host',
	'authorization',
	'x-api-key',
	'cookie'
])

const STRIPPED_RESPONSE_HEADERS = new Set([
	...HOP_BY_HOP_HEADERS,
	'content-encoding',
	'set-cookie',
	'access-control-allow-origin',
	'access-control-allow-methods',
	'access-control-allow-headers',
	'access-control-expose-headers',
	'access-control-allow-credentials'
])

async function parseJsonBody (req) {
	const rawBody = await getBody(req)
	if (!rawBody || !rawBody.trim()) return {}
	let parsed
	try {
		parsed = JSON.parse(rawBody)
	} catch {
		const err = new Error('Invalid JSON body')
		err.status = 400
		throw err
	}
	if (!isPlainObject(parsed)) {
		const err = new Error('JSON body must be an object')
		err.status = 400
		throw err
	}
	return parsed
}

async function handleProviderProxy (req, res, provider, targetPath, url, token) {
	if (!targetPath) {
		const err = new Error('not found')
		err.status = 404
		throw err
	}
	const appId = url?.searchParams?.get('app_id') || undefined
	const account = url?.searchParams?.get('account') || undefined
	const forwardParams = new URLSearchParams(url?.searchParams)
	forwardParams.delete('app_id')
	forwardParams.delete('account')
	const qs = forwardParams.toString()
	const search = qs ? `?${qs}` : ''
	const targetUrl = `${targetPath}${search}`
	const headers = {}
	for (const [k, v] of Object.entries(req.headers)) {
		const lower = k.toLowerCase()
		if (STRIPPED_REQUEST_HEADERS.has(lower) || v === undefined) continue
		headers[lower] = Array.isArray(v) ? v.join(', ') : v
	}
	let body = undefined
	if (!['GET', 'HEAD'].includes(req.method)) {
		const rawBody = await getRawBody(req)
		if (rawBody.byteLength > 0) {
			body = rawBody
		}
	}
	const upstream = await api.proxy.request({
		provider,
		url: targetUrl,
		method: req.method,
		body,
		headers,
		appId,
		account
	}, token, { raw: true })
	res.statusCode = upstream.status
	for (const [k, v] of upstream.headers.entries()) {
		if (!STRIPPED_RESPONSE_HEADERS.has(k.toLowerCase())) {
			res.setHeader(k, v)
		}
	}
	res.end(upstream.body)
}

async function parseQueryOrBody (req, query) {
	return Object.keys(query).length > 0 ? query : parseJsonBody(req)
}

const routes = {
	'/api/health': {
		GET (req, res, { query }) {
			assertKeys(query, [])
			sendText(res, 'ok\n')
		},
		HEAD (req, res, { query }) {
			assertKeys(query, [])
			sendText(res, '')
		}
	},
	'/api/whoami': {
		async GET (req, res, { token, query }) {
			const result = await api.auth.whoami(token, query, getBaseUrl(req))
			sendJson(res, result)
		}
	},
	'/api/logins': {
		async POST (req, res, { token, query }) {
			assertKeys(query, [])
			const body = await parseJsonBody(req)
			const result = await api.auth.linkLogin(token, body, getBaseUrl(req))
			sendJson(res, result)
		},
		async DELETE (req, res, { token, query }) {
			const opts = await parseQueryOrBody(req, query)
			const result = await api.auth.unlinkLogin(token, opts)
			sendJson(res, result)
		}
	},
	'/api/sessions': {
		async GET (req, res, { token, query }) {
			const result = await api.auth.listSessions(token, query)
			sendJson(res, result)
		},
		async POST (req, res, { token, query }) {
			assertKeys(query, [])
			const body = await parseJsonBody(req)
			const result = await api.auth.createSession(token, body)
			sendJson(res, result, 201)
		},
		async DELETE (req, res, { token, query }) {
			const result = await api.auth.revokeSession(token, query)
			sendJson(res, result)
		}
	},
	'/api/apps': {
		async GET (req, res, { token, query }) {
			const result = await api.auth.listApps(token, query)
			sendJson(res, result)
		},
		async POST (req, res, { token, query }) {
			assertKeys(query, [])
			const body = await parseJsonBody(req)
			const result = await api.auth.connectApp(token, body, getBaseUrl(req))
			sendJson(res, result, 201)
		}
	},
	'/api/links': {
		async POST (req, res, { token, query }) {
			assertKeys(query, [])
			const body = await parseJsonBody(req)
			const result = await api.auth.linkApp(token, body)
			sendJson(res, result, 201)
		},
		async DELETE (req, res, { token, query }) {
			const opts = await parseQueryOrBody(req, query)
			const result = await api.auth.unlinkApp(token, opts)
			sendJson(res, result)
		}
	},
	'/api/shares': {
		async POST (req, res, { token, query }) {
			assertKeys(query, [])
			const body = await parseJsonBody(req)
			const result = await api.auth.shareApp(token, body)
			sendJson(res, result, 201)
		},
		async DELETE (req, res, { token, query }) {
			const opts = await parseQueryOrBody(req, query)
			const result = await api.auth.unshareApp(token, opts)
			sendJson(res, result)
		}
	},
	'/api/logs': {
		async GET (req, res, { token, query }) {
			const result = await api.auth.listLogs(token, query)
			sendJson(res, result)
		}
	}
}

const RESERVED_API_PROVIDERS = new Set(Object.keys(routes).map(r => r.slice('/api/'.length)))

function decodePathParam (raw) {
	try {
		return decodeURIComponent(raw)
	} catch {
		const err = new Error('Malformed URI path parameter')
		err.status = 400
		throw err
	}
}

function assertMatchingPathId (bodyId, pathId, name) {
	if (bodyId !== undefined && bodyId !== pathId) {
		const err = new Error(`Conflicting ${name} in URL path and request body`)
		err.status = 400
		throw err
	}
}

async function handleRest (req, res, { pathname, url, query, token }) {
	if (pathname.startsWith('/api/logins/')) {
		const loginId = decodePathParam(pathname.slice('/api/logins/'.length))
		if (req.method === 'DELETE') {
			assertKeys(query, [])
			const result = await api.auth.unlinkLogin(token, { loginId })
			sendJson(res, result)
			return
		}
		const err = new Error('Method Not Allowed')
		err.status = 405
		throw err
	}
	if (pathname.startsWith('/api/sessions/')) {
		const sessionId = decodePathParam(pathname.slice('/api/sessions/'.length))
		if (req.method === 'GET') {
			assertKeys(query, [])
			const result = await api.auth.getSession(token, { sessionId })
			sendJson(res, result)
			return
		}
		if (req.method === 'DELETE') {
			assertKeys(query, [])
			const result = await api.auth.revokeSession(token, { sessionId })
			sendJson(res, result)
			return
		}
		if (req.method === 'PATCH' || req.method === 'PUT') {
			assertKeys(query, [])
			const body = await parseJsonBody(req)
			assertMatchingPathId(body.sessionId, sessionId, 'sessionId')
			const result = await api.auth.updateSession(token, { ...body, sessionId })
			sendJson(res, result)
			return
		}
		const err = new Error('Method Not Allowed')
		err.status = 405
		throw err
	}
	if (pathname.startsWith('/api/apps/')) {
		const appId = decodePathParam(pathname.slice('/api/apps/'.length))
		if (req.method === 'PATCH' || req.method === 'PUT') {
			assertKeys(query, [])
			const body = await parseJsonBody(req)
			assertMatchingPathId(body.appId, appId, 'appId')
			const result = await api.auth.updateApp(token, { ...body, appId })
			sendJson(res, result)
			return
		}
		if (req.method === 'DELETE') {
			assertKeys(query, ['revoke'])
			const result = await api.auth.disconnectApp(token, { appId, revoke: query?.revoke })
			sendJson(res, result)
			return
		}
		const err = new Error('Method Not Allowed')
		err.status = 405
		throw err
	}
	const route = routes[pathname]
	if (route) {
		const handler = route[req.method]
		if (!handler) {
			const err = new Error('Method Not Allowed')
			err.status = 405
			throw err
		}
		await handler(req, res, { token, query })
		return
	}
	const rawPathname = url?.pathname || pathname
	const restMatch = rawPathname.match(/^\/api\/([a-z0-9_-]+)\/(.+)$/i)
	if (restMatch) {
		const provider = restMatch[1].toLowerCase()
		if (RESERVED_API_PROVIDERS.has(provider)) {
			const err = new Error('not found')
			err.status = 404
			throw err
		}
		await handleProviderProxy(req, res, provider, restMatch[2], url, token)
		return
	}
	const err = new Error('not found')
	err.status = 404
	throw err
}
