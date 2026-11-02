import * as api from './api/index.js'
import { getBody } from './util.js'

export {
	handleRest
}

function sendJson (res, data, status = 200) {
	res.statusCode = status
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(typeof data === 'string' ? data : JSON.stringify(data, null, '\t'))
}

function sendBinary (res, data, mimeType = 'application/octet-stream') {
	res.statusCode = 200
	res.setHeader('content-type', mimeType)
	res.end(Buffer.from(data, 'base64'))
}

async function parseJsonBody (req) {
	const rawBody = await getBody(req)
	if (!rawBody || !rawBody.trim()) return {}
	try {
		return JSON.parse(rawBody)
	} catch {
		const err = new Error('Invalid JSON body')
		err.code = 400
		err.status = 400
		throw err
	}
}

async function handleProviderProxy (req, res, provider, targetPath, url, token) {
	if (!targetPath) {
		const err = new Error('not found')
		err.code = 404
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
	let body = undefined
	if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
		const rawBody = await getBody(req)
		if (rawBody && rawBody.trim()) {
			const contentType = (req.headers['content-type'] || '').toLowerCase()
			if (contentType.includes('application/json') || rawBody.trim().startsWith('{') || rawBody.trim().startsWith('[')) {
				try {
					body = JSON.parse(rawBody)
				} catch {
					const err = new Error('Invalid JSON body')
					err.code = 400
					err.status = 400
					throw err
				}
			} else {
				body = rawBody
			}
		}
	}
	const result = await api.proxy.request({
		provider,
		url: targetUrl,
		method: req.method,
		body,
		appId,
		account
	}, token)
	if (result?.binary) {
		sendBinary(res, result.data, result.mimeType)
		return
	}
	sendJson(res, result)
}

const routes = {
	'/api/health': {
		GET (req, res) {
			res.statusCode = 200
			res.setHeader('content-type', 'text/plain')
			res.end('ok\n')
		}
	},
	'/api/whoami': {
		async GET (req, res, { token }) {
			const result = await api.auth.whoami(token)
			sendJson(res, result)
		}
	},
	'/api/sessions': {
		async GET (req, res, { token }) {
			const result = await api.auth.list(token)
			sendJson(res, result)
		},
		async POST (req, res, { token }) {
			const body = await parseJsonBody(req)
			const result = await api.auth.createSession(token, body)
			sendJson(res, result, 201)
		},
		async DELETE (req, res, { token, query }) {
			const result = await api.auth.revoke(token, { allOthers: query.allOthers === 'true' })
			sendJson(res, result)
		}
	},
	'/api/apps': {
		async GET (req, res, { token }) {
			const result = await api.auth.listApps(token)
			sendJson(res, result)
		},
		async POST (req, res, { token }) {
			const body = await parseJsonBody(req)
			const result = await api.auth.connectApp(token, body)
			sendJson(res, result, 201)
		}
	},
	'/api/links': {
		async POST (req, res, { token }) {
			const body = await parseJsonBody(req)
			const result = await api.auth.linkApp(token, body)
			sendJson(res, result, 201)
		},
		async DELETE (req, res, { token, query }) {
			const result = await api.auth.unlinkApp(token, {
				sessionId: query.sessionId,
				appId: query.appId
			})
			sendJson(res, result)
		}
	}
}

async function handleRest (req, res, { pathname, url, query, token }) {
	if (pathname.startsWith('/api/sessions/')) {
		const sessionId = pathname.slice('/api/sessions/'.length)
		if (req.method === 'GET') {
			const result = await api.auth.get(token, sessionId)
			sendJson(res, result)
			return
		}
		if (req.method === 'DELETE') {
			const result = await api.auth.revoke(token, { sessionId })
			sendJson(res, result)
			return
		}
		if (req.method === 'PATCH' || req.method === 'PUT') {
			const body = await parseJsonBody(req)
			const result = await api.auth.updateSession(token, { ...body, sessionId })
			sendJson(res, result)
			return
		}
		const err = new Error('Method Not Allowed')
		err.code = 405
		throw err
	}
	if (pathname.startsWith('/api/apps/')) {
		const appId = pathname.slice('/api/apps/'.length)
		if (req.method === 'PATCH' || req.method === 'PUT') {
			const body = await parseJsonBody(req)
			const result = await api.auth.updateApp(token, { ...body, appId })
			sendJson(res, result)
			return
		}
		if (req.method === 'DELETE') {
			const revoke = query?.revoke !== 'false' && query?.revoke !== '0'
			const result = await api.auth.disconnectApp(token, { appId, revoke })
			sendJson(res, result)
			return
		}
		const err = new Error('Method Not Allowed')
		err.code = 405
		throw err
	}
	const route = routes[pathname]
	if (route) {
		const handler = route[req.method]
		if (!handler) {
			const err = new Error('Method Not Allowed')
			err.code = 405
			throw err
		}
		await handler(req, res, { token, query })
		return
	}
	const rawPathname = url?.pathname || pathname
	const restMatch = rawPathname.match(/^\/api\/([a-z0-9_-]+)\/(.+)$/i)
	if (restMatch) {
		const [, provider, targetPath] = restMatch
		await handleProviderProxy(req, res, provider.toLowerCase(), targetPath, url, token)
		return
	}
	const err = new Error('not found')
	err.code = 404
	throw err
}
