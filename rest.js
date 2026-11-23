import * as api from './api/index.js'
import { isValidProviderId, RESERVED_PROVIDERS } from './providers/index.js'
import { assertKeys, getBody, getBaseUrl, httpError, isPlainObject, requireBoolean, sendJson, sendText } from './util.js'

export {
	handleRest
}

function assertNoBody (req) {
	const len = Number(req.headers['content-length'])
	if (len > 0 || req.headers['transfer-encoding'] !== undefined) {
		throw httpError(400, `${req.method} requests do not accept a request body`)
	}
}

async function parseJsonBody (req) {
	const rawBody = await getBody(req)
	if (!rawBody || !rawBody.trim()) return {}
	let parsed
	try {
		parsed = JSON.parse(rawBody)
	} catch {
		throw httpError(400, 'Invalid JSON body')
	}
	if (!isPlainObject(parsed)) {
		throw httpError(400, 'JSON body must be an object')
	}
	return parsed
}

function decodePathParam (raw) {
	try {
		return decodeURIComponent(raw)
	} catch {
		throw httpError(400, 'Malformed URI path parameter')
	}
}

async function handleProviderProxy (req, res, provider, targetPath, url, token) {
	if (!targetPath) {
		throw httpError(404, 'not found')
	}
	const search = url?.search || ''
	await api.proxy.stream({
		provider,
		url: `${targetPath}${search}`,
		app: req.headers['x-upstream-app']
	}, token, req, res)
}

const resources = Object.assign(Object.create(null), {
	health: {
		GET (req, res, { query }) {
			assertKeys(query, [])
			sendText(res, 'ok\n')
		},
		HEAD (req, res, { query }) {
			assertKeys(query, [])
			sendText(res, '')
		}
	},
	whoami: {
		async GET (req, res, { token, query }) {
			sendJson(res, await api.auth.whoami(token, query, getBaseUrl(req)))
		}
	},
	logins: {
		async POST (req, res, { token, body }) {
			sendJson(res, await api.auth.linkLogin(token, body, getBaseUrl(req)))
		},
		item: {
			idKey: 'loginId',
			async DELETE (req, res, { token, query, id }) {
				assertKeys(query, [])
				sendJson(res, await api.auth.unlinkLogin(token, { loginId: id }))
			}
		}
	},
	sessions: {
		async GET (req, res, { token, query }) {
			sendJson(res, await api.auth.listSessions(token, query))
		},
		async POST (req, res, { token, body }) {
			sendJson(res, await api.auth.createSession(token, body), 201)
		},
		async DELETE (req, res, { token, query }) {
			assertKeys(query, ['allOthers'])
			if (requireBoolean(query.allOthers, 'allOthers') !== true) {
				throw httpError(400, 'allOthers=true is required on DELETE /api/sessions; use DELETE /api/sessions/:id to revoke a specific session')
			}
			sendJson(res, await api.auth.revokeSession(token, { allOthers: true }))
		},
		item: {
			idKey: 'sessionId',
			async GET (req, res, { token, query, id }) {
				assertKeys(query, [])
				sendJson(res, await api.auth.getSession(token, { sessionId: id }))
			},
			async PATCH (req, res, { token, body, id }) {
				sendJson(res, await api.auth.updateSession(token, { ...body, sessionId: id }))
			},
			async DELETE (req, res, { token, query, id }) {
				assertKeys(query, [])
				sendJson(res, await api.auth.revokeSession(token, { sessionId: id }))
			}
		}
	},
	apps: {
		async GET (req, res, { token, query }) {
			sendJson(res, await api.auth.listApps(token, query))
		},
		async POST (req, res, { token, body }) {
			sendJson(res, await api.auth.connectApp(token, body, getBaseUrl(req)), 201)
		},
		item: {
			idKey: 'appId',
			async PATCH (req, res, { token, body, id }) {
				sendJson(res, await api.auth.updateApp(token, { ...body, appId: id }))
			},
			async DELETE (req, res, { token, query, id }) {
				assertKeys(query, ['revoke'])
				sendJson(res, await api.auth.disconnectApp(token, { appId: id, revoke: query.revoke }))
			}
		}
	},
	links: {
		async POST (req, res, { token, body }) {
			sendJson(res, await api.auth.linkApp(token, body), 201)
		},
		async DELETE (req, res, { token, query }) {
			assertKeys(query, ['sessionId', 'appId'])
			sendJson(res, await api.auth.unlinkApp(token, query))
		}
	},
	shares: {
		async POST (req, res, { token, body }) {
			sendJson(res, await api.auth.shareApp(token, body), 201)
		},
		async DELETE (req, res, { token, query }) {
			assertKeys(query, ['appId', 'account', 'provider'])
			sendJson(res, await api.auth.unshareApp(token, query))
		}
	},
	logs: {
		async GET (req, res, { token, query }) {
			sendJson(res, await api.auth.listLogs(token, query))
		}
	}
})

async function dispatchRest (req, res, handlerTable, { token, query, id, idKey }) {
	const handler = Object.hasOwn(handlerTable, req.method) && typeof handlerTable[req.method] === 'function'
		? handlerTable[req.method]
		: null
	if (!handler) {
		throw httpError(405, 'Method Not Allowed')
	}
	if (req.method === 'POST' || req.method === 'PATCH') {
		assertKeys(query, [])
		const body = await parseJsonBody(req)
		if (idKey && Object.hasOwn(body, idKey)) {
			throw httpError(400, `${idKey} must be passed in the URL path, not the request body`)
		}
		await handler(req, res, { token, query, body, id })
		return
	}
	assertNoBody(req)
	await handler(req, res, { token, query, id })
}

async function handleRest (req, res, { pathname, url, query, token }) {
	const rawPathname = url?.pathname || pathname
	const match = rawPathname.match(/^\/api\/([^/]+)(?:\/([^/]+))?$/)
	if (match) {
		const [, resourceName, encodedId] = match
		const resource = resources[resourceName]
		if (resource) {
			if (encodedId !== undefined) {
				if (!resource.item) {
					throw httpError(404, 'not found')
				}
				const id = decodePathParam(encodedId)
				await dispatchRest(req, res, resource.item, { token, query, id, idKey: resource.item.idKey })
				return
			}
			await dispatchRest(req, res, resource, { token, query })
			return
		}
		if (RESERVED_PROVIDERS.has(resourceName.toLowerCase())) {
			throw httpError(404, 'not found')
		}
	}
	const restMatch = rawPathname.match(/^\/api\/([^/]+)\/(.+)$/)
	if (restMatch) {
		const provider = restMatch[1].toLowerCase()
		if (!isValidProviderId(provider)) {
			throw httpError(404, 'not found')
		}
		await handleProviderProxy(req, res, provider, restMatch[2], url, token)
		return
	}
	throw httpError(404, 'not found')
}
