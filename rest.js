import * as api from './api/index.js'
import { isValidProviderId, RESERVED_PROVIDERS } from './providers/index.js'
import { assertKeys, getBody, getBaseUrl, isPlainObject, requireBoolean, sendJson, sendText } from './util.js'

export {
	handleRest
}

function assertNoBody (req) {
	const len = Number(req.headers['content-length'])
	if (len > 0 || req.headers['transfer-encoding'] !== undefined) {
		const err = new Error(`${req.method} requests do not accept a request body`)
		err.status = 400
		throw err
	}
}

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

function decodePathParam (raw) {
	try {
		return decodeURIComponent(raw)
	} catch {
		const err = new Error('Malformed URI path parameter')
		err.status = 400
		throw err
	}
}

async function handleProviderProxy (req, res, provider, targetPath, url, token) {
	if (!targetPath) {
		const err = new Error('not found')
		err.status = 404
		throw err
	}
	const appValues = url?.searchParams?.getAll('app') || []
	if (appValues.length > 1) {
		const err = new Error('Duplicate query parameter "app"')
		err.status = 400
		throw err
	}
	const app = appValues.length === 1 ? appValues[0] : undefined
	const forwardParams = new URLSearchParams(url?.searchParams)
	forwardParams.delete('app')
	const qs = forwardParams.toString()
	const search = qs ? `?${qs}` : ''
	await api.proxy.stream({
		provider,
		url: `${targetPath}${search}`,
		app
	}, token, req, res)
}

const resources = {
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
				const err = new Error('allOthers=true is required on DELETE /api/sessions; use DELETE /api/sessions/:id to revoke a specific session')
				err.status = 400
				throw err
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
}

async function dispatchRest (req, res, handlerTable, { token, query, id, idKey }) {
	const handler = Object.hasOwn(handlerTable, req.method) && typeof handlerTable[req.method] === 'function'
		? handlerTable[req.method]
		: null
	if (!handler) {
		const err = new Error('Method Not Allowed')
		err.status = 405
		throw err
	}
	if (req.method === 'POST' || req.method === 'PATCH') {
		assertKeys(query, [])
		const body = await parseJsonBody(req)
		if (idKey && Object.hasOwn(body, idKey)) {
			const err = new Error(`${idKey} must be passed in the URL path, not the request body`)
			err.status = 400
			throw err
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
					const err = new Error('not found')
					err.status = 404
					throw err
				}
				const id = decodePathParam(encodedId)
				await dispatchRest(req, res, resource.item, { token, query, id, idKey: resource.item.idKey })
				return
			}
			await dispatchRest(req, res, resource, { token, query })
			return
		}
		if (RESERVED_PROVIDERS.has(resourceName.toLowerCase())) {
			const err = new Error('not found')
			err.status = 404
			throw err
		}
	}
	const restMatch = rawPathname.match(/^\/api\/([^/]+)\/(.+)$/)
	if (restMatch) {
		const provider = restMatch[1].toLowerCase()
		if (!isValidProviderId(provider)) {
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
