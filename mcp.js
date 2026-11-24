import fs from 'node:fs'
import RpcEngine from 'rpc-engine'
import * as api from './api/index.js'
import * as db from './db/index.js'
import { getProvider, listOauthProviders, parseProviderTool } from './providers/index.js'
import { assertKeys, getBody, getBaseUrl, httpError, isPlainObject, sendJson } from './util.js'

export {
	executeTool,
	formatError,
	handleMcp
}

const PKG_VERSION = JSON.parse(fs.readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version

function formatProviderServices (provider) {
	const entries = Object.values(provider.services || {})
	if (entries.length === 0) return ''
	const items = entries.map(svc => {
		const modes = Object.keys(svc.scopes || {})
		if (modes.length === 2 && modes.includes('read') && modes.includes('write')) return svc.id
		return `${svc.id} [${modes.join(', ')}]`
	})
	return `${provider.id}: ${items.join(', ')}`
}

function buildAdminTool () {
	const providerGuides = listOauthProviders('app')
		.filter(p => p.services)
		.map(formatProviderServices)
		.filter(Boolean)
	const servicesDesc = 'Optional list of OAuth service permissions to pre-check on connect_app (e.g. ["<service1>", "<service2>:read", "<service2>:write"]). Bare "<service>" selects "read" (or the sole mode for single-mode services); specify "<service>:<mode>" for each desired mode.'
		+ (providerGuides.length > 0 ? ` Unqualified names support read & write unless noted — ${providerGuides.join('; ')}.` : '')
	return {
		name: 'admin',
		description: 'Administer MCP sessions, connected upstream apps, cross-user app shares, routing policies, login keys, and usage logs. Note: link_app and share_app upsert in place—re-calling them replaces the existing policy.',
		inputSchema: {
			type: 'object',
			properties: {
				action: {
					type: 'string',
					enum: [
						'whoami',
						'list_sessions',
						'get_session',
						'create_session',
						'update_session',
						'revoke_session',
						'list_apps',
						'connect_app',
						'disconnect_app',
						'update_app',
						'share_app',
						'unshare_app',
						'link_app',
						'unlink_app',
						'link_login',
						'unlink_login',
						'list_logs'
					],
					description: 'Administrative action to perform.'
				},
				sessionId: { type: 'string', description: 'Target session token ID.' },
				appId: { type: 'string', description: 'Target upstream app token ID (used for connect_app, update_app, disconnect_app, share_app, unshare_app, link_app, unlink_app, list_logs).' },
				linkAppIds: {
					type: 'array',
					items: { type: 'string' },
					description: 'Optional list of upstream or shared app IDs to link immediately when action is create_session.'
				},
				loginId: { type: 'string', description: 'Target login key ID (optional for unlink_login).' },
				name: { type: 'string', description: 'Human-readable label for a session or upstream app.' },
				account: { type: 'string', description: 'Upstream account, login key account, or recipient user account identifier (e.g. email, username, or "provider:account").' },
				baseUrl: { type: 'string', description: 'Optional upstream base URL for custom or static-credential providers (e.g. "https://api.stripe.com").' },
				credentials: {
					type: ['string', 'object'],
					description: 'Upstream static credentials for connect_app and update_app: pass a string shorthand "<token>" for Bearer auth, or a structured object { bearer?, basic?, headers?, query? } where bearer is "<token>", basic is "user:pass", headers is { [name]: value } (e.g. { "x-api-key": "..." }), and query is { [name]: value }.',
					properties: {
						bearer: { type: 'string', description: 'Bearer token sent as Authorization: Bearer <token>.' },
						basic: { type: 'string', description: 'HTTP Basic credentials in "user:pass" format.' },
						headers: { type: 'object', description: 'Exact HTTP headers to attach on upstream requests (e.g. { "x-api-key": "sk-ant-...", "anthropic-version": "2023-06-01" }).' },
						query: { type: 'object', description: 'URL query parameters to attach on upstream requests (e.g. { ApiKey: "..." }).' }
					}
				},
				provider: { type: 'string', description: 'Provider name (e.g. "google", "stripe", "github").' },
				services: {
					type: 'array',
					items: { type: 'string' },
					description: servicesDesc
				},
				policy: {
					type: ['array', 'null'],
					description: 'Ordered list of rules evaluated top-to-bottom (first match wins; unmatched requests are denied). Semantics: (1) null or omitted = unrestricted allow-all; [] = deny-all. (2) Within a rule, all present fields (methods, origin, path, query, body) are ANDed; omitted fields match anything. Place specific deny rules BEFORE broader allow rules. (3) On shared apps, the owner share_app policy acts as an immutable ceiling—both the share policy AND the recipient link_app policy must independently allow each request. (4) Prefer minimal allowlists over denylists.',
					items: {
						type: 'object',
						required: ['action'],
						properties: {
							action: {
								type: 'string',
								enum: ['allow', 'deny'],
								description: 'Rule outcome when all predicates on this rule match: "allow" or "deny".'
							},
							methods: {
								type: 'array',
								items: { type: 'string' },
								description: 'Case-insensitive HTTP methods (["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "*"]). Omit (or use ["*"]) to match all methods.'
							},
							origin: {
								type: 'string',
								description: 'HTTPS origin glob without path or query (e.g. "https://sheets.googleapis.com" or "https://*.googleapis.com"). Always set origin on multi-host providers like Google so a path rule such as "/v4/spreadsheets/**" cannot match another host.'
							},
							path: {
								type: 'string',
								description: 'Case-insensitive URL pathname glob (* matches within one segment excluding "/", ** matches across segments). Trailing "/**" matches both the base path and all nested sub-paths (e.g. "/v1/events/**" matches "/v1/events" and "/v1/events/123"). Trailing slashes and safe percent-encoding are normalized automatically—write literal "@" rather than "%40", and never include "?query" here.'
							},
							query: {
								type: 'object',
								description: 'Non-empty map of URL query parameter names to expected primitive glob(s) or null. Matching is case-insensitive and "*" matches any character (including "/"). IMPORTANT: a string pattern requires the parameter to be PRESENT—use ["none", null] to allow a parameter to be either "none" or omitted, or null alone to require absence. Repeated parameters (?tag=a&tag=b) only match when EVERY value matches at least one pattern.'
							},
							body: {
								type: ['object', 'string', 'array', 'null'],
								description: 'Optional request body constraint (omit to pass body through uninspected): (a) field-map object: non-empty map of literal field keys (or nested plain objects mirroring JSON, e.g. { recipient: { email: "*@good.com" } }; use flat keys like "metadata[env]" for form) to primitive glob(s) or null—same presence/absence and array-every semantics as query; empty bodies evaluate as {}; (b) string or string[] of globs: case-insensitive full-body match where "*" crosses newlines (e.g. "*<DeleteDomain*" matches both "<DeleteDomain>" and "<DeleteDomain/>"); (c) null: requires an empty request body.'
							},
							bodyType: {
								type: 'string',
								enum: ['json', 'form'],
								description: 'Required serialization format when "body" is a field-map object (invalid otherwise): "json" (default) or "form" (application/x-www-form-urlencoded—use "form" for Stripe, Twilio, Mailgun, etc.). Caveat: if a non-empty payload cannot be parsed as bodyType, an "allow" rule skips it, whereas a "deny" rule FAILS CLOSED and blocks the request immediately so callers cannot bypass field blocks by switching formats.'
							},
							description: {
								type: 'string',
								description: 'Optional human-readable label; returned as the error reason when a "deny" rule blocks a request.'
							}
						}
					}
				},
				admin: { type: 'boolean', description: 'Grant or revoke admin permissions on a session (used for create_session and update_session).' },
				rotateToken: { type: 'boolean', description: 'When action is update_session, set to true to rotate and regenerate the session bearer token.' },
				merge: { type: 'boolean', description: 'When action is link_login, set to true to merge an existing Jump account into the current user if that login is already registered.' },
				revoke: { type: 'boolean', description: 'When action is disconnect_app, set to false to remove locally without upstream revocation (defaults to true).' },
				allOthers: { type: 'boolean', description: 'When action is revoke_session, set to true to revoke all other sessions.' },
				allowed: { type: 'boolean', description: 'When action is list_logs, filter logs by whether the request was allowed by policy.' },
				limit: { type: 'number', description: 'When action is list_logs, maximum number of log entries to return (defaults to 100, max 1000).' }
			}
		}
	}
}

function buildProviderTool (providerName, providerLinks = []) {
	const provider = getProvider(providerName)
	const id = provider.id
	const linkedApps = api.proxy.formatLinkedApps(providerLinks, provider)
	const appsHint = linkedApps.length > 0 ? ` Linked apps: ${linkedApps.join(', ')}.` : ''
	const baseHint = providerLinks.find(l => l.app?.credentials?.baseUrl)?.app?.credentials?.baseUrl || provider.baseUrl
	const multi = providerLinks.length > 1
	return {
		name: `${id}_api`,
		description: `${provider.toolDescription(baseHint)}${appsHint}`,
		inputSchema: {
			type: 'object',
			properties: {
				url: {
					type: 'string',
					description: provider.urlParamDescription(baseHint)
				},
				method: {
					type: 'string',
					description: 'HTTP method (GET, POST, PUT, PATCH, DELETE). Defaults to GET.'
				},
				body: {
					type: ['object', 'string'],
					description: 'Request body payload for POST/PUT/PATCH requests: JS object (serialized as JSON by default, or URL-encoded when headers["content-type"] is "application/x-www-form-urlencoded") or raw string (sent byte-for-byte without injecting a Content-Type header—set headers["content-type"] explicitly when upstream requires one).'
				},
				headers: {
					type: 'object',
					description: 'Optional additional HTTP headers to include with the request.'
				},
				app: {
					type: 'string',
					description: `${multi ? 'Target' : 'Optional target'} ${provider.name} app name, account, or ID${multi ? ' (required when multiple apps are linked).' : '.'}`
				}
			},
			required: multi ? ['url', 'app'] : ['url']
		}
	}
}

const adminActions = Object.assign(Object.create(null), {
	whoami: api.auth.whoami,
	list_sessions: api.auth.listSessions,
	get_session: api.auth.getSession,
	create_session: api.auth.createSession,
	update_session: api.auth.updateSession,
	revoke_session: api.auth.revokeSession,
	list_apps: api.auth.listApps,
	connect_app: api.auth.connectApp,
	disconnect_app: api.auth.disconnectApp,
	update_app: api.auth.updateApp,
	share_app: api.auth.shareApp,
	unshare_app: api.auth.unshareApp,
	link_app: api.auth.linkApp,
	unlink_app: api.auth.unlinkApp,
	link_login: api.auth.linkLogin,
	unlink_login: api.auth.unlinkLogin,
	list_logs: api.auth.listLogs
})

function formatContent (result) {
	if (result?.binary) {
		if (result.mimeType?.startsWith('image/')) {
			return [{ type: 'image', data: result.data, mimeType: result.mimeType }]
		}
		return [{
			type: 'text',
			text: JSON.stringify({
				mimeType: result.mimeType,
				...(result.charset && { charset: result.charset }),
				encoding: 'base64',
				data: result.data
			}, null, '\t')
		}]
	}
	return [{
		type: 'text',
		text: typeof result === 'string' ? result : JSON.stringify(result, null, '\t')
	}]
}

function formatError (err, toolName = 'tool') {
	if (!err?.status || (err.status === 500 && !err.upstream)) {
		console.error(err)
		return {
			isError: true,
			content: [{ type: 'text', text: 'Internal Server Error' }]
		}
	}
	if (err.message?.startsWith('Policy violation:')) {
		console.warn(`[mcp] ${toolName} policy violation: ${err.message.replace(/^Policy violation:\s*/, '')}`)
	} else if (err.message?.startsWith('Access denied:')) {
		console.warn(`[mcp] ${toolName} access denied: ${err.message}`)
	} else if (err.message?.startsWith('Authentication required')) {
		console.warn(`[mcp] ${toolName} rejected: Authentication required`)
	} else if (err.message?.startsWith('Failed to refresh ')) {
		console.warn(`[mcp] ${err.message}`)
	} else {
		console.warn(`[mcp] ${toolName} error (${err.status}): ${err.message}`)
		const providerId = err.upstream ? parseProviderTool(toolName) : null
		const prefix = providerId ? `${getProvider(providerId).name} API Error (${err.status}): ` : ''
		return {
			isError: true,
			content: [{ type: 'text', text: `${prefix}${err.message}` }]
		}
	}
	return {
		isError: true,
		content: [{ type: 'text', text: err.message }]
	}
}

async function executeTool (name, args = {}, token, appUrl) {
	if (!name || typeof name !== 'string') {
		console.warn('[mcp] tools/call rejected: Missing tool name')
		return { isError: true, content: [{ type: 'text', text: 'Tool name is required' }] }
	}
	try {
		if (args !== undefined && !isPlainObject(args)) {
			throw httpError(400, 'Tool arguments must be an object')
		}
		if (name === 'admin') {
			const { action: rawAction, ...actionArgs } = args || {}
			const action = rawAction || 'whoami'
			const handle = adminActions[action]
			if (!handle) {
				console.warn(`[mcp] admin action rejected: Unknown action "${action}"`)
				throw httpError(400, `Unknown action: ${action}`)
			}
			const result = await handle(token, actionArgs, appUrl)
			return { content: formatContent(result) }
		}
		const provider = parseProviderTool(name)
		if (provider) {
			assertKeys(args, ['url', 'method', 'body', 'headers', 'app'])
			const result = await api.proxy.request({ ...args, provider }, token)
			return { content: formatContent(result) }
		}
		console.warn(`[mcp] tools/call rejected: Unknown tool "${name}"`)
		return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] }
	} catch (err) {
		return formatError(err, name)
	}
}

function getAvailableTools (auth) {
	const session = db.tokens.resolveSession(auth)
	if (!session) return []
	const links = db.links.listBySessionId(session.id)
	const list = []
	if (session.admin) {
		list.push(buildAdminTool())
	}
	const grouped = new Map()
	for (const link of links) {
		const p = link.app?.provider
		if (!p || p === 'self') continue
		if (!grouped.has(p)) grouped.set(p, [])
		grouped.get(p).push(link)
	}
	for (const [providerName, providerLinks] of grouped.entries()) {
		list.push(buildProviderTool(providerName, providerLinks))
	}
	return list
}

const rpcMethods = Object.assign(Object.create(null), {
	initialize: params => {
		const requested = params?.protocolVersion
		const protocolVersion = typeof requested === 'string' && requested ? requested : '2024-11-05'
		const client = params?.clientInfo ? `${params.clientInfo.name || 'unknown'}/${params.clientInfo.version || ''}` : 'unknown'
		console.log(`[mcp] initialize (client: ${client}, protocol: ${protocolVersion})`)
		return {
			protocolVersion,
			capabilities: { tools: { listChanged: false } },
			serverInfo: { name: 'jump', version: PKG_VERSION }
		}
	},
	'notifications/initialized': () => {
		console.log('[mcp] notifications/initialized')
		return {}
	},
	ping: () => {
		console.log('[mcp] ping')
		return {}
	},
	'tools/list': (params, token) => {
		console.log('[mcp] tools/list')
		return { tools: getAvailableTools(token) }
	},
	'tools/call': (params, token, appUrl) => {
		const name = params?.name
		const args = params?.arguments
		const preview = isPlainObject(args) ? args : {}
		const detail = name === 'admin'
			? ` action=${preview.action || 'whoami'}`
			: preview.method ? ` method=${String(preview.method).toUpperCase()}` : ''
		console.log(`[mcp] tools/call: name=${name || '(missing)'}${detail}`)
		return executeTool(name, args, token, appUrl)
	}
})

async function handleMcp (req, res, token) {
	const base = getBaseUrl(req)
	const session = db.tokens.resolveSession(token)
	if (!session) {
		const rawPath = new URL(req.url || '/mcp', 'http://localhost').pathname.replace(/\/+$/, '') || '/'
		const resourceSuffix = rawPath.startsWith('/mcp/') ? rawPath : ''
		sendJson(res, {
			jsonrpc: '2.0',
			id: null,
			error: { code: -32001, message: 'Unauthorized: Bearer token required' }
		}, 401, {
			'www-authenticate': `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource${resourceSuffix}", authorization_uri="${base}/oauth/authorize"`
		})
		return
	}
	if (req.method !== 'POST') {
		throw httpError(405, 'Method Not Allowed')
	}
	const request = await getBody(req)
	let parsed
	try {
		parsed = JSON.parse(request)
	} catch (err) {
		console.warn(`[mcp] JSON-RPC parse error: ${err.message}`)
		sendJson(res, {
			jsonrpc: '2.0',
			id: null,
			error: { code: -32700, message: 'parse error' }
		})
		return
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
		sendJson(res, {
			jsonrpc: '2.0',
			id: null,
			error: { code: -32600, message: 'Invalid Request' }
		})
		return
	}
	if (typeof parsed.method !== 'string' || !parsed.method) {
		sendJson(res, {
			jsonrpc: '2.0',
			id: 'id' in parsed ? parsed.id : null,
			error: { code: -32600, message: 'Invalid Request' }
		})
		return
	}
	const rpc = new RpcEngine({
		objectMode: true,
		serialize: data => {
			data = typeof data === 'object' && !data?.jsonrpc
				? { ...data, jsonrpc: '2.0' }
				: data
			return JSON.stringify(data)
		},
		send: data => {
			if (data) {
				res.statusCode = 200
				res.setHeader('content-type', 'application/json; charset=utf-8')
				res.end(data)
			} else {
				res.statusCode = 202
				res.setHeader('content-type', 'application/json; charset=utf-8')
				res.end(JSON.stringify({ status: 'accepted' }))
			}
		},
		methods: Object.assign(Object.create(null), rpcMethods, {
			'tools/list': params => rpcMethods['tools/list'](params, session),
			'tools/call': params => rpcMethods['tools/call'](params, session, base)
		})
	})
	rpc.addEventListener('error', evt => {
		if (!res.writableEnded) {
			sendJson(res, {
				jsonrpc: '2.0',
				id: 'id' in parsed ? parsed.id : null,
				error: {
					code: evt.code ?? -32600,
					message: evt.message || 'Invalid Request'
				}
			})
		}
	})
	await rpc.receive(parsed)
	if (!res.writableEnded) {
		rpc.send()
	}
}
