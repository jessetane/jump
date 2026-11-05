import RpcEngine from 'rpc-engine'
import * as api from './api/index.js'
import * as db from './db/index.js'
import { getBaseUrl } from './oauth.js'
import { getProvider } from './providers/index.js'
import { getBody, sendJson } from './util.js'

export {
	buildProviderTool,
	getAvailableTools,
	executeTool,
	handleMcp
}

const adminTool = {
	name: 'admin',
	description: 'Administer MCP sessions, connected upstream apps, routing policies, and user account settings.',
	inputSchema: {
		type: 'object',
		properties: {
			action: {
				type: 'string',
				enum: [
					'whoami',
					'list',
					'get',
					'create_session',
					'revoke',
					'list_apps',
					'connect_app',
					'disconnect_app',
					'link_app',
					'unlink_app',
					'update_app',
					'update_session',
					'update_email',
					'update_user',
					'list_logs'
				],
				description: 'Administrative action to perform.'
			},
			sessionId: { type: 'string', description: 'Target session token ID.' },
			appId: { type: 'string', description: 'Target upstream app token ID (used for connect_app, update_app, disconnect_app, link_app, unlink_app).' },
			name: { type: 'string', description: 'Human-readable label or user display name.' },
			account: { type: 'string', description: 'Upstream account or tenant identifier (e.g. email, username, account ID).' },
			baseUrl: { type: 'string', description: 'Optional upstream base URL for custom or API-key providers (e.g. "https://api.stripe.com").' },
			apiKey: { type: 'string', description: 'Upstream API credential when connecting an API-key provider: Bearer token, HTTP Basic "user:pass", or query string "?key=val".' },
			email: { type: 'string', description: 'New email address (for update_email action).' },
			provider: { type: 'string', description: 'Provider name (e.g. "google", "stripe", "github").' },
			policy: {
				type: 'array',
				description: 'Ordered list of policy rules evaluated top-to-bottom (first match wins, default deny). Best practice: write a minimal allowlist of specific paths (e.g. "/calendar/v3/calendars/xyz/events/**"); unlisted paths are automatically denied. Do NOT duplicate rules for URL-encoding—paths are automatically decoded (use literal "@" rather than "%40").',
				items: {
					type: 'object',
					required: ['action'],
					properties: {
						action: {
							type: 'string',
							enum: ['allow', 'deny'],
							description: 'Rule action: "allow" or "deny".'
						},
						methods: {
							type: 'array',
							items: { type: 'string' },
							description: 'Allowed HTTP methods (e.g. ["GET", "POST", "PUT", "PATCH", "DELETE", "*"]). Omit (or use ["*"]) to allow all methods.'
						},
						path: {
							type: 'string',
							description: 'Path glob pattern (* matches single segment, ** matches recursively, e.g. "/calendar/v3/calendars/xyz/events/**"). Trailing "/**" matches both the endpoint and all nested sub-paths (e.g. ".../events/**" matches both ".../events" and ".../events/123"). Use literal "@" (automatically matches "%40").'
						},
						origin: {
							type: 'string',
							description: 'Origin glob pattern (e.g. "https://sheets.googleapis.com" or "https://*.googleapis.com").'
						},
						body: {
							type: 'object',
							description: 'Optional map of request body field paths (supporting dot-notation like "recipient.email") to expected glob patterns or arrays of patterns.'
						},
						description: {
							type: 'string',
							description: 'Optional human-readable label or explanation for this rule.'
						}
					}
				}
			},
			admin: { type: 'boolean', description: 'Grant admin permissions to a new session.' },
			rotateToken: { type: 'boolean', description: 'When action is update_session, set to true to rotate and regenerate the session bearer token.' },
			revoke: { type: 'boolean', description: 'When action is disconnect_app, set to false to remove locally without upstream revocation (defaults to true).' },
			allOthers: { type: 'boolean', description: 'When action is revoke, set to true to revoke all other sessions.' },
			allowed: { type: 'boolean', description: 'When action is list_logs, filter logs by whether the request was allowed by policy.' },
			limit: { type: 'number', description: 'When action is list_logs, maximum number of log entries to return (defaults to 100, max 1000).' }
		}
	}
}

function buildProviderTool (providerName, providerLinks = []) {
	const provider = getProvider(providerName)
	const id = provider.id
	const accounts = providerLinks
		.map(l => l.app?.credentials?.account || l.app?.name)
		.filter(Boolean)
	const accountHint = accounts.length > 0 ? ` Linked accounts: ${accounts.join(', ')}.` : ''
	const baseHint = providerLinks.find(l => l.app?.credentials?.baseUrl)?.app?.credentials?.baseUrl || provider.baseUrl
	return {
		name: `${id}_api`,
		description: `${provider.toolDescription(baseHint)}${accountHint}`,
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
					description: 'Request body payload for POST/PUT/PATCH requests (JSON object, form-urlencoded object when Content-Type is application/x-www-form-urlencoded, or raw XML/text string).'
				},
				headers: {
					type: 'object',
					description: 'Optional additional HTTP headers to include with the request.'
				},
				appId: {
					type: 'string',
					description: `Optional target ${provider.name} app token ID if multiple accounts are linked.`
				},
				account: {
					type: 'string',
					description: `Optional target account identifier or app name if multiple ${provider.name} accounts are linked.`
				}
			},
			required: ['url']
		}
	}
}

const adminActions = {
	whoami: (args, token, appUrl) => api.auth.whoami(token, { appUrl }),
	list: (args, token, appUrl) => api.auth.list(token, { appUrl }),
	get: (args, token, appUrl) => api.auth.get(token, args.sessionId, { appUrl }),
	create_session: (args, token, appUrl) => api.auth.createSession(token, { ...args, appUrl }),
	update_session: (args, token, appUrl) => api.auth.updateSession(token, { ...args, appUrl }),
	revoke: (args, token) => api.auth.revoke(token, args),
	list_apps: (args, token, appUrl) => api.auth.listApps(token, { appUrl }),
	connect_app: (args, token, appUrl) => api.auth.connectApp(token, { ...args, appUrl }),
	disconnect_app: (args, token, appUrl) => api.auth.disconnectApp(token, { ...args, appUrl }),
	update_app: (args, token, appUrl) => api.auth.updateApp(token, { ...args, appUrl }),
	link_app: (args, token, appUrl) => api.auth.linkApp(token, { ...args, appUrl }),
	unlink_app: (args, token, appUrl) => api.auth.unlinkApp(token, { ...args, appUrl }),
	update_email: (args, token, appUrl) => api.auth.updateEmail(token, { ...args, appUrl }),
	update_user: (args, token, appUrl) => api.auth.updateUser(token, { ...args, appUrl }),
	list_logs: (args, token, appUrl) => api.auth.listLogs(token, { ...args, appUrl })
}

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
	if (err.message?.startsWith('Policy violation:')) {
		console.warn(`[mcp] ${toolName} policy violation: ${err.message.replace(/^Policy violation:\s*/, '')}`)
	} else if (err.message?.startsWith('Access denied:')) {
		console.warn(`[mcp] ${toolName} access denied: ${err.message}`)
		return {
			isError: true,
			content: [{ type: 'text', text: err.message }]
		}
	} else if (err.message?.startsWith('Authentication required:')) {
		console.warn(`[mcp] ${toolName} rejected: Authentication required`)
	} else if (err.message?.startsWith('Failed to refresh ')) {
		console.warn(`[mcp] ${err.message}`)
	} else if (err.status) {
		console.warn(`[mcp] ${toolName} error (${err.status}): ${err.message}`)
		const providerMatch = toolName.match(/^([a-z0-9_-]+)_api$/i)
		const prefix = providerMatch
			? `${getProvider(providerMatch[1]).name} API Error (${err.status}): `
			: ''
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
		if (name === 'admin') {
			const action = args.action || 'whoami'
			const handle = adminActions[action]
			if (!handle) {
				console.warn(`[mcp] admin action rejected: Unknown action "${action}"`)
				const err = new Error(`Unknown action: ${action}`)
				err.status = 400
				throw err
			}
			const result = await handle(args, token, appUrl)
			return { content: formatContent(result) }
		}
		const apiMatch = name.match(/^([a-z0-9_-]+)_api$/i)
		if (apiMatch) {
			const provider = apiMatch[1].toLowerCase()
			const result = await api.proxy.request({ ...args, provider, appUrl }, token)
			return { content: formatContent(result) }
		}
		console.warn(`[mcp] tools/call rejected: Unknown tool "${name}"`)
		return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] }
	} catch (err) {
		return formatError(err, name)
	}
}

function getAvailableTools (token) {
	if (!token) return []
	const session = db.tokens.getByToken(token)
	if (!session) return []
	const links = db.links.listBySessionId(session.id)
	const list = []
	if (session.admin) {
		list.push(adminTool)
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

const rpcMethods = {
	initialize: params => {
		const requested = params?.protocolVersion
		const protocolVersion = typeof requested === 'string' && requested ? requested : '2024-11-05'
		if (process.env.NODE_ENV !== 'test') {
			const client = params?.clientInfo ? `${params.clientInfo.name || 'unknown'}/${params.clientInfo.version || ''}` : 'unknown'
			console.log(`[mcp] initialize (client: ${client}, protocol: ${protocolVersion})`)
		}
		return {
			protocolVersion,
			capabilities: { tools: { listChanged: false } },
			serverInfo: { name: 'jump', version: '1.0.0' }
		}
	},
	'notifications/initialized': () => {
		if (process.env.NODE_ENV !== 'test') {
			console.log('[mcp] notifications/initialized')
		}
		return {}
	},
	ping: () => {
		if (process.env.NODE_ENV !== 'test') {
			console.log('[mcp] ping')
		}
		return {}
	},
	'tools/list': (params, token) => {
		if (process.env.NODE_ENV !== 'test') {
			console.log('[mcp] tools/list')
		}
		return { tools: getAvailableTools(token) }
	},
	'tools/call': (params, token, appUrl) => {
		const name = params?.name
		const args = { ...params?.arguments }
		if (process.env.NODE_ENV !== 'test') {
			console.log(`[mcp] tools/call: name=${name || '(missing)'} args=${JSON.stringify(args)}`)
		}
		return executeTool(name, args, token, appUrl)
	}
}

async function handleMcp (req, res, token) {
	const base = getBaseUrl(req)
	const session = token ? db.tokens.getByToken(token) : null
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
		console.warn(`[mcp] Rejected non-POST request to /mcp: ${req.method}`)
		const err = new Error('Method Not Allowed')
		err.status = 405
		throw err
	}
	const rpc = new RpcEngine({
		objectMode: true,
		deserialize: data => {
			try {
				return JSON.parse(data)
			} catch (err) {
				console.warn(`[mcp] JSON-RPC parse error: ${err.message}`)
				throw err
			}
		},
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
		methods: {
			...rpcMethods,
			'tools/list': params => rpcMethods['tools/list'](params, token),
			'tools/call': params => rpcMethods['tools/call'](params, token, base)
		}
	})
	const request = await getBody(req)
	await rpc.receive(request)
	if (!res.writableEnded) {
		rpc.send()
	}
}
