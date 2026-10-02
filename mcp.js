import RpcEngine from 'rpc-engine'
import * as api from './api/index.js'
import * as db from './db/index.js'
import { getBody } from './util.js'

export {
	tools,
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
					'status',
					'list',
					'list_sessions',
					'get',
					'create_session',
					'revoke',
					'revoke_session',
					'list_apps',
					'connect_app',
					'disconnect_app',
					'link_app',
					'unlink_app',
					'update_app',
					'update_session',
					'update_email',
					'update_user'
				],
				description: 'Administrative action to perform.'
			},
			sessionId: { type: 'string', description: 'Target session token ID.' },
			appId: { type: 'string', description: 'Target upstream app token ID.' },
			name: { type: 'string', description: 'Human-readable label or user display name.' },
			email: { type: 'string', description: 'New email address (for update_email action).' },
			provider: { type: 'string', description: 'Provider name (e.g. "google", "stripe").' },
			apiKey: { type: 'string', description: 'API Key (for static key apps).' },
			policy: { type: 'array', description: 'Granular policy JSON rules for a link.' },
			admin: { type: 'boolean', description: 'Grant admin permissions to a new session.' },
			allOthers: { type: 'boolean', description: 'When action is revoke, set to true to revoke all other sessions.' }
		}
	}
}

const googleApiTool = {
	name: 'google_api',
	description: 'Make HTTP requests directly to Google APIs (e.g. Drive, Docs, Sheets, Calendar, Gmail, Tasks) restricted to *.googleapis.com. Automatically attaches the user\'s Google OAuth Bearer token.',
	inputSchema: {
		type: 'object',
		properties: {
			url: {
				type: 'string',
				description: 'Full https://*.googleapis.com URL or relative path with optional query parameters (e.g. "drive/v3/files?pageSize=10", "calendar/v3/calendars/primary/events", or "https://sheets.googleapis.com/v4/spreadsheets/ID").'
			},
			method: {
				type: 'string',
				description: 'HTTP method (GET, POST, PUT, PATCH, DELETE). Defaults to GET.'
			},
			body: {
				type: ['object', 'string'],
				description: 'JSON body object or string payload for POST/PUT/PATCH requests.'
			},
			headers: {
				type: 'object',
				description: 'Optional additional HTTP headers to include with the request.'
			},
			appId: {
				type: 'string',
				description: 'Optional target Google app token ID if multiple Google accounts are linked.'
			}
		},
		required: ['url']
	}
}

const tools = [adminTool, googleApiTool]

const adminActions = {
	whoami: (args, token) => api.auth.whoami(token),
	status: (args, token) => api.auth.whoami(token),
	list: (args, token) => api.auth.list(token),
	list_sessions: (args, token) => api.auth.list(token),
	get: (args, token) => api.auth.get(token, args.sessionId),
	create_session: (args, token) => api.auth.createSession(token, args),
	update_session: (args, token) => api.auth.updateSession(token, args),
	revoke: (args, token) => api.auth.revoke(token, args),
	revoke_session: (args, token) => api.auth.revoke(token, args),
	list_apps: (args, token) => api.auth.listApps(token),
	connect_app: (args, token) => api.auth.connectApp(token, args),
	disconnect_app: (args, token) => api.auth.disconnectApp(token, args),
	update_app: (args, token) => api.auth.updateApp(token, args),
	link_app: (args, token) => api.auth.linkApp(token, args),
	unlink_app: (args, token) => api.auth.unlinkApp(token, args),
	update_email: (args, token) => api.auth.updateEmail(token, args),
	update_user: (args, token) => api.auth.updateUser(token, args)
}

const toolHandlers = {
	admin (args, token) {
		const action = args.action || 'whoami'
		const handle = adminActions[action]
		if (!handle) {
			console.warn(`[mcp] admin action rejected: Unknown action "${action}"`)
			const err = new Error(`Unknown action: ${action}`)
			err.status = 400
			throw err
		}
		return handle(args, token)
	},
	google_api (args, token) {
		return api.google.request(args, token)
	}
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
	} else if (err.message?.startsWith('Failed to refresh Google access token:')) {
		console.warn(`[mcp] ${err.message}`)
	} else if (err.status) {
		console.warn(`[mcp] ${toolName} error (${err.status}): ${err.message}`)
		return {
			isError: true,
			content: [{ type: 'text', text: toolName === 'google_api' ? `Google API Error (${err.status}): ${err.message}` : err.message }]
		}
	}
	return {
		isError: true,
		content: [{ type: 'text', text: err.message }]
	}
}

async function executeTool (name, args = {}, token) {
	if (!name || typeof name !== 'string') {
		console.warn('[mcp] tools/call rejected: Missing tool name')
		return { isError: true, content: [{ type: 'text', text: 'Tool name is required' }] }
	}
	const handler = toolHandlers[name]
	if (!handler) {
		console.warn(`[mcp] tools/call rejected: Unknown tool "${name}"`)
		return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${name}` }] }
	}
	try {
		const result = await handler(args, token)
		return { content: formatContent(result) }
	} catch (err) {
		return formatError(err, name)
	}
}

function getAvailableTools (token) {
	if (!token) return []
	db.tokens.touchByToken(token)
	const session = db.tokens.getByToken(token)
	if (!session) return []
	const links = db.links.listBySessionId(session.id)
	const list = []
	if (session.admin) {
		list.push(adminTool)
	}
	if (links.some(l => l.app?.provider === 'google')) {
		list.push(googleApiTool)
	}
	return list
}

const rpcMethods = {
	initialize: params => {
		if (process.env.NODE_ENV !== 'test') {
			const client = params?.clientInfo ? `${params.clientInfo.name || 'unknown'}/${params.clientInfo.version || ''}` : 'unknown'
			console.log(`[mcp] initialize (client: ${client}, protocol: ${params?.protocolVersion || 'unknown'})`)
		}
		return {
			protocolVersion: '2024-11-05',
			capabilities: { tools: { listChanged: false } },
			serverInfo: { name: 'google-mcp', version: '1.0.0' }
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
	'tools/call': (params, token) => {
		const name = params?.name
		const args = { ...params?.arguments }
		if (process.env.NODE_ENV !== 'test') {
			console.log(`[mcp] tools/call: name=${name || '(missing)'} args=${JSON.stringify(args)}`)
		}
		if (token) db.tokens.touchByToken(token)
		return executeTool(name, args, token)
	}
}

async function handleMcp (req, res, token) {
	if (req.method !== 'POST') {
		console.warn(`[mcp] Rejected non-POST request to /mcp: ${req.method}`)
		const err = new Error('Method Not Allowed')
		err.code = 405
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
		}
	})
	rpc.methods = {
		...rpcMethods,
		'tools/list': params => rpcMethods['tools/list'](params, token),
		'tools/call': params => rpcMethods['tools/call'](params, token)
	}
	const request = await getBody(req)
	await rpc.receive(request)
	if (!res.writableEnded) {
		rpc.send()
	}
}
