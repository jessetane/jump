import * as db from '../db/index.js'

export {
	getFreshToken,
	refreshAppToken,
	proxyGoogleApi,
	getUserInfo,
	revokeGoogleToken,
	readResponseBody,
	normalizeTargetUrl,
	isGoogleApiUrl,
	baseScopes,
	services,
	buildScopesFromSelection
}

const clientId = process.env.GOOGLE_CLIENT_ID
const clientSecret = process.env.GOOGLE_CLIENT_SECRET

const baseScopes = [
	'https://www.googleapis.com/auth/userinfo.email',
	'https://www.googleapis.com/auth/userinfo.profile'
]

const services = {
	drive: {
		id: 'drive',
		name: 'Google Drive',
		ro: ['https://www.googleapis.com/auth/drive.readonly'],
		rw: ['https://www.googleapis.com/auth/drive']
	},
	docs: {
		id: 'docs',
		name: 'Google Docs',
		ro: ['https://www.googleapis.com/auth/documents.readonly'],
		rw: ['https://www.googleapis.com/auth/documents']
	},
	sheets: {
		id: 'sheets',
		name: 'Google Sheets',
		ro: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
		rw: ['https://www.googleapis.com/auth/spreadsheets']
	},
	slides: {
		id: 'slides',
		name: 'Google Slides',
		ro: ['https://www.googleapis.com/auth/presentations.readonly'],
		rw: ['https://www.googleapis.com/auth/presentations']
	},
	forms: {
		id: 'forms',
		name: 'Google Forms',
		ro: ['https://www.googleapis.com/auth/forms.body.readonly'],
		rw: ['https://www.googleapis.com/auth/forms.body']
	},
	calendar: {
		id: 'calendar',
		name: 'Google Calendar',
		ro: ['https://www.googleapis.com/auth/calendar.readonly'],
		rw: ['https://www.googleapis.com/auth/calendar']
	},
	tasks: {
		id: 'tasks',
		name: 'Google Tasks',
		ro: ['https://www.googleapis.com/auth/tasks.readonly'],
		rw: ['https://www.googleapis.com/auth/tasks']
	},
	contacts: {
		id: 'contacts',
		name: 'Google Contacts',
		ro: ['https://www.googleapis.com/auth/contacts.readonly'],
		rw: ['https://www.googleapis.com/auth/contacts']
	},
	youtube: {
		id: 'youtube',
		name: 'YouTube',
		ro: ['https://www.googleapis.com/auth/youtube.readonly'],
		rw: ['https://www.googleapis.com/auth/youtube']
	},
	gmail: {
		id: 'gmail',
		name: 'Gmail',
		ro: ['https://www.googleapis.com/auth/gmail.readonly'],
		rw: ['https://mail.google.com/']
	},
	photos: {
		id: 'photos',
		name: 'Google Photos',
		ro: ['https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata'],
		rw: [
			'https://www.googleapis.com/auth/photoslibrary.appendonly',
			'https://www.googleapis.com/auth/photoslibrary.readonly.appcreateddata'
		]
	},
	meet: {
		id: 'meet',
		name: 'Google Meet',
		ro: ['https://www.googleapis.com/auth/meetings.space.readonly'],
		rw: ['https://www.googleapis.com/auth/meetings.space.created']
	},
	chat: {
		id: 'chat',
		name: 'Google Chat',
		ro: [
			'https://www.googleapis.com/auth/chat.spaces.readonly',
			'https://www.googleapis.com/auth/chat.messages.readonly'
		],
		rw: [
			'https://www.googleapis.com/auth/chat.spaces',
			'https://www.googleapis.com/auth/chat.messages'
		]
	},
	keep: {
		id: 'keep',
		name: 'Google Keep',
		enterprise: true,
		ro: ['https://www.googleapis.com/auth/keep.readonly'],
		rw: ['https://www.googleapis.com/auth/keep']
	}
}

function buildScopesFromSelection (selectedServices = [], writeServiceIds = []) {
	const scopeSet = new Set(baseScopes)
	const writeSet = new Set(writeServiceIds)
	for (const id of selectedServices) {
		const svc = services[id]
		if (!svc) continue
		const scopes = writeSet.has(id) ? svc.rw : svc.ro
		for (const s of scopes) scopeSet.add(s)
	}
	return Array.from(scopeSet).join(' ')
}

async function refreshAppToken (appToken) {
	const refreshToken = appToken.credentials?.refreshToken
	if (!refreshToken) {
		const err = new Error('No refresh token available for Google app')
		err.status = 401
		throw err
	}
	const params = new URLSearchParams({
		client_id: clientId,
		client_secret: clientSecret,
		refresh_token: refreshToken,
		grant_type: 'refresh_token'
	})
	const res = await fetch('https://oauth2.googleapis.com/token', {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: params.toString()
	})
	const data = await res.json()
	if (!res.ok) {
		const err = new Error(data.error_description || data.error || 'Failed to refresh Google token')
		err.status = res.status
		err.data = data
		throw err
	}
	const expiresAt = Date.now() + ((data.expires_in || 3600) * 1000)
	const updatedCreds = {
		...appToken.credentials,
		accessToken: data.access_token,
		refreshToken: data.refresh_token || refreshToken
	}
	const updated = db.tokens.updateCredentials(appToken.id, {
		credentials: updatedCreds,
		expiresAt,
		scopes: data.scope || appToken.scopes
	})
	return {
		token: data.access_token,
		app: updated
	}
}

async function getFreshToken (appToken) {
	if (!appToken) return null
	const creds = appToken.credentials || {}
	if (creds.refreshToken && (!appToken.expiresAt || Date.now() > appToken.expiresAt - 60000)) {
		const refreshed = await refreshAppToken(appToken)
		return {
			token: refreshed.token,
			app: refreshed.app
		}
	}
	return {
		token: creds.accessToken,
		app: appToken
	}
}

async function getUserInfo (googleToken) {
	const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
		headers: { authorization: `Bearer ${googleToken}` }
	})
	if (!res.ok) {
		let data = await res.text()
		try {
			data = JSON.parse(data)
		} catch (e) {}
		const msg = typeof data === 'object'
			? (data?.error_description || data?.error?.message || JSON.stringify(data))
			: (data || 'Failed to fetch user info')
		const err = new Error(msg)
		err.status = res.status
		err.data = data
		throw err
	}
	return await res.json()
}

async function revokeGoogleToken (token) {
	if (!token) return
	try {
		await fetch('https://oauth2.googleapis.com/revoke', {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ token }).toString()
		})
	} catch (err) {
		console.warn('Failed to revoke token with Google upstream:', err.message)
	}
}

function isGoogleApiUrl (urlString) {
	try {
		const parsed = new URL(urlString)
		if (parsed.protocol !== 'https:') return false
		const hostname = parsed.hostname.toLowerCase()
		return hostname === 'googleapis.com' || hostname.endsWith('.googleapis.com')
	} catch {
		return false
	}
}

async function readResponseBody (res, maxBytes) {
	if (!res.body) return Buffer.alloc(0)
	const chunks = []
	let totalBytes = 0
	const reader = res.body.getReader()
	try {
		while (true) {
			const { done, value } = await reader.read()
			if (done) break
			totalBytes += value.byteLength
			if (totalBytes > maxBytes) {
				await reader.cancel()
				const sizeMb = (totalBytes / (1024 * 1024)).toFixed(1)
				const limitMb = (maxBytes / (1024 * 1024)).toFixed(0)
				const err = new Error(`File too large: size (${sizeMb} MB) exceeds server limit of ${limitMb} MB. Consider exporting specific sheets, ranges, or text sections instead.`)
				err.status = 413
				throw err
			}
			chunks.push(value)
		}
	} finally {
		reader.releaseLock?.()
	}
	return Buffer.concat(chunks)
}

function normalizeTargetUrl (targetUrl) {
	if (!targetUrl || typeof targetUrl !== 'string') return ''
	let clean = targetUrl.trim()
	if (clean.startsWith('https:/') && !clean.startsWith('https://')) {
		clean = clean.replace(/^https:\/+/, 'https://')
	}
	if (clean.startsWith('http://') || clean.startsWith('https://')) {
		return clean
	}
	const noLeadingSlash = clean.replace(/^\/+/, '')
	if (/^[a-zA-Z0-9-]+\.googleapis\.com(\/|$)/i.test(noLeadingSlash)) {
		return `https://${noLeadingSlash}`
	}
	return `https://www.googleapis.com/${noLeadingSlash}`
}

async function proxyGoogleApi (opts = {}) {
	const { token, url: targetUrl, method = 'GET', body, headers = {} } = opts
	if (!targetUrl) {
		const err = new Error('Missing url parameter')
		err.status = 400
		throw err
	}
	const fullUrl = normalizeTargetUrl(targetUrl)
	if (!isGoogleApiUrl(fullUrl)) {
		const err = new Error(`Target URL domain not allowed. Requests must target *.googleapis.com, got: ${fullUrl}`)
		err.status = 403
		throw err
	}
	const reqHeaders = {
		authorization: `Bearer ${token}`,
		...headers
	}
	let reqBody
	if (body !== undefined && body !== null) {
		if (typeof body === 'object') {
			reqHeaders['content-type'] = reqHeaders['content-type'] || 'application/json'
			reqBody = JSON.stringify(body)
		} else {
			reqBody = String(body)
		}
	}
	const reqMethod = method.toUpperCase()
	const fetchOpts = {
		method: reqMethod,
		headers: reqHeaders
	}
	if (reqMethod !== 'GET' && reqMethod !== 'HEAD' && reqBody !== undefined) {
		fetchOpts.body = reqBody
	}
	const res = await fetch(fullUrl, fetchOpts)
	const maxFileSizeMb = Number(process.env.MAX_FILE_SIZE_MB) || 10
	const maxFileSizeBytes = maxFileSizeMb * 1024 * 1024
	const contentLength = res.headers.get('content-length')
	if (contentLength && Number(contentLength) > maxFileSizeBytes) {
		const sizeMb = (Number(contentLength) / (1024 * 1024)).toFixed(1)
		const limitMb = (maxFileSizeBytes / (1024 * 1024)).toFixed(0)
		const err = new Error(`File too large: size (${sizeMb} MB) exceeds server limit of ${limitMb} MB. Consider exporting specific sheets, ranges, or text sections instead.`)
		err.status = 413
		throw err
	}
	const rawContentType = res.headers.get('content-type') || ''
	const contentType = rawContentType.split(';')[0].trim()
	const charsetMatch = rawContentType.match(/charset=([^;]+)/i)
	const charset = charsetMatch ? charsetMatch[1].trim().replace(/^["']|["']$/g, '') : undefined
	const buf = await readResponseBody(res, maxFileSizeBytes)
	let result
	if (contentType === 'application/json') {
		const str = buf.toString('utf8')
		try {
			result = str ? JSON.parse(str) : {}
		} catch {
			result = str
		}
	} else if (contentType.startsWith('text/')) {
		result = buf.toString(charset || 'utf8')
	} else {
		result = { binary: true, mimeType: contentType, ...(charset && { charset }), data: buf.toString('base64') }
	}
	if (!res.ok) {
		const msg = result?.binary ? `Binary error response (${contentType})`
			: typeof result === 'object' ? JSON.stringify(result)
			: result
		const err = new Error(msg)
		err.status = res.status
		err.data = result
		throw err
	}
	return result
}
