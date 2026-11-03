import * as db from '../db/index.js'

export {
	id,
	name,
	type,
	baseUrl,
	services,
	toolDescription,
	urlParamDescription,
	buildAuthUrl,
	exchangeCode,
	getFreshToken,
	revokeToken,
	normalizeTargetUrl,
	isAllowedUrl
}

const id = 'google'
const name = 'Google'
const type = 'oauth'
const baseUrl = 'https://www.googleapis.com'

function toolDescription () {
	return "Make HTTP requests directly to Google APIs (e.g. Drive, Docs, Sheets, Calendar, Gmail, Tasks) restricted to *.googleapis.com. Automatically attaches the user's Google OAuth Bearer token."
}

function urlParamDescription () {
	return 'Full https://*.googleapis.com URL or relative path with optional query parameters (e.g. "drive/v3/files?pageSize=10", "calendar/v3/calendars/primary/events", or "https://sheets.googleapis.com/v4/spreadsheets/ID").'
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
	admin: {
		id: 'admin',
		name: 'Google Admin',
		ro: [
			'https://www.googleapis.com/auth/admin.directory.user.readonly',
			'https://www.googleapis.com/auth/admin.directory.group.readonly',
			'https://www.googleapis.com/auth/admin.directory.domain.readonly',
			'https://www.googleapis.com/auth/admin.directory.orgunit.readonly',
			'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly',
			'https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly',
			'https://www.googleapis.com/auth/admin.reports.audit.readonly',
			'https://www.googleapis.com/auth/admin.reports.usage.readonly',
			'https://www.googleapis.com/auth/apps.groups.settings',
			'https://www.googleapis.com/auth/apps.licensing',
			'https://www.googleapis.com/auth/cloud-identity.groups.readonly'
		],
		rw: [
			'https://www.googleapis.com/auth/admin.directory.user',
			'https://www.googleapis.com/auth/admin.directory.group',
			'https://www.googleapis.com/auth/admin.directory.domain',
			'https://www.googleapis.com/auth/admin.directory.orgunit',
			'https://www.googleapis.com/auth/admin.directory.device.mobile',
			'https://www.googleapis.com/auth/admin.directory.device.chromeos',
			'https://www.googleapis.com/auth/admin.datatransfer',
			'https://www.googleapis.com/auth/admin.reports.audit.readonly',
			'https://www.googleapis.com/auth/admin.reports.usage.readonly',
			'https://www.googleapis.com/auth/apps.groups.settings',
			'https://www.googleapis.com/auth/apps.licensing',
			'https://www.googleapis.com/auth/cloud-identity.groups'
		]
	}
}

function buildScopesFromSelection (selectedServices = [], writeServiceIds = []) {
	const scopeSet = new Set(baseScopes)
	const writeSet = new Set(writeServiceIds)
	for (const svcId of selectedServices) {
		const svc = services[svcId]
		if (!svc) continue
		const scopes = writeSet.has(svcId) ? svc.rw : svc.ro
		for (const s of scopes) scopeSet.add(s)
	}
	return Array.from(scopeSet).join(' ')
}

function buildAuthUrl ({ state, callbackUrl, services: selectedServices = [], write = [] }) {
	if (!clientId) {
		const err = new Error('GOOGLE_CLIENT_ID environment variable is missing')
		err.status = 500
		throw err
	}
	const scopes = buildScopesFromSelection(selectedServices, write)
	const u = new URL('https://accounts.google.com/o/oauth2/v2/auth')
	u.searchParams.set('client_id', clientId)
	u.searchParams.set('redirect_uri', callbackUrl)
	u.searchParams.set('response_type', 'code')
	u.searchParams.set('scope', scopes)
	u.searchParams.set('access_type', 'offline')
	u.searchParams.set('prompt', 'consent')
	u.searchParams.set('state', state)
	return u.toString()
}

async function exchangeCode ({ code, callbackUrl }) {
	const params = new URLSearchParams({
		code,
		client_id: clientId,
		client_secret: clientSecret,
		redirect_uri: callbackUrl,
		grant_type: 'authorization_code'
	})
	const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: params.toString()
	})
	const tokenData = await tokenRes.json()
	if (!tokenRes.ok) {
		const err = new Error(tokenData.error_description || tokenData.error || 'Failed to exchange authorization code with Google')
		err.status = 502
		err.data = tokenData
		throw err
	}
	const googleUser = await getUserInfo(tokenData.access_token)
	const email = (googleUser.email || '').toLowerCase()
	if (!email) {
		const err = new Error('Could not retrieve user email from Google account.')
		err.status = 400
		throw err
	}
	return {
		accessToken: tokenData.access_token,
		refreshToken: tokenData.refresh_token || null,
		expiresAt: Date.now() + ((tokenData.expires_in || 3600) * 1000),
		scopes: tokenData.scope || null,
		email,
		account: email,
		userName: googleUser.name || null
	}
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
		} catch {}
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

async function revokeToken (appToken) {
	const upstream = appToken?.credentials?.refreshToken || appToken?.credentials?.accessToken
	if (upstream) await revokeGoogleToken(upstream)
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

function isAllowedUrl (urlString) {
	if (!isGoogleApiUrl(urlString)) {
		return {
			allowed: false,
			reason: `Target URL domain not allowed. Requests must target *.googleapis.com, got: ${urlString}`
		}
	}
	return { allowed: true }
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
