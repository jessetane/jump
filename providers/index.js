import * as google from './google.js'

export {
	getProvider,
	google
}

const providers = {
	google
}

function createGenericProvider (name) {
	const id = String(name || '').toLowerCase()
	const label = id ? id.charAt(0).toUpperCase() + id.slice(1) : 'Upstream'
	return {
		id,
		name: label,
		type: 'api_key',
		baseUrl: null,
		toolDescription (baseHint) {
			return `Make HTTP requests to ${label} REST APIs${baseHint ? ` (${baseHint})` : ''}. Automatically attaches the configured ${label} credentials.`
		},
		urlParamDescription (baseHint) {
			return baseHint
				? `Full URL or relative path against ${baseHint} (e.g. "/v1/customers").`
				: 'Target HTTPS URL (or relative path if baseUrl is configured on the app).'
		},
		async getFreshToken (appToken) {
			const creds = appToken?.credentials || {}
			return {
				token: creds.apiKey || creds.accessToken || null,
				app: appToken
			}
		},
		normalizeTargetUrl (targetUrl, appToken) {
			if (!targetUrl || typeof targetUrl !== 'string') return ''
			let clean = targetUrl.trim()
			if (clean.startsWith('https:/') && !clean.startsWith('https://')) {
				clean = clean.replace(/^https:\/+/, 'https://')
			}
			if (clean.startsWith('http://') || clean.startsWith('https://')) {
				return clean
			}
			const base = appToken?.credentials?.baseUrl || null
			if (!base) return clean
			const cleanBase = base.replace(/\/+$/, '')
			const noLeadingSlash = clean.replace(/^\/+/, '')
			return `${cleanBase}/${noLeadingSlash}`
		},
		isAllowedUrl (urlString, appToken) {
			const base = appToken?.credentials?.baseUrl
			if (!base || typeof base !== 'string') {
				return { allowed: false, reason: 'App is missing a valid baseUrl' }
			}
			let allowedBase
			try {
				allowedBase = new URL(base)
			} catch {
				return { allowed: false, reason: 'App is missing a valid baseUrl' }
			}
			const isLocal = allowedBase.hostname === 'localhost' || allowedBase.hostname === '127.0.0.1' || allowedBase.hostname === '[::1]'
			if (allowedBase.protocol !== 'https:' && !(allowedBase.protocol === 'http:' && isLocal)) {
				return { allowed: false, reason: 'App is missing a valid baseUrl' }
			}
			let parsed
			try {
				parsed = new URL(urlString)
			} catch {
				return { allowed: false, reason: `Invalid target URL: ${urlString}` }
			}
			if (parsed.protocol !== allowedBase.protocol || parsed.origin !== allowedBase.origin) {
				return {
					allowed: false,
					reason: `Target URL origin not allowed. Requests must target ${allowedBase.origin}, got: ${urlString}`
				}
			}
			const basePrefix = allowedBase.pathname.replace(/\/+$/, '')
			if (basePrefix && parsed.pathname !== basePrefix && !parsed.pathname.startsWith(`${basePrefix}/`)) {
				return {
					allowed: false,
					reason: `Target URL path not allowed. Requests must target ${allowedBase.origin}${basePrefix}, got: ${urlString}`
				}
			}
			return { allowed: true }
		}
	}
}

function getProvider (name) {
	if (!name) return null
	const key = String(name).toLowerCase()
	return providers[key] || createGenericProvider(key)
}
