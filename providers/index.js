import * as google from './google.js'
import { validateBaseUrl } from '../util.js'

export {
	getProvider,
	summarizeScopes,
	google
}

const providers = {
	google
}

function summarizeScopes (scopesStr, services) {
	if (!scopesStr || typeof scopesStr !== 'string' || !services) return ''
	const granted = new Set(scopesStr.split(/\s+/).filter(Boolean))
	const allServices = Object.values(services)
	if (allServices.length === 0) return ''
	const matched = []
	for (const svc of allServices) {
		const rwDiff = svc.rw.filter(s => !svc.ro.includes(s))
		const isRw = rwDiff.length > 0 ? rwDiff.some(s => granted.has(s)) : svc.rw.some(s => granted.has(s))
		const isRo = !isRw && svc.ro.some(s => granted.has(s))
		if (isRw || isRo) {
			matched.push({ id: svc.id, mode: isRw ? 'rw' : 'ro' })
		}
	}
	if (matched.length === 0) return ''
	const allRw = matched.every(m => m.mode === 'rw')
	const allRo = matched.every(m => m.mode === 'ro')
	const uniformMode = allRw ? 'rw' : (allRo ? 'ro' : null)
	if (matched.length === allServices.length && uniformMode) {
		return `all (${uniformMode})`
	}
	if (matched.length <= 3) {
		if (uniformMode && matched.length > 1) {
			return `${matched.map(m => m.id).join(', ')} (${uniformMode})`
		}
		return matched.map(m => `${m.id} (${m.mode})`).join(', ')
	}
	if (uniformMode) {
		return `${matched.length} (${uniformMode})`
	}
	const rwCount = matched.filter(m => m.mode === 'rw').length
	const roCount = matched.length - rwCount
	return `${matched.length} (${rwCount} rw, ${roCount} ro)`
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
			const normalizedBase = validateBaseUrl(appToken?.credentials?.baseUrl)
			if (!normalizedBase) {
				return { allowed: false, reason: 'App is missing a valid baseUrl' }
			}
			const allowedBase = new URL(normalizedBase)
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
