import * as db from '../db/index.js'
import { validateBaseUrl } from '../util.js'
import googleConfig from './google.js'
import githubConfig from './github.js'

export {
	createProvider,
	getProvider,
	summarizeScopes,
	google,
	github
}

const google = createProvider(googleConfig)
const github = createProvider(githubConfig)

const providers = {
	google,
	github
}

function summarizeScopes (scopesStr, services) {
	if (!scopesStr || typeof scopesStr !== 'string' || !services) return ''
	const granted = new Set(scopesStr.split(/[\s,]+/).filter(Boolean))
	const allServices = Object.values(services)
	if (allServices.length === 0) return ''
	const matched = []
	for (const svc of allServices) {
		const ro = svc.ro || []
		const rw = svc.rw || []
		const rwDiff = rw.filter(s => !ro.includes(s))
		const isRw = rw.length > 0 && (rwDiff.length > 0 ? rwDiff.some(s => granted.has(s)) : rw.every(s => granted.has(s)))
		const isRo = !isRw && ro.length > 0 && ro.some(s => granted.has(s))
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

function matchesAllowedHost (hostname, allowedHosts) {
	const host = hostname.toLowerCase()
	for (const pattern of allowedHosts) {
		const p = pattern.toLowerCase()
		if (p.startsWith('*.')) {
			const suffix = p.slice(1)
			if (host.endsWith(suffix) && host.length > suffix.length) return true
		} else if (host === p) {
			return true
		}
	}
	return false
}

function buildScopesFromSelection (services, baseScopes = [], selectedServices = [], writeServiceIds = []) {
	const scopeSet = new Set(baseScopes)
	const writeSet = new Set(writeServiceIds.map(s => String(s).trim().toLowerCase()))
	if (services) {
		for (const rawId of selectedServices) {
			const svcId = String(rawId).trim().toLowerCase()
			const svc = services[svcId]
			if (!svc) continue
			const ro = svc.ro || []
			const rw = svc.rw || []
			const scopes = writeSet.has(svcId)
				? (rw.length ? rw : ro)
				: (ro.length ? ro : rw)
			for (const s of scopes) scopeSet.add(s)
		}
	}
	return Array.from(scopeSet).join(' ')
}

async function parseTokenResponse (res, fallbackErrorMsg) {
	const rawText = await res.text()
	let data = {}
	try {
		data = rawText ? JSON.parse(rawText) : {}
	} catch {
		data = { error_description: rawText }
	}
	if (!res.ok || data.error) {
		const err = new Error(data.error_description || data.error || fallbackErrorMsg)
		err.status = res.ok ? 401 : res.status
		err.data = data
		throw err
	}
	return data
}

function createProvider (config) {
	const rawConfig = typeof config === 'string' ? { id: config } : (config || {})
	const id = String(rawConfig.id || '').toLowerCase()
	const label = rawConfig.name || (id ? id.charAt(0).toUpperCase() + id.slice(1) : 'Upstream')
	const oauth = rawConfig.oauth || null
	const type = oauth ? 'oauth' : 'api_key'
	const baseUrl = rawConfig.baseUrl || null
	const parsedProviderBase = baseUrl ? new URL(baseUrl) : null
	const allowedHosts = rawConfig.allowedHosts || (parsedProviderBase ? [parsedProviderBase.hostname] : [])
	const hasWildcardHost = allowedHosts.some(h => h.startsWith('*.'))
	let services = null
	if (oauth?.services) {
		services = {}
		for (const [key, svc] of Object.entries(oauth.services)) {
			services[key] = { id: key, ...svc }
		}
	}
	const envPrefix = id.toUpperCase()
	return {
		id,
		name: label,
		type,
		baseUrl,
		...(services && { services }),
		toolDescription (baseHint) {
			if (typeof rawConfig.toolDescription === 'string') return rawConfig.toolDescription
			if (typeof rawConfig.toolDescription === 'function') return rawConfig.toolDescription(baseHint)
			const effectiveHint = baseHint || baseUrl
			return `Make HTTP requests to ${label} REST APIs${effectiveHint ? ` (${effectiveHint})` : ''}. Automatically attaches the configured ${label} credentials.`
		},
		urlParamDescription (baseHint) {
			if (typeof rawConfig.urlParamDescription === 'string') return rawConfig.urlParamDescription
			if (typeof rawConfig.urlParamDescription === 'function') return rawConfig.urlParamDescription(baseHint)
			const effectiveHint = baseHint || baseUrl
			return effectiveHint
				? `Full URL or relative path against ${effectiveHint} (e.g. "/v1/customers").`
				: 'Target HTTPS URL (or relative path if baseUrl is configured on the app).'
		},
		...(oauth && {
			buildAuthUrl ({ state, callbackUrl, services: selectedServices = [], write = [] }) {
				const clientId = process.env[`${envPrefix}_CLIENT_ID`]
				if (!clientId) {
					const err = new Error(`${envPrefix}_CLIENT_ID environment variable is missing`)
					err.status = 500
					throw err
				}
				const scopes = buildScopesFromSelection(services, oauth.baseScopes, selectedServices, write)
				const u = new URL(oauth.authUrl)
				u.searchParams.set('client_id', clientId)
				u.searchParams.set('redirect_uri', callbackUrl)
				u.searchParams.set('response_type', 'code')
				if (scopes) u.searchParams.set('scope', scopes)
				if (oauth.authParams) {
					for (const [k, v] of Object.entries(oauth.authParams)) {
						u.searchParams.set(k, v)
					}
				}
				u.searchParams.set('state', state)
				return u.toString()
			},
			async exchangeCode ({ code, callbackUrl }) {
				const clientId = process.env[`${envPrefix}_CLIENT_ID`]
				const clientSecret = process.env[`${envPrefix}_CLIENT_SECRET`]
				if (!clientId || !clientSecret) {
					const err = new Error(`${envPrefix}_CLIENT_ID or ${envPrefix}_CLIENT_SECRET environment variable is missing`)
					err.status = 500
					throw err
				}
				const params = new URLSearchParams({
					code,
					client_id: clientId,
					client_secret: clientSecret,
					redirect_uri: callbackUrl,
					grant_type: 'authorization_code'
				})
				const tokenRes = await fetch(oauth.tokenUrl, {
					method: 'POST',
					headers: {
						accept: 'application/json',
						'content-type': 'application/x-www-form-urlencoded',
						'user-agent': 'jump'
					},
					body: params.toString()
				})
				let tokenData
				try {
					tokenData = await parseTokenResponse(tokenRes, `Failed to exchange authorization code with ${label}`)
				} catch (err) {
					err.status = 502
					throw err
				}
				const userRes = await fetch(oauth.userInfoUrl, {
					headers: {
						authorization: `Bearer ${tokenData.access_token}`,
						accept: 'application/json',
						'user-agent': 'jump'
					}
				})
				if (!userRes.ok) {
					let data = await userRes.text()
					try {
						data = JSON.parse(data)
					} catch {}
					const msg = typeof data === 'object'
						? (data?.error_description || data?.error?.message || data?.message || JSON.stringify(data))
						: (data || 'Failed to fetch user info')
					const err = new Error(msg)
					err.status = userRes.status
					err.data = data
					throw err
				}
				const userInfo = await userRes.json()
				const account = oauth.extractAccount ? oauth.extractAccount(userInfo) : null
				if (!account) {
					const err = new Error(`Could not retrieve account identifier from ${label}.`)
					err.status = 400
					throw err
				}
				return {
					accessToken: tokenData.access_token,
					refreshToken: tokenData.refresh_token || null,
					expiresAt: tokenData.expires_in ? Date.now() + (tokenData.expires_in * 1000) : null,
					scopes: tokenData.scope || null,
					account
				}
			},
			async revokeToken (appToken) {
				if (appToken?.type !== 'oauth' || !oauth.revoke) return
				const token = appToken.credentials?.refreshToken || appToken.credentials?.accessToken
				if (!token) return
				try {
					const clientId = process.env[`${envPrefix}_CLIENT_ID`]
					const clientSecret = process.env[`${envPrefix}_CLIENT_SECRET`]
					await oauth.revoke({ token, clientId, clientSecret })
				} catch (err) {
					console.warn(`Failed to revoke token with ${label} upstream:`, err.message)
				}
			}
		}),
		async getFreshToken (appToken) {
			if (!appToken) return null
			const creds = appToken.credentials || {}
			if (creds.apiKey) {
				return {
					token: creds.apiKey,
					app: appToken
				}
			}
			if (oauth && creds.refreshToken && (!appToken.expiresAt || Date.now() > appToken.expiresAt - 60000)) {
				const clientId = process.env[`${envPrefix}_CLIENT_ID`]
				const clientSecret = process.env[`${envPrefix}_CLIENT_SECRET`]
				if (!clientId || !clientSecret) {
					const err = new Error(`${envPrefix}_CLIENT_ID or ${envPrefix}_CLIENT_SECRET environment variable is missing`)
					err.status = 500
					throw err
				}
				const params = new URLSearchParams({
					client_id: clientId,
					client_secret: clientSecret,
					refresh_token: creds.refreshToken,
					grant_type: 'refresh_token'
				})
				const res = await fetch(oauth.tokenUrl, {
					method: 'POST',
					headers: {
						accept: 'application/json',
						'content-type': 'application/x-www-form-urlencoded',
						'user-agent': 'jump'
					},
					body: params.toString()
				})
				const data = await parseTokenResponse(res, `Failed to refresh ${label} token`)
				const expiresAt = data.expires_in ? Date.now() + (data.expires_in * 1000) : null
				const updatedCreds = {
					...creds,
					accessToken: data.access_token,
					refreshToken: data.refresh_token || creds.refreshToken
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
			return {
				token: creds.accessToken || null,
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
			const noLeadingSlash = clean.replace(/^\/+/, '')
			const appBase = appToken?.credentials?.baseUrl || null
			if (!appBase && hasWildcardHost) {
				const slashIdx = noLeadingSlash.indexOf('/')
				const firstSegment = slashIdx === -1 ? noLeadingSlash : noLeadingSlash.slice(0, slashIdx)
				if (firstSegment.includes('.') && matchesAllowedHost(firstSegment, allowedHosts)) {
					return `https://${noLeadingSlash}`
				}
			}
			const base = appBase || baseUrl
			if (!base) return clean
			const cleanBase = base.replace(/\/+$/, '')
			return `${cleanBase}/${noLeadingSlash}`
		},
		isAllowedUrl (urlString, appToken) {
			let parsed
			try {
				parsed = new URL(urlString)
			} catch {
				return { allowed: false, reason: `Invalid target URL: ${urlString}` }
			}
			const appBase = appToken?.credentials?.baseUrl
			if (appBase || (!baseUrl && allowedHosts.length === 0)) {
				const normalizedBase = validateBaseUrl(appBase)
				if (!normalizedBase) {
					return { allowed: false, reason: 'App is missing a valid baseUrl' }
				}
				const allowedBase = new URL(normalizedBase)
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
			if (parsed.protocol !== 'https:' || !matchesAllowedHost(parsed.hostname, allowedHosts)) {
				const hostHint = allowedHosts.find(h => h.startsWith('*.')) || parsedProviderBase?.origin || allowedHosts[0]
				return {
					allowed: false,
					reason: `Target URL domain not allowed. Requests must target ${hostHint}, got: ${urlString}`
				}
			}
			const basePrefix = parsedProviderBase ? parsedProviderBase.pathname.replace(/\/+$/, '') : ''
			if (basePrefix && parsed.pathname !== basePrefix && !parsed.pathname.startsWith(`${basePrefix}/`)) {
				return {
					allowed: false,
					reason: `Target URL path not allowed. Requests must target ${parsedProviderBase.origin}${basePrefix}, got: ${urlString}`
				}
			}
			return { allowed: true }
		}
	}
}

function getProvider (name) {
	if (!name) return null
	const key = String(name).toLowerCase()
	return providers[key] || createProvider(key)
}
