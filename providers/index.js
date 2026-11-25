import * as db from '../db/index.js'
import { validateBaseUrl, hasUrlScheme, resolveTargetUrl, hasPathTraversal, positiveNumberEnv, getUserAgent, httpError } from '../util.js'
import googleConfig from './google.js'
import githubConfig from './github.js'

export {
	RESERVED_PROVIDERS,
	isValidProviderId,
	parseProviderTool,
	createProvider,
	getProvider,
	parseOauthProviders,
	isOauthProviderAllowed,
	listOauthProviders,
	requireOauthProvider,
	parseGrantedServices,
	summarizeScopes,
	normalizeServiceSelections,
	fetchOauth,
	fetchOauthJson,
	google,
	github
}

const PROVIDER_ID_PATTERN = /^[a-z0-9_-]+$/
const RESERVED_PROVIDERS = new Set(['self', 'health', 'whoami', 'logins', 'sessions', 'apps', 'links', 'shares', 'logs', '__proto__', 'constructor', 'prototype'])

function isValidProviderId (name) {
	return typeof name === 'string' && PROVIDER_ID_PATTERN.test(name) && !RESERVED_PROVIDERS.has(name)
}

function parseProviderTool (toolName) {
	if (typeof toolName !== 'string' || !toolName.toLowerCase().endsWith('_api')) return null
	const slug = toolName.slice(0, -4).toLowerCase()
	return isValidProviderId(slug) ? slug : null
}

const google = createProvider(googleConfig)
const github = createProvider(githubConfig)

const providers = Object.assign(Object.create(null), {
	google,
	github
})

const DEFAULT_OAUTH_TIMEOUT_MS = 30000
const inflightRefreshes = new Map()

function oauthTimeout () {
	return AbortSignal.timeout(positiveNumberEnv('OAUTH_TIMEOUT_MS', DEFAULT_OAUTH_TIMEOUT_MS))
}

function parseGrantedServices (scopesStr, services) {
	if (!scopesStr || typeof scopesStr !== 'string' || !services) return []
	const granted = new Set(scopesStr.split(/[\s,]+/).filter(Boolean))
	const matched = []
	for (const svc of Object.values(services)) {
		const modeEntries = Object.entries(svc.scopes || {}).filter(([, list]) => Array.isArray(list) && list.length > 0)
		const matchedModes = []
		for (let i = 0; i < modeEntries.length; i++) {
			const [mode, list] = modeEntries[i]
			const priorScopes = new Set(modeEntries.slice(0, i).flatMap(([, s]) => s))
			const unique = list.filter(s => !priorScopes.has(s))
			const isMatch = unique.length > 0
				? unique.some(s => granted.has(s))
				: list.every(s => granted.has(s))
			if (isMatch) matchedModes.push({ mode, list, grantedScopes: list.filter(s => granted.has(s)) })
		}
		const activeModes = matchedModes
			.filter((cand, i) => !matchedModes.some((other, j) => {
				if (j === i) return false
				if (!cand.grantedScopes.every(s => other.list.includes(s))) return false
				return cand.grantedScopes.length < other.grantedScopes.length || j > i
			}))
			.map(m => m.mode)
		if (activeModes.length > 0) {
			matched.push({ id: svc.id, modes: activeModes })
		}
	}
	return matched
}

function summarizeScopes (scopesStr, services) {
	if (!scopesStr || typeof scopesStr !== 'string' || !services) return ''
	const allServices = Object.values(services)
	if (allServices.length === 0) return ''
	const matched = parseGrantedServices(scopesStr, services)
	if (matched.length === 0) return ''
	const labels = matched.map(m => m.modes.join('+'))
	const uniformLabel = labels.every(l => l === labels[0]) ? labels[0] : null
	if (matched.length === allServices.length && uniformLabel) {
		return `all (${uniformLabel})`
	}
	if (matched.length <= 3) {
		if (uniformLabel && matched.length > 1) {
			return `${matched.map(m => m.id).join(', ')} (${uniformLabel})`
		}
		return matched.map((m, i) => `${m.id} (${labels[i]})`).join(', ')
	}
	if (uniformLabel) {
		return `${matched.length} (${uniformLabel})`
	}
	const counts = new Map()
	for (const l of labels) {
		counts.set(l, (counts.get(l) || 0) + 1)
	}
	const summary = Array.from(counts.entries())
		.sort((a, b) => b[1] - a[1])
		.map(([label, n]) => `${n} ${label}`)
		.join(', ')
	return `${matched.length} (${summary})`
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

function normalizeServiceSelections (services, entries = [], { strict = false, providerId = '' } = {}) {
	if (!Array.isArray(entries)) {
		if (strict) throw httpError(400, 'services must be an array of service strings')
		return []
	}
	const targetLabel = providerId ? ` for provider "${providerId}"` : ''
	const seen = new Set()
	const normalized = []
	for (const raw of entries) {
		if (typeof raw !== 'string') {
			if (strict) throw httpError(400, 'services entries must be strings')
			continue
		}
		const cleaned = raw.trim().toLowerCase()
		if (!cleaned) {
			if (strict) throw httpError(400, 'services entries cannot be empty')
			continue
		}
		const parts = cleaned.split(':')
		if (parts.length > 2 || !parts[0] || (parts.length === 2 && !parts[1])) {
			if (strict) throw httpError(400, `Invalid service specification "${raw}" (expected "<service>" or "<service>:<mode>")`)
			continue
		}
		const [svcId, explicitMode] = parts
		const svc = services?.[svcId]
		if (!svc) {
			if (strict) throw httpError(400, `Unknown service "${svcId}"${targetLabel}`)
			continue
		}
		const availableModes = Object.entries(svc.scopes || {})
			.filter(([, list]) => Array.isArray(list) && list.length > 0)
			.map(([mode]) => mode)
		let mode = explicitMode
		if (mode) {
			if (!availableModes.includes(mode)) {
				if (strict) throw httpError(400, `Unknown mode "${mode}" for service "${svcId}"${targetLabel} (available: ${availableModes.join(', ')})`)
				continue
			}
		} else if (availableModes.includes('read')) {
			mode = 'read'
		} else if (availableModes.length === 1) {
			mode = availableModes[0]
		} else {
			if (strict) throw httpError(400, `Service "${svcId}"${targetLabel} requires an explicit mode (available: ${availableModes.join(', ')})`)
			continue
		}
		const token = `${svcId}:${mode}`
		if (!seen.has(token)) {
			seen.add(token)
			normalized.push(token)
		}
	}
	return normalized
}

function buildScopesFromSelection (services, baseScopes = [], selectedServices = []) {
	const scopeSet = new Set(baseScopes)
	for (const token of normalizeServiceSelections(services, selectedServices)) {
		const [svcId, mode] = token.split(':')
		for (const s of services[svcId].scopes[mode]) {
			scopeSet.add(s)
		}
	}
	return Array.from(scopeSet).join(' ')
}

function parseOAuthResponse (res, rawText, fallbackErrorMsg) {
	let data = {}
	try {
		data = rawText ? JSON.parse(rawText) : {}
	} catch {
		data = { error_description: rawText }
	}
	if (!res.ok || data.error) {
		const errorText = typeof data.error === 'string'
			? data.error
			: (data.error?.message || (data.error ? JSON.stringify(data) : ''))
		throw httpError(res.ok ? 401 : res.status, data.error_description || errorText || data.message || fallbackErrorMsg, { data })
	}
	return data
}

async function withOauthTransport (fn, label, action) {
	try {
		return await fn()
	} catch (err) {
		if (err.name === 'TimeoutError' || err.name === 'AbortError') {
			throw httpError(504, `Timed out ${action} (${label})`)
		}
		throw httpError(502, `Failed ${action} (${label}): ${err.message}`)
	}
}

function fetchOauth (url, { method = 'GET', headers, body, form } = {}, label = 'Upstream', action = 'contacting OAuth endpoint') {
	const resolvedHeaders = new Headers(headers || undefined)
	if (!resolvedHeaders.has('user-agent')) resolvedHeaders.set('user-agent', getUserAgent())
	let resolvedMethod = method
	let resolvedBody = body
	if (form !== undefined) {
		resolvedMethod = 'POST'
		if (!resolvedHeaders.has('content-type')) resolvedHeaders.set('content-type', 'application/x-www-form-urlencoded')
		resolvedBody = new URLSearchParams(form).toString()
	}
	return withOauthTransport(() => fetch(url, {
		method: resolvedMethod,
		headers: Object.fromEntries(resolvedHeaders),
		...(resolvedBody !== undefined && { body: resolvedBody }),
		signal: oauthTimeout()
	}), label, action)
}

async function fetchOauthJson (url, opts, label, action, fallbackErrorMsg) {
	const resolvedHeaders = new Headers(opts?.headers || undefined)
	if (!resolvedHeaders.has('accept')) resolvedHeaders.set('accept', 'application/json')
	const res = await fetchOauth(url, {
		...opts,
		headers: resolvedHeaders
	}, label, action)
	const rawText = await withOauthTransport(() => res.text(), label, action)
	return parseOAuthResponse(res, rawText, fallbackErrorMsg)
}

async function fetchOauthToken (url, form, label, action, fallbackErrorMsg) {
	const data = await fetchOauthJson(url, { form }, label, action, fallbackErrorMsg)
	if (typeof data.access_token !== 'string' || !data.access_token.trim()) {
		throw httpError(502, `${fallbackErrorMsg}: missing access_token`, { data })
	}
	return data
}

function requireOauthEnv (envPrefix) {
	const clientId = process.env[`${envPrefix}_CLIENT_ID`]
	if (!clientId) {
		throw httpError(500, `${envPrefix}_CLIENT_ID environment variable is missing`)
	}
	const clientSecret = process.env[`${envPrefix}_CLIENT_SECRET`]
	if (!clientSecret) {
		throw httpError(500, `${envPrefix}_CLIENT_SECRET environment variable is missing`)
	}
	return { clientId, clientSecret }
}

function createProvider (config) {
	const rawConfig = typeof config === 'string' ? { id: config } : (config || {})
	const id = String(rawConfig.id || '').toLowerCase()
	const label = rawConfig.name || (id ? id.charAt(0).toUpperCase() + id.slice(1) : 'Upstream')
	const oauth = rawConfig.oauth || null
	const type = oauth ? 'oauth' : 'static'
	const baseUrl = rawConfig.baseUrl || null
	const parsedProviderBase = baseUrl ? new URL(baseUrl) : null
	const allowedHosts = rawConfig.allowedHosts || (parsedProviderBase ? [parsedProviderBase.hostname] : [])
	const hasWildcardHost = allowedHosts.some(h => h.startsWith('*.'))
	let services = null
	if (oauth?.services) {
		services = Object.create(null)
		for (const [key, svc] of Object.entries(oauth.services)) {
			const scopes = Object.create(null)
			for (const [mode, list] of Object.entries(svc.scopes || {})) {
				if (Array.isArray(list) && list.length > 0) {
					scopes[mode] = [...list]
				}
			}
			if (Object.keys(scopes).length === 0) {
				throw new Error(`Provider "${id}" service "${key}" must define at least one non-empty mode`)
			}
			services[key] = { id: key, name: svc.name, scopes }
		}
	}
	const envPrefix = id.toUpperCase()
	const verifiedEmail = Boolean(rawConfig.verifiedEmail || oauth?.verifiedEmail)
	const supportsAuth = Boolean(oauth && oauth.userInfoUrl && oauth.extractAccount)
	const supportsApp = !oauth || Boolean(baseUrl || allowedHosts.length > 0 || services)
	return {
		id,
		name: label,
		type,
		baseUrl,
		verifiedEmail,
		supportsAuth,
		supportsApp,
		...(services && { services }),
		toolDescription () {
			if (typeof rawConfig.toolDescription === 'string') return rawConfig.toolDescription
			if (typeof rawConfig.toolDescription === 'function') return rawConfig.toolDescription()
			return `Make HTTP requests to ${label} APIs. Automatically attaches the configured ${label} credentials.`
		},
		urlParamDescription () {
			if (typeof rawConfig.urlParamDescription === 'string') return rawConfig.urlParamDescription
			if (typeof rawConfig.urlParamDescription === 'function') return rawConfig.urlParamDescription()
			return "Target HTTPS URL or relative path against the linked app's base URL."
		},
		...(oauth && {
			requireEnv () {
				return requireOauthEnv(envPrefix)
			},
			buildAuthUrl ({ state, callbackUrl, services: selectedServices = [], login = false, loginHint = null }) {
				const { clientId } = requireOauthEnv(envPrefix)
				const scopes = login
					? (oauth.baseScopes || []).join(' ')
					: buildScopesFromSelection(services, oauth.baseScopes, selectedServices)
				const u = new URL(oauth.authUrl)
				u.searchParams.set('client_id', clientId)
				u.searchParams.set('redirect_uri', callbackUrl)
				u.searchParams.set('response_type', 'code')
				if (scopes) u.searchParams.set('scope', scopes)
				if (!login && oauth.authParams) {
					for (const [k, v] of Object.entries(oauth.authParams)) {
						u.searchParams.set(k, v)
					}
				}
				if (loginHint && oauth.loginHintParam) {
					u.searchParams.set(oauth.loginHintParam, loginHint)
				}
				u.searchParams.set('state', state)
				return u.toString()
			},
			async exchangeCode ({ code, callbackUrl }) {
				const { clientId, clientSecret } = requireOauthEnv(envPrefix)
				const asBadGateway = fn => fn().catch(err => {
					if (err.status !== 504) err.status = 502
					throw err
				})
				const tokenData = await asBadGateway(() => fetchOauthToken(oauth.tokenUrl, {
					code,
					client_id: clientId,
					client_secret: clientSecret,
					redirect_uri: callbackUrl,
					grant_type: 'authorization_code'
				}, label, 'exchanging authorization code', `Failed to exchange authorization code with ${label}`))
				const userInfo = await asBadGateway(() => fetchOauthJson(oauth.userInfoUrl, {
					headers: { authorization: `Bearer ${tokenData.access_token}` }
				}, label, 'fetching user info', 'Failed to fetch user info'))
				const account = oauth.extractAccount ? oauth.extractAccount(userInfo) : null
				if (!account) {
					throw httpError(400, `Could not retrieve account identifier from ${label}.`)
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
					await oauth.revoke({
						token,
						clientId,
						clientSecret,
						fetch: (url, init) => fetchOauth(url, init, label, 'revoking token')
					})
				} catch (err) {
					console.warn(`Failed to revoke token with ${label} upstream:`, err.message)
				}
			}
		}),
		async resolveCredentials (appToken) {
			if (!appToken) return null
			const creds = appToken.credentials || {}
			if (appToken.type === 'static') {
				if (!creds.headers && !creds.query) return null
				return {
					...(creds.headers && { headers: creds.headers }),
					...(creds.query && { query: creds.query })
				}
			}
			const isExpiring = Boolean(appToken.expiresAt && Date.now() > appToken.expiresAt - 60000)
			const needsRefresh = !creds.accessToken || isExpiring
			if (oauth && creds.refreshToken && needsRefresh) {
				if (inflightRefreshes.has(appToken.id)) {
					return inflightRefreshes.get(appToken.id)
				}
				const refreshPromise = (async () => {
					const { clientId, clientSecret } = requireOauthEnv(envPrefix)
					let data
					try {
						data = await fetchOauthToken(oauth.tokenUrl, {
							client_id: clientId,
							client_secret: clientSecret,
							refresh_token: creds.refreshToken,
							grant_type: 'refresh_token'
						}, label, 'refreshing access token', `Failed to refresh ${label} token`)
					} catch (err) {
						if (err.status >= 500 || err.data?.error === 'invalid_client' || err.data?.error === 'unauthorized_client') {
							err.status = err.status === 504 ? 504 : 502
						}
						throw err
					}
					const expiresAt = data.expires_in ? Date.now() + (data.expires_in * 1000) : null
					const updatedCreds = {
						...creds,
						accessToken: data.access_token,
						refreshToken: data.refresh_token || creds.refreshToken
					}
					db.tokens.updateCredentials(appToken.id, {
						credentials: updatedCreds,
						expiresAt,
						scopes: data.scope || appToken.scopes
					})
					return {
						headers: { authorization: `Bearer ${data.access_token}` }
					}
				})()
				inflightRefreshes.set(appToken.id, refreshPromise)
				try {
					return await refreshPromise
				} finally {
					inflightRefreshes.delete(appToken.id)
				}
			}
			if (!creds.accessToken) return null
			return {
				headers: { authorization: `Bearer ${creds.accessToken}` }
			}
		},
		normalizeTargetUrl (targetUrl, appToken) {
			if (!targetUrl || typeof targetUrl !== 'string') return ''
			const appBase = appToken?.credentials?.baseUrl || null
			if (!appBase && hasWildcardHost) {
				const clean = targetUrl.trim()
				if (clean && !hasUrlScheme(clean)) {
					const noLeadingSlash = clean.replace(/^\/+/, '')
					const slashIdx = noLeadingSlash.indexOf('/')
					const firstSegment = slashIdx === -1 ? noLeadingSlash : noLeadingSlash.slice(0, slashIdx)
					if (firstSegment.includes('.') && matchesAllowedHost(firstSegment, allowedHosts)) {
						return `https://${noLeadingSlash}`
					}
				}
			}
			return resolveTargetUrl(targetUrl, appBase || baseUrl)
		},
		isAllowedUrl (urlString, appToken) {
			let parsed
			try {
				parsed = new URL(urlString)
			} catch {
				return { allowed: false, reason: `Invalid target URL: ${urlString}` }
			}
			if (parsed.username || parsed.password) {
				return { allowed: false, reason: 'Invalid target URL: embedded credentials are not permitted' }
			}
			if (hasPathTraversal(urlString) || hasPathTraversal(parsed.pathname)) {
				return { allowed: false, reason: 'Invalid target URL: path traversal is not permitted' }
			}
			const appBase = appToken?.credentials?.baseUrl
			const pinnedToAppBase = Boolean(appBase || (!baseUrl && allowedHosts.length === 0))
			let allowedBase = parsedProviderBase
			if (pinnedToAppBase) {
				const normalizedBase = validateBaseUrl(appBase)
				if (!normalizedBase) {
					return { allowed: false, reason: 'App is missing a valid baseUrl' }
				}
				allowedBase = new URL(normalizedBase)
			}
			const expectedPort = allowedBase?.port || ''
			const hostAllowed = pinnedToAppBase
				? parsed.hostname === allowedBase.hostname
				: matchesAllowedHost(parsed.hostname, allowedHosts)
			if (parsed.protocol !== 'https:' || parsed.port !== expectedPort || !hostAllowed) {
				const hint = pinnedToAppBase
					? allowedBase.origin
					: (allowedHosts.find(h => h.startsWith('*.')) || parsedProviderBase?.origin || allowedHosts[0])
				const kind = pinnedToAppBase ? 'origin' : 'domain'
				return {
					allowed: false,
					reason: `Target URL ${kind} not allowed. Requests must target ${hint}, got: ${urlString}`
				}
			}
			const basePrefix = allowedBase ? allowedBase.pathname.replace(/\/+$/, '') : ''
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
	return providers[key] || createProvider(key)
}

function parseOauthProviders (raw = process.env.OAUTH_PROVIDERS, registry = providers) {
	if (raw === undefined || raw === null) return null
	if (typeof raw !== 'string') {
		throw httpError(500, 'Invalid OAUTH_PROVIDERS value')
	}
	if (!raw.trim()) return null
	const configured = new Map()
	for (const item of raw.split(',')) {
		const entry = item.trim()
		if (!entry) {
			throw httpError(500, `Invalid OAUTH_PROVIDERS entry "${raw}"`)
		}
		const parts = entry.split(':')
		if (parts.length > 2) {
			throw httpError(500, `Invalid OAUTH_PROVIDERS entry "${entry}"; expected "provider" or "provider:auth|app"`)
		}
		const id = parts[0].trim().toLowerCase()
		const role = parts.length === 2 ? parts[1].trim().toLowerCase() : null
		const provider = id ? registry[id] : null
		if (!provider || provider.type !== 'oauth') {
			throw httpError(500, `Invalid OAUTH_PROVIDERS provider "${parts[0].trim()}"`)
		}
		if (role !== null && role !== 'auth' && role !== 'app') {
			throw httpError(500, `Invalid OAUTH_PROVIDERS role "${parts[1].trim()}" in "${entry}"; expected "auth" or "app"`)
		}
		if (configured.has(id)) {
			throw httpError(500, `Duplicate provider "${id}" in OAUTH_PROVIDERS`)
		}
		if ((role === 'auth' && !provider.supportsAuth) || (role === 'app' && !provider.supportsApp)) {
			throw httpError(500, `Provider "${id}" does not support "${role}"`)
		}
		configured.set(id, {
			auth: role ? role === 'auth' : provider.supportsAuth,
			app: role ? role === 'app' : provider.supportsApp
		})
	}
	return configured
}

function hasOauthRole (provider, role, configured) {
	if (!provider || provider.type !== 'oauth') return false
	if (role === 'auth' ? !provider.supportsAuth : !provider.supportsApp) return false
	return !configured || Boolean(configured.get(provider.id)?.[role])
}

function isOauthProviderAllowed (provider, role) {
	if (role !== 'auth' && role !== 'app') {
		throw httpError(500, `Invalid OAuth role "${role}"`)
	}
	return hasOauthRole(provider, role, parseOauthProviders())
}

function listOauthProviders (role = 'auth') {
	if (role !== 'auth' && role !== 'app') {
		throw httpError(500, `Invalid OAuth role "${role}"`)
	}
	const configured = parseOauthProviders()
	return Object.values(providers).filter(p => {
		if (!hasOauthRole(p, role, configured)) return false
		const prefix = p.id.toUpperCase()
		return Boolean(process.env[`${prefix}_CLIENT_ID`] && process.env[`${prefix}_CLIENT_SECRET`])
	})
}

function requireOauthProvider (rawName, role = 'auth') {
	const name = typeof rawName === 'string' ? rawName.trim().toLowerCase() : ''
	const provider = name ? providers[name] : null
	if (!provider || !listOauthProviders(role).some(p => p.id === provider.id)) {
		throw httpError(400, `Invalid or unsupported OAuth provider: ${rawName}`)
	}
	return provider
}
