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
	listAuthProviders,
	requireAuthProvider,
	parseGrantedServices,
	summarizeScopes,
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
		const ro = svc.ro || []
		const rw = svc.rw || []
		const rwDiff = rw.filter(s => !ro.includes(s))
		const isRw = rw.length > 0 && (rwDiff.length > 0 ? rwDiff.some(s => granted.has(s)) : rw.every(s => granted.has(s)))
		const isRo = !isRw && ro.length > 0 && ro.some(s => granted.has(s))
		if (isRw || isRo) {
			matched.push({ id: svc.id, mode: isRw ? 'rw' : 'ro' })
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
			services[key] = { id: key, ...svc }
		}
	}
	const envPrefix = id.toUpperCase()
	const verifiedEmail = Boolean(rawConfig.verifiedEmail || oauth?.verifiedEmail)
	return {
		id,
		name: label,
		type,
		baseUrl,
		verifiedEmail,
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
			requireEnv () {
				return requireOauthEnv(envPrefix)
			},
			buildAuthUrl ({ state, callbackUrl, services: selectedServices = [], write = [], login = false, loginHint = null }) {
				const { clientId } = requireOauthEnv(envPrefix)
				const scopes = login
					? (oauth.baseScopes || []).join(' ')
					: buildScopesFromSelection(services, oauth.baseScopes, selectedServices, write)
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

function listAuthProviders () {
	return Object.values(providers).filter(p => {
		if (p.type !== 'oauth') return false
		const prefix = p.id.toUpperCase()
		return Boolean(process.env[`${prefix}_CLIENT_ID`] && process.env[`${prefix}_CLIENT_SECRET`])
	})
}

function requireAuthProvider (rawName) {
	const name = typeof rawName === 'string' ? rawName.trim().toLowerCase() : ''
	const provider = name ? providers[name] : null
	if (!provider || !listAuthProviders().some(p => p.id === provider.id)) {
		throw httpError(400, `Invalid or unsupported OAuth provider: ${rawName}`)
	}
	return provider
}
