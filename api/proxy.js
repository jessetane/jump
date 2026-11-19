import * as db from '../db/index.js'
import { getProvider } from '../providers/index.js'
import { evaluatePolicy } from '../policy.js'
import { assertUpstreamHost, serializeFormBody, validateBaseUrl } from '../util.js'

export {
	request,
	readResponseBody
}

const DEFAULT_TIMEOUT_MS = 60000
const MAX_REDIRECT_HOPS = 5
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

function reqMethodAllowsBody (method) {
	return method !== 'GET' && method !== 'HEAD'
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

function stripQueryAuth (parsed, queryEntries) {
	const secretKeysLower = new Set(queryEntries.map(([k]) => k.toLowerCase()))
	for (const existingKey of Array.from(parsed.searchParams.keys())) {
		if (secretKeysLower.has(existingKey.toLowerCase())) {
			parsed.searchParams.delete(existingKey)
		}
	}
}

function stripLocationAuth (rawLocation, baseUrl, queryEntries) {
	if (queryEntries.length === 0) return rawLocation
	let parsed
	try {
		parsed = new URL(rawLocation, baseUrl)
	} catch {
		const err = new Error('Invalid upstream redirect Location')
		err.status = 502
		throw err
	}
	const before = parsed.toString()
	stripQueryAuth(parsed, queryEntries)
	const after = parsed.toString()
	if (after === before) return rawLocation
	const trimmed = rawLocation.trim()
	if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmed)) return after
	if (trimmed.startsWith('//')) return `//${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`
	return `${parsed.pathname}${parsed.search}${parsed.hash}`
}

function attachAuth (targetUrl, baseHeaders, authHeaders, queryEntries) {
	const hopHeaders = Object.assign(Object.create(null), baseHeaders)
	delete hopHeaders.authorization
	delete hopHeaders.cookie
	for (const [k, v] of authHeaders) {
		hopHeaders[k] = v
	}
	if (queryEntries.length === 0) {
		return { url: targetUrl, headers: hopHeaders }
	}
	const parsed = new URL(targetUrl)
	stripQueryAuth(parsed, queryEntries)
	for (const [k, v] of queryEntries) {
		parsed.searchParams.append(k, v)
	}
	return { url: parsed.toString(), headers: hopHeaders }
}

async function executeUpstream ({ credentials, url, method = 'GET', body, headers = {}, raw = false, onStatus, onSameOriginRedirect }) {
	const baseHeaders = Object.create(null)
	if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
		for (const [k, v] of Object.entries(headers)) {
			if (v !== undefined && v !== null) {
				baseHeaders[k.toLowerCase()] = String(v)
			}
		}
	}
	delete baseHeaders.authorization
	delete baseHeaders.cookie
	baseHeaders['user-agent'] ||= 'jump'
	let reqBody
	if (body !== undefined && body !== null) {
		if (ArrayBuffer.isView(body)) {
			if (body.byteLength > 0) {
				reqBody = Buffer.from(body.buffer, body.byteOffset, body.byteLength)
			}
		} else if (typeof body === 'object') {
			const ct = (baseHeaders['content-type'] || '').split(';')[0].trim().toLowerCase()
			if (ct === 'application/x-www-form-urlencoded') {
				reqBody = Buffer.from(serializeFormBody(body), 'utf8')
			} else {
				baseHeaders['content-type'] ||= 'application/json'
				reqBody = Buffer.from(JSON.stringify(body), 'utf8')
			}
		} else {
			const str = String(body)
			if (str.length > 0) {
				reqBody = Buffer.from(str, 'utf8')
			}
		}
	}
	const authHeaders = credentials?.headers && typeof credentials.headers === 'object'
		? Object.entries(credentials.headers).map(([k, v]) => [k.toLowerCase(), String(v)])
		: []
	const queryEntries = credentials?.query && typeof credentials.query === 'object'
		? Object.entries(credentials.query).map(([k, v]) => [k, String(v)])
		: []
	const initialOrigin = new URL(url).origin
	let curMethod = method.toUpperCase()
	let curUrl = url
	let curBody = reqMethodAllowsBody(curMethod) ? reqBody : undefined
	const signal = AbortSignal.timeout(Number(process.env.UPSTREAM_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS)
	let res
	for (let hop = 0; ; hop++) {
		const hopUrl = new URL(curUrl)
		await assertUpstreamHost(hopUrl.hostname)
		const isInitialOrigin = hopUrl.origin === initialOrigin
		const hopReq = isInitialOrigin
			? attachAuth(curUrl, baseHeaders, authHeaders, queryEntries)
			: { url: curUrl, headers: baseHeaders }
		res = await fetch(hopReq.url, {
			method: curMethod,
			headers: Object.entries(hopReq.headers),
			...(curBody !== undefined && { body: curBody }),
			redirect: 'manual',
			signal
		})
		if (raw) break
		const location = REDIRECT_STATUSES.has(res.status) ? res.headers.get('location') : null
		if (!location) break
		await res.body?.cancel()
		if (hop >= MAX_REDIRECT_HOPS) {
			const err = new Error(`Too many upstream redirects (exceeded ${MAX_REDIRECT_HOPS})`)
			err.status = 502
			throw err
		}
		let nextParsed
		try {
			nextParsed = new URL(location, curUrl)
		} catch {
			const err = new Error('Invalid upstream redirect Location')
			err.status = 502
			throw err
		}
		if (!validateBaseUrl(nextParsed.origin)) {
			const err = new Error(`Blocked unsafe upstream redirect target: ${nextParsed.origin}`)
			err.status = 403
			throw err
		}
		if (res.status === 303 || ((res.status === 301 || res.status === 302) && curMethod === 'POST')) {
			curMethod = 'GET'
			curBody = undefined
			delete baseHeaders['content-type']
			delete baseHeaders['content-length']
		}
		if (queryEntries.length > 0) {
			stripQueryAuth(nextParsed, queryEntries)
		}
		curUrl = nextParsed.toString()
		if (nextParsed.origin === initialOrigin && onSameOriginRedirect) {
			onSameOriginRedirect({ url: curUrl, method: curMethod, hasBody: curBody !== undefined })
		}
	}
	if (onStatus) onStatus(res.status)
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
	const buf = await readResponseBody(res, maxFileSizeBytes)
	if (raw) {
		const rawLocation = res.headers.get('location')
		const cleanedLocation = rawLocation ? stripLocationAuth(rawLocation, curUrl, queryEntries) : rawLocation
		let outHeaders = res.headers
		if (cleanedLocation !== rawLocation) {
			outHeaders = new Headers(res.headers)
			outHeaders.set('location', cleanedLocation)
		}
		return {
			status: res.status,
			headers: outHeaders,
			body: buf
		}
	}
	const contentType = rawContentType.split(';')[0].trim().toLowerCase()
	const charsetMatch = rawContentType.match(/charset=([^;]+)/i)
	const charset = charsetMatch ? charsetMatch[1].trim().replace(/^["']|["']$/g, '') : undefined
	let result
	if (contentType === 'application/json' || contentType.endsWith('+json')) {
		const str = buf.toString('utf8')
		try {
			result = str ? JSON.parse(str) : {}
		} catch {
			result = str
		}
	} else if (
		contentType.startsWith('text/') ||
		contentType === 'application/xml' ||
		contentType.endsWith('+xml') ||
		contentType === 'application/x-www-form-urlencoded'
	) {
		try {
			result = new TextDecoder(charset || 'utf-8').decode(buf)
		} catch {
			result = buf.toString('utf8')
		}
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

async function request ({ provider: providerName = 'google', url, method = 'GET', body, headers, appId, account, appUrl: rawAppUrl, raw = false } = {}, auth) {
	if (!url) {
		const err = new Error('URL is required')
		err.status = 400
		throw err
	}
	const appUrl = (rawAppUrl || 'http://localhost:8080').replace(/\/$/, '')
	const session = db.tokens.resolveSession(auth)
	if (!session) {
		const err = new Error(`Authentication required: ${appUrl}/oauth/authorize`)
		err.status = 401
		throw err
	}
	const start = Date.now()
	const normalizedMethod = (method || 'GET').toUpperCase()
	const provider = getProvider(providerName)
	let targetAppId = null
	let resolvedUrl = String(url)
	let allowed = false
	const recordLog = (status, error = null) => {
		db.logs.create({
			userId: session.userId,
			sessionId: session.id,
			appId: targetAppId,
			provider: provider.id,
			method: normalizedMethod,
			url: resolvedUrl,
			allowed,
			status,
			duration: Date.now() - start,
			error
		})
	}
	try {
		const links = db.links.listBySessionId(session.id)
		const providerLinks = links.filter(l => l.app?.provider === provider.id)
		if (providerLinks.length === 0) {
			const hint = session.admin
				? 'Use connect_app or link_app to attach one.'
				: 'Ask an admin to link one.'
			const err = new Error(`No ${provider.name} app linked to session. ${hint}`)
			err.status = 403
			throw err
		}
		let targetLink = providerLinks[0]
		if (appId) {
			const found = providerLinks.find(l => l.app?.id === appId)
			if (!found) {
				const err = new Error(`App not linked to session or not found: ${appId}`)
				err.status = 404
				throw err
			}
			targetLink = found
		} else if (account) {
			const cleanAccount = String(account).trim().toLowerCase()
			const found = providerLinks.find(l => {
				const appAcc = (l.app?.credentials?.account || '').toLowerCase()
				const appName = (l.app?.name || '').toLowerCase()
				return appAcc === cleanAccount || appName === cleanAccount || l.app?.id === account
			})
			if (!found) {
				const err = new Error(`App account not linked to session or not found: ${account}`)
				err.status = 404
				throw err
			}
			targetLink = found
		}
		targetAppId = targetLink.app?.id || null
		let upstreamApp = targetLink.app
		if (upstreamApp?.type === 'share') {
			targetAppId = upstreamApp.credentials?.appId || null
			upstreamApp = db.tokens.get(targetAppId)
			if (!db.tokens.isUpstreamApp(upstreamApp)) {
				const err = new Error(`Shared upstream app not found: ${targetLink.app.id}`)
				err.status = 404
				throw err
			}
		}
		resolvedUrl = provider.normalizeTargetUrl(url, upstreamApp)
		let contentType = ''
		if (headers && typeof headers === 'object') {
			for (const [k, v] of Object.entries(headers)) {
				if (k.toLowerCase() === 'content-type' && v !== undefined && v !== null) {
					contentType = String(v)
					break
				}
			}
		}
		const objectFormat = contentType.split(';')[0].trim().toLowerCase() === 'application/x-www-form-urlencoded' ? 'form' : 'json'
		const sharePolicy = targetLink.app?.type === 'share' ? targetLink.app.credentials?.policy : null
		const checkTargetPolicy = (targetUrl, targetMethod, targetBody, targetContentType) => {
			const urlCheck = provider.isAllowedUrl(targetUrl, upstreamApp)
			if (!urlCheck.allowed) {
				const err = new Error(urlCheck.reason)
				err.status = 403
				throw err
			}
			if (sharePolicy) {
				const check = evaluatePolicy(sharePolicy, {
					url: targetUrl,
					method: targetMethod,
					body: targetBody,
					objectFormat,
					contentType: targetContentType
				})
				if (!check.allowed) {
					const err = new Error(`Policy violation: ${check.reason || 'Operation not permitted by shared app policy'}`)
					err.status = 403
					throw err
				}
			}
			if (targetLink.policy) {
				const check = evaluatePolicy(targetLink.policy, {
					url: targetUrl,
					method: targetMethod,
					body: targetBody,
					objectFormat,
					contentType: targetContentType
				})
				if (!check.allowed) {
					const err = new Error(`Policy violation: ${check.reason || 'Operation not permitted by session policy'}`)
					err.status = 403
					throw err
				}
			}
		}
		checkTargetPolicy(resolvedUrl, normalizedMethod, body, contentType)
		allowed = true
		let freshInfo = null
		try {
			freshInfo = await provider.getFreshToken(upstreamApp)
		} catch (err) {
			const hint = targetLink.app?.type === 'share'
				? `Ask the app owner (${targetLink.app.sharedBy || 'admin'}) to re-authenticate.`
				: session.admin
					? `Use connect_app with appId "${upstreamApp.id}" to re-authenticate.`
					: 'Ask an admin to re-authenticate.'
			const error = new Error(`Failed to refresh ${provider.name} access token: ${err.message}. ${hint}`)
			error.status = 401
			throw error
		}
		if (!freshInfo?.headers && !freshInfo?.query) {
			const err = new Error(`Authentication required: ${appUrl}/oauth/authorize`)
			err.status = 401
			throw err
		}
		let upstreamStatus = 200
		const result = await executeUpstream({
			credentials: freshInfo,
			url: resolvedUrl,
			method: normalizedMethod,
			body,
			headers,
			raw,
			onStatus: s => { upstreamStatus = s },
			onSameOriginRedirect: ({ url: nextUrl, method: nextMethod, hasBody }) => {
				allowed = false
				resolvedUrl = nextUrl
				checkTargetPolicy(nextUrl, nextMethod, hasBody ? body : undefined, hasBody ? contentType : '')
				allowed = true
			}
		})
		const logError = raw && upstreamStatus >= 400
			? (result.body.length > 0 ? result.body.subarray(0, 512).toString('utf8') : `HTTP ${upstreamStatus}`)
			: null
		recordLog(upstreamStatus, logError)
		return result
	} catch (err) {
		recordLog(err.status || 502, err.message)
		throw err
	}
}
