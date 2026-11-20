import http from 'node:http'
import https from 'node:https'
import { PassThrough } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import zlib from 'node:zlib'
import * as db from '../db/index.js'
import { getProvider } from '../providers/index.js'
import { evaluatePolicy, hasBodyPolicy } from '../policy.js'
import { HOP_BY_HOP_HEADERS, assertKeys, getRawBody, isAllowedUpstreamHost, lookupUpstreamHost, serializeFormBody, validateBaseUrl } from '../util.js'

export {
	formatLinkedApps,
	request,
	stream,
	readResponseBody
}

const DEFAULT_TIMEOUT_MS = 60000
const MAX_REDIRECT_HOPS = 5
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
const BODILESS_STATUSES = new Set([204, 205, 304])
const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
const SUPPORTED_ENCODINGS = 'gzip, br, zstd'

const STRIPPED_REQUEST_HEADERS = new Set([
	...HOP_BY_HOP_HEADERS,
	'host',
	'authorization',
	'proxy-authorization',
	'cookie'
])

const STRIPPED_RESPONSE_HEADERS = new Set([
	...HOP_BY_HOP_HEADERS,
	'set-cookie',
	'access-control-allow-origin',
	'access-control-allow-methods',
	'access-control-allow-headers',
	'access-control-expose-headers',
	'access-control-allow-credentials'
])

function reqMethodAllowsBody (method) {
	return method !== 'GET' && method !== 'HEAD'
}

function fileTooLargeError (totalBytes, maxBytes) {
	const sizeMb = (totalBytes / (1024 * 1024)).toFixed(1)
	const limitMb = (maxBytes / (1024 * 1024)).toFixed(0)
	const err = new Error(`File too large: size (${sizeMb} MB) exceeds server limit of ${limitMb} MB. Consider exporting specific sheets, ranges, or text sections instead.`)
	err.status = 413
	return err
}

function timeoutError (timeoutMs) {
	const err = new Error(`Upstream request timed out after ${timeoutMs}ms of inactivity`)
	err.status = 504
	return err
}

function normalizeUpstreamError (err) {
	if (err && typeof err === 'object' && !err.status) {
		err.status = 502
	}
	return err
}

function createDecompressor (encoding) {
	if (encoding === 'gzip' || encoding === 'x-gzip' || encoding === 'deflate') return zlib.createUnzip()
	if (encoding === 'br') return zlib.createBrotliDecompress()
	if (encoding === 'zstd') return zlib.createZstdDecompress()
	return null
}

async function readResponseBody (source, maxBytes) {
	if (!source) return Buffer.alloc(0)
	const encoding = typeof source.headers?.['content-encoding'] === 'string'
		? source.headers['content-encoding'].split(',')[0].trim().toLowerCase()
		: ''
	if (!encoding || encoding === 'identity') {
		return readStreamBytes(source, maxBytes)
	}
	const decompressor = createDecompressor(encoding)
	if (!decompressor) {
		const err = new Error(`Unsupported upstream Content-Encoding: ${encoding}`)
		err.status = 502
		source.destroy()
		throw err
	}
	return readCompressedBytes(source, decompressor, maxBytes)
}

function readCompressedBytes (source, decompressor, maxBytes) {
	return new Promise((resolve, reject) => {
		const chunks = []
		let totalBytes = 0
		let started = false
		let settled = false
		const fail = err => {
			if (settled) return
			settled = true
			source.destroy()
			decompressor.destroy()
			reject(normalizeUpstreamError(err))
		}
		decompressor.on('data', chunk => {
			if (settled) return
			totalBytes += chunk.byteLength
			if (totalBytes > maxBytes) {
				fail(fileTooLargeError(totalBytes, maxBytes))
				return
			}
			chunks.push(chunk)
		})
		decompressor.on('end', () => {
			if (settled) return
			settled = true
			resolve(Buffer.concat(chunks))
		})
		decompressor.on('error', fail)
		source.on('data', chunk => {
			if (settled || chunk.byteLength === 0) return
			started = true
			if (!decompressor.write(chunk)) {
				source.pause()
				decompressor.once('drain', () => source.resume())
			}
		})
		source.on('end', () => {
			if (settled) return
			if (!started) {
				settled = true
				decompressor.destroy()
				resolve(Buffer.alloc(0))
				return
			}
			decompressor.end()
		})
		source.on('error', fail)
		source.on('aborted', () => {
			if (!settled) setImmediate(() => fail(new Error('Upstream response stream aborted')))
		})
		source.on('close', () => {
			if (!settled && !source.readableEnded) {
				setImmediate(() => fail(new Error('Upstream response stream closed prematurely')))
			}
		})
	})
}

function readStreamBytes (source, maxBytes) {
	return new Promise((resolve, reject) => {
		const chunks = []
		let totalBytes = 0
		let settled = false
		const fail = err => {
			if (settled) return
			settled = true
			source.destroy()
			reject(normalizeUpstreamError(err))
		}
		source.on('data', chunk => {
			if (settled) return
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
			totalBytes += buf.byteLength
			if (totalBytes > maxBytes) {
				fail(fileTooLargeError(totalBytes, maxBytes))
				return
			}
			chunks.push(buf)
		})
		source.on('end', () => {
			if (settled) return
			settled = true
			resolve(Buffer.concat(chunks))
		})
		source.on('error', fail)
		source.on('aborted', () => {
			if (!settled) setImmediate(() => fail(new Error('Upstream response stream aborted')))
		})
		source.on('close', () => {
			if (!settled && !source.readableEnded) {
				setImmediate(() => fail(new Error('Upstream response stream closed prematurely')))
			}
		})
	})
}

function sanitizeCallerHeaders (headers, extraStrip = null) {
	const clean = {}
	if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return clean
	for (const [k, v] of Object.entries(headers)) {
		if (v === undefined || v === null) continue
		const lower = k.toLowerCase()
		if (STRIPPED_REQUEST_HEADERS.has(lower) || extraStrip?.has(lower)) continue
		clean[lower] = Array.isArray(v) ? v.join(', ') : String(v)
	}
	return clean
}

function stripQueryAuth (parsed, queryEntries) {
	if (queryEntries.length === 0) return false
	const secretKeysLower = new Set(queryEntries.map(([k]) => k.toLowerCase()))
	let removed = false
	for (const existingKey of Array.from(parsed.searchParams.keys())) {
		if (secretKeysLower.has(existingKey.toLowerCase())) {
			parsed.searchParams.delete(existingKey)
			removed = true
		}
	}
	return removed
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
	if (!stripQueryAuth(parsed, queryEntries)) return rawLocation
	const trimmed = rawLocation.trim()
	if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmed)) return parsed.toString()
	if (trimmed.startsWith('//')) return `//${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`
	return `${parsed.pathname}${parsed.search}${parsed.hash}`
}

function attachAuth (hopUrl, baseHeaders, authHeaders, queryEntries) {
	const hopHeaders = { ...baseHeaders }
	for (const [k, v] of authHeaders) {
		hopHeaders[k] = v
	}
	if (queryEntries.length === 0) {
		return { url: hopUrl.toString(), headers: hopHeaders }
	}
	stripQueryAuth(hopUrl, queryEntries)
	for (const [k, v] of queryEntries) {
		hopUrl.searchParams.append(k, v)
	}
	return { url: hopUrl.toString(), headers: hopHeaders }
}

function sendUpstreamHop (targetUrl, { method, headers, body, bodyStream, timeoutMs }) {
	const parsed = new URL(targetUrl)
	if (!isAllowedUpstreamHost(parsed.hostname)) {
		const err = new Error(`Blocked unsafe upstream host: ${parsed.hostname}`)
		err.status = 403
		return Promise.reject(err)
	}
	const isHttps = parsed.protocol === 'https:'
	const transport = isHttps ? https : http
	const servername = isHttps && !parsed.hostname.startsWith('[') ? parsed.hostname : undefined
	return new Promise((resolve, reject) => {
		let settled = false
		const fail = err => {
			if (settled) return
			settled = true
			reject(normalizeUpstreamError(err))
		}
		const req = transport.request(parsed, {
			method,
			headers,
			lookup: lookupUpstreamHost,
			...(servername && { servername })
		}, res => {
			settled = true
			res.setTimeout(timeoutMs, () => res.destroy(timeoutError(timeoutMs)))
			resolve(res)
		})
		req.setTimeout(timeoutMs, () => req.destroy(timeoutError(timeoutMs)))
		req.on('upgrade', (_res, socket) => {
			socket.destroy()
			fail(new Error('Upstream protocol upgrade is not supported'))
		})
		req.on('connect', (_res, socket) => {
			socket.destroy()
			fail(new Error('Upstream CONNECT tunnel is not supported'))
		})
		req.on('error', fail)
		req.on('close', () => {
			if (!settled) fail(new Error('Upstream connection closed before response'))
		})
		if (bodyStream) {
			bodyStream.on('error', err => req.destroy(err))
			bodyStream.pipe(req)
			return
		}
		if (body !== undefined) req.write(body)
		req.end()
	})
}

async function executeBufferedUpstream ({ credentials, url, method, body, headers, timeoutMs, onStatus, onSameOriginRedirect }) {
	const baseHeaders = sanitizeCallerHeaders(headers)
	baseHeaders['user-agent'] ||= 'jump'
	baseHeaders['accept-encoding'] = SUPPORTED_ENCODINGS
	let curMethod = method
	const allowsBody = reqMethodAllowsBody(curMethod)
	let reqBody
	if (allowsBody && body !== undefined && body !== null) {
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
	let curUrl = url
	let curBody = reqBody
	let res
	for (let hop = 0; ; hop++) {
		const hopUrl = new URL(curUrl)
		const isInitialOrigin = hopUrl.origin === initialOrigin
		const hopReq = isInitialOrigin
			? attachAuth(hopUrl, baseHeaders, authHeaders, queryEntries)
			: { url: curUrl, headers: { ...baseHeaders } }
		if (curBody !== undefined) {
			hopReq.headers['content-length'] = String(curBody.byteLength)
		} else {
			delete hopReq.headers['content-length']
		}
		res = await sendUpstreamHop(hopReq.url, {
			method: curMethod,
			headers: hopReq.headers,
			body: curBody,
			timeoutMs
		})
		const location = REDIRECT_STATUSES.has(res.statusCode) ? res.headers.location : null
		if (!location) break
		res.destroy()
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
		if (res.statusCode === 303 || ((res.statusCode === 301 || res.statusCode === 302) && curMethod === 'POST')) {
			curMethod = 'GET'
			curBody = undefined
			delete baseHeaders['content-type']
		}
		if (queryEntries.length > 0) {
			stripQueryAuth(nextParsed, queryEntries)
		}
		curUrl = nextParsed.toString()
		if (nextParsed.origin === initialOrigin && onSameOriginRedirect) {
			onSameOriginRedirect({ url: curUrl, method: curMethod, hasBody: curBody !== undefined })
		}
	}
	const status = res.statusCode || 502
	if (onStatus) onStatus(status)
	const maxFileSizeMb = Number(process.env.MAX_FILE_SIZE_MB) || 10
	const maxFileSizeBytes = maxFileSizeMb * 1024 * 1024
	const contentLength = res.headers['content-length']
	if (contentLength && Number(contentLength) > maxFileSizeBytes) {
		res.destroy()
		throw fileTooLargeError(Number(contentLength), maxFileSizeBytes)
	}
	const rawContentType = res.headers['content-type'] || ''
	const skipBody = curMethod === 'HEAD' || BODILESS_STATUSES.has(status)
	const buf = skipBody ? (res.resume(), Buffer.alloc(0)) : await readResponseBody(res, maxFileSizeBytes)
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
	if (status < 200 || status >= 300) {
		const msg = result?.binary ? `Binary error response (${contentType})`
			: typeof result === 'object' ? JSON.stringify(result)
			: result
		const err = new Error(msg)
		err.status = status
		err.data = result
		throw err
	}
	return result
}

const PROXY_REQUEST_KEYS = ['provider', 'url', 'method', 'body', 'headers', 'app']
const REST_EXTRA_STRIPPED_HEADERS = new Set(['x-api-key'])

function countValues (items, getKey) {
	const counts = new Map()
	for (const item of items) {
		const k = getKey(item)
		if (k) counts.set(k, (counts.get(k) || 0) + 1)
	}
	return counts
}

function formatLinkedApps (providerLinks, provider) {
	const nameCounts = countValues(providerLinks, l => (l.app?.name || '').toLowerCase())
	const accCounts = countValues(providerLinks, l => (l.app?.credentials?.account || '').toLowerCase())
	const defaultName = provider.name.toLowerCase()
	return providerLinks.map(l => {
		const name = l.app?.name || ''
		const acc = l.app?.credentials?.account || ''
		const id = l.app?.id || ''
		const nameDup = nameCounts.get(name.toLowerCase()) > 1
		const accDup = accCounts.get(acc.toLowerCase()) > 1
		if (name && (name.toLowerCase() !== defaultName || accDup || (nameDup && !acc))) {
			if (!nameDup) return acc ? `${name} (${acc})` : name
			return acc && !accDup ? `${name} (${acc})` : `${name} (${acc ? `${acc}, ` : ''}${id})`
		}
		if (acc) return accDup ? `${acc} (${id})` : acc
		return name || id
	}).filter(Boolean)
}

function resolveTargetLink (providerLinks, rawApp, provider) {
	if (rawApp === undefined || rawApp === null) {
		if (providerLinks.length === 1) return providerLinks[0]
		const labels = formatLinkedApps(providerLinks, provider).join(', ')
		const err = new Error(`Multiple ${provider.name} apps linked to session (${labels}); specify app`)
		err.status = 400
		throw err
	}
	if (typeof rawApp !== 'string' || !rawApp.trim()) {
		const err = new Error('app must be a non-empty string')
		err.status = 400
		throw err
	}
	const trimmed = rawApp.trim()
	const lower = trimmed.toLowerCase()
	const byId = providerLinks.find(l => l.app?.id === trimmed)
	if (byId) return byId
	const byName = providerLinks.filter(l => (l.app?.name || '').toLowerCase() === lower)
	if (byName.length === 1) return byName[0]
	if (byName.length > 1) {
		const err = new Error(`Ambiguous app "${trimmed}" matches multiple linked ${provider.name} apps; specify a unique app name, account, or ID`)
		err.status = 400
		throw err
	}
	const byAccount = providerLinks.filter(l => (l.app?.credentials?.account || '').toLowerCase() === lower)
	if (byAccount.length === 1) return byAccount[0]
	if (byAccount.length > 1) {
		const err = new Error(`Ambiguous app "${trimmed}" matches multiple linked ${provider.name} apps; specify a unique app name or ID`)
		err.status = 400
		throw err
	}
	const err = new Error(`App not linked to session or not found: ${trimmed}`)
	err.status = 404
	throw err
}

function normalizeMethod (method) {
	const upper = String(method || 'GET').trim().toUpperCase()
	if (!ALLOWED_METHODS.has(upper)) {
		const err = new Error(`Unsupported HTTP method: ${upper}`)
		err.status = 400
		throw err
	}
	return upper
}

function resolveUpstreamContext (session, provider, rawApp, url, headers) {
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
	const targetLink = resolveTargetLink(providerLinks, rawApp, provider)
	let targetAppId = targetLink.app?.id || null
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
	const resolvedUrl = provider.normalizeTargetUrl(url, upstreamApp)
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
	const inspectsBody = hasBodyPolicy(sharePolicy) || hasBodyPolicy(targetLink.policy)
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
	return { targetLink, targetAppId, upstreamApp, resolvedUrl, contentType, inspectsBody, checkTargetPolicy }
}

async function resolveUpstreamCredentials (session, provider, targetLink, upstreamApp) {
	let resolvedCreds = null
	try {
		resolvedCreds = await provider.resolveCredentials(upstreamApp)
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
	if (!resolvedCreds?.headers && !resolvedCreds?.query) {
		const err = new Error('Missing upstream credentials')
		err.status = 401
		throw err
	}
	return resolvedCreds
}

async function request (opts = {}, auth) {
	const session = db.tokens.resolveSession(auth)
	if (!session) {
		const err = new Error('Authentication required')
		err.status = 401
		throw err
	}
	assertKeys(opts, PROXY_REQUEST_KEYS)
	const { provider: providerName = 'google', url, method = 'GET', body, headers, app } = opts
	if (!url) {
		const err = new Error('URL is required')
		err.status = 400
		throw err
	}
	const start = Date.now()
	const normalizedMethod = normalizeMethod(method)
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
		const ctx = resolveUpstreamContext(session, provider, app, url, headers)
		targetAppId = ctx.targetAppId
		resolvedUrl = ctx.resolvedUrl
		ctx.checkTargetPolicy(resolvedUrl, normalizedMethod, body, ctx.contentType)
		allowed = true
		const resolvedCreds = await resolveUpstreamCredentials(session, provider, ctx.targetLink, ctx.upstreamApp)
		const timeoutMs = Number(process.env.UPSTREAM_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS
		let upstreamStatus = 200
		const result = await executeBufferedUpstream({
			credentials: resolvedCreds,
			url: resolvedUrl,
			method: normalizedMethod,
			body,
			headers,
			timeoutMs,
			onStatus: s => { upstreamStatus = s },
			onSameOriginRedirect: ({ url: nextUrl, method: nextMethod, hasBody }) => {
				allowed = false
				resolvedUrl = nextUrl
				ctx.checkTargetPolicy(nextUrl, nextMethod, hasBody ? body : undefined, hasBody ? ctx.contentType : '')
				allowed = true
			}
		})
		recordLog(upstreamStatus, null)
		return result
	} catch (err) {
		recordLog(err.status || 502, err.message)
		throw err
	}
}

async function stream (opts = {}, auth, req, res) {
	const session = db.tokens.resolveSession(auth)
	if (!session) {
		const err = new Error('Authentication required')
		err.status = 401
		throw err
	}
	const { provider: providerName = 'google', url, app } = opts
	if (!url) {
		const err = new Error('URL is required')
		err.status = 400
		throw err
	}
	const start = Date.now()
	const normalizedMethod = normalizeMethod(req.method)
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
		const ctx = resolveUpstreamContext(session, provider, app, url, req.headers)
		targetAppId = ctx.targetAppId
		resolvedUrl = ctx.resolvedUrl
		const allowsBody = reqMethodAllowsBody(normalizedMethod)
		let bufferedBody = undefined
		let bodyStream = null
		if (allowsBody) {
			if (ctx.inspectsBody) {
				const rawBuf = await getRawBody(req)
				if (rawBuf.byteLength > 0) bufferedBody = rawBuf
			} else {
				bodyStream = req
			}
		}
		ctx.checkTargetPolicy(resolvedUrl, normalizedMethod, bufferedBody, ctx.contentType)
		allowed = true
		const resolvedCreds = await resolveUpstreamCredentials(session, provider, ctx.targetLink, ctx.upstreamApp)
		const baseHeaders = sanitizeCallerHeaders(req.headers, REST_EXTRA_STRIPPED_HEADERS)
		baseHeaders['user-agent'] ||= 'jump'
		if (allowsBody && !bodyStream) {
			if (bufferedBody !== undefined) {
				baseHeaders['content-length'] = String(bufferedBody.byteLength)
			}
		} else if (bodyStream && req.headers['content-length'] !== undefined) {
			baseHeaders['content-length'] = String(req.headers['content-length'])
		}
		const authHeaders = resolvedCreds?.headers && typeof resolvedCreds.headers === 'object'
			? Object.entries(resolvedCreds.headers).map(([k, v]) => [k.toLowerCase(), String(v)])
			: []
		const queryEntries = resolvedCreds?.query && typeof resolvedCreds.query === 'object'
			? Object.entries(resolvedCreds.query).map(([k, v]) => [k, String(v)])
			: []
		const hopReq = attachAuth(new URL(resolvedUrl), baseHeaders, authHeaders, queryEntries)
		const timeoutMs = Number(process.env.UPSTREAM_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS
		const upstreamRes = await sendUpstreamHop(hopReq.url, {
			method: normalizedMethod,
			headers: hopReq.headers,
			body: bufferedBody,
			bodyStream,
			timeoutMs
		})
		const status = upstreamRes.statusCode || 502
		const rawLocation = upstreamRes.headers.location
		let cleanedLocation = null
		if (rawLocation !== undefined) {
			try {
				cleanedLocation = stripLocationAuth(rawLocation, resolvedUrl, queryEntries)
			} catch (err) {
				upstreamRes.destroy()
				throw err
			}
		}
		res.statusCode = status
		const rawHeaders = upstreamRes.rawHeaders || []
		for (let i = 0; i < rawHeaders.length; i += 2) {
			const name = rawHeaders[i]
			const lower = name.toLowerCase()
			if (STRIPPED_RESPONSE_HEADERS.has(lower) || lower === 'location') continue
			res.appendHeader(name, rawHeaders[i + 1])
		}
		if (cleanedLocation !== null) {
			res.setHeader('location', cleanedLocation)
		}
		if (normalizedMethod === 'HEAD' || BODILESS_STATUSES.has(status)) {
			upstreamRes.resume()
			res.end()
			recordLog(status, status >= 400 ? `HTTP ${status}` : null)
			return
		}
		const errorChunks = []
		let errorBytes = 0
		if (status >= 400) {
			const tap = new PassThrough()
			tap.on('data', chunk => {
				if (errorBytes >= 512) return
				const slice = chunk.subarray(0, 512 - errorBytes)
				errorChunks.push(Buffer.from(slice))
				errorBytes += slice.byteLength
			})
			await pipeline(upstreamRes, tap, res)
			const errText = errorBytes > 0 ? Buffer.concat(errorChunks).toString('utf8') : `HTTP ${status}`
			recordLog(status, errText)
			return
		}
		await pipeline(upstreamRes, res)
		recordLog(status, null)
	} catch (err) {
		recordLog(err.status || 502, err.message)
		throw err
	}
}
