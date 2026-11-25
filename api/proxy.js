import { once } from 'node:events'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { Transform, Writable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import zlib from 'node:zlib'
import * as db from '../db/index.js'
import { getProvider } from '../providers/index.js'
import { evaluatePolicy, hasBodyPolicy } from '../policy.js'
import { HOP_BY_HOP_HEADERS, assertKeys, blockedHostError, getRawBody, getUserAgent, httpError, isAllowedUpstreamHost, isAllowedUpstreamProtocol, isJsonMime, lookupUpstreamHost, parseMimeType, positiveNumberEnv, serializeFormBody, streamAbortError, stripTrailingDot, validateBaseUrl } from '../util.js'

export {
	drainSilently,
	formatLinkedApps,
	request,
	stream,
	readResponseBody,
	sendUpstreamHop
}

function drainSilently (stream) {
	stream.on('error', () => {})
	stream.resume()
}

const DEFAULT_TIMEOUT_MS = 60000
const MAX_REDIRECT_HOPS = 5
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])
const BODILESS_STATUSES = new Set([204, 205, 304])
const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
const SUPPORTED_ENCODINGS = 'gzip, br, zstd'

const STRIPPED_REQUEST_HEADERS = new Set([
	...HOP_BY_HOP_HEADERS,
	'content-length',
	'host',
	'authorization',
	'proxy-authorization',
	'cookie'
])

const STRIPPED_RESPONSE_HEADERS = new Set([
	...HOP_BY_HOP_HEADERS,
	'set-cookie',
	'content-security-policy',
	'x-content-type-options',
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
	return httpError(413, `File too large: size (${sizeMb} MB) exceeds server limit of ${limitMb} MB. Consider exporting specific sheets, ranges, or text sections instead.`)
}

function timeoutError (timeoutMs) {
	return httpError(504, `Upstream request timed out after ${timeoutMs}ms of inactivity`)
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

function createDecompressTransform (encoding) {
	let decoder = null
	return new Transform({
		transform (chunk, _enc, cb) {
			if (chunk.byteLength === 0) {
				cb()
				return
			}
			if (!decoder) {
				decoder = createDecompressor(encoding)
				decoder.on('data', out => this.push(out))
				decoder.on('error', err => this.destroy(normalizeUpstreamError(err)))
			}
			if (!decoder.write(chunk)) {
				decoder.once('drain', cb)
			} else {
				cb()
			}
		},
		flush (cb) {
			if (!decoder) {
				cb()
				return
			}
			decoder.once('end', cb)
			decoder.end()
		},
		destroy (err, cb) {
			decoder?.destroy()
			cb(err)
		}
	})
}

async function readResponseBody (source, maxBytes) {
	if (!source) return Buffer.alloc(0)
	const rawEncoding = source.headers?.['content-encoding']
	const codings = (Array.isArray(rawEncoding) ? rawEncoding.join(',') : typeof rawEncoding === 'string' ? rawEncoding : '')
		.split(',')
		.map(s => s.trim().toLowerCase())
		.filter(s => s && s !== 'identity')
	for (const coding of codings) {
		if (!createDecompressor(coding)) {
			source.destroy()
			throw httpError(502, `Unsupported upstream Content-Encoding: ${coding}`)
		}
	}
	const chunks = []
	let totalBytes = 0
	const collector = new Writable({
		write (chunk, _enc, cb) {
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
			totalBytes += buf.byteLength
			if (totalBytes > maxBytes) {
				cb(fileTooLargeError(totalBytes, maxBytes))
				return
			}
			chunks.push(buf)
			cb()
		}
	})
	try {
		await pipeline(source, ...codings.reverse().map(c => createDecompressTransform(c)), collector)
	} catch (err) {
		throw normalizeUpstreamError(err)
	}
	return Buffer.concat(chunks)
}

function sanitizeCallerHeaders (headers, extraStrip = null) {
	const clean = Object.create(null)
	if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return clean
	for (const [k, v] of Object.entries(headers)) {
		if (v === undefined || v === null) continue
		const lower = k.toLowerCase()
		if (STRIPPED_REQUEST_HEADERS.has(lower) || extraStrip?.has(lower)) continue
		const val = Array.isArray(v) ? v.join(', ') : String(v)
		try {
			http.validateHeaderName(lower)
			http.validateHeaderValue(lower, val)
		} catch (err) {
			err.status = 400
			throw err
		}
		clean[lower] = val
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
		throw httpError(502, 'Invalid upstream redirect Location')
	}
	if (!stripQueryAuth(parsed, queryEntries)) return rawLocation
	const trimmed = rawLocation.trim()
	if (/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(trimmed)) return parsed.toString()
	if (trimmed.startsWith('//')) return `//${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`
	return `${parsed.pathname}${parsed.search}${parsed.hash}`
}

function toAuthEntries (credentials) {
	const authHeaders = credentials?.headers && typeof credentials.headers === 'object'
		? Object.entries(credentials.headers).map(([k, v]) => [k.toLowerCase(), String(v)])
		: []
	const queryEntries = credentials?.query && typeof credentials.query === 'object'
		? Object.entries(credentials.query).map(([k, v]) => [k, String(v)])
		: []
	return { authHeaders, queryEntries }
}

function attachAuth (hopUrl, baseHeaders, authHeaders, queryEntries) {
	const hopHeaders = Object.assign(Object.create(null), baseHeaders)
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

function escapeRegex (str) {
	return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function redactCredentialText (text, credentials) {
	if (typeof text !== 'string' || !text || !credentials) return text
	let scrubbed = text
	const { authHeaders, queryEntries } = toAuthEntries(credentials)
	const literalSecrets = new Set()
	for (const [k, v] of queryEntries) {
		for (const keyForm of new Set([k, encodeURIComponent(k)])) {
			if (!keyForm) continue
			scrubbed = scrubbed.replace(new RegExp(`([?&]${escapeRegex(keyForm)}=)[^&\\s"'<>\\\\)]+`, 'g'), '$1[REDACTED]')
		}
		if (v.length >= 6) {
			literalSecrets.add(v)
			literalSecrets.add(encodeURIComponent(v))
			const formVal = new URLSearchParams([[k, v]]).toString().split('=')[1]
			if (formVal && formVal.length >= 6) literalSecrets.add(formVal)
		}
	}
	for (const [, v] of authHeaders) {
		if (v.length >= 6) literalSecrets.add(v)
		const stripped = v.replace(/^(?:Bearer|Basic)\s+/i, '')
		if (stripped.length >= 6) literalSecrets.add(stripped)
	}
	for (const secret of Array.from(literalSecrets).sort((a, b) => b.length - a.length)) {
		scrubbed = scrubbed.replaceAll(secret, '[REDACTED]')
	}
	return scrubbed
}

function isFormContentType (contentType) {
	return parseMimeType(contentType) === 'application/x-www-form-urlencoded'
}

function sendUpstreamHop (targetUrl, { method, headers, body, bodyStream, timeoutMs }) {
	const abortErr = streamAbortError(bodyStream, 'Client upload aborted')
	if (abortErr) return Promise.reject(abortErr)
	const parsed = new URL(targetUrl)
	if (!isAllowedUpstreamProtocol(parsed)) {
		return Promise.reject(httpError(400, `Unsupported upstream protocol: ${parsed.protocol}`))
	}
	if (!isAllowedUpstreamHost(parsed.hostname)) {
		return Promise.reject(blockedHostError(parsed.hostname))
	}
	const isHttps = parsed.protocol === 'https:'
	const transport = isHttps ? https : http
	const cleanHost = stripTrailingDot(parsed.hostname)
	const servername = isHttps && cleanHost && !net.isIP(cleanHost) ? cleanHost : undefined
	return new Promise((resolve, reject) => {
		let settled = false
		const fail = err => {
			if (settled) return
			settled = true
			reject(normalizeUpstreamError(err))
		}
		let req
		try {
			req = transport.request(parsed, {
				method,
				headers,
				lookup: lookupUpstreamHost,
				...(servername && { servername })
			}, res => {
				settled = true
				req.setTimeout(0)
				res.setTimeout(timeoutMs, () => res.destroy(timeoutError(timeoutMs)))
				resolve(res)
			})
		} catch (err) {
			fail(err)
			return
		}
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
			const onStreamErr = err => {
				if (err && typeof err === 'object' && !err.status) err.status = 400
				req.destroy(err)
			}
			const onStreamClose = () => {
				if (!bodyStream.readableEnded) {
					req.destroy(httpError(400, 'Client upload aborted'))
				}
			}
			bodyStream.on('error', onStreamErr)
			bodyStream.on('close', onStreamClose)
			req.on('close', () => {
				bodyStream.off('error', onStreamErr)
				bodyStream.off('close', onStreamClose)
				bodyStream.unpipe(req)
				if (!bodyStream.readableEnded) bodyStream.pause()
			})
			bodyStream.pipe(req)
			return
		}
		if (body !== undefined) req.write(body)
		req.end()
	})
}

async function executeBufferedUpstream ({ credentials, url, method, body, baseHeaders, timeoutMs, onStatus, onSameOriginRedirect }) {
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
			if (isFormContentType(baseHeaders['content-type'])) {
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
	const { authHeaders, queryEntries } = toAuthEntries(credentials)
	let authOrigin = new URL(url).origin
	let curUrl = url
	let curBody = reqBody
	let res
	for (let hop = 0; ; hop++) {
		const hopUrl = new URL(curUrl)
		const hopReq = hopUrl.origin === authOrigin
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
			throw httpError(502, `Too many upstream redirects (exceeded ${MAX_REDIRECT_HOPS})`)
		}
		let nextParsed
		try {
			nextParsed = new URL(location, curUrl)
		} catch {
			throw httpError(502, 'Invalid upstream redirect Location')
		}
		if (nextParsed.username || nextParsed.password || !validateBaseUrl(nextParsed.origin)) {
			throw httpError(403, `Blocked unsafe upstream redirect target: ${nextParsed.origin}`)
		}
		if ((res.statusCode === 303 && curMethod !== 'HEAD') || ((res.statusCode === 301 || res.statusCode === 302) && curMethod === 'POST')) {
			curMethod = 'GET'
			curBody = undefined
			delete baseHeaders['content-type']
		}
		if (queryEntries.length > 0) {
			stripQueryAuth(nextParsed, queryEntries)
		}
		curUrl = nextParsed.toString()
		if (nextParsed.origin !== authOrigin) {
			authOrigin = null
		} else if (onSameOriginRedirect) {
			onSameOriginRedirect({ url: curUrl, method: curMethod, hasBody: curBody !== undefined })
		}
	}
	const status = res.statusCode || 502
	if (onStatus) onStatus(status)
	const maxFileSizeMb = positiveNumberEnv('MAX_FILE_SIZE_MB', 10)
	const maxFileSizeBytes = maxFileSizeMb * 1024 * 1024
	const contentLength = res.headers['content-length']
	const skipBody = curMethod === 'HEAD' || BODILESS_STATUSES.has(status)
	if (!skipBody && contentLength && Number(contentLength) > maxFileSizeBytes) {
		res.destroy()
		throw fileTooLargeError(Number(contentLength), maxFileSizeBytes)
	}
	const rawContentType = res.headers['content-type'] || ''
	const buf = skipBody ? (drainSilently(res), Buffer.alloc(0)) : await readResponseBody(res, maxFileSizeBytes)
	const contentType = parseMimeType(rawContentType)
	const charsetMatch = rawContentType.match(/charset=([^;]+)/i)
	const charset = charsetMatch ? charsetMatch[1].trim().replace(/^["']|["']$/g, '') : undefined
	let result
	if (isJsonMime(contentType)) {
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
		throw httpError(status, redactCredentialText(msg, credentials), { upstream: true })
	}
	return result
}

const PROXY_REQUEST_KEYS = ['provider', 'url', 'method', 'body', 'headers', 'app']
const REST_EXTRA_STRIPPED_HEADERS = new Set(['x-api-key', 'x-upstream-app'])

function formatLinkedApps (providerLinks, provider, { includeBaseUrl = false } = {}) {
	return providerLinks.map(l => {
		const name = l.app?.name || ''
		const acc = l.app?.credentials?.account || ''
		const id = l.app?.id || ''
		const label = name && acc ? `${name} (${acc})` : (name || acc || id)
		if (!label) return ''
		const meta = []
		if (id && label !== id) meta.push(`id=${id}`)
		const base = includeBaseUrl ? (l.app?.credentials?.baseUrl || provider.baseUrl) : null
		if (base) meta.push(base)
		return meta.length > 0 ? `${label} [${meta.join(', ')}]` : label
	}).filter(Boolean)
}

function resolveTargetLink (providerLinks, rawApp, provider) {
	if (rawApp === undefined || rawApp === null) {
		if (providerLinks.length === 1) return providerLinks[0]
		const labels = formatLinkedApps(providerLinks, provider).join(', ')
		throw httpError(400, `Multiple ${provider.name} apps linked to session (${labels}); specify app`)
	}
	if (typeof rawApp !== 'string' || !rawApp.trim()) {
		throw httpError(400, 'app must be a non-empty string')
	}
	const id = rawApp.trim()
	const target = providerLinks.find(l => l.app?.id === id)
	if (!target) {
		throw httpError(404, `App not linked to session or not found: ${id}`)
	}
	return target
}

function normalizeMethod (method) {
	const upper = String(method || 'GET').trim().toUpperCase()
	if (!ALLOWED_METHODS.has(upper)) {
		throw httpError(400, `Unsupported HTTP method: ${upper}`)
	}
	return upper
}

function resolveUpstreamContext (session, provider, rawApp, url, baseHeaders) {
	const links = db.links.listBySessionId(session.id)
	const providerLinks = links.filter(l => l.app?.provider === provider.id)
	if (providerLinks.length === 0) {
		const hint = session.admin
			? 'Use connect_app or link_app to attach one.'
			: 'Ask an admin to link one.'
		throw httpError(403, `No ${provider.name} app linked to session. ${hint}`)
	}
	const targetLink = resolveTargetLink(providerLinks, rawApp, provider)
	let targetAppId = targetLink.app?.id || null
	let upstreamApp = targetLink.app
	if (upstreamApp?.type === 'share') {
		targetAppId = upstreamApp.credentials?.appId || null
		upstreamApp = db.tokens.get(targetAppId)
		if (!db.tokens.isUpstreamApp(upstreamApp)) {
			throw httpError(404, `Shared upstream app not found: ${targetLink.app.id}`)
		}
	}
	const resolvedUrl = provider.normalizeTargetUrl(url, upstreamApp)
	const contentType = baseHeaders['content-type'] || ''
	const objectFormat = isFormContentType(contentType) ? 'form' : 'json'
	const sharePolicy = targetLink.app?.type === 'share' ? targetLink.app.credentials?.policy : null
	const inspectsBody = hasBodyPolicy(sharePolicy) || hasBodyPolicy(targetLink.policy)
	const policies = [
		[sharePolicy, 'Operation not permitted by shared app policy'],
		[targetLink.policy, 'Operation not permitted by session policy']
	]
	const checkTargetPolicy = (targetUrl, targetMethod, targetBody, targetContentType) => {
		const urlCheck = provider.isAllowedUrl(targetUrl, upstreamApp)
		if (!urlCheck.allowed) {
			throw httpError(403, urlCheck.reason)
		}
		for (const [policy, fallbackMsg] of policies) {
			if (!policy) continue
			const check = evaluatePolicy(policy, {
				url: targetUrl,
				method: targetMethod,
				body: targetBody,
				objectFormat,
				contentType: targetContentType
			})
			if (!check.allowed) {
				throw httpError(403, `Policy violation: ${check.reason || fallbackMsg}`)
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
		if (err.status !== 400 && err.status !== 401) {
			throw err
		}
		const hint = targetLink.app?.type === 'share'
			? `Ask the app owner (${targetLink.app.sharedBy || 'admin'}) to re-authenticate.`
			: session.admin
				? `Use connect_app with appId "${upstreamApp.id}" to re-authenticate.`
				: 'Ask an admin to re-authenticate.'
		throw httpError(401, `Failed to refresh ${provider.name} access token: ${err.message}. ${hint}`)
	}
	if (!resolvedCreds?.headers && !resolvedCreds?.query) {
		throw httpError(401, 'Missing upstream credentials')
	}
	return resolvedCreds
}

async function runProxyCall ({ auth, providerName = 'google', url, method, app, headers, extraStrip = null }, fn) {
	const session = db.tokens.resolveSession(auth)
	if (!session) {
		throw httpError(401, 'Authentication required')
	}
	if (!url) {
		throw httpError(400, 'URL is required')
	}
	const start = Date.now()
	const normalizedMethod = normalizeMethod(method)
	const baseHeaders = sanitizeCallerHeaders(headers, extraStrip)
	baseHeaders['user-agent'] ||= getUserAgent()
	const provider = getProvider(providerName)
	const timeoutMs = positiveNumberEnv('UPSTREAM_TIMEOUT_MS', DEFAULT_TIMEOUT_MS)
	const logState = {
		targetAppId: null,
		resolvedUrl: String(url),
		allowed: false,
		credentials: null
	}
	const recordLog = (status, error = null) => {
		const safeError = typeof error === 'string' ? redactCredentialText(error, logState.credentials) : error
		db.logs.create({
			userId: session.userId,
			sessionId: session.id,
			appId: logState.targetAppId,
			provider: provider.id,
			method: normalizedMethod,
			url: logState.resolvedUrl,
			allowed: logState.allowed,
			status,
			duration: Date.now() - start,
			error: safeError
		})
	}
	try {
		const ctx = resolveUpstreamContext(session, provider, app, url, baseHeaders)
		logState.targetAppId = ctx.targetAppId
		logState.resolvedUrl = ctx.resolvedUrl
		return await fn({ session, provider, normalizedMethod, baseHeaders, timeoutMs, ctx, logState, recordLog })
	} catch (err) {
		recordLog(err.status || 502, err.message)
		throw err
	}
}

async function request (opts = {}, auth) {
	assertKeys(opts, PROXY_REQUEST_KEYS)
	const { provider: providerName = 'google', url, method = 'GET', body, headers, app } = opts
	return runProxyCall({ auth, providerName, url, method, app, headers }, async ({ session, provider, normalizedMethod, baseHeaders, timeoutMs, ctx, logState, recordLog }) => {
		ctx.checkTargetPolicy(ctx.resolvedUrl, normalizedMethod, body, ctx.contentType)
		logState.allowed = true
		const credentials = await resolveUpstreamCredentials(session, provider, ctx.targetLink, ctx.upstreamApp)
		logState.credentials = credentials
		let upstreamStatus = 200
		const result = await executeBufferedUpstream({
			credentials,
			url: ctx.resolvedUrl,
			method: normalizedMethod,
			body,
			baseHeaders,
			timeoutMs,
			onStatus: s => { upstreamStatus = s },
			onSameOriginRedirect: ({ url: nextUrl, method: nextMethod, hasBody }) => {
				logState.allowed = false
				logState.resolvedUrl = nextUrl
				ctx.checkTargetPolicy(nextUrl, nextMethod, hasBody ? body : undefined, hasBody ? ctx.contentType : '')
				logState.allowed = true
			}
		})
		recordLog(upstreamStatus, null)
		return result
	})
}

async function stream (opts = {}, auth, req, res) {
	const { provider: providerName = 'google', url, app } = opts
	return runProxyCall({ auth, providerName, url, method: req.method, app, headers: req.headers, extraStrip: REST_EXTRA_STRIPPED_HEADERS }, async ({ session, provider, normalizedMethod, baseHeaders, timeoutMs, ctx, logState, recordLog }) => {
		const allowsBody = reqMethodAllowsBody(normalizedMethod)
		let bufferedBody = undefined
		let bodyStream = null
		if (allowsBody) {
			if (ctx.inspectsBody) {
				if (String(req.headers['content-encoding'] || '').trim()) {
					throw httpError(415, 'Content-Encoding is not supported when a policy inspects the request body')
				}
				const rawBuf = await getRawBody(req)
				if (rawBuf.byteLength > 0) bufferedBody = rawBuf
			} else {
				bodyStream = req
			}
		}
		ctx.checkTargetPolicy(ctx.resolvedUrl, normalizedMethod, bufferedBody, ctx.contentType)
		logState.allowed = true
		const credentials = await resolveUpstreamCredentials(session, provider, ctx.targetLink, ctx.upstreamApp)
		logState.credentials = credentials
		if (allowsBody && !bodyStream) {
			if (bufferedBody !== undefined) {
				baseHeaders['content-length'] = String(bufferedBody.byteLength)
			}
		} else if (bodyStream && req.headers['content-length'] !== undefined) {
			baseHeaders['content-length'] = String(req.headers['content-length'])
		}
		const { authHeaders, queryEntries } = toAuthEntries(credentials)
		const hopReq = attachAuth(new URL(ctx.resolvedUrl), baseHeaders, authHeaders, queryEntries)
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
				cleanedLocation = stripLocationAuth(rawLocation, ctx.resolvedUrl, queryEntries)
			} catch (err) {
				upstreamRes.destroy()
				throw err
			}
		}
		const incompleteUpload = Boolean(bodyStream && !bodyStream.readableEnded)
		if (incompleteUpload) {
			bodyStream.unpipe(upstreamRes.req)
			bodyStream.pause()
		}
		let headersCommitted = false
		const commitHeaders = () => {
			if (headersCommitted) return
			headersCommitted = true
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
			if (incompleteUpload) {
				res.setHeader('connection', 'close')
			}
			res.setHeader('content-security-policy', 'sandbox')
		}
		const errorChunks = []
		let errorBytes = 0
		const drainAbort = new AbortController()
		const onResClose = () => {
			if (!upstreamRes.readableEnded) upstreamRes.destroy()
			drainAbort.abort()
		}
		res.once('close', onResClose)
		try {
			if (normalizedMethod === 'HEAD' || BODILESS_STATUSES.has(status)) {
				commitHeaders()
				drainSilently(upstreamRes)
				res.end()
				recordLog(status, status >= 400 ? `HTTP ${status}` : null)
				return
			}
			for await (const chunk of upstreamRes) {
				if (chunk.byteLength === 0) continue
				if (drainAbort.signal.aborted) break
				commitHeaders()
				if (status >= 400 && errorBytes < 512) {
					const slice = chunk.subarray(0, 512 - errorBytes)
					errorChunks.push(Buffer.from(slice))
					errorBytes += slice.byteLength
				}
				if (!res.write(chunk)) {
					await once(res, 'drain', { signal: drainAbort.signal })
				}
			}
			if (drainAbort.signal.aborted) {
				throw new Error('Downstream client disconnected')
			}
			commitHeaders()
			res.end()
		} catch (err) {
			if (drainAbort.signal.aborted) {
				res.destroy()
				recordLog(status, 'Downstream client disconnected')
				return
			}
			normalizeUpstreamError(err)
			if (!res.headersSent) throw err
			res.destroy(err)
			recordLog(status, err.message)
			return
		} finally {
			res.off('close', onResClose)
			if (incompleteUpload && upstreamRes.req && !upstreamRes.req.writableFinished) {
				upstreamRes.req.destroy()
			}
		}
		const errText = status >= 400
			? (errorBytes > 0 ? Buffer.concat(errorChunks).toString('utf8') : `HTTP ${status}`)
			: null
		recordLog(status, errText)
	})
}
