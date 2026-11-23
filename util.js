import dns from 'node:dns'
import fs from 'node:fs'
import net from 'node:net'

export {
	HOP_BY_HOP_HEADERS,
	getRawBody,
	getBody,
	parseAppUrl,
	positiveNumberEnv,
	getBaseUrl,
	getClientIp,
	serializeFormBody,
	sendJson,
	sendText,
	sendHtml,
	redirect,
	isLoopbackHost,
	isAllowedUpstreamHost,
	isAllowedUpstreamProtocol,
	blockedHostError,
	stripTrailingDot,
	lookupUpstreamHost,
	validateBaseUrl,
	hasUrlScheme,
	resolveTargetUrl,
	hasPathTraversal,
	parseAccountSpec,
	isPlainObject,
	httpError,
	assertKeys,
	tightenFileMode,
	requireBoolean
}

const HOP_BY_HOP_HEADERS = [
	'connection',
	'keep-alive',
	'transfer-encoding',
	'te',
	'trailer',
	'upgrade'
]

function serializeFormBody (body) {
	const params = new URLSearchParams()
	for (const [k, v] of Object.entries(body)) {
		if (v === undefined || v === null) continue
		if (Array.isArray(v)) {
			for (const item of v) {
				if (item !== undefined && item !== null) {
					params.append(k, typeof item === 'object' ? JSON.stringify(item) : String(item))
				}
			}
		} else {
			params.append(k, typeof v === 'object' ? JSON.stringify(v) : String(v))
		}
	}
	return params.toString()
}

function isPlainObject (val) {
	if (!val || typeof val !== 'object' || Array.isArray(val) || ArrayBuffer.isView(val)) return false
	const proto = Object.getPrototypeOf(val)
	return proto === Object.prototype || proto === null
}

function httpError (status, message, props) {
	return Object.assign(new Error(message), { status, ...props })
}

function assertKeys (opts, allowed) {
	if (opts === undefined || opts === null) return
	if (!isPlainObject(opts)) {
		throw httpError(400, 'Options must be a JSON object')
	}
	for (const key of Object.keys(opts)) {
		if (opts[key] !== undefined && !allowed.includes(key)) {
			throw httpError(400, `Unknown parameter "${key}"`)
		}
	}
}

function tightenFileMode (filePath) {
	if (fs.existsSync(filePath) && (fs.statSync(filePath).mode & 0o077) !== 0) {
		fs.chmodSync(filePath, 0o600)
	}
}

function requireBoolean (val, name, defaultValue = undefined) {
	if (val === undefined) return defaultValue
	if (typeof val === 'boolean') return val
	if (val === 1) return true
	if (val === 0) return false
	if (typeof val === 'string') {
		const lower = val.trim().toLowerCase()
		if (lower === 'true' || lower === '1') return true
		if (lower === 'false' || lower === '0') return false
	}
	throw httpError(400, `${name} must be a boolean`)
}

function parseAccountSpec (rawAccount, rawProvider = null) {
	const hasAccount = rawAccount !== undefined && rawAccount !== null && String(rawAccount).trim() !== ''
	const hasProvider = rawProvider !== undefined && rawProvider !== null && String(rawProvider).trim() !== ''
	let cleanProvider = hasProvider ? String(rawProvider).trim().toLowerCase() : null
	if (cleanProvider && cleanProvider.includes(':')) {
		throw httpError(400, `Invalid provider identifier: ${rawProvider}`)
	}
	if (!hasAccount) {
		return { account: null, provider: cleanProvider }
	}
	if (typeof rawAccount !== 'string') {
		throw httpError(400, 'Account identifier must be a string')
	}
	const trimmed = rawAccount.trim().toLowerCase()
	if (!trimmed.includes(':')) {
		return { account: trimmed, provider: cleanProvider }
	}
	const parts = trimmed.split(':')
	if (parts.length !== 2 || !parts[0].trim() || !parts[1].trim() || /\s/.test(parts[0]) || /\s/.test(parts[1])) {
		throw httpError(400, `Malformed account identifier "${rawAccount}"; expected "provider:account"`)
	}
	const prefixProvider = parts[0]
	const cleanAccount = parts[1]
	if (cleanProvider && cleanProvider !== prefixProvider) {
		throw httpError(400, `Conflicting provider "${cleanProvider}" and account prefix "${prefixProvider}:${cleanAccount}"`)
	}
	return { account: cleanAccount, provider: prefixProvider }
}

function sendJson (res, data, status = 200, headers = null) {
	res.statusCode = status
	if (headers) {
		for (const [k, v] of Object.entries(headers)) {
			res.setHeader(k, v)
		}
	}
	res.setHeader('content-type', 'application/json; charset=utf-8')
	res.end(typeof data === 'string' ? data : JSON.stringify(data, null, '\t'))
}

function sendText (res, text, status = 200) {
	res.statusCode = status
	res.setHeader('content-type', 'text/plain; charset=utf-8')
	res.end(text)
}

function sendHtml (res, html, status = 200) {
	res.statusCode = status
	res.setHeader('content-type', 'text/html; charset=utf-8')
	res.setHeader('cache-control', 'no-store')
	res.setHeader('content-security-policy', "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
	res.setHeader('referrer-policy', 'same-origin')
	res.setHeader('x-frame-options', 'DENY')
	res.end(html)
}

function redirect (res, location, status = 302) {
	res.statusCode = status
	res.setHeader('location', location)
	res.end()
}

function parseAppUrl (raw) {
	const trimmed = typeof raw === 'string' ? raw.trim().replace(/\/+$/, '') : ''
	if (!trimmed) return ''
	let parsed
	try {
		parsed = new URL(trimmed)
	} catch {
		throw new Error(`Invalid APP_URL: ${raw}`)
	}
	if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || parsed.port === '0' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.hostname.endsWith('.')) {
		throw new Error(`Invalid APP_URL: ${raw}`)
	}
	return parsed.origin
}

if (process.env.APP_URL !== undefined) {
	process.env.APP_URL = parseAppUrl(process.env.APP_URL)
}

function positiveNumberEnv (name, fallback) {
	const raw = process.env[name]
	if (raw === undefined || String(raw).trim() === '') return fallback
	const n = Number(raw)
	if (!Number.isFinite(n) || n <= 0) {
		throw new Error(`Invalid ${name}: ${raw}`)
	}
	return n
}

function isTrustedProxy (req) {
	const addr = req?.socket?.remoteAddress
	if (!addr) return false
	const clean = addr.toLowerCase().startsWith('::ffff:') ? addr.slice(7) : addr
	return isLoopbackHost(clean)
}

function parseHostOrigin (rawHost, rawProtoHeader) {
	const host = String(rawHost || '').split(',')[0].trim().toLowerCase()
	if (!host) return null
	try {
		const parsed = new URL(`http://${host}`)
		const isLocal = isLoopbackHost(parsed.hostname) || (!parsed.hostname.includes('.') && !parsed.hostname.startsWith('['))
		const proto = String(rawProtoHeader || (isLocal ? 'http' : 'https')).split(',')[0].trim().toLowerCase()
		const validHost = parsed.host === host || (!parsed.port && host === `${parsed.hostname}:80`)
		if ((proto !== 'http' && proto !== 'https') || parsed.port === '0' || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.hostname.endsWith('.') || !validHost) {
			return null
		}
		const port = parsed.port || (host === `${parsed.hostname}:80` ? '80' : '')
		const effectivePort = (proto === 'https' && port === '443') || (proto === 'http' && port === '80') ? '' : port
		return {
			origin: `${proto}://${parsed.hostname}${effectivePort ? `:${effectivePort}` : ''}`,
			isLocal
		}
	} catch {
		return null
	}
}

function getBaseUrl (req) {
	if (process.env.APP_URL) return process.env.APP_URL
	if (!req?.headers) return 'http://localhost:8080'
	const trustForwarded = isTrustedProxy(req)
	const protoHeader = trustForwarded ? req.headers['x-forwarded-proto'] : undefined
	const direct = req.headers.host ? parseHostOrigin(req.headers.host, protoHeader) : null
	if (direct && !direct.isLocal) return direct.origin
	if (trustForwarded && req.headers['x-forwarded-host']) {
		const forwarded = parseHostOrigin(req.headers['x-forwarded-host'], protoHeader)
		return forwarded ? forwarded.origin : 'http://localhost:8080'
	}
	return direct ? direct.origin : 'http://localhost:8080'
}

function getClientIp (req) {
	if (isTrustedProxy(req) && req?.headers?.['x-forwarded-for']) {
		const raw = req.headers['x-forwarded-for']
		const parts = (Array.isArray(raw) ? raw.join(',') : String(raw)).split(',')
		for (let i = parts.length - 1; i >= 0; i--) {
			const ip = parts[i].trim()
			if (net.isIP(ip)) return ip
		}
	}
	return req?.socket?.remoteAddress || null
}

const LOOPBACK_IPV4 = new net.BlockList()
LOOPBACK_IPV4.addSubnet('127.0.0.0', 8, 'ipv4')

const GLOBAL_UNICAST_IPV6 = new net.BlockList()
GLOBAL_UNICAST_IPV6.addSubnet('2000::', 3, 'ipv6')

const BLOCKED_IPS = new net.BlockList()
for (const [addr, prefix] of [
	['0.0.0.0', 8],
	['10.0.0.0', 8],
	['100.64.0.0', 10],
	['127.0.0.0', 8],
	['169.254.0.0', 16],
	['172.16.0.0', 12],
	['192.0.0.0', 24],
	['192.0.2.0', 24],
	['192.88.99.0', 24],
	['192.168.0.0', 16],
	['198.18.0.0', 15],
	['198.51.100.0', 24],
	['203.0.113.0', 24],
	['224.0.0.0', 4],
	['240.0.0.0', 4]
]) {
	BLOCKED_IPS.addSubnet(addr, prefix, 'ipv4')
}
for (const [addr, prefix] of [
	['2001::', 23],
	['2001:db8::', 32],
	['2002::', 16],
	['3fff::', 20]
]) {
	BLOCKED_IPS.addSubnet(addr, prefix, 'ipv6')
}

function isPublicIp (ip) {
	const family = net.isIP(ip)
	if (family === 4) return !BLOCKED_IPS.check(ip, 'ipv4')
	if (family === 6) return GLOBAL_UNICAST_IPV6.check(ip, 'ipv6') && !BLOCKED_IPS.check(ip, 'ipv6')
	return false
}

function stripTrailingDot (hostname) {
	return hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '')
}

function isLoopbackHost (hostname) {
	if (!hostname || typeof hostname !== 'string') return false
	const host = stripTrailingDot(hostname)
	if (host === 'localhost' || host.endsWith('.localhost') || host === '::1') return true
	return net.isIP(host) === 4 && LOOPBACK_IPV4.check(host, 'ipv4')
}

function isAllowedUpstreamHost (hostname) {
	if (!hostname || typeof hostname !== 'string') return false
	const raw = hostname.toLowerCase().replace(/^\[|\]$/g, '')
	const ipFamily = net.isIP(raw)
	if (ipFamily) return isPublicIp(raw)
	if (raw.startsWith('.') || raw.includes('..') || isLoopbackHost(hostname)) return false
	const host = stripTrailingDot(hostname)
	if (!host || host === 'metadata.google.internal') return false
	return true
}

function blockedHostError (hostname) {
	return httpError(403, `Blocked unsafe upstream host: ${hostname}`)
}

function deliverLookup (records, all, cb) {
	if (all) {
		cb(null, records)
		return
	}
	cb(null, records[0].address, records[0].family)
}

async function resolveDnsRecords (hostname, host, options) {
	let records
	try {
		records = await dns.promises.lookup(host, {
			family: options.family,
			hints: options.hints,
			all: true
		})
	} catch (err) {
		err.status ||= 502
		throw err
	}
	if (!Array.isArray(records) || records.length === 0) {
		throw httpError(502, `Unable to resolve upstream host: ${hostname}`)
	}
	for (const { address } of records) {
		if (!isPublicIp(address)) {
			throw blockedHostError(hostname)
		}
	}
	return records
}

async function resolveAndDeliver (hostname, host, options, wantAll, callback) {
	let records
	try {
		records = await resolveDnsRecords(hostname, host, options)
	} catch (err) {
		callback(err)
		return
	}
	deliverLookup(records, wantAll, callback)
}

function lookupUpstreamHost (hostname, opts, cb) {
	const callback = typeof opts === 'function' ? opts : cb
	const options = typeof opts === 'object' && opts !== null ? opts : {}
	const wantAll = Boolean(options.all)
	if (!isAllowedUpstreamHost(hostname)) {
		queueMicrotask(() => callback(blockedHostError(hostname)))
		return
	}
	const host = stripTrailingDot(hostname)
	const ipFamily = net.isIP(host)
	if (ipFamily) {
		queueMicrotask(() => deliverLookup([{ address: host, family: ipFamily }], wantAll, callback))
		return
	}
	resolveAndDeliver(hostname, host, options, wantAll, callback)
}

function isAllowedUpstreamProtocol (parsed) {
	return parsed?.protocol === 'https:'
}

function validateBaseUrl (baseUrl) {
	if (!baseUrl || typeof baseUrl !== 'string') return null
	let parsed
	try {
		parsed = new URL(baseUrl.trim())
	} catch {
		return null
	}
	if (parsed.username || parsed.password || !isAllowedUpstreamHost(parsed.hostname) || !isAllowedUpstreamProtocol(parsed)) {
		return null
	}
	const pathname = parsed.pathname.replace(/\/+$/, '')
	return `${parsed.origin}${pathname}`
}

function hasUrlScheme (str) {
	return typeof str === 'string' && /^(?:https?:\/|[a-z][a-z\d+.-]*:\/\/)/i.test(str)
}

function resolveTargetUrl (targetUrl, baseUrl = null) {
	if (!targetUrl || typeof targetUrl !== 'string') return ''
	let clean = targetUrl.trim()
	if (!clean) return ''
	if (/^https:\/[^/]/i.test(clean)) {
		clean = clean.replace(/^https:\/+/i, 'https://')
	}
	if (hasUrlScheme(clean)) {
		return clean
	}
	if (!baseUrl) return clean
	const noLeadingSlash = clean.replace(/^\/+/, '')
	const cleanBase = baseUrl.replace(/\/+$/, '')
	return `${cleanBase}/${noLeadingSlash}`
}

function hasPathTraversal (urlOrPath) {
	if (typeof urlOrPath !== 'string' || !urlOrPath) return false
	const pathPart = urlOrPath.split(/[?#]/, 1)[0]
	if (/\\|%5c|%25(?:2e|2f|5c|25)/i.test(pathPart)) return true
	return /(?:^|\/|%2f)(?:\.\.|%2e\.|\.%2e|%2e%2e)(?:\/|%2f|;|%3b|$)/i.test(pathPart)
}

function getRawBody (req, maxBytes = 1024 * 1024) {
	return new Promise((resolve, reject) => {
		let size = 0
		let settled = false
		const buffers = []
		const fail = err => {
			if (settled) return
			settled = true
			reject(err)
		}
		req.on('data', chunk => {
			if (settled) return
			size += chunk.length
			if (size > maxBytes) {
				req.pause()
				fail(httpError(413, 'Payload Too Large'))
				return
			}
			buffers.push(chunk)
		})
		req.on('error', fail)
		req.on('end', () => {
			if (settled) return
			settled = true
			resolve(Buffer.concat(buffers))
		})
		req.on('close', () => {
			if (!settled && !req.readableEnded) {
				fail(httpError(400, 'Request stream closed prematurely'))
			}
		})
	})
}

async function getBody (req, maxBytes = 1024 * 1024) {
	return (await getRawBody(req, maxBytes)).toString('utf8')
}
