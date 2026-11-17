export {
	getRawBody,
	getBody,
	getBaseUrl,
	serializeFormBody,
	sendJson,
	sendText,
	sendHtml,
	redirect,
	isLoopbackHost,
	validateBaseUrl,
	resolveTargetUrl,
	hasPathTraversal,
	parseAccountSpec,
	requireBoolean
}

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
	const err = new Error(`${name} must be a boolean`)
	err.status = 400
	throw err
}

function parseAccountSpec (rawAccount, rawProvider = null) {
	const hasAccount = rawAccount !== undefined && rawAccount !== null && String(rawAccount).trim() !== ''
	const hasProvider = rawProvider !== undefined && rawProvider !== null && String(rawProvider).trim() !== ''
	let cleanProvider = hasProvider ? String(rawProvider).trim().toLowerCase() : null
	if (cleanProvider && cleanProvider.includes(':')) {
		const err = new Error(`Invalid provider identifier: ${rawProvider}`)
		err.status = 400
		throw err
	}
	if (!hasAccount) {
		return { account: null, provider: cleanProvider }
	}
	if (typeof rawAccount !== 'string') {
		const err = new Error('Account identifier must be a string')
		err.status = 400
		throw err
	}
	const trimmed = rawAccount.trim().toLowerCase()
	if (!trimmed.includes(':')) {
		return { account: trimmed, provider: cleanProvider }
	}
	const parts = trimmed.split(':')
	if (parts.length !== 2 || !parts[0].trim() || !parts[1].trim() || /\s/.test(parts[0]) || /\s/.test(parts[1])) {
		const err = new Error(`Malformed account identifier "${rawAccount}"; expected "provider:account"`)
		err.status = 400
		throw err
	}
	const prefixProvider = parts[0]
	const cleanAccount = parts[1]
	if (cleanProvider && cleanProvider !== prefixProvider) {
		const err = new Error(`Conflicting provider "${cleanProvider}" and account prefix "${prefixProvider}:${cleanAccount}"`)
		err.status = 400
		throw err
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
	res.end(html)
}

function redirect (res, location, status = 302) {
	res.statusCode = status
	res.setHeader('location', location)
	res.end()
}

function getBaseUrl (req) {
	if (req && req.headers && (req.headers['x-forwarded-host'] || req.headers.host)) {
		const rawHost = String(req.headers['x-forwarded-host'] || req.headers.host).split(',')[0].trim().toLowerCase()
		if (rawHost) {
			try {
				const parsed = new URL(`http://${rawHost}`)
				const isLocal = isLoopbackHost(parsed.hostname)
				const rawProto = String(req.headers['x-forwarded-proto'] || (isLocal ? 'http' : 'https')).split(',')[0].trim().toLowerCase()
				const validHost = parsed.host === rawHost || (!parsed.port && rawHost === `${parsed.hostname}:80`)
				if ((rawProto === 'http' || rawProto === 'https') && parsed.port !== '0' && !parsed.username && !parsed.password && parsed.pathname === '/' && !parsed.search && !parsed.hash && validHost) {
					const port = parsed.port || (rawHost === `${parsed.hostname}:80` ? '80' : '')
					const effectivePort = (rawProto === 'https' && port === '443') || (rawProto === 'http' && port === '80') ? '' : port
					return `${rawProto}://${parsed.hostname}${effectivePort ? `:${effectivePort}` : ''}`
				}
			} catch {}
		}
	}
	return 'http://localhost:8080'
}

function stripTrailingDot (hostname) {
	return hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
}

function isLoopbackHost (hostname) {
	if (!hostname || typeof hostname !== 'string') return false
	const host = stripTrailingDot(hostname)
	return host === 'localhost' || host.endsWith('.localhost') || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
}

function isAllowedUpstreamHost (hostname) {
	if (!hostname || typeof hostname !== 'string') return false
	if (isLoopbackHost(hostname)) {
		return process.env.NODE_ENV === 'test'
	}
	const host = stripTrailingDot(hostname)
	if (
		!host ||
		host === '0.0.0.0' ||
		host === '::' ||
		host === 'metadata.google.internal' ||
		/^fe[89ab][0-9a-f]:/.test(host) ||
		/^f[cd][0-9a-f]{0,2}:/.test(host) ||
		host.startsWith('::ffff:') ||
		/^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
		/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
		/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$/.test(host) ||
		/^169\.254\.\d{1,3}\.\d{1,3}$/.test(host) ||
		/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
		/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host)
	) {
		return false
	}
	return true
}

function validateBaseUrl (baseUrl) {
	if (!baseUrl || typeof baseUrl !== 'string') return null
	let parsed
	try {
		parsed = new URL(baseUrl.trim())
	} catch {
		return null
	}
	if (!isAllowedUpstreamHost(parsed.hostname)) return null
	if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname) && process.env.NODE_ENV === 'test')) {
		return null
	}
	const pathname = parsed.pathname.replace(/\/+$/, '')
	return `${parsed.origin}${pathname}`
}

function resolveTargetUrl (targetUrl, baseUrl = null) {
	if (!targetUrl || typeof targetUrl !== 'string') return ''
	let clean = targetUrl.trim()
	if (!clean) return ''
	if (clean.startsWith('https:/') && !clean.startsWith('https://')) {
		clean = clean.replace(/^https:\/+/, 'https://')
	}
	if (clean.startsWith('http://') || clean.startsWith('https://')) {
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
	return /(?:^|\/|%2f)(?:\.\.|%2e\.|\.%2e|%2e%2e)(?:\/|%2f|$)/i.test(pathPart)
}

function getRawBody (req, maxBytes = 1024 * 1024) {
	return new Promise((resolve, reject) => {
		let size = 0
		let exceeded = false
		const buffers = []
		req.on('data', chunk => {
			if (exceeded) return
			size += chunk.length
			if (size > maxBytes) {
				exceeded = true
				req.pause()
				const err = new Error('Payload Too Large')
				err.status = 413
				reject(err)
				return
			}
			buffers.push(chunk)
		})
		req.on('error', reject)
		req.on('end', () => {
			if (!exceeded) {
				resolve(Buffer.concat(buffers))
			}
		})
	})
}

async function getBody (req, maxBytes = 1024 * 1024) {
	return (await getRawBody(req, maxBytes)).toString('utf8')
}
