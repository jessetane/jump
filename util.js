export {
	getBody,
	sendJson,
	isLoopbackHost,
	isXml,
	validateBaseUrl,
	resolveTargetUrl,
	hasPathTraversal,
	parseAccountSpec,
	requireBoolean
}

function isXmlNameStart (code) {
	return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95
}

function isXmlNameChar (code) {
	return isXmlNameStart(code) || (code >= 48 && code <= 57) || code === 58 || code === 45 || code === 46
}

function readXmlName (s, start) {
	if (start >= s.length || !isXmlNameStart(s.charCodeAt(start))) return -1
	let i = start + 1
	while (i < s.length && isXmlNameChar(s.charCodeAt(i))) i++
	return i
}

function scanXmlDelimited (s, start, mode) {
	let quote = null
	let bracketDepth = 0
	for (let i = start; i < s.length; i++) {
		const ch = s[i]
		if (quote) {
			if (ch === quote) quote = null
			continue
		}
		if (ch === '"' || ch === "'") {
			quote = ch
			continue
		}
		if (mode === 'doctype') {
			if (ch === '[') {
				bracketDepth++
				continue
			}
			if (ch === ']' && bracketDepth > 0) {
				bracketDepth--
				continue
			}
			if (bracketDepth === 0 && ch === '>') return { end: i + 1 }
			continue
		}
		if (mode === 'pi') {
			if (ch === '?' && s[i + 1] === '>') return { end: i + 2 }
			continue
		}
		if (ch === '/') {
			if (s[i + 1] === '>') return { end: i + 2, selfClose: true }
			return null
		}
		if (ch === '>') return { end: i + 1, selfClose: false }
	}
	return null
}

function isXml (str) {
	if (typeof str !== 'string') return false
	const s = str.trim()
	const n = s.length
	if (!n || s[0] !== '<') return false
	let i = 0
	const stack = []
	let rootSeen = false
	let rootClosed = false
	while (i < n) {
		if (stack.length === 0) {
			while (i < n && s.charCodeAt(i) <= 32) i++
			if (i >= n) break
			if (s[i] !== '<') return false
		} else {
			const nextLt = s.indexOf('<', i)
			if (nextLt === -1) return false
			i = nextLt
		}
		if (s.startsWith('<!--', i)) {
			const end = s.indexOf('-->', i + 4)
			if (end === -1) return false
			i = end + 3
			continue
		}
		if (s.startsWith('<![CDATA[', i)) {
			if (stack.length === 0) return false
			const end = s.indexOf(']]>', i + 9)
			if (end === -1) return false
			i = end + 3
			continue
		}
		if (s.startsWith('<?', i)) {
			const nameEnd = readXmlName(s, i + 2)
			if (nameEnd === -1) return false
			if (s.charCodeAt(nameEnd) > 32 && !s.startsWith('?>', nameEnd)) return false
			const res = scanXmlDelimited(s, nameEnd, 'pi')
			if (!res) return false
			i = res.end
			continue
		}
		if (s.startsWith('<!', i)) {
			if (rootSeen || stack.length > 0) return false
			const nameEnd = readXmlName(s, i + 2)
			if (nameEnd === -1 || (s.charCodeAt(nameEnd) > 32 && s[nameEnd] !== '>')) return false
			const res = scanXmlDelimited(s, nameEnd, 'doctype')
			if (!res) return false
			i = res.end
			continue
		}
		if (s.startsWith('</', i)) {
			const nameEnd = readXmlName(s, i + 2)
			if (nameEnd === -1) return false
			const tagName = s.slice(i + 2, nameEnd)
			let j = nameEnd
			while (j < n && s.charCodeAt(j) <= 32) j++
			if (s[j] !== '>' || stack.pop() !== tagName) return false
			if (stack.length === 0) rootClosed = true
			i = j + 1
			continue
		}
		if (rootClosed) return false
		const nameEnd = readXmlName(s, i + 1)
		if (nameEnd === -1) return false
		const tagName = s.slice(i + 1, nameEnd)
		const nextCh = s[nameEnd]
		if (s.charCodeAt(nameEnd) > 32 && nextCh !== '>' && nextCh !== '/') return false
		const res = scanXmlDelimited(s, nameEnd, 'tag')
		if (!res) return false
		rootSeen = true
		if (res.selfClose) {
			if (stack.length === 0) rootClosed = true
		} else {
			stack.push(tagName)
		}
		i = res.end
	}
	return rootSeen && rootClosed && stack.length === 0
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

function isLoopbackHost (hostname) {
	if (!hostname || typeof hostname !== 'string') return false
	const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
	return host === 'localhost' || host.endsWith('.localhost') || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
}

function isAllowedUpstreamHost (hostname) {
	if (!hostname || typeof hostname !== 'string') return false
	if (isLoopbackHost(hostname)) {
		return process.env.NODE_ENV === 'test'
	}
	const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
	if (
		host === '0.0.0.0' ||
		host === '::' ||
		/^fe[89ab][0-9a-f]:/.test(host) ||
		/^f[cd][0-9a-f]{2}:/.test(host) ||
		host.startsWith('::ffff:') ||
		/^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
		/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
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
	return /(?:^|\/|\\|%2f|%5c)(?:\.\.|%2e\.|\.%2e|%2e%2e)(?:\/|\\|%2f|%5c|$)/i.test(pathPart)
}

function getBody (req, maxBytes = 1024 * 1024) {
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
				resolve(Buffer.concat(buffers).toString('utf8'))
			}
		})
	})
}
