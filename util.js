export {
	getBody,
	sendJson,
	validateBaseUrl,
	parseAccountSpec
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

function isAllowedUpstreamHost (hostname) {
	if (!hostname || typeof hostname !== 'string') return false
	const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
	const isLoopback = host === 'localhost' || host.endsWith('.localhost') || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
	if (isLoopback) {
		return process.env.NODE_ENV === 'test'
	}
	if (
		host === '0.0.0.0' ||
		host === '::' ||
		host.startsWith('fe80:') ||
		host.startsWith('fc') ||
		host.startsWith('fd') ||
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
	const host = parsed.hostname.toLowerCase()
	const isLocal = host === 'localhost' || host.endsWith('.localhost') || host === '127.0.0.1' || host === '[::1]'
	if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocal && process.env.NODE_ENV === 'test')) {
		return null
	}
	const pathname = parsed.pathname.replace(/\/+$/, '')
	return `${parsed.origin}${pathname}`
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
