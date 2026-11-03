export {
	getBody,
	sendJson,
	sendMail,
	isAllowedUpstreamHost,
	validateBaseUrl
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

async function sendMail (opts = {}) {
	const { to, subject, html, text } = opts
	const apiKey = process.env.MAILGUN_API_KEY
	const domain = process.env.MAILGUN_DOMAIN
	const sender = process.env.MAILGUN_SENDER || `jump <admin@${domain || 'localhost'}>`
	if (!apiKey || !domain || process.env.NODE_ENV === 'test') {
		if (process.env.NODE_ENV !== 'test') {
			console.log(`[mailgun:dev] To: ${to} | Subject: ${subject} | Content: ${text || html}`)
		}
		return { ok: true, dev: true }
	}
	const params = new URLSearchParams()
	params.set('from', sender)
	params.set('to', to)
	params.set('subject', subject)
	if (text) params.set('text', text)
	if (html) params.set('html', html)
	const authHeader = `Basic ${Buffer.from(`api:${apiKey}`).toString('base64')}`
	const res = await fetch(`https://api.mailgun.net/v3/${domain}/messages`, {
		method: 'POST',
		headers: {
			authorization: authHeader,
			'content-type': 'application/x-www-form-urlencoded'
		},
		body: params.toString()
	})
	if (!res.ok) {
		const errText = await res.text()
		console.error(`[mailgun] Error sending email (${res.status}): ${errText}`)
		const err = new Error(`Mailgun delivery failed: ${errText}`)
		err.status = res.status
		throw err
	}
	return await res.json()
}
