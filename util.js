import { spawn } from 'node:child_process'

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

function sendMail (opts = {}) {
	const { to, subject, text } = opts
	const cleanFrom = String(process.env.MAIL_FROM || 'jump <noreply@localhost>').replace(/[\r\n]+/g, ' ').trim()
	const cleanTo = String(to || '').replace(/[\r\n]+/g, ' ').trim()
	const cleanSubject = String(subject || '').replace(/[\r\n]+/g, ' ').trim()
	const cmd = process.env.SENDMAIL
	if (!cmd) {
		if (process.env.NODE_ENV !== 'test') {
			console.log(`[sendmail:dev] To: ${cleanTo} | Subject: ${cleanSubject} | Content: ${text}`)
		}
		return Promise.resolve({ ok: true, dev: true })
	}
	const cleanBody = String(text || '').replace(/\r?\n/g, '\r\n')
	const message = `From: ${cleanFrom}\r\nTo: ${cleanTo}\r\nSubject: ${cleanSubject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${cleanBody}\r\n`
	return new Promise((resolve, reject) => {
		const child = spawn(cmd, {
			shell: true,
			stdio: ['pipe', 'ignore', 'pipe'],
			env: {
				...process.env,
				MAIL_FROM: cleanFrom,
				MAIL_TO: cleanTo,
				MAIL_SUBJECT: cleanSubject
			}
		})
		let stderr = ''
		child.stderr.on('data', chunk => {
			stderr += chunk.toString('utf8')
		})
		child.stdin.on('error', () => {})
		child.on('error', reject)
		child.on('close', code => {
			if (code !== 0) {
				reject(new Error(`SENDMAIL exited with code ${code}${stderr.trim() ? `: ${stderr.trim()}` : ''}`))
				return
			}
			resolve({ ok: true })
		})
		child.stdin.end(message)
	})
}
