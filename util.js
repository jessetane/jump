export {
	getBody,
	sendMail
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
				err.code = 413
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
