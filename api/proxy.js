import * as db from '../db/index.js'
import { getProvider } from '../providers/index.js'
import { evaluatePolicy } from '../policy.js'

export {
	request,
	executeUpstream,
	readResponseBody
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

async function executeUpstream ({ token, url, method = 'GET', body, headers = {} }) {
	const reqHeaders = {
		...(token ? { authorization: `Bearer ${token}` } : {}),
		...headers
	}
	let reqBody
	if (body !== undefined && body !== null) {
		if (typeof body === 'object') {
			reqHeaders['content-type'] = reqHeaders['content-type'] || 'application/json'
			reqBody = JSON.stringify(body)
		} else {
			reqBody = String(body)
		}
	}
	const reqMethod = method.toUpperCase()
	const fetchOpts = {
		method: reqMethod,
		headers: reqHeaders
	}
	if (reqMethod !== 'GET' && reqMethod !== 'HEAD' && reqBody !== undefined) {
		fetchOpts.body = reqBody
	}
	const res = await fetch(url, fetchOpts)
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
	const contentType = rawContentType.split(';')[0].trim()
	const charsetMatch = rawContentType.match(/charset=([^;]+)/i)
	const charset = charsetMatch ? charsetMatch[1].trim().replace(/^["']|["']$/g, '') : undefined
	const buf = await readResponseBody(res, maxFileSizeBytes)
	let result
	if (contentType === 'application/json') {
		const str = buf.toString('utf8')
		try {
			result = str ? JSON.parse(str) : {}
		} catch {
			result = str
		}
	} else if (contentType.startsWith('text/')) {
		result = buf.toString(charset || 'utf8')
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

async function request ({ provider: providerName = 'google', url, method = 'GET', body, headers, appId, account } = {}, token) {
	if (!url) {
		const err = new Error('URL is required')
		err.status = 400
		throw err
	}
	const appUrl = (process.env.APP_URL || 'http://localhost:8080').replace(/\/$/, '')
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const err = new Error(`Authentication required: ${appUrl}/oauth/authorize`)
		err.status = 401
		throw err
	}
	const provider = getProvider(providerName)
	const links = db.links.listBySessionId(session.id)
	const providerLinks = links.filter(l => l.app?.provider === provider.id)
	if (providerLinks.length === 0) {
		const connectHint = provider.type === 'oauth'
			? ` Connect an account at: ${appUrl}/providers/${provider.id}/connect`
			: ''
		const err = new Error(`No ${provider.name} app linked to session.${connectHint}`)
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
			const appAcc = (l.app?.credentials?.account || l.app?.credentials?.email || '').toLowerCase()
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
	const normalizedMethod = (method || 'GET').toUpperCase()
	const fullUrl = provider.normalizeTargetUrl(url, targetLink.app)
	const urlCheck = provider.isAllowedUrl(fullUrl, targetLink.app)
	if (!urlCheck.allowed) {
		const err = new Error(urlCheck.reason)
		err.status = 403
		throw err
	}
	if (targetLink.policy) {
		const check = evaluatePolicy(targetLink.policy, {
			url: fullUrl,
			method: normalizedMethod
		})
		if (!check.allowed) {
			const err = new Error(`Policy violation: ${check.reason || 'Operation not permitted by session policy'}`)
			err.status = 403
			throw err
		}
	}
	let freshInfo = null
	try {
		freshInfo = await provider.getFreshToken(targetLink.app)
	} catch (err) {
		const reauthUrl = `${appUrl}/providers/${provider.id}/connect?reauth_app_id=${targetLink.app.id}`
		const error = new Error(`Failed to refresh ${provider.name} access token: ${err.message}. Re-authenticate: ${reauthUrl}`)
		error.status = 401
		throw error
	}
	if (!freshInfo?.token) {
		const err = new Error(`Authentication required: ${appUrl}/oauth/authorize`)
		err.status = 401
		throw err
	}
	return executeUpstream({
		token: freshInfo.token,
		url: fullUrl,
		method: normalizedMethod,
		body,
		headers
	})
}
