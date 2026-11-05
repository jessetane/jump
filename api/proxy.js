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

async function executeUpstream ({ token, url, method = 'GET', body, headers = {}, onStatus }) {
	const reqHeaders = {}
	if (headers && typeof headers === 'object') {
		for (const [k, v] of Object.entries(headers)) {
			if (v !== undefined && v !== null) {
				reqHeaders[k.toLowerCase()] = String(v)
			}
		}
	}
	reqHeaders['user-agent'] ||= 'jump'
	let fetchUrl = url
	const cleanToken = typeof token === 'string' ? token.trim() : ''
	if (cleanToken) {
		if (cleanToken.startsWith('?')) {
			delete reqHeaders.authorization
			const parsed = new URL(url)
			const secretParams = new URLSearchParams(cleanToken.slice(1))
			const secretKeysLower = new Set(Array.from(secretParams.keys(), k => k.toLowerCase()))
			for (const existingKey of Array.from(parsed.searchParams.keys())) {
				if (secretKeysLower.has(existingKey.toLowerCase())) {
					parsed.searchParams.delete(existingKey)
				}
			}
			for (const [k, v] of secretParams.entries()) {
				parsed.searchParams.append(k, v)
			}
			fetchUrl = parsed.toString()
		} else if (/^(?:Bearer|Basic)\s+/i.test(cleanToken)) {
			const isBasic = /^basic/i.test(cleanToken)
			reqHeaders.authorization = `${isBasic ? 'Basic' : 'Bearer'} ${cleanToken.replace(/^(?:Bearer|Basic)\s+/i, '').trim()}`
		} else if (cleanToken.includes(':')) {
			reqHeaders.authorization = `Basic ${Buffer.from(cleanToken).toString('base64')}`
		} else {
			reqHeaders.authorization = `Bearer ${cleanToken}`
		}
	}
	let reqBody
	if (body !== undefined && body !== null) {
		if (typeof body === 'object') {
			const ct = (reqHeaders['content-type'] || '').split(';')[0].trim().toLowerCase()
			if (ct === 'application/x-www-form-urlencoded') {
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
				reqBody = params.toString()
			} else {
				reqHeaders['content-type'] = reqHeaders['content-type'] || 'application/json'
				reqBody = JSON.stringify(body)
			}
		} else {
			reqBody = String(body)
			if (!reqHeaders['content-type'] && /^<[a-zA-Z?_!][\s\S]*>$/.test(reqBody.trim())) {
				reqHeaders['content-type'] = 'application/xml'
			}
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
	const res = await fetch(fetchUrl, fetchOpts)
	if (onStatus) onStatus(res.status)
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
	const contentType = rawContentType.split(';')[0].trim().toLowerCase()
	const charsetMatch = rawContentType.match(/charset=([^;]+)/i)
	const charset = charsetMatch ? charsetMatch[1].trim().replace(/^["']|["']$/g, '') : undefined
	const buf = await readResponseBody(res, maxFileSizeBytes)
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

async function request ({ provider: providerName = 'google', url, method = 'GET', body, headers, appId, account, appUrl: rawAppUrl } = {}, token) {
	if (!url) {
		const err = new Error('URL is required')
		err.status = 400
		throw err
	}
	const appUrl = (rawAppUrl || 'http://localhost:8080').replace(/\/$/, '')
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const err = new Error(`Authentication required: ${appUrl}/oauth/authorize`)
		err.status = 401
		throw err
	}
	const start = Date.now()
	const normalizedMethod = (method || 'GET').toUpperCase()
	const provider = getProvider(providerName)
	let targetAppId = appId ? String(appId) : null
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
				const appAcc = (l.app?.credentials?.account || '').toLowerCase()
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
		targetAppId = targetLink.app?.id || null
		resolvedUrl = provider.normalizeTargetUrl(url, targetLink.app)
		const urlCheck = provider.isAllowedUrl(resolvedUrl, targetLink.app)
		if (!urlCheck.allowed) {
			const err = new Error(urlCheck.reason)
			err.status = 403
			throw err
		}
		if (targetLink.policy) {
			let contentType
			if (headers && typeof headers === 'object') {
				for (const [k, v] of Object.entries(headers)) {
					if (k.toLowerCase() === 'content-type' && v !== undefined && v !== null) {
						contentType = String(v)
						break
					}
				}
			}
			const check = evaluatePolicy(targetLink.policy, {
				url: resolvedUrl,
				method: normalizedMethod,
				body,
				contentType
			})
			if (!check.allowed) {
				const err = new Error(`Policy violation: ${check.reason || 'Operation not permitted by session policy'}`)
				err.status = 403
				throw err
			}
		}
		allowed = true
		let freshInfo = null
		try {
			freshInfo = await provider.getFreshToken(targetLink.app)
		} catch (err) {
			const reauthUrl = `${appUrl}/providers/${provider.id}/connect?session_id=${encodeURIComponent(session.id)}&reauth_app_id=${encodeURIComponent(targetLink.app.id)}`
			const error = new Error(`Failed to refresh ${provider.name} access token: ${err.message}. Re-authenticate: ${reauthUrl}`)
			error.status = 401
			throw error
		}
		if (!freshInfo?.token) {
			const err = new Error(`Authentication required: ${appUrl}/oauth/authorize`)
			err.status = 401
			throw err
		}
		let upstreamStatus = 200
		const result = await executeUpstream({
			token: freshInfo.token,
			url: resolvedUrl,
			method: normalizedMethod,
			body,
			headers,
			onStatus: s => { upstreamStatus = s }
		})
		recordLog(upstreamStatus, null)
		return result
	} catch (err) {
		recordLog(err.status || 502, err.message)
		throw err
	}
}
