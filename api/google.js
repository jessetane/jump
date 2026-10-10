import * as db from '../db/index.js'
import * as googleProvider from '../providers/google.js'
import { evaluatePolicy } from '../policy.js'

export {
	request
}

async function request ({ url, method = 'GET', body, headers, appId } = {}, token) {
	if (!url) {
		const err = new Error('URL is required')
		err.status = 400
		throw err
	}
	const appUrl = process.env.APP_URL || 'http://localhost:8080'
	const session = token ? db.tokens.getByToken(token) : null
	if (!session) {
		const err = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		err.status = 401
		throw err
	}
	const links = db.links.listBySessionId(session.id)
	const googleLinks = links.filter(l => l.app?.provider === 'google')
	if (googleLinks.length === 0) {
		const err = new Error(`No Google app linked to session. Connect an account at: ${appUrl.replace(/\/$/, '')}/providers/google/connect`)
		err.status = 403
		throw err
	}
	let targetLink = googleLinks[0]
	if (appId) {
		const found = googleLinks.find(l => l.app?.id === appId)
		if (!found) {
			const err = new Error(`App not linked to session or not found: ${appId}`)
			err.status = 404
			throw err
		}
		targetLink = found
	}
	const normalizedMethod = (method || 'GET').toUpperCase()
	if (targetLink.policy) {
		const check = evaluatePolicy(targetLink.policy, {
			url,
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
		freshInfo = await googleProvider.getFreshToken(targetLink.app)
	} catch (err) {
		const reauthUrl = `${appUrl.replace(/\/$/, '')}/providers/google/connect?reauth_app_id=${targetLink.app.id}`
		const error = new Error(`Failed to refresh Google access token: ${err.message}. Re-authenticate: ${reauthUrl}`)
		error.status = 401
		throw error
	}
	if (!freshInfo?.token) {
		const err = new Error(`Authentication required: ${appUrl.replace(/\/$/, '')}/oauth/authorize`)
		err.status = 401
		throw err
	}
	return googleProvider.proxyGoogleApi({
		token: freshInfo.token,
		url,
		method: normalizedMethod,
		body,
		headers
	})
}
