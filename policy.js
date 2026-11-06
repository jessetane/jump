export {
	evaluatePolicy,
	matchPattern,
	normalizeUrl,
	parsePolicy,
	validatePolicy
}

const ALLOWED_RULE_KEYS = new Set(['action', 'methods', 'origin', 'path', 'query', 'body', 'description'])
const ALLOWED_HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', '*'])

function isValidFieldScalar (val) {
	if (val === null) return true
	const t = typeof val
	return t === 'string' || t === 'number' || t === 'boolean'
}

function parseUrlEncoded (str) {
	const params = new URLSearchParams(str)
	const obj = {}
	for (const [k, v] of params.entries()) {
		if (Object.hasOwn(obj, k)) {
			obj[k] = Array.isArray(obj[k]) ? [...obj[k], v] : [obj[k], v]
		} else {
			obj[k] = v
		}
	}
	return obj
}

function parseBodyObject (body, contentType = '') {
	if (body === undefined || body === null || body === '') return {}
	if (typeof body === 'object' && !Array.isArray(body)) return body
	if (typeof body === 'string') {
		const trimmed = body.trim()
		if (!trimmed) return {}
		const ct = String(contentType || '').split(';')[0].trim().toLowerCase()
		if (ct === 'application/x-www-form-urlencoded') {
			return parseUrlEncoded(trimmed)
		}
		if (ct && ct !== 'application/json' && !ct.endsWith('+json')) {
			return null
		}
		if (/^<[a-zA-Z?_!][\s\S]*>$/.test(trimmed) || trimmed.startsWith('[') || trimmed.startsWith('{')) {
			try {
				const parsed = JSON.parse(trimmed)
				if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed
			} catch {}
			return null
		}
		if (!ct && trimmed.split('&').every(part => /^[^=\s&]+=[^]*$/.test(part))) {
			return parseUrlEncoded(trimmed)
		}
	}
	return null
}

function resolveField (obj, key) {
	if (!obj || typeof obj !== 'object') return undefined
	if (Object.hasOwn(obj, key)) return obj[key]
	if (!key.includes('.')) return undefined
	const parts = key.split('.')
	let cur = obj
	for (const part of parts) {
		if (!cur || typeof cur !== 'object' || !Object.hasOwn(cur, part)) return undefined
		cur = cur[part]
	}
	return cur
}

function matchValuePattern (pattern, str) {
	if (typeof pattern !== 'string' || typeof str !== 'string') return false
	if (pattern === '*' || pattern === '**') return true
	if (pattern === str) return true
	const escaped = pattern.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*+/g, '.*')
	try {
		const regex = new RegExp(`^${escaped}$`, 'i')
		return regex.test(str)
	} catch {
		return false
	}
}

function matchFieldValue (expected, actual) {
	const patterns = Array.isArray(expected) ? expected : [expected]
	if (actual === undefined || actual === null) return patterns.includes(null)
	const values = Array.isArray(actual) ? actual : [actual]
	if (values.length === 0) return false
	return values.every(val => {
		if (val === undefined || val === null) return patterns.includes(null)
		if (typeof val === 'object') return false
		const valStr = String(val)
		return patterns.some(pat => pat !== null && matchValuePattern(String(pat), valStr))
	})
}

function validateFieldMap (map, label, ruleIndex) {
	if (!map || typeof map !== 'object' || Array.isArray(map)) {
		return `Rule at index ${ruleIndex} ${label} must be a non-empty object`
	}
	const entries = Object.entries(map)
	if (entries.length === 0) {
		return `Rule at index ${ruleIndex} ${label} must be a non-empty object`
	}
	for (const [k, v] of entries) {
		if (!k.trim()) {
			return `Rule at index ${ruleIndex} ${label} field key must be a non-empty string`
		}
		if (Array.isArray(v)) {
			if (v.length === 0 || !v.every(isValidFieldScalar)) {
				return `Rule at index ${ruleIndex} ${label} field "${k}" must be a primitive or non-empty array of primitives`
			}
		} else if (!isValidFieldScalar(v)) {
			return `Rule at index ${ruleIndex} ${label} field "${k}" must be a primitive or non-empty array of primitives`
		}
	}
	return null
}

function matchFieldMap (expectedMap, actualObj) {
	if (!actualObj) return false
	for (const [key, expected] of Object.entries(expectedMap)) {
		if (!matchFieldValue(expected, resolveField(actualObj, key))) return false
	}
	return true
}

function canonicalizePath (str) {
	if (typeof str !== 'string') return ''
	if (/(?:%2e%2e|%2e\.|%2E%2E|%2E\.|\.%2e|\.%2E)(?:[/?#]|$)/i.test(str) || /\/\.\.(?:[/?#]|$)/.test(str)) {
		return null
	}
	let decoded = str.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
		const code = parseInt(hex, 16)
		if (
			(code >= 65 && code <= 90) ||
			(code >= 97 && code <= 122) ||
			(code >= 48 && code <= 57) ||
			code === 45 || code === 95 || code === 46 || code === 126 || code === 64
		) {
			return String.fromCharCode(code)
		}
		return match
	})
	if (decoded.length > 1 && !decoded.endsWith('*')) {
		decoded = decoded.replace(/\/+$/, '')
	}
	return decoded
}

function validatePolicy (policy) {
	if (!policy) return { valid: true, policy: null }
	let parsed = policy
	if (typeof policy === 'string') {
		const trimmed = policy.trim()
		if (!trimmed) return { valid: true, policy: null }
		try {
			parsed = JSON.parse(trimmed)
		} catch (err) {
			return { valid: false, error: `Invalid JSON policy: ${err.message}` }
		}
	}
	if (!Array.isArray(parsed)) {
		return { valid: false, error: 'Policy must be a JSON array of rules' }
	}
	if (parsed.length === 0) {
		return { valid: true, policy: [] }
	}
	for (let i = 0; i < parsed.length; i++) {
		const rule = parsed[i]
		if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
			return { valid: false, error: `Rule at index ${i} must be an object` }
		}
		for (const key of Object.keys(rule)) {
			if (!ALLOWED_RULE_KEYS.has(key)) {
				return { valid: false, error: `Rule at index ${i} has unknown property "${key}"` }
			}
		}
		const action = typeof rule.action === 'string' ? rule.action.toLowerCase() : ''
		if (action !== 'allow' && action !== 'deny') {
			return { valid: false, error: `Rule at index ${i} action must be "allow" or "deny"` }
		}
		if (rule.methods !== undefined) {
			if (!Array.isArray(rule.methods) || rule.methods.length === 0) {
				return { valid: false, error: `Rule at index ${i} methods must be an array of HTTP method strings` }
			}
			for (const m of rule.methods) {
				if (typeof m !== 'string' || !ALLOWED_HTTP_METHODS.has(m.trim().toUpperCase())) {
					return { valid: false, error: `Rule at index ${i} contains invalid HTTP method "${m}"` }
				}
			}
		}
		if (rule.origin !== undefined) {
			if (typeof rule.origin !== 'string' || !rule.origin.startsWith('https://')) {
				return { valid: false, error: `Rule at index ${i} origin must be an HTTPS origin (e.g. "https://api.stripe.com" or "https://*.googleapis.com")` }
			}
			const stripped = rule.origin.trim().replace(/\/+$/, '')
			const hostPart = stripped.slice('https://'.length)
			if (!hostPart || hostPart.includes('/') || hostPart.includes('?')) {
				return { valid: false, error: `Rule at index ${i} origin must not contain a path or query` }
			}
		}
		if (rule.path !== undefined) {
			if (typeof rule.path !== 'string' || !rule.path.trim()) {
				return { valid: false, error: `Rule at index ${i} path must be a non-empty string` }
			}
			if (rule.path.includes('?')) {
				return { valid: false, error: `Rule at index ${i} path must not contain query parameters` }
			}
			if (rule.path.startsWith('http://') || rule.path.startsWith('https://')) {
				return { valid: false, error: `Rule at index ${i} path must be a pathname; use "origin" to specify hostnames` }
			}
		}
		if (rule.query !== undefined) {
			const queryErr = validateFieldMap(rule.query, 'query', i)
			if (queryErr) return { valid: false, error: queryErr }
		}
		if (rule.body !== undefined) {
			const bodyErr = validateFieldMap(rule.body, 'body', i)
			if (bodyErr) return { valid: false, error: bodyErr }
		}
		if (rule.description !== undefined && typeof rule.description !== 'string') {
			return { valid: false, error: `Rule at index ${i} description must be a string` }
		}
	}
	return { valid: true, policy: parsed }
}

function parsePolicy (policy) {
	const res = validatePolicy(policy)
	return res.valid ? res.policy : null
}

function matchPattern (pattern, str) {
	if (!pattern || typeof pattern !== 'string' || typeof str !== 'string') return false
	if (pattern === '*' || pattern === '**') return true
	if (pattern === str) return true
	let p = pattern.replace(/(?:\/\*\*)+/g, '/**')
	p = p.replace(/\/\*\*$/, '§§SLASH_GLOB_END§§')
	p = p.replace(/\/\*\*\//g, '§§SLASH_GLOB_MID§§')
	p = p.replace(/^\*\*\//, '§§GLOB_START_SLASH§§')
	p = p.replace(/[.+^${}()|[\]\\?]/g, '\\$&')
	p = p.replace(/\*\*/g, '.*')
	p = p.replace(/\*/g, '[^/]*')
	p = p.replace(/§§SLASH_GLOB_END§§/g, '(?:/.*)?')
	p = p.replace(/§§SLASH_GLOB_MID§§/g, '(?:/|/.+/)')
	p = p.replace(/§§GLOB_START_SLASH§§/g, '(?:.*/)?')
	try {
		const regex = new RegExp(`^${p}$`, 'i')
		return regex.test(str)
	} catch {
		return false
	}
}

function normalizeUrl (targetUrl, baseUrl = null) {
	if (!targetUrl || typeof targetUrl !== 'string') return null
	let clean = targetUrl.trim()
	if (clean.startsWith('https:/') && !clean.startsWith('https://')) {
		clean = clean.replace(/^https:\/+/, 'https://')
	}
	let fullUrl = clean
	if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
		const noLeadingSlash = clean.replace(/^\/+/, '')
		const cleanBase = (baseUrl || 'http://localhost').replace(/\/+$/, '')
		fullUrl = `${cleanBase}/${noLeadingSlash}`
	}
	try {
		return new URL(fullUrl)
	} catch {
		return null
	}
}

function evaluatePolicy (policy, req = {}) {
	const validation = validatePolicy(policy)
	if (!validation.valid) {
		return { allowed: false, reason: validation.error }
	}
	const parsedPolicy = validation.policy
	if (!parsedPolicy || !Array.isArray(parsedPolicy)) {
		return { allowed: true }
	}
	if (parsedPolicy.length === 0) {
		return { allowed: false, reason: 'Empty policy denies all requests' }
	}
	const reqMethod = (req.method || 'GET').toUpperCase()
	if (typeof req.url === 'string' && (/(?:%2e%2e|%2e\.|%2E%2E|%2E\.|\.%2e|\.%2E)(?:[/?#]|$)/i.test(req.url) || /\/\.\.(?:[/?#]|$)/.test(req.url))) {
		return { allowed: false, reason: 'Invalid path: path traversal is not permitted' }
	}
	const parsedUrl = req.url ? normalizeUrl(req.url, req.baseUrl) : null
	if (!parsedUrl) {
		return { allowed: false, reason: 'Invalid or missing target URL' }
	}
	const canonicalPath = canonicalizePath(parsedUrl.pathname)
	if (canonicalPath === null) {
		return { allowed: false, reason: 'Invalid path: path traversal is not permitted' }
	}
	let parsedQuery = undefined
	let parsedBody = undefined
	for (const rule of parsedPolicy) {
		const action = rule.action.toLowerCase()
		if (rule.methods) {
			const methods = rule.methods.map(m => m.trim().toUpperCase())
			if (!methods.includes('*') && !methods.includes(reqMethod)) continue
		}
		if (rule.origin) {
			const ruleOrigin = rule.origin.trim().replace(/\/+$/, '')
			if (!matchPattern(ruleOrigin, parsedUrl.origin)) continue
		}
		if (rule.path) {
			const rawPath = rule.path
			const normPath = rawPath.startsWith('/') || rawPath === '*' || rawPath === '**' ? rawPath : `/${rawPath}`
			const canonicalNormPath = canonicalizePath(normPath)
			if (!matchPattern(canonicalNormPath, canonicalPath)) continue
		}
		if (rule.query) {
			if (parsedQuery === undefined) {
				parsedQuery = parseUrlEncoded(parsedUrl.search.slice(1))
			}
			if (!matchFieldMap(rule.query, parsedQuery)) continue
		}
		if (rule.body) {
			if (parsedBody === undefined) {
				parsedBody = parseBodyObject(req.body, req.contentType)
			}
			if (!matchFieldMap(rule.body, parsedBody)) continue
		}
		if (action === 'deny') {
			return {
				allowed: false,
				reason: rule.description || `Request matched deny rule for method "${reqMethod}" on "${req.url}"`
			}
		}
		if (action === 'allow') {
			return { allowed: true }
		}
	}
	return { allowed: false, reason: `Request did not match any allow rule for method "${reqMethod}" on "${req.url}"` }
}
