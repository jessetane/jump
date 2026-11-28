import { hasUrlScheme, resolveTargetUrl, hasPathTraversal, parseMimeType, isJsonMime, serializeFormBody, isPlainObject } from './util.js'

export {
	evaluatePolicy,
	hasBodyPolicy,
	matchPattern,
	parsePolicy,
	serializePolicy,
	validatePolicy
}

const ALLOWED_RULE_KEYS = new Set(['action', 'methods', 'origin', 'path', 'query', 'body', 'bodyType', 'description'])
const ALLOWED_HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', '*'])
const ALLOWED_BODY_TYPES = new Set(['json', 'form'])

function isEmptyBody (body) {
	if (body === undefined || body === null || body === '') return true
	if (ArrayBuffer.isView(body)) return body.byteLength === 0
	return false
}

function isValidFieldScalar (val) {
	if (val === null) return true
	const t = typeof val
	return t === 'string' || t === 'number' || t === 'boolean'
}

function parseUrlEncoded (str) {
	const params = new URLSearchParams(str)
	const obj = Object.create(null)
	for (const [k, v] of params.entries()) {
		if (Object.hasOwn(obj, k)) {
			obj[k] = Array.isArray(obj[k]) ? [...obj[k], v] : [obj[k], v]
		} else {
			obj[k] = v
		}
	}
	return obj
}

function hasDuplicateJsonKeys (str) {
	const stack = []
	let i = 0
	const n = str.length
	while (i < n) {
		const ch = str[i]
		if (ch === '"') {
			let j = i + 1
			while (j < n) {
				if (str[j] === '\\') {
					j += 2
					continue
				}
				if (str[j] === '"') break
				j++
			}
			if (j >= n) return false
			const rawLit = str.slice(i, j + 1)
			i = j + 1
			while (i < n && str.charCodeAt(i) <= 32) i++
			if (str[i] === ':' && stack.length > 0 && stack[stack.length - 1] !== null) {
				const key = JSON.parse(rawLit)
				if (stack[stack.length - 1].has(key)) return true
				stack[stack.length - 1].add(key)
				i++
			}
			continue
		}
		if (ch === '{') {
			stack.push(new Set())
		} else if (ch === '[') {
			stack.push(null)
		} else if (ch === '}' || ch === ']') {
			stack.pop()
		}
		i++
	}
	return false
}

function isCompatibleContentType (contentType, bodyType) {
	const mime = parseMimeType(contentType)
	if (!mime) return true
	if (bodyType === 'json') return isJsonMime(mime)
	if (bodyType === 'form') return mime === 'application/x-www-form-urlencoded'
	return false
}

function parseBodyObject (body, bodyType = 'json', objectFormat = 'json', contentType = '') {
	if (!isCompatibleContentType(contentType, bodyType)) {
		return isEmptyBody(body) ? {} : null
	}
	if (isEmptyBody(body)) return {}
	if (isPlainObject(body)) {
		if (objectFormat !== bodyType) return null
		return bodyType === 'form' ? parseUrlEncoded(serializeFormBody(body)) : body
	}
	let raw
	if (typeof body === 'string') {
		raw = body
	} else if (ArrayBuffer.isView(body)) {
		raw = Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString('utf8')
	} else {
		return null
	}
	const trimmed = raw.trim()
	if (!trimmed) return {}
	if (bodyType === 'json') {
		if (!trimmed.startsWith('{')) return null
		try {
			const parsed = JSON.parse(trimmed)
			if (isPlainObject(parsed) && !hasDuplicateJsonKeys(trimmed)) return parsed
		} catch {}
		return null
	}
	if (bodyType === 'form') {
		if (trimmed.startsWith('{') || trimmed.startsWith('[') || /[\r\n\0]/.test(raw)) return null
		if (!trimmed.split('&').every(part => part.length > 0 && !/\s/.test(part) && part[0] !== '=')) return null
		return parseUrlEncoded(trimmed)
	}
	return null
}

function bodyToString (body, objectFormat = 'json') {
	if (isEmptyBody(body)) return ''
	if (typeof body === 'string') return body
	if (ArrayBuffer.isView(body)) {
		return Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString('utf8')
	}
	if (typeof body === 'object') {
		return objectFormat === 'form' ? serializeFormBody(body) : JSON.stringify(body)
	}
	return String(body)
}

function matchValuePattern (pattern, str) {
	if (typeof pattern !== 'string' || typeof str !== 'string') return false
	if (pattern === '*' || pattern === '**') return true
	const p = pattern.replace(/\*+/g, '*').toLowerCase()
	const s = str.toLowerCase()
	if (p === s) return true
	let pi = 0
	let si = 0
	let starIdx = -1
	let matchIdx = 0
	while (si < s.length) {
		if (pi < p.length && p.charCodeAt(pi) === s.charCodeAt(si)) {
			pi++
			si++
		} else if (pi < p.length && p.charCodeAt(pi) === 42) {
			starIdx = pi++
			matchIdx = si
		} else if (starIdx !== -1) {
			pi = starIdx + 1
			si = ++matchIdx
		} else {
			return false
		}
	}
	while (pi < p.length && p.charCodeAt(pi) === 42) pi++
	return pi === p.length
}

function matchFieldValue (expected, actual, action = 'allow') {
	const patterns = Array.isArray(expected) ? expected : [expected]
	if (actual === undefined || actual === null) return patterns.includes(null)
	const hasNonNullPattern = patterns.some(p => p !== null)
	const values = Array.isArray(actual) ? actual : [actual]
	if (values.length === 0) return action === 'deny' && hasNonNullPattern
	const matchOne = val => {
		if (val === undefined || val === null) return patterns.includes(null)
		if (typeof val === 'object') return action === 'deny' && hasNonNullPattern
		const valStr = String(val)
		return patterns.some(pat => pat !== null && matchValuePattern(String(pat), valStr))
	}
	return action === 'deny' ? values.some(matchOne) : values.every(matchOne)
}

function validateFieldMap (map, label, ruleIndex, allowNested = false) {
	if (!isPlainObject(map)) {
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
		} else if (allowNested && isPlainObject(v)) {
			const nestedErr = validateFieldMap(v, `${label}.${k}`, ruleIndex, true)
			if (nestedErr) return nestedErr
		} else if (!isValidFieldScalar(v)) {
			return `Rule at index ${ruleIndex} ${label} field "${k}" must be a primitive${allowNested ? ', non-empty object,' : ''} or non-empty array of primitives`
		}
	}
	return null
}

function matchFieldMap (expectedMap, actualObj, action = 'allow') {
	if (!actualObj || typeof actualObj !== 'object') return false
	for (const [key, expected] of Object.entries(expectedMap)) {
		const actual = Object.hasOwn(actualObj, key) ? actualObj[key] : undefined
		if (isPlainObject(expected)) {
			if (Array.isArray(actual)) {
				if (actual.length === 0) return false
				const ok = action === 'deny'
					? actual.some(item => isPlainObject(item) && matchFieldMap(expected, item, action))
					: actual.every(item => isPlainObject(item) && matchFieldMap(expected, item, action))
				if (!ok) return false
			} else if (actual === undefined || actual === null) {
				if (!matchFieldMap(expected, Object.create(null), action)) return false
			} else if (!isPlainObject(actual) || !matchFieldMap(expected, actual, action)) {
				return false
			}
			continue
		}
		if (!matchFieldValue(expected, actual, action)) return false
	}
	return true
}

function canonicalizePath (str) {
	if (typeof str !== 'string') return ''
	if (hasPathTraversal(str)) {
		return null
	}
	let decoded = str.replace(/\/+/g, '/').replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
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
		if (!isPlainObject(rule)) {
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
			if (typeof rule.origin !== 'string' || !rule.origin.trim().toLowerCase().startsWith('https://')) {
				return { valid: false, error: `Rule at index ${i} origin must be an HTTPS origin (e.g. "https://api.stripe.com" or "https://*.googleapis.com")` }
			}
			const rawOrigin = rule.origin.trim()
			const stripped = rawOrigin.replace(/\/+$/, '')
			let parsedOrigin
			try {
				parsedOrigin = new URL(stripped)
			} catch {
				return { valid: false, error: `Rule at index ${i} origin is not a valid HTTPS origin` }
			}
			if (parsedOrigin.protocol !== 'https:' || parsedOrigin.username || parsedOrigin.password || parsedOrigin.pathname !== '/' || rawOrigin.includes('?') || rawOrigin.includes('#') || parsedOrigin.search || parsedOrigin.hash) {
				return { valid: false, error: `Rule at index ${i} origin must not contain a path, query, fragment, or credentials` }
			}
		}
		if (rule.path !== undefined) {
			if (typeof rule.path !== 'string' || !rule.path.trim()) {
				return { valid: false, error: `Rule at index ${i} path must be a non-empty string` }
			}
			if (rule.path.includes('?') || rule.path.includes('#')) {
				return { valid: false, error: `Rule at index ${i} path must not contain query parameters or fragments` }
			}
			if (hasUrlScheme(rule.path.trim())) {
				return { valid: false, error: `Rule at index ${i} path must be a pathname; use "origin" to specify hostnames` }
			}
			if (hasPathTraversal(rule.path)) {
				return { valid: false, error: `Rule at index ${i} path must not contain path traversal` }
			}
		}
		if (rule.query !== undefined) {
			const queryErr = validateFieldMap(rule.query, 'query', i)
			if (queryErr) return { valid: false, error: queryErr }
		}
		if (rule.body !== undefined && rule.body !== null) {
			if (typeof rule.body === 'string') {
				if (!rule.body.trim()) {
					return { valid: false, error: `Rule at index ${i} body pattern must be a non-empty string` }
				}
			} else if (Array.isArray(rule.body)) {
				if (rule.body.length === 0 || !rule.body.every(p => typeof p === 'string' && p.trim())) {
					return { valid: false, error: `Rule at index ${i} body array must be a non-empty array of non-empty pattern strings` }
				}
			} else if (isPlainObject(rule.body)) {
				const bodyType = typeof rule.bodyType === 'string' ? rule.bodyType.trim().toLowerCase() : 'json'
				const bodyErr = validateFieldMap(rule.body, 'body', i, bodyType !== 'form')
				if (bodyErr) return { valid: false, error: bodyErr }
			} else {
				return { valid: false, error: `Rule at index ${i} body must be a non-empty object, pattern string, array of pattern strings, or null` }
			}
		}
		if (rule.bodyType !== undefined) {
			if (!isPlainObject(rule.body)) {
				return { valid: false, error: `Rule at index ${i} bodyType is only valid when body is a field-map object` }
			}
			const bt = typeof rule.bodyType === 'string' ? rule.bodyType.trim().toLowerCase() : ''
			if (!ALLOWED_BODY_TYPES.has(bt)) {
				return { valid: false, error: `Rule at index ${i} bodyType must be "json" or "form"` }
			}
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

function hasBodyPolicy (policy) {
	const parsed = parsePolicy(policy)
	return Boolean(parsed && parsed.some(r => r.body !== undefined))
}

function matchPattern (pattern, str) {
	if (!pattern || typeof pattern !== 'string' || typeof str !== 'string') return false
	if (pattern === '*' || pattern === '**') return true
	if (pattern === str) return true
	const patSegs = pattern.split('/')
	const strSegs = str.split('/')
	const n = strSegs.length
	let dp = new Uint8Array(n + 1)
	dp[0] = 1
	for (const pat of patSegs) {
		const next = new Uint8Array(n + 1)
		if (pat === '**') {
			let reachable = 0
			for (let s = 0; s <= n; s++) {
				if (dp[s]) reachable = 1
				next[s] = reachable
			}
		} else if (pat.includes('**')) {
			for (let s = 0; s < n; s++) {
				if (!dp[s]) continue
				for (let end = s + 1; end <= n; end++) {
					if (!next[end] && matchValuePattern(pat, strSegs.slice(s, end).join('/'))) {
						next[end] = 1
					}
				}
			}
		} else {
			for (let s = 0; s < n; s++) {
				if (dp[s] && matchValuePattern(pat, strSegs[s])) next[s + 1] = 1
			}
		}
		dp = next
	}
	return dp[n] === 1
}

function normalizeUrl (targetUrl, baseUrl = null) {
	const fullUrl = resolveTargetUrl(targetUrl, baseUrl || 'http://localhost')
	if (!fullUrl) return null
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
	if (typeof req.url === 'string' && hasPathTraversal(req.url)) {
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
	const objectFormat = req.objectFormat === 'form' ? 'form' : 'json'
	let parsedQuery = undefined
	let bodyText = undefined
	const parsedBodies = {}
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
			if (!matchFieldMap(rule.query, parsedQuery, action)) continue
		}
		if (rule.body !== undefined) {
			if (rule.body === null) {
				if (!isEmptyBody(req.body)) continue
			} else if (typeof rule.body === 'string' || Array.isArray(rule.body)) {
				if (bodyText === undefined) {
					bodyText = bodyToString(req.body, objectFormat)
				}
				const patterns = Array.isArray(rule.body) ? rule.body : [rule.body]
				if (!patterns.some(p => matchValuePattern(p, bodyText))) continue
			} else {
				const bodyType = rule.bodyType ? rule.bodyType.trim().toLowerCase() : 'json'
				if (!Object.hasOwn(parsedBodies, bodyType)) {
					parsedBodies[bodyType] = parseBodyObject(req.body, bodyType, objectFormat, req.contentType)
				}
				const parsedBody = parsedBodies[bodyType]
				if (parsedBody === null) {
					if (action === 'deny') {
						return {
							allowed: false,
							reason: `Invalid request body: expected ${bodyType} object for deny rule on "${req.url}"`
						}
					}
					continue
				}
				if (!matchFieldMap(rule.body, parsedBody, action)) continue
			}
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

function serializePolicy (policy) {
	if (policy === undefined || policy === null) return null
	return typeof policy === 'object' ? JSON.stringify(policy) : String(policy)
}
