export {
	parseSsoDomains,
	getSsoDomain,
	assertSsoLogin,
	assertSsoLink,
	resolveShareProvider,
	shouldClaimUnscoped
}

function getEmailDomain (account) {
	if (!account || typeof account !== 'string') return null
	const clean = account.trim().toLowerCase()
	const at = clean.lastIndexOf('@')
	if (at <= 0 || at === clean.length - 1) return null
	return clean.slice(at + 1)
}

function parseSsoDomains (raw = process.env.SSO_DOMAINS) {
	const domains = new Map()
	if (!raw || typeof raw !== 'string') return domains
	for (const item of raw.split(',')) {
		const entry = item.trim()
		if (!entry) continue
		const parts = entry.split(':')
		if (parts.length < 2 || parts.length > 3) {
			const err = new Error(`Invalid SSO_DOMAINS entry "${entry}"; expected "domain:provider" or "domain:provider:strict"`)
			err.status = 500
			throw err
		}
		const domain = parts[0].trim().toLowerCase()
		const provider = parts[1].trim().toLowerCase()
		const flag = parts.length === 3 ? parts[2].trim().toLowerCase() : null
		if (!domain || !provider || domain.includes('@') || /\s/.test(domain) || /\s/.test(provider) || (flag !== null && flag !== 'strict')) {
			const err = new Error(`Invalid SSO_DOMAINS entry "${entry}"; expected "domain:provider" or "domain:provider:strict"`)
			err.status = 500
			throw err
		}
		if (domains.has(domain)) {
			const err = new Error(`Duplicate domain "${domain}" in SSO_DOMAINS`)
			err.status = 500
			throw err
		}
		domains.set(domain, { domain, provider, strict: flag === 'strict' })
	}
	return domains
}

function getSsoDomain (account, domains = parseSsoDomains()) {
	const domain = getEmailDomain(account)
	return domain ? (domains.get(domain) || null) : null
}

function assertSsoLogin (provider, account) {
	const cleanProvider = String(provider || '').trim().toLowerCase()
	const pin = getSsoDomain(account)
	if (pin && pin.provider !== cleanProvider) {
		const err = new Error(`Access denied: SSO domain "${pin.domain}" requires signing in with "${pin.provider}"`)
		err.status = 403
		throw err
	}
}

function assertSsoLink (existingLogins = [], provider, account = null) {
	const cleanProvider = String(provider || '').trim().toLowerCase()
	const domains = parseSsoDomains()
	for (const login of existingLogins) {
		const existingPin = getSsoDomain(login.account, domains)
		if (existingPin && existingPin.provider !== cleanProvider) {
			const err = new Error(`Access denied: SSO domain "${existingPin.domain}" prevents linking logins from "${cleanProvider}"`)
			err.status = 403
			throw err
		}
	}
	const targetPin = account ? getSsoDomain(account, domains) : null
	if (targetPin) {
		if (targetPin.provider !== cleanProvider) {
			const err = new Error(`Access denied: SSO domain "${targetPin.domain}" requires linking with "${targetPin.provider}"`)
			err.status = 403
			throw err
		}
		if (existingLogins.some(l => String(l.provider || '').trim().toLowerCase() !== targetPin.provider)) {
			const err = new Error(`Access denied: SSO domain "${targetPin.domain}" cannot be linked to an account with other sign-in providers`)
			err.status = 403
			throw err
		}
	}
}

function resolveShareProvider (selfLogins = [], targetAccount, explicitProvider = null) {
	const domains = parseSsoDomains()
	const cleanProvider = explicitProvider ? String(explicitProvider).trim().toLowerCase() : null
	const targetPin = getSsoDomain(targetAccount, domains)
	if (targetPin && cleanProvider && cleanProvider !== targetPin.provider) {
		const err = new Error(`Access denied: SSO domain "${targetPin.domain}" requires sharing within "${targetPin.provider}"`)
		err.status = 403
		throw err
	}
	const strictPins = []
	for (const login of selfLogins) {
		const pin = getSsoDomain(login.account, domains)
		if (pin?.strict) strictPins.push(pin)
	}
	const effectiveProvider = cleanProvider || targetPin?.provider || strictPins[0]?.provider || null
	for (const pin of strictPins) {
		if (effectiveProvider !== pin.provider) {
			const err = new Error(`Access denied: SSO domain "${pin.domain}" requires sharing within "${pin.provider}"`)
			err.status = 403
			throw err
		}
	}
	return effectiveProvider
}

function shouldClaimUnscoped (provider, account, { verifiedEmail = false } = {}) {
	const cleanProvider = String(provider || '').trim().toLowerCase()
	const pin = getSsoDomain(account)
	return pin ? pin.provider === cleanProvider : Boolean(verifiedEmail)
}
