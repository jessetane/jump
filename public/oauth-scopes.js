export {
	dedupeImpliedScopes,
	findSubsumedTokens,
	measureAuthUrlLength
}

function walkImpliedScopes (scopes, impliedScopes, includeRoots = true) {
	const result = new Set(includeRoots ? scopes : undefined)
	if (!impliedScopes) return result
	const queue = Array.from(scopes)
	for (let i = 0; i < queue.length; i++) {
		const scope = queue[i]
		const children = impliedScopes[scope]
		if (!children) continue
		for (const child of children) {
			if (child !== scope && !result.has(child)) {
				result.add(child)
				queue.push(child)
			}
		}
	}
	return result
}

function collectCoveredScopes (items, activeTokens, excludeToken = null) {
	const covered = new Set()
	for (const source of items) {
		if (source.token === excludeToken || !activeTokens.has(source.token)) continue
		for (const s of source.covered) covered.add(s)
	}
	return covered
}

function findSubsumedTokens (services, selectedTokens, impliedScopes = null) {
	if (!Array.isArray(services)) return new Set()
	const selected = selectedTokens instanceof Set ? selectedTokens : new Set(selectedTokens)
	const items = []
	for (const svc of services) {
		if (!svc?.scopes) continue
		for (const [mode, scopes] of Object.entries(svc.scopes)) {
			if (!Array.isArray(scopes) || scopes.length === 0) continue
			items.push({
				token: `${svc.id}:${mode}`,
				scopes,
				covered: walkImpliedScopes(scopes, impliedScopes, true)
			})
		}
	}
	const activeSelected = new Set(selected)
	const subsumed = new Set()
	for (const target of items) {
		if (!activeSelected.has(target.token)) continue
		const coveredByOthers = collectCoveredScopes(items, activeSelected, target.token)
		if (target.scopes.every(s => coveredByOthers.has(s))) {
			activeSelected.delete(target.token)
			subsumed.add(target.token)
		}
	}
	const activeCovered = collectCoveredScopes(items, activeSelected)
	for (const target of items) {
		if (!selected.has(target.token) && target.scopes.every(s => activeCovered.has(s))) {
			subsumed.add(target.token)
		}
	}
	return subsumed
}

function dedupeImpliedScopes (scopeSet, impliedScopes) {
	if (!impliedScopes) return Array.from(scopeSet)
	const suppressed = walkImpliedScopes(scopeSet, impliedScopes, false)
	return Array.from(scopeSet).filter(s => !suppressed.has(s))
}

function measureAuthUrlLength (templateUrl, scopeSet, impliedScopes = null) {
	const u = new URL(templateUrl)
	const scopeStr = dedupeImpliedScopes(scopeSet, impliedScopes).join(' ')
	if (scopeStr) u.searchParams.set('scope', scopeStr)
	else u.searchParams.delete('scope')
	return u.toString().length
}
