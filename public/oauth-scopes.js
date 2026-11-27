export {
	dedupeImpliedScopes,
	measureAuthUrlLength
}

function dedupeImpliedScopes (scopeSet, impliedScopes) {
	if (!impliedScopes) return Array.from(scopeSet)
	const suppressed = new Set()
	const queue = Array.from(scopeSet)
	for (let i = 0; i < queue.length; i++) {
		const scope = queue[i]
		const children = impliedScopes[scope]
		if (!children) continue
		for (const child of children) {
			if (child !== scope && !suppressed.has(child)) {
				suppressed.add(child)
				queue.push(child)
			}
		}
	}
	return Array.from(scopeSet).filter(s => !suppressed.has(s))
}

function measureAuthUrlLength (templateUrl, scopeSet, impliedScopes = null) {
	const u = new URL(templateUrl)
	const scopeStr = dedupeImpliedScopes(scopeSet, impliedScopes).join(' ')
	if (scopeStr) u.searchParams.set('scope', scopeStr)
	else u.searchParams.delete('scope')
	return u.toString().length
}
