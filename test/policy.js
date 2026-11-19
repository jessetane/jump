import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePolicy, matchPattern, parsePolicy, validatePolicy } from '../policy.js'

test('policy: null or empty string allows all; empty array denies all', () => {
	const req = { url: 'https://www.googleapis.com/calendar/v3/calendars/primary/events', method: 'GET' }
	assert.equal(evaluatePolicy(null, req).allowed, true)
	assert.equal(evaluatePolicy(undefined, req).allowed, true)
	assert.equal(evaluatePolicy('', req).allowed, true)
	assert.equal(evaluatePolicy('   ', req).allowed, true)
	assert.equal(evaluatePolicy([], req).allowed, false)
	assert.equal(evaluatePolicy('[]', req).allowed, false)
	assert.deepEqual(parsePolicy(JSON.stringify([{ action: 'allow' }])), [{ action: 'allow' }])
	assert.equal(parsePolicy(null), null)
	assert.equal(parsePolicy(''), null)
	assert.equal(parsePolicy('not-json'), null)
	assert.equal(parsePolicy([{ invalid: true }]), null)
})

test('policy: schema validation rejects malformed rules fast', () => {
	for (const bad of [
		'not json',
		'{}',
		{ rules: [] },
		['not-an-object'],
		[null],
		[[]],
		[Object.assign(new Date(), { action: 'allow' })],
		[{}],
		[{ action: 'maybe' }],
		[{ action: 'allow', method: 'GET' }],
		[{ action: 'allow', unknownKey: 1 }],
		[{ action: 'allow', methods: 'GET' }],
		[{ action: 'allow', methods: [] }],
		[{ action: 'allow', methods: ['TRACE'] }],
		[{ action: 'allow', origin: 123 }],
		[{ action: 'allow', origin: 'http://api.stripe.com' }],
		[{ action: 'allow', origin: 'api.stripe.com' }],
		[{ action: 'allow', origin: 'https://api.stripe.com/v1' }],
		[{ action: 'allow', origin: 'https://api.stripe.com?a=1' }],
		[{ action: 'allow', path: '' }],
		[{ action: 'allow', path: '   ' }],
		[{ action: 'allow', path: 123 }],
		[{ action: 'allow', path: '/v1/events?sendUpdates=none' }],
		[{ action: 'allow', path: 'https://api.stripe.com/v1/charges' }],
		[{ action: 'allow', query: null }],
		[{ action: 'allow', query: [] }],
		[{ action: 'allow', query: Object.assign(new Date(), { a: '1' }) }],
		[{ action: 'allow', query: {} }],
		[{ action: 'allow', query: { '': '1' } }],
		[{ action: 'allow', query: { k: [] } }],
		[{ action: 'allow', query: { k: { nested: 1 } } }],
		[{ action: 'allow', query: { k: undefined } }],
		[{ action: 'allow', body: '' }],
		[{ action: 'allow', body: '   ' }],
		[{ action: 'allow', body: [] }],
		[{ action: 'allow', body: ['ok', ''] }],
		[{ action: 'allow', body: 123 }],
		[{ action: 'allow', body: Object.assign(new Date(), { a: '1' }) }],
		[{ action: 'allow', body: {} }],
		[{ action: 'allow', body: { '': '1' } }],
		[{ action: 'allow', body: { k: [] } }],
		[{ action: 'allow', body: { k: { nested: 1 } } }],
		[{ action: 'allow', body: { k: ['ok', undefined] } }],
		[{ action: 'allow', bodyType: 'form' }],
		[{ action: 'allow', body: null, bodyType: 'json' }],
		[{ action: 'allow', body: '*<Ping*', bodyType: 'form' }],
		[{ action: 'allow', body: { a: '1' }, bodyType: 'xml' }],
		[{ action: 'allow', description: 123 }]
	]) {
		assert.equal(validatePolicy(bad).valid, false, `Expected policy to fail validation: ${JSON.stringify(bad)}`)
		assert.equal(evaluatePolicy(bad, { url: 'https://api.example.com/v1', method: 'GET' }).allowed, false)
	}
	const valid = [
		{ action: 'deny', methods: ['DELETE'], description: 'No deletes' },
		{ action: 'allow', methods: ['GET', 'HEAD'], origin: 'https://*.googleapis.com/', path: '/v4/**' },
		{ action: 'allow', methods: ['POST'], path: '/v1/ping', body: null },
		{ action: 'allow', methods: ['POST'], path: '/soap', body: ['*<Get*', '*<List*'] },
		{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { currency: 'usd', capture: [true, false], coupon: null }, bodyType: 'form' }
	]
	assert.equal(validatePolicy(valid).valid, true)
})

test('policy: rule ordering, ANDed predicates, method & origin scoping', () => {
	const policy = [
		{
			action: 'deny',
			methods: ['DELETE'],
			origin: 'https://www.googleapis.com',
			path: '/calendar/v3/calendars/protected/**',
			description: 'Protected calendar deletions forbidden'
		},
		{
			action: 'allow',
			methods: ['GET', 'POST', 'DELETE'],
			origin: 'https://*.googleapis.com',
			path: '/calendar/v3/calendars/**'
		}
	]
	const blocked = evaluatePolicy(policy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/protected/events/1',
		method: 'delete'
	})
	assert.equal(blocked.allowed, false)
	assert.equal(blocked.reason, 'Protected calendar deletions forbidden')
	assert.equal(evaluatePolicy(policy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/protected/events/1',
		method: 'GET'
	}).allowed, true, 'AND semantics: GET on protected path does not match DELETE deny rule')
	assert.equal(evaluatePolicy(policy, {
		url: 'https://www.googleapis.com/calendar/v3/calendars/team/events/1',
		method: 'DELETE'
	}).allowed, true, 'AND semantics: DELETE on non-protected path does not match deny rule')
	assert.equal(evaluatePolicy(policy, {
		url: 'https://api.stripe.com/calendar/v3/calendars/team/events/1',
		method: 'GET'
	}).allowed, false, 'Origin mismatch does not match allow rule')
	assert.equal(evaluatePolicy(policy, {
		url: 'https://sheets.googleapis.com/calendar/v3/calendars/team',
		method: 'PATCH'
	}).allowed, false, 'Unlisted method PATCH falls through to default deny')
})

test('policy: path globbing, normalization, encoding, traversal, and linear-time safety', () => {
	assert.equal(matchPattern('*', 'anything'), true)
	assert.equal(matchPattern('**', '/a/b/c'), true)
	assert.equal(matchPattern('/v1/*/items', '/v1/acct_1/items'), true)
	assert.equal(matchPattern('/v1/*/items', '/v1/acct_1/sub/items'), false)
	assert.equal(matchPattern('/v1/**/items', '/v1/items'), true)
	assert.equal(matchPattern('/v1/**/items', '/v1/a/b/items'), true)
	assert.equal(matchPattern('/v1/items/**', '/v1/items'), true)
	assert.equal(matchPattern('/v1/items/**', '/v1/items/123/sub'), true)
	assert.equal(matchPattern('/**/items', '/items'), true)
	assert.equal(matchPattern('/**/items', '/a/b/items'), true)
	const start = performance.now()
	assert.equal(matchPattern('/*a*a*a*a*a*a*a*a*b', `/${'a'.repeat(40)}c`), false)
	assert.ok(performance.now() - start < 20, 'Path pattern matching must run in linear time without exponential backtracking')
	const denyAdmin = [
		{ action: 'deny', path: '/v1/admin/**' },
		{ action: 'allow', path: '/v1/**' }
	]
	for (const bypassAttempt of [
		'https://api.example.com/v1/admin/users',
		'https://api.example.com/v1/ADMIN/users',
		'https://api.example.com/v1//admin//users',
		'https://api.example.com///v1/admin',
		'https://api.example.com/v1/%61%64%6d%69%6e/users',
		'https://api.example.com/v1/public/../admin/users',
		'https://api.example.com/v1/public/%2e%2e/admin/users',
		'https://api.example.com/v1/public/%252e%252e/admin/users',
		'https://api.example.com/v1/public\\..\\admin\\users',
		'https://api.example.com/v1/admin%5cusers'
	]) {
		assert.equal(
			evaluatePolicy(denyAdmin, { url: bypassAttempt, method: 'GET' }).allowed,
			false,
			`Path bypass attempt must be blocked: ${bypassAttempt}`
		)
	}
	assert.equal(evaluatePolicy([
		{ action: 'allow', path: '/storage/v1/b/my-bucket/o/*' }
	], {
		url: 'https://storage.googleapis.com/storage/v1/b/my-bucket/o/folder%2Freport%402026.pdf',
		method: 'GET'
	}).allowed, true, 'Intra-segment %2F stays within single segment while %40 normalizes to @')
})

test('policy: allow vs deny symmetry on query parameters (scalars, globs, null, and repeated params)', () => {
	const allowOnlySafe = [
		{
			action: 'allow',
			path: '/events/**',
			query: {
				sendUpdates: ['none', null],
				conferenceDataVersion: null
			}
		}
	]
	assert.equal(evaluatePolicy(allowOnlySafe, { url: 'https://api.example.com/events/1' }).allowed, true)
	assert.equal(evaluatePolicy(allowOnlySafe, { url: 'https://api.example.com/events/1?sendUpdates=none' }).allowed, true)
	assert.equal(evaluatePolicy(allowOnlySafe, { url: 'https://api.example.com/events/1?sendUpdates=NONE' }).allowed, true)
	assert.equal(evaluatePolicy(allowOnlySafe, { url: 'https://api.example.com/events/1?sendUpdates=all' }).allowed, false)
	assert.equal(evaluatePolicy(allowOnlySafe, { url: 'https://api.example.com/events/1?sendUpdates=none&sendUpdates=all' }).allowed, false, 'allow rule requires EVERY repeated param to match')
	assert.equal(evaluatePolicy(allowOnlySafe, { url: 'https://api.example.com/events/1?conferenceDataVersion=1' }).allowed, false)
	const denyDangerous = [
		{
			action: 'deny',
			path: '/events/**',
			query: { sendUpdates: 'all' }
		},
		{ action: 'allow', path: '/events/**' }
	]
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1' }).allowed, true)
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1?sendUpdates=none' }).allowed, true)
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1?sendUpdates=all' }).allowed, false)
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1?sendUpdates=all&sendUpdates=none' }).allowed, false, 'deny rule must block when ANY repeated query param matches (parameter pollution)')
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1?sendUpdates=none&sendUpdates=ALL' }).allowed, false, 'deny rule must block when trailing repeated query param matches case-insensitively')
})

test('policy: allow vs deny symmetry on JSON & form body fields (arrays, nested objects, null, prototype keys)', () => {
	const allowTags = [
		{ action: 'allow', methods: ['POST'], path: '/v1/items', body: { tags: ['safe-*', 'public'], debug: null } }
	]
	assert.equal(evaluatePolicy(allowTags, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { tags: ['public', 'safe-1'] }
	}).allowed, true)
	assert.equal(evaluatePolicy(allowTags, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { tags: ['public', 'secret'] }
	}).allowed, false, 'allow rule rejects array when any element fails pattern')
	assert.equal(evaluatePolicy(allowTags, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { tags: [] }
	}).allowed, false, 'allow rule rejects empty array against non-null pattern')
	assert.equal(evaluatePolicy(allowTags, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { tags: { nested: 'public' } }
	}).allowed, false, 'allow rule rejects nested object against scalar pattern')
	const denyTagsJson = [
		{ action: 'deny', methods: ['POST'], path: '/v1/items', body: { tags: 'admin-*' } },
		{ action: 'deny', methods: ['POST'], path: '/v1/items', body: { recipient: '*@competitor.com' } },
		{ action: 'allow', methods: ['POST'], path: '/v1/items' }
	]
	assert.equal(evaluatePolicy(denyTagsJson, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { tags: ['public', 'safe'], recipient: 'alice@partner.com' }
	}).allowed, true)
	assert.equal(evaluatePolicy(denyTagsJson, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { tags: ['public', 'admin-root'] }
	}).allowed, false, 'deny rule must block JSON array when ANY element matches forbidden pattern')
	assert.equal(evaluatePolicy(denyTagsJson, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { recipient: ['alice@partner.com', 'leak@competitor.com'] }
	}).allowed, false, 'deny rule must block when scalar field is replaced with array containing forbidden value')
	assert.equal(evaluatePolicy(denyTagsJson, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: { recipient: { email: 'leak@competitor.com' } }
	}).allowed, false, 'deny rule must fail closed when expected scalar field is sent as a nested object')
	const denyForm = [
		{ action: 'deny', methods: ['POST'], path: '/v3/messages', body: { tag: 'internal-*' }, bodyType: 'form' },
		{ action: 'allow', methods: ['POST'], path: '/v3/messages' }
	]
	assert.equal(evaluatePolicy(denyForm, {
		url: 'https://api.mailgun.net/v3/messages',
		method: 'POST',
		body: 'to=a@b.com&tag=welcome&tag=internal-secret'
	}).allowed, false, 'deny rule with bodyType: form must block repeated form key when any value matches')
	assert.equal(evaluatePolicy(denyForm, {
		url: 'https://api.mailgun.net/v3/messages',
		method: 'POST',
		body: 'to=a@b.com&tag=welcome&tag=onboarding'
	}).allowed, true)
	assert.equal(evaluatePolicy([
		{ action: 'allow', methods: ['POST'], path: '/v1/proto', body: { toString: '*', constructor: '*' } }
	], {
		url: 'https://api.example.com/v1/proto',
		method: 'POST',
		body: {}
	}).allowed, false, 'Object.prototype properties never satisfy field-map rules')
})

test('policy: raw string/Buffer parser differentials, duplicate JSON keys, and Content-Type consistency', () => {
	const allowUsdJson = [
		{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { currency: 'usd' } }
	]
	assert.equal(evaluatePolicy(allowUsdJson, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		contentType: 'multipart/form-data; boundary=B',
		body: '{"currency":"usd","_":"\\r\\n--B\\r\\nContent-Disposition: form-data; name=\\"currency\\"\\r\\n\\r\\neur\\r\\n--B--\\r\\n"}'
	}).allowed, false, 'JSON/multipart polyglot with Content-Type: multipart/form-data must not pass bodyType: json allow rule')
	assert.equal(evaluatePolicy(allowUsdJson, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		contentType: 'application/json; charset=utf-8',
		body: '{"currency":"usd"}'
	}).allowed, true)
	assert.equal(evaluatePolicy(allowUsdJson, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '{"currency":"eur","currency":"usd"}'
	}).allowed, false, 'Raw JSON string with duplicate keys must be rejected to prevent first-key vs last-key parser differentials')
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' } },
		{ action: 'allow' }
	], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '{"currency":"btc","currency":"usd"}'
	}).allowed, false, 'Deny rule must fail closed on raw JSON with duplicate keys')
	const allowFormNoDest = [
		{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { destination: null }, bodyType: 'form' }
	]
	assert.equal(evaluatePolicy(allowFormNoDest, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		contentType: 'application/xml',
		body: '<Charge><destination>acct_evil</destination></Charge>&dry_run=1'
	}).allowed, false, 'Compact XML with Content-Type: application/xml must not pass bodyType: form allow rule')
	const denyRawSecret = [
		{ action: 'deny', methods: ['POST'], path: '/v1/items', body: '*secret*' },
		{ action: 'allow', methods: ['POST'], path: '/v1/items' }
	]
	assert.equal(evaluatePolicy(denyRawSecret, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: [{ k: 'secret_val' }]
	}).allowed, false, 'Raw glob deny rule must inspect JSON-serialized array body matching executeUpstream')
	const customInstance = Object.assign(Object.create({ protoProp: 1 }), { k: 'secret_val' })
	assert.equal(evaluatePolicy(denyRawSecret, {
		url: 'https://api.example.com/v1/items',
		method: 'POST',
		body: customInstance
	}).allowed, false, 'Raw glob deny rule must inspect JSON-serialized non-plain object body matching executeUpstream')
})
