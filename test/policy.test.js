import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePolicy, matchPattern, parsePolicy, validatePolicy } from '../policy.js'

test('null or empty policy allows all; empty array denies all; parsePolicy handles invalid input safely', () => {
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

test('validatePolicy rejects malformed rules and accepts valid schemas', () => {
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
		[{ action: 'allow', origin: 'https://user@api.stripe.com' }],
		[{ action: 'allow', path: '' }],
		[{ action: 'allow', path: '   ' }],
		[{ action: 'allow', path: 123 }],
		[{ action: 'allow', path: '/v1/events?sendUpdates=none' }],
		[{ action: 'allow', path: '/v1/events#frag' }],
		[{ action: 'allow', path: 'https://api.stripe.com/v1/charges' }],
		[{ action: 'allow', path: 'HTTP://api.stripe.com/v1/charges' }],
		[{ action: 'deny', path: '/v1/public/../admin/**' }],
		[{ action: 'deny', path: '/v1/public/..;/admin/**' }],
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
		[{ action: 'allow', body: { k: {} } }],
		[{ action: 'allow', body: { k: { nested: 1 } }, bodyType: 'form' }],
		[{ action: 'allow', body: { k: [{ nested: 1 }] } }],
		[{ action: 'allow', body: { k: ['ok', undefined] } }],
		[{ action: 'allow', bodyType: 'form' }],
		[{ action: 'allow', body: null, bodyType: 'json' }],
		[{ action: 'allow', body: '*<Ping*', bodyType: 'form' }],
		[{ action: 'allow', body: { a: '1' }, bodyType: 'xml' }],
		[{ action: 'allow', description: 123 }]
	]) {
		assert.equal(validatePolicy(bad).valid, false, `Expected failure: ${JSON.stringify(bad)}`)
		assert.equal(evaluatePolicy(bad, { url: 'https://api.example.com/v1', method: 'GET' }).allowed, false)
	}
	const valid = [
		{ action: 'deny', methods: ['DELETE'], description: 'No deletes' },
		{ action: 'allow', methods: ['GET', 'HEAD'], origin: 'https://*.googleapis.com/', path: '/v4/**' },
		{ action: 'allow', methods: ['POST'], path: '/v1/ping', body: null },
		{ action: 'allow', methods: ['POST'], path: '/soap', body: ['*<Get*', '*<List*'] },
		{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { currency: 'usd', 'meta.env': 'prod', capture: [true, false], coupon: null }, bodyType: 'form' }
	]
	assert.equal(validatePolicy(valid).valid, true)
})

test('sequential rule evaluation, AND semantics, method & origin scoping', () => {
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
	assert.equal(evaluatePolicy(policy, { url: 'https://www.googleapis.com/calendar/v3/calendars/protected/events/1', method: 'GET' }).allowed, true)
	assert.equal(evaluatePolicy(policy, { url: 'https://www.googleapis.com/calendar/v3/calendars/team/events/1', method: 'DELETE' }).allowed, true)
	assert.equal(evaluatePolicy(policy, { url: 'https://api.stripe.com/calendar/v3/calendars/team/events/1', method: 'GET' }).allowed, false)
	assert.equal(evaluatePolicy(policy, { url: 'https://sheets.googleapis.com/calendar/v3/calendars/team', method: 'PATCH' }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'allow', origin: 'https://www.googleapis.com', path: '/drive/**' }], { url: '/drive/v3/files', method: 'GET' }).allowed, false, 'Bare path without baseUrl must not assume googleapis.com')
	assert.equal(evaluatePolicy([{ action: 'allow', path: 'calendar/**' }], { url: '/calendar/v3/calendars', method: 'GET' }).allowed, true)
})

test('path globbing, traversal canonicalization, %2F preservation, and linear-time safety', () => {
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
	assert.equal(matchPattern('/v1/items/**', '/v1/items2'), false)
	assert.equal(matchPattern('/v1/**/items/**', '/v1/items'), true)
	assert.equal(matchPattern('/v1/**/a/*/b', '/v1/a/a/x/b'), true)
	assert.equal(matchPattern('/V1/*/Items', '/v1/abc/items'), true)
	assert.equal(matchPattern('/v1/**/a**b', '/v1/a1b'), true)
	assert.equal(matchPattern('/v1/**/a**b', '/v1/x/a1b'), true)
	assert.equal(matchPattern('/v1/**/a**b', '/v1/x/a/mid/b'), true)
	assert.equal(matchPattern('/v1/**/a**b', '/v1/x/nope'), false)
	assert.equal(matchPattern('/v1/a**b/*', '/v1/a1b/x/y'), false)
	assert.equal(matchPattern('/v1/a**b/*', '/v1/a/mid/b/x'), true)
	assert.equal(matchPattern('/v1/**/a**b/*', '/v1/x/a/mid/b/y'), true)
	assert.equal(matchPattern('/v1/**/a**b/*', '/v1/x/a1b/y/z'), false)
	assert.equal(matchPattern(null, 'x'), false)
	assert.equal(matchPattern('x', null), false)
	const startPath = performance.now()
	assert.equal(matchPattern('/*a*a*a*a*a*a*a*a*b', `/${'a'.repeat(40)}c`), false)
	assert.equal(matchPattern('/**/a/**/a/**/a/**/b', `${'/a'.repeat(30)}/c`), false)
	assert.equal(matchPattern('/**/a**a/**/a**a/**/b', `${'/a'.repeat(25)}/c`), false)
	assert.ok(performance.now() - startPath < 20)
	const startBody = performance.now()
	assert.equal(evaluatePolicy([
		{ action: 'deny', methods: ['POST'], path: '/soap', body: '*<a>*<a>*<a>*<a>*<a>*</b>*' },
		{ action: 'allow' }
	], { url: 'https://api.example.com/soap', method: 'POST', body: '<a>'.repeat(2000) }).allowed, true)
	assert.ok(performance.now() - startBody < 25)
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
		'https://api.example.com/v1/public/..;/admin/users',
		'https://api.example.com/v1/public/%2e%2e%3b/admin/users',
		'https://api.example.com/v1/.;/admin/users',
		'https://api.example.com/v1/.;v=1/admin/users',
		'https://api.example.com/v1/%2e%3b/admin/users',
		'https://api.example.com/v1/public/%252e%252e/admin/users',
		'https://api.example.com/v1/public\\..\\admin\\users',
		'https://api.example.com/v1/admin%5cusers'
	]) {
		assert.equal(evaluatePolicy(denyAdmin, { url: bypassAttempt, method: 'GET' }).allowed, false, `Must block bypass: ${bypassAttempt}`)
	}
	assert.equal(evaluatePolicy([{ action: 'allow', path: '/storage/v1/b/my-bucket/o/*' }], {
		url: 'https://storage.googleapis.com/storage/v1/b/my-bucket/o/folder%2Freport%402026.pdf',
		method: 'GET'
	}).allowed, true, 'Intra-segment %2F stays single-segment while %40 normalizes to @')
})

test('query parameter allow vs deny symmetry across scalars, null, and repeated params', () => {
	const allowSafe = [{ action: 'allow', path: '/events/**', query: { sendUpdates: ['none', null], conferenceDataVersion: null } }]
	assert.equal(evaluatePolicy(allowSafe, { url: 'https://api.example.com/events/1' }).allowed, true)
	assert.equal(evaluatePolicy(allowSafe, { url: 'https://api.example.com/events/1?sendUpdates=none' }).allowed, true)
	assert.equal(evaluatePolicy(allowSafe, { url: 'https://api.example.com/events/1?sendUpdates=NONE' }).allowed, true)
	assert.equal(evaluatePolicy(allowSafe, { url: 'https://api.example.com/events/1?sendUpdates=all' }).allowed, false)
	assert.equal(evaluatePolicy(allowSafe, { url: 'https://api.example.com/events/1?sendUpdates=none&sendUpdates=all' }).allowed, false)
	assert.equal(evaluatePolicy(allowSafe, { url: 'https://api.example.com/events/1?sendUpdates=none&sendUpdates=none' }).allowed, true)
	assert.equal(evaluatePolicy(allowSafe, { url: 'https://api.example.com/events/1?conferenceDataVersion=1' }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'allow', path: '/search', query: { q: 'project-*', toString: null } }], { url: 'https://api.example.com/search?q=project-alpha' }).allowed, true)
	const denyDangerous = [
		{ action: 'deny', path: '/events/**', query: { sendUpdates: 'all' } },
		{ action: 'allow', path: '/events/**' }
	]
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1?sendUpdates=none' }).allowed, true)
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1?sendUpdates=all' }).allowed, false)
	assert.equal(evaluatePolicy(denyDangerous, { url: 'https://api.example.com/events/1?sendUpdates=none&sendUpdates=ALL' }).allowed, false)
})

test('body field-map and raw-glob predicates across JSON, form, nested paths, arrays, and prototype keys', () => {
	const allowTags = [
		{ action: 'allow', methods: ['POST'], path: '/v1/items', body: { tags: ['safe-*', 'public'], meta: { env: 'staging' }, debug: null } }
	]
	assert.equal(evaluatePolicy(allowTags, { url: 'https://api.example.com/v1/items', method: 'POST', body: { tags: ['public', 'safe-1'], meta: { env: 'staging' } } }).allowed, true)
	assert.equal(evaluatePolicy(allowTags, { url: 'https://api.example.com/v1/items', method: 'POST', body: Buffer.from(JSON.stringify({ tags: 'safe-1', 'meta.env': 'staging' })) }).allowed, false, 'Literal dotted key does not satisfy nested object rule')
	assert.equal(evaluatePolicy(allowTags, { url: 'https://api.example.com/v1/items', method: 'POST', body: { tags: ['public', 'secret'], meta: { env: 'staging' } } }).allowed, false)
	assert.equal(evaluatePolicy(allowTags, { url: 'https://api.example.com/v1/items', method: 'POST', body: { tags: [], meta: { env: 'staging' } } }).allowed, false)
	assert.equal(evaluatePolicy(allowTags, { url: 'https://api.example.com/v1/items', method: 'POST', body: { tags: { nested: 'public' }, meta: { env: 'staging' } } }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/items', body: { 'meta.env': 'staging' } }], { url: 'https://api.example.com/v1/items', method: 'POST', body: { meta: { env: 'staging' } } }).allowed, false, 'Flat dotted rule does not traverse nested objects')
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/items', body: { 'meta.env': 'staging' } }], { url: 'https://api.example.com/v1/items', method: 'POST', body: { 'meta.env': 'staging' } }).allowed, true)
	assert.equal(validatePolicy([{ action: 'allow', body: { meta: { env: 'staging' } }, bodyType: 'form' }]).valid, false, 'Form rules reject nested objects')
	assert.equal(validatePolicy([{ action: 'allow', body: { meta: {} } }]).valid, false, 'Empty nested object rejected')
	assert.equal(validatePolicy([{ action: 'allow', query: { meta: { env: 'staging' } } }]).valid, false, 'Query rules reject nested objects')
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/ping', body: null }], { url: 'https://api.example.com/v1/ping', method: 'POST', body: Buffer.alloc(0) }).allowed, true)
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/ping', body: null }], { url: 'https://api.example.com/v1/ping', method: 'POST', body: 'non-empty' }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/slash', body: { text: 'a*b' } }], { url: 'https://api.example.com/v1/slash', method: 'POST', body: { text: 'a/mid/b' } }).allowed, true)
	const denyJson = [
		{ action: 'deny', methods: ['POST'], path: '/v1/items', body: { tags: 'admin-*' } },
		{ action: 'deny', methods: ['POST'], path: '/v1/items', body: { recipient: '*@competitor.com' } },
		{ action: 'allow', methods: ['POST'], path: '/v1/items' }
	]
	assert.equal(evaluatePolicy(denyJson, { url: 'https://api.example.com/v1/items', method: 'POST', body: { tags: ['public', 'admin-root'] } }).allowed, false)
	assert.equal(evaluatePolicy(denyJson, { url: 'https://api.example.com/v1/items', method: 'POST', body: { recipient: ['a@ok.com', 'leak@competitor.com'] } }).allowed, false)
	assert.equal(evaluatePolicy(denyJson, { url: 'https://api.example.com/v1/items', method: 'POST', body: { recipient: { email: 'ok@good.com' } } }).allowed, false, 'Scalar deny rule fails closed on object value')
	const denyNested = [
		{ action: 'deny', methods: ['POST'], path: '/v1/items', body: { recipient: { email: '*@competitor.com' } } },
		{ action: 'allow', methods: ['POST'], path: '/v1/items' }
	]
	assert.equal(evaluatePolicy(denyNested, { url: 'https://api.example.com/v1/items', method: 'POST', body: { recipient: { email: 'ok@good.com' } } }).allowed, true)
	assert.equal(evaluatePolicy(denyNested, { url: 'https://api.example.com/v1/items', method: 'POST', body: { recipient: { email: 'leak@competitor.com' } } }).allowed, false)
	assert.equal(evaluatePolicy(denyNested, { url: 'https://api.example.com/v1/items', method: 'POST', body: { 'recipient.email': 'ok@good.com', recipient: { email: 'leak@competitor.com' } } }).allowed, false)
	assert.equal(evaluatePolicy(denyNested, { url: 'https://api.example.com/v1/items', method: 'POST', body: { recipient: [{ email: 'ok@good.com' }, { email: 'leak@competitor.com' }] } }).allowed, false)
	assert.equal(evaluatePolicy(denyNested, { url: 'https://api.example.com/v1/items', method: 'POST', body: { recipient: [{ email: 'ok@good.com' }] } }).allowed, true)
	const denyForm = [
		{ action: 'deny', methods: ['POST'], path: '/v3/messages', body: { tag: 'internal-*' }, bodyType: 'form' },
		{ action: 'allow', methods: ['POST'], path: '/v3/messages' }
	]
	assert.equal(evaluatePolicy(denyForm, { url: 'https://api.mailgun.net/v3/messages', method: 'POST', body: 'to=a@b.com&tag=welcome&tag=internal-secret' }).allowed, false)
	assert.equal(evaluatePolicy(denyForm, { url: 'https://api.mailgun.net/v3/messages', method: 'POST', body: 'to=a@b.com&tag=welcome&tag=onboarding' }).allowed, true)
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/flags', body: { dry_run: '', mode: 'fast' }, bodyType: 'form' }], { url: 'https://api.example.com/v1/flags', method: 'POST', body: 'dry_run&mode=fast' }).allowed, true)
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/form', body: { '<foo>': 'bar>' }, bodyType: 'form' }], { url: 'https://api.stripe.com/v1/form', method: 'POST', body: '<foo>=bar>' }).allowed, true)
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/proto', body: { toString: '*', constructor: '*' } }], { url: 'https://api.example.com/v1/proto', method: 'POST', body: {} }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'deny', methods: ['POST'], path: '/v1/proto', body: { ['__proto__']: 'evil' }, bodyType: 'form' }, { action: 'allow', methods: ['POST'], path: '/v1/proto', body: { toString: 'hello', ['__proto__']: 'safe' }, bodyType: 'form' }], { url: 'https://api.example.com/v1/proto', method: 'POST', body: 'toString=hello&__proto__=safe' }).allowed, true)
	assert.equal(evaluatePolicy([{ action: 'deny', methods: ['POST'], path: '/v1/proto', body: { ['__proto__']: 'evil' }, bodyType: 'form' }, { action: 'allow' }], { url: 'https://api.example.com/v1/proto', method: 'POST', body: '__proto__=evil' }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'deny', query: { ['__proto__']: 'evil' } }, { action: 'allow' }], { url: 'https://api.example.com/v1/proto?__proto__=evil' }).allowed, false)
	const denyXml = [
		{ action: 'deny', methods: ['POST'], path: '/soap', body: ['*<DeleteDomain*', '*<Transfer*'] },
		{ action: 'allow', methods: ['POST'], path: '/soap', body: '*<DomainList*>*' }
	]
	assert.equal(evaluatePolicy(denyXml, { url: 'https://api.namecheap.com/soap', method: 'POST', body: '<soap:Envelope>\n<DomainList/>\n</soap:Envelope>' }).allowed, true)
	assert.equal(evaluatePolicy(denyXml, { url: 'https://api.namecheap.com/soap', method: 'POST', body: '<soap:Envelope><DeleteDomain id="1"/></soap:Envelope>' }).allowed, false)
})

test('body parser-differential defenses across Content-Type, duplicate JSON keys, polyglots, and binary payloads', () => {
	const allowUsdJson = [{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { currency: 'usd' } }]
	assert.equal(evaluatePolicy(allowUsdJson, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		contentType: 'multipart/form-data; boundary=B',
		body: '{"currency":"usd","_":"\\r\\n--B\\r\\nContent-Disposition: form-data; name=\\"currency\\"\\r\\n\\r\\neur\\r\\n--B--\\r\\n"}'
	}).allowed, false, 'Multipart Content-Type must not match bodyType: json rule')
	assert.equal(evaluatePolicy(allowUsdJson, { url: 'https://api.stripe.com/v1/charges', method: 'POST', body: '{"currency":"eur","currency":"usd"}' }).allowed, false, 'Duplicate JSON keys must fail allow rule')
	assert.equal(evaluatePolicy([{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' } }, { action: 'allow' }], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '{"currency":"btc","currency":"usd"}'
	}).allowed, false, 'Duplicate JSON keys must fail closed on deny rule')
	assert.equal(evaluatePolicy([{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' }, bodyType: 'form' }, { action: 'allow' }], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '{"currency":"btc"}'
	}).allowed, false, 'JSON sent against form deny rule fails closed')
	assert.equal(evaluatePolicy([{ action: 'deny', methods: ['POST'], path: '/v1/charges', body: { currency: 'btc' } }, { action: 'allow' }], {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: 'currency=btc&amount=1000'
	}).allowed, false, 'Form sent against json deny rule fails closed')
	const allowFormNoDest = [{ action: 'allow', methods: ['POST'], path: '/v1/charges', body: { destination: null }, bodyType: 'form' }]
	assert.equal(evaluatePolicy(allowFormNoDest, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		body: '--b=1\r\nContent-Disposition: form-data; name="destination"\r\n\r\nacct_evil\r\n--b=1--'
	}).allowed, false, 'Multipart CRLF payload must not parse as form-urlencoded')
	assert.equal(evaluatePolicy(allowFormNoDest, {
		url: 'https://api.stripe.com/v1/charges',
		method: 'POST',
		contentType: 'application/xml',
		body: '<Charge><destination>acct_evil</destination></Charge>&dry_run=1'
	}).allowed, false, 'XML Content-Type must not parse as form-urlencoded')
	const denyRawSecret = [{ action: 'deny', methods: ['POST'], path: '/v1/items', body: '*secret*' }, { action: 'allow', methods: ['POST'], path: '/v1/items' }]
	assert.equal(evaluatePolicy(denyRawSecret, { url: 'https://api.example.com/v1/items', method: 'POST', body: [{ k: 'secret_val' }] }).allowed, false)
	assert.equal(evaluatePolicy(denyRawSecret, { url: 'https://api.example.com/v1/items', method: 'POST', body: Object.assign(Object.create({ p: 1 }), { k: 'secret_val' }) }).allowed, false)
	assert.equal(evaluatePolicy([{ action: 'allow', methods: ['POST'], path: '/v1/raw' }], { url: 'https://api.example.com/v1/raw', method: 'POST', body: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0xff, 0x00]) }).allowed, true)
	assert.equal(evaluatePolicy(denyRawSecret, { url: 'https://api.example.com/v1/items', method: 'POST', objectFormat: 'form', body: { a: '1', note: 'top-secret' } }).allowed, false)
	assert.equal(evaluatePolicy(allowUsdJson, { url: 'https://api.stripe.com/v1/charges', method: 'POST', contentType: 'application/problem+json; charset=utf-8', body: '{"currency":"usd"}' }).allowed, true)
})
