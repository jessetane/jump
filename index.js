#!/usr/bin/env node

import fs from 'node:fs'
import { pathToFileURL } from 'node:url'

const isMain = Boolean(process.argv[1] && fs.existsSync(process.argv[1]) && pathToFileURL(fs.realpathSync(process.argv[1])).href === import.meta.url)
if (isMain) {
	try {
		process.loadEnvFile()
	} catch (err) {
		if (err.code !== 'ENOENT') throw err
	}
}

const [{ server, bootstrapLocalAdmin }, db] = await Promise.all([
	import('./server.js'),
	import('./db/index.js')
])

export { server, bootstrapLocalAdmin }

if (isMain) {
	const host = process.env.HOST || '127.0.0.1'
	const port = process.env.PORT || '8080'
	const bootstrapped = bootstrapLocalAdmin()
	if (bootstrapped) {
		console.log(`[bootstrap] Admin session created for localhost: ${bootstrapped.token}`)
	}
	server.listen(port, host, () => {
		console.log(`jump listening on ${host}:${port}`)
	})
	let shuttingDown = false
	function shutdown () {
		if (shuttingDown) return
		shuttingDown = true
		server.close(() => {
			db.sqlite.close()
			process.exit(0)
		})
		server.closeIdleConnections()
	}
	process.on('SIGINT', shutdown)
	process.on('SIGTERM', shutdown)
}
