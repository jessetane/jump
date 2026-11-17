try {
	process.loadEnvFile()
} catch (err) {
	if (err.code !== 'ENOENT') throw err
}
