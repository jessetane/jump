import * as google from './google.js'

export {
	getProvider,
	google
}

const providers = {
	google
}

function getProvider (name) {
	return providers[name] || null
}
