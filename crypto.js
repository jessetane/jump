import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

export {
	generateKey,
	parseKey,
	parseKeyList,
	loadKeys,
	getKeys,
	secretContext,
	encryptSecret,
	openSecret,
	decryptSecret
}

const KEY_BYTES = 32
const SALT_BYTES = 16
const IV_BYTES = 12
const TAG_BYTES = 16
const KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/
const HKDF_INFO_PREFIX = 'jump:tokens:v1:'

let activeKeys = null

function generateKey () {
	return randomBytes(KEY_BYTES).toString('base64url')
}

function parseKey (raw, label = 'encryption key') {
	const trimmed = typeof raw === 'string' ? raw.trim() : ''
	if (!KEY_PATTERN.test(trimmed)) {
		throw new Error(`Invalid ${label}: expected 32-byte base64url key (43 chars)`)
	}
	const buf = Buffer.from(trimmed, 'base64url')
	if (buf.byteLength !== KEY_BYTES || buf.toString('base64url') !== trimmed) {
		throw new Error(`Invalid ${label}: expected canonical 32-byte base64url key`)
	}
	return buf
}

function parseKeyList (raw, label = 'ENCRYPTION_KEY') {
	const trimmed = typeof raw === 'string' ? raw.trim() : ''
	if (!trimmed) {
		throw new Error(`Invalid ${label}: key material is empty`)
	}
	const keys = []
	const seen = new Set()
	for (const part of trimmed.split(',')) {
		const clean = part.trim()
		if (!clean) {
			throw new Error(`Invalid ${label}: empty key entry`)
		}
		if (seen.has(clean)) {
			throw new Error(`Invalid ${label}: duplicate encryption key`)
		}
		seen.add(clean)
		keys.push(parseKey(clean, label))
	}
	return keys
}

function tightenKeyMode (filePath) {
	if ((fs.statSync(filePath).mode & 0o077) !== 0) {
		fs.chmodSync(filePath, 0o600)
	}
}

function writeKeyFile (filePath) {
	const key = generateKey()
	const prevUmask = process.umask(0o077)
	try {
		fs.writeFileSync(filePath, `${key}\n`, { mode: 0o600, flag: 'wx' })
	} finally {
		process.umask(prevUmask)
	}
	return key
}

function loadKeys ({ dbPath = process.env.DB_PATH || './data.db', encrypted = false } = {}) {
	const credDir = process.env.CREDENTIALS_DIRECTORY?.trim()
	if (credDir) {
		const keyPath = path.join(credDir, 'jump.key')
		if (!fs.existsSync(keyPath)) {
			throw new Error(`Missing systemd credential: ${keyPath}`)
		}
		const currentKey = parseKey(fs.readFileSync(keyPath, 'utf8'), keyPath)
		const keys = [currentKey]
		const oldKeyPath = path.join(credDir, 'jump.key.old')
		if (fs.existsSync(oldKeyPath)) {
			const oldKey = parseKey(fs.readFileSync(oldKeyPath, 'utf8'), oldKeyPath)
			if (!oldKey.equals(currentKey)) keys.push(oldKey)
		}
		activeKeys = keys
		return activeKeys
	}
	const envKey = process.env.ENCRYPTION_KEY?.trim()
	if (envKey) {
		activeKeys = parseKeyList(envKey, 'ENCRYPTION_KEY')
		return activeKeys
	}
	const keyPath = `${dbPath}.key`
	const oldKeyPath = `${dbPath}.key.old`
	const hasKey = fs.existsSync(keyPath)
	const hasOldKey = fs.existsSync(oldKeyPath)
	if (!hasKey && encrypted && !hasOldKey) {
		throw new Error(`Missing encryption key file "${keyPath}" for encrypted database`)
	}
	const oldKey = hasOldKey ? parseKey(fs.readFileSync(oldKeyPath, 'utf8'), oldKeyPath) : null
	if (hasOldKey) tightenKeyMode(oldKeyPath)
	const rawCurrent = hasKey ? fs.readFileSync(keyPath, 'utf8') : writeKeyFile(keyPath)
	if (hasKey) tightenKeyMode(keyPath)
	const currentKey = parseKey(rawCurrent, keyPath)
	const keys = [currentKey]
	if (oldKey && !oldKey.equals(currentKey)) keys.push(oldKey)
	activeKeys = keys
	return activeKeys
}

function getKeys () {
	if (!activeKeys) {
		throw new Error('Encryption key is not initialized')
	}
	return activeKeys
}

function secretContext (id, provider, type, field) {
	return JSON.stringify([id, provider, type, field])
}

function deriveSubkey (masterKey, salt, context) {
	return Buffer.from(hkdfSync('sha256', masterKey, salt, `${HKDF_INFO_PREFIX}${context}`, KEY_BYTES))
}

function encryptSecret (plaintext, context, keys = getKeys()) {
	if (plaintext === undefined || plaintext === null || plaintext === '') return plaintext
	if (typeof plaintext !== 'string') {
		throw new Error('encryptSecret requires a string plaintext')
	}
	const masterKey = keys[0]
	const salt = randomBytes(SALT_BYTES)
	const iv = randomBytes(IV_BYTES)
	const subkey = deriveSubkey(masterKey, salt, context)
	const cipher = createCipheriv('aes-256-gcm', subkey, iv, { authTagLength: TAG_BYTES })
	cipher.setAAD(Buffer.from(context, 'utf8'))
	const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
	const tag = cipher.getAuthTag()
	return `${salt.toString('base64url')}:${iv.toString('base64url')}:${tag.toString('base64url')}:${ct.toString('base64url')}`
}

function openSecret (value, context, keys = getKeys()) {
	if (typeof value !== 'string' || !value) {
		throw new Error('Malformed encrypted credential envelope')
	}
	const parts = value.split(':')
	if (parts.length !== 4) {
		throw new Error('Malformed encrypted credential envelope')
	}
	const [saltB64, ivB64, tagB64, ctB64] = parts
	const salt = Buffer.from(saltB64, 'base64url')
	const iv = Buffer.from(ivB64, 'base64url')
	const tag = Buffer.from(tagB64, 'base64url')
	const ct = Buffer.from(ctB64, 'base64url')
	if (salt.byteLength !== SALT_BYTES || iv.byteLength !== IV_BYTES || tag.byteLength !== TAG_BYTES || ct.byteLength === 0) {
		throw new Error('Malformed encrypted credential parameters')
	}
	const aad = Buffer.from(context, 'utf8')
	let lastErr = null
	for (let i = 0; i < keys.length; i++) {
		try {
			const subkey = deriveSubkey(keys[i], salt, context)
			const decipher = createDecipheriv('aes-256-gcm', subkey, iv, { authTagLength: TAG_BYTES })
			decipher.setAAD(aad)
			decipher.setAuthTag(tag)
			const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8')
			return { plaintext, keyIndex: i }
		} catch (err) {
			lastErr = err
		}
	}
	throw lastErr
}

function decryptSecret (value, context, keys = getKeys()) {
	if (value === undefined || value === null || value === '') return value
	return openSecret(value, context, keys).plaintext
}
