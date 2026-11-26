'use strict';

const crypto = require('node:crypto');
const KEY_ENV = 'PROVIDER_CREDENTIAL_ENCRYPTION_KEY';
const TEST_KEY = Buffer.alloc(32, 0x5a);

const getKey = () => {
    if (!process.env[KEY_ENV] && process.env.NODE_ENV === 'test') return TEST_KEY;
    const key = Buffer.from(process.env[KEY_ENV] || '', 'base64');
    if (key.length !== 32) throw new Error(`${KEY_ENV} must be a base64 encoded 32-byte key`);
    return key;
};

const encryptCredential = (value) => {
    if (value == null || value === '') return value;
    const text = String(value);
    if (text.startsWith('enc:v1:')) return text;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return `enc:v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${encrypted.toString('base64')}`;
};

const decryptCredential = (value) => {
    if (value == null || value === '' || !String(value).startsWith('enc:')) return value;
    const parts = String(value).split(':');
    if (parts.length !== 5 || parts[1] !== 'v1') throw new Error('Unsupported provider credential ciphertext version');
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(parts[2], 'base64'));
        decipher.setAuthTag(Buffer.from(parts[3], 'base64'));
        return Buffer.concat([decipher.update(Buffer.from(parts[4], 'base64')), decipher.final()]).toString('utf8');
    } catch {
        throw new Error('Provider credentials cannot be decrypted; replace credentials using the controlled migration procedure');
    }
};

module.exports = { encryptCredential, decryptCredential };
