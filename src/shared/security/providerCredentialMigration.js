'use strict';

const crypto = require('node:crypto');
const { canonicalProviderUrl, parseTrustedHosts } = require('./providerHttp');

const parseKey = (value, name) => {
    const key = Buffer.from(String(value || ''), 'base64');
    if (key.length !== 32) throw new Error(`${name} must be a base64 encoded 32-byte key`);
    return key;
};

const sealBackup = (value, keyValue) => {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', parseKey(keyValue, 'PROVIDER_MIGRATION_BACKUP_KEY'), iv);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return { version: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
};

const openBackup = (envelope, keyValue) => {
    if (envelope?.version !== 1) throw new Error('Unsupported provider migration backup version');
    const decipher = crypto.createDecipheriv('aes-256-gcm', parseKey(keyValue, 'PROVIDER_MIGRATION_BACKUP_KEY'), Buffer.from(envelope.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
};

const prepareProviderMigration = (provider, { trustedHosts = parseTrustedHosts(), encrypt }) => {
    const base = canonicalProviderUrl(provider.baseUrl, trustedHosts);
    const changes = {};
    const previous = {};
    for (const field of ['apiToken', 'apiKey']) {
        const value = provider[field];
        if (value == null || value === '') continue;
        if (typeof value !== 'string') throw new Error(`Provider ${provider._id} has a malformed ${field}`);
        if (value.startsWith('enc:')) {
            if (!/^enc:v1:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*$/.test(value)) {
                throw new Error(`Provider ${provider._id} has unsupported or malformed encrypted ${field}`);
            }
            continue;
        }
        previous[field] = value;
        changes[field] = encrypt(value);
    }
    if (!Object.keys(changes).length) return { providerId: String(provider._id), changed: false, reason: 'already encrypted or no credentials' };
    previous.credentialHost = provider.credentialHost || null;
    return {
        providerId: String(provider._id),
        changed: true,
        changes: { ...changes, credentialHost: base.hostname },
        previous,
    };
};

const assertStagingDatabase = (uri, env) => {
    if (env.NODE_ENV !== 'staging') throw new Error('Provider credential migration may connect only with NODE_ENV=staging');
    if (!uri) throw new Error('MONGO_URI is required for an explicitly authorized staging run');
    const stagingHosts = String(env.PROVIDER_MIGRATION_STAGING_HOSTS || '').split(',').map((host) => host.trim().toLowerCase()).filter(Boolean);
    const stagingDatabase = String(env.PROVIDER_MIGRATION_STAGING_DATABASE || '').trim();
    if (!stagingHosts.length || !stagingDatabase) throw new Error('Explicit PROVIDER_MIGRATION_STAGING_HOSTS and PROVIDER_MIGRATION_STAGING_DATABASE are required');
    let parsed;
    try { parsed = new URL(uri); } catch { throw new Error('MONGO_URI is invalid'); }
    const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
    const database = decodeURIComponent(parsed.pathname.replace(/^\//, '').split('/')[0] || '');
    const target = `${host}/${database}`.toLowerCase();
    if (/(^|[./-])prod(uction)?([./-]|$)/.test(target)) throw new Error('Production database targets are prohibited');
    if (['localhost', '127.0.0.1', '::1'].includes(host)) throw new Error('Use an explicit isolated staging database, not local or production');
    if (!stagingHosts.includes(host)) throw new Error('MONGO_URI host is not in PROVIDER_MIGRATION_STAGING_HOSTS');
    if (database !== stagingDatabase) throw new Error('MONGO_URI database does not match PROVIDER_MIGRATION_STAGING_DATABASE');
    return true;
};

module.exports = { sealBackup, openBackup, prepareProviderMigration, assertStagingDatabase };
