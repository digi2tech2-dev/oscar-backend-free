'use strict';

const {
    canonicalProviderUrl,
    isProhibitedAddress,
    createPinnedLookup,
} = require('../shared/security/providerHttp');
const { encryptCredential, decryptCredential } = require('../shared/security/providerCredentials');
const executionGate = require('../shared/security/executionGate');
const { BaseProviderAdapter } = require('../modules/providers/adapters/base.adapter');
const { Provider } = require('../modules/providers/provider.model');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const axios = require('axios');
const { createProviderHttpClient } = require('../shared/security/providerHttp');
const { sealBackup, openBackup, prepareProviderMigration, assertStagingDatabase } = require('../shared/security/providerCredentialMigration');

describe('supplier destination policy', () => {
    afterEach(() => { delete process.env.TRUSTED_PROVIDER_HOSTS; });

    test('accepts an explicitly trusted HTTPS destination', () => {
        process.env.TRUSTED_PROVIDER_HOSTS = 'supplier.example';
        expect(canonicalProviderUrl('https://supplier.example/api').hostname).toBe('supplier.example');
    });

    test.each([
        'http://supplier.example',
        'https://user:pass@supplier.example',
        'https://supplier.example:8443',
        'https://supplier.example/#fragment',
        'https://127.0.0.1',
        'https://[::1]',
    ])('rejects unsafe or malformed destination %s', (destination) => {
        process.env.TRUSTED_PROVIDER_HOSTS = 'supplier.example';
        expect(() => canonicalProviderUrl(destination)).toThrow();
    });

    test('rejects non-public IPv4 and IPv6 addresses', () => {
        for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', 'fc00::1', 'fe80::1']) {
            expect(isProhibitedAddress(address)).toBe(true);
        }
        expect(isProhibitedAddress('8.8.8.8')).toBe(false);
    });

    test('rejects mixed public and private DNS answers to prevent rebinding', async () => {
        const resolver = { lookup: (_host, _options, callback) => callback(null, [
            { address: '8.8.8.8', family: 4 },
            { address: '169.254.169.254', family: 4 },
        ]) };
        const lookup = createPinnedLookup('supplier.example', resolver);
        await new Promise((resolve) => lookup('supplier.example', {}, (error) => {
            expect(error).toBeTruthy();
            resolve();
        }));
    });

    test('DNS rebinding from public to private is rejected before a new socket connects', async () => {
        let resolution = 0;
        const resolver = { lookup: (_host, _options, callback) => {
            resolution += 1;
            callback(null, [{ address: resolution === 1 ? '8.8.8.8' : '10.0.0.7', family: 4 }]);
        } };
        const lookup = createPinnedLookup('supplier.example', resolver, new Set(['supplier.example']));
        const resolve = () => new Promise((done) => lookup('supplier.example', {}, (error) => done(error)));
        expect(await resolve()).toBeNull();
        expect(await resolve()).toBeTruthy();
    });

    test('provider HTTP client enforces redirects off, absolute URL rejection, no proxy, and TLS verification', () => {
        process.env.TRUSTED_PROVIDER_HOSTS = 'supplier.example';
        const createSpy = jest.spyOn(axios, 'create').mockReturnValue({ testClient: true });
        try {
            expect(createProviderHttpClient('https://supplier.example/api', { authorization: 'test-only' })).toEqual({ testClient: true });
            const options = createSpy.mock.calls.at(-1)[0];
            expect(options.maxRedirects).toBe(0);
            expect(options.allowAbsoluteUrls).toBe(false);
            expect(options.proxy).toBe(false);
            expect(options.httpsAgent.options.rejectUnauthorized).toBe(true);
        } finally {
            createSpy.mockRestore();
        }
    });

    test('legacy credentials without a matching trusted host are never returned to adapters', () => {
        const adapter = Object.create(BaseProviderAdapter.prototype);
        adapter.provider = { baseUrl: 'https://new.example', credentialHost: 'old.example', apiToken: 'legacy-token' };
        expect(adapter._resolveToken()).toBeNull();
    });
});

describe('provider credential migration safety', () => {
    const key = crypto.randomBytes(32).toString('base64');
    const encrypt = (value) => `enc:v1:test:${Buffer.from(value).toString('base64')}`;

    test('migration is a dry plan and binds encrypted credentials to a trusted HTTPS host', () => {
        const entry = prepareProviderMigration({ _id: 'provider-id', baseUrl: 'https://supplier.example/api', apiToken: 'sample-secret' }, {
            trustedHosts: new Set(['supplier.example']), encrypt,
        });
        expect(entry.changed).toBe(true);
        expect(entry.changes.apiToken).not.toContain('sample-secret');
        expect(entry.changes.credentialHost).toBe('supplier.example');
        expect(entry.previous.apiToken).toBe('sample-secret');
    });

    test('authenticated backup restores only when its independent key is correct', () => {
        const envelope = sealBackup({ items: [{ providerId: 'p', previous: { apiToken: 'sample-secret' } }] }, key);
        expect(openBackup(envelope, key).items[0].previous.apiToken).toBe('sample-secret');
        expect(() => openBackup(envelope, crypto.randomBytes(32).toString('base64'))).toThrow();
    });

    test('migration blocks non-staging and production database targets', () => {
        const staging = { NODE_ENV: 'staging', PROVIDER_MIGRATION_STAGING_HOSTS: 'stage.example', PROVIDER_MIGRATION_STAGING_DATABASE: 'staging' };
        expect(() => assertStagingDatabase('mongodb+srv://stage.example/staging', { ...staging, NODE_ENV: 'production' })).toThrow(/NODE_ENV=staging/);
        expect(() => assertStagingDatabase('mongodb+srv://stage.example/production', staging)).toThrow(/Production/);
        expect(() => assertStagingDatabase('mongodb+srv://other.example/staging', staging)).toThrow(/STAGING_HOSTS/);
        expect(() => assertStagingDatabase('mongodb+srv://stage.example/other', staging)).toThrow(/STAGING_DATABASE/);
        expect(assertStagingDatabase('mongodb+srv://stage.example/staging', staging)).toBe(true);
    });
});

describe('supplier credential protection and emergency control', () => {
    test('credential ciphertext is versioned, randomized, and round trips', () => {
        const first = encryptCredential('sample-credential');
        const second = encryptCredential('sample-credential');
        expect(first).toMatch(/^enc:v1:/);
        expect(first).not.toBe(second);
        expect(decryptCredential(first)).toBe('sample-credential');
    });

    test('provider API serialization omits credentials and stores ciphertext', () => {
        const provider = new Provider({
            name: 'Credential serialization test',
            baseUrl: 'https://supplier.example',
            credentialHost: 'supplier.example',
            apiToken: 'sensitive-test-value',
        });
        expect(provider.$__getValue('apiToken')).toMatch(/^enc:v1:/);
        expect(provider.toJSON()).not.toHaveProperty('apiToken');
        expect(provider.toJSON()).not.toHaveProperty('apiKey');
        expect(provider.toObject()).not.toHaveProperty('apiToken');
    });

    test('emergency mode blocks execution', () => {
        process.env.FINANCIAL_EXECUTION_ENABLED = 'false';
        expect(executionGate.isEnabled()).toBe(false);
        expect(() => executionGate.assertEnabled()).toThrow(expect.objectContaining({ code: 'EXECUTION_EMERGENCY_STOP' }));
        delete process.env.FINANCIAL_EXECUTION_ENABLED;
    });

    test.each(['false', '0', 'no', 'off'])('emergency control treats %s as disabled', (value) => {
        process.env.FINANCIAL_EXECUTION_ENABLED = value;
        expect(executionGate.isEnabled()).toBe(false);
        delete process.env.FINANCIAL_EXECUTION_ENABLED;
    });

    test('financial execution defaults off in production and on in local test mode', () => {
        const previousEnvironment = process.env.NODE_ENV;
        const previousExecution = process.env.FINANCIAL_EXECUTION_ENABLED;
        try {
            delete process.env.FINANCIAL_EXECUTION_ENABLED;
            process.env.NODE_ENV = 'production';
            expect(executionGate.isEnabled()).toBe(false);
            process.env.NODE_ENV = 'test';
            expect(executionGate.isEnabled()).toBe(true);
        } finally {
            process.env.NODE_ENV = previousEnvironment;
            if (previousExecution === undefined) delete process.env.FINANCIAL_EXECUTION_ENABLED;
            else process.env.FINANCIAL_EXECUTION_ENABLED = previousExecution;
        }
    });

    test('production configuration rejects a weak JWT secret before startup', () => {
        const result = spawnSync(process.execPath, ['-e', "require('./src/config/config')"], {
            cwd: process.cwd(),
            env: { ...process.env, NODE_ENV: 'production', MONGO_URI: 'mongodb://invalid.invalid/db', JWT_SECRET: 'short' },
            encoding: 'utf8',
        });
        expect(result.status).not.toBe(0);
        expect(`${result.stdout}${result.stderr}`).toContain('JWT_SECRET must be a high-entropy secret');
    });

    test('production configuration rejects a multi-day JWT lifetime', () => {
        const result = spawnSync(process.execPath, ['-e', "require('./src/config/config')"], {
            cwd: process.cwd(),
            env: { ...process.env, NODE_ENV: 'production', MONGO_URI: 'mongodb://invalid.invalid/db', JWT_SECRET: crypto.randomBytes(32).toString('base64'), JWT_EXPIRES_IN: '7d' },
            encoding: 'utf8',
        });
        expect(result.status).not.toBe(0);
        expect(`${result.stdout}${result.stderr}`).toContain('JWT_EXPIRES_IN must be between 1 second and 1 hour');
    });

    test('production configuration requires an independent theme code pepper', () => {
        const secret = crypto.randomBytes(32).toString('base64');
        const result = spawnSync(process.execPath, ['-e', "require('./src/config/config')"], {
            cwd: process.cwd(),
            env: { ...process.env, NODE_ENV: 'production', MONGO_URI: 'mongodb://invalid.invalid/db', JWT_SECRET: secret, THEME_CODE_PEPPER: secret },
            encoding: 'utf8',
        });
        expect(result.status).not.toBe(0);
        expect(`${result.stdout}${result.stderr}`).toContain('THEME_CODE_PEPPER must be an independent high-entropy secret');
    });
});
