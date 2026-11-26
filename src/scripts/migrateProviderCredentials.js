'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const mongoose = require('mongoose');
const { Provider } = require('../modules/providers/provider.model');
const { encryptCredential } = require('../shared/security/providerCredentials');
const { parseTrustedHosts } = require('../shared/security/providerHttp');
const { assertStagingDatabase, prepareProviderMigration, sealBackup, openBackup } = require('../shared/security/providerCredentialMigration');

const args = new Set(process.argv.slice(2));
const isRollback = args.has('--rollback');
const isApply = args.has('--apply') || isRollback;
const allowedFlags = new Set(['--dry-run', '--apply', '--rollback', '--allow-staging-db', '--confirm-staging']);
for (const arg of args) if (!allowedFlags.has(arg)) throw new Error(`Unknown option: ${arg}`);
if (args.has('--apply') && args.has('--rollback')) throw new Error('Choose either --apply or --rollback');

const run = async () => {
    if (!isApply && !args.has('--dry-run')) {
        console.log('DRY RUN (default): no database connection was made. Use --allow-staging-db --dry-run to inspect an isolated staging database.');
        return;
    }
    if (!args.has('--allow-staging-db')) throw new Error('A database connection requires --allow-staging-db');
    if (isApply && !args.has('--confirm-staging')) throw new Error('Changes require --confirm-staging');
    assertStagingDatabase(process.env.MONGO_URI, process.env);
    if (!process.env.PROVIDER_CREDENTIAL_ENCRYPTION_KEY) throw new Error('PROVIDER_CREDENTIAL_ENCRYPTION_KEY is required');
    if (isApply && !process.env.PROVIDER_MIGRATION_BACKUP_KEY) throw new Error('PROVIDER_MIGRATION_BACKUP_KEY is required');
    if (!parseTrustedHosts().size) throw new Error('TRUSTED_PROVIDER_HOSTS must be configured for staging');

    const backupFile = process.env.PROVIDER_MIGRATION_BACKUP_FILE;
    if (isApply && (!backupFile || !path.isAbsolute(backupFile))) throw new Error('Set PROVIDER_MIGRATION_BACKUP_FILE to an absolute path outside the repository');
    if (backupFile && path.resolve(backupFile).startsWith(`${path.resolve(process.cwd())}${path.sep}`)) throw new Error('Migration backup must be stored outside the repository');

    await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 10000 });
    try {
        const providers = await Provider.collection.find({}, { projection: { name: 1, baseUrl: 1, credentialHost: 1, apiToken: 1, apiKey: 1 } }).toArray();
        if (isRollback) {
            const envelope = JSON.parse(await fs.readFile(backupFile, 'utf8'));
            const backup = openBackup(envelope, process.env.PROVIDER_MIGRATION_BACKUP_KEY);
            let rolledBack = 0;
            for (const item of backup.items) {
                const provider = providers.find((record) => String(record._id) === item.providerId);
                if (!provider) throw new Error(`Provider ${item.providerId} is missing; rollback stopped`);
                const filter = { _id: provider._id, ...item.migratedValues };
                const $set = {};
                for (const [field, value] of Object.entries(item.previous)) {
                    $set[field] = field === 'credentialHost' ? value : encryptCredential(value);
                }
                const result = await Provider.collection.updateOne(filter, { $set });
                if (result.matchedCount === 1) {
                    rolledBack += 1;
                    continue;
                }
                const alreadyRestored = Object.entries(item.previous).every(([field, value]) => (provider[field] ?? null) === value);
                if (!alreadyRestored) throw new Error(`Provider ${item.providerId} changed since migration; rollback stopped safely`);
            }
            console.log(`Rollback complete for ${rolledBack} provider records. Credential values remain encrypted.`);
            return;
        }

        const plan = providers.map((provider) => ({
            provider,
            entry: prepareProviderMigration(provider, { encrypt: encryptCredential }),
        }));
        const changed = plan.filter(({ entry }) => entry.changed);
        console.log(`${isApply ? 'APPLY' : 'DRY RUN'}: ${providers.length} provider records inspected; ${changed.length} require migration.`);
        for (const { entry } of changed) console.log(`Provider ${entry.providerId}: credential encryption and trusted host binding required.`);
        if (!isApply) return;

        const items = changed.map(({ entry }) => ({ providerId: entry.providerId, previous: entry.previous, migratedValues: entry.changes }));
        const envelope = sealBackup({ version: 1, createdAt: new Date().toISOString(), items }, process.env.PROVIDER_MIGRATION_BACKUP_KEY);
        // Persist and verify the rollback artifact before making the first DB write.
        await fs.writeFile(backupFile, `${JSON.stringify(envelope)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
        openBackup(JSON.parse(await fs.readFile(backupFile, 'utf8')), process.env.PROVIDER_MIGRATION_BACKUP_KEY);
        for (const { provider, entry } of changed) {
            const filter = { _id: provider._id };
            for (const key of Object.keys(entry.previous)) filter[key] = provider[key] ?? null;
            const result = await Provider.collection.updateOne(filter, { $set: entry.changes });
            if (result.matchedCount !== 1) throw new Error(`Provider ${entry.providerId} changed during migration; encrypted backup is available for recovery`);
        }
        console.log(`Migration complete for ${items.length} records. Encrypted rollback backup saved to the configured external path.`);
    } finally {
        await mongoose.disconnect();
    }
};

run().catch((error) => {
    console.error(`Provider credential migration stopped: ${error.message}`);
    process.exitCode = 1;
});
