# Controlled Security Recovery Runbook

This is a future deployment procedure. It has not been executed. Do not deploy from this document without the required security, operations, supplier, and business approvals. Preserve incident records and work only in isolated staging until all gates pass.

## 1. Clean release and environment

1. Build from a reviewed, clean checkout of the patched release; record commit, artifact digest, dependency lockfile digest, and approvers. Do not deploy from a developer workstation or a working tree containing incident artifacts.
2. Use a clean application host/container image, non-root OS identity, read-only application filesystem where practical, current supported Node runtime, and a dedicated least-privilege database identity.
3. Ensure outbound firewall policy blocks private, loopback, link-local, multicast, reserved, and cloud metadata destinations. Permit only required DNS and explicitly approved supplier egress. Do not rely on application checks as a replacement for network egress filtering.
4. Remove inherited proxy variables from application workers unless a reviewed egress proxy is intentionally used. Configure trusted reverse proxies explicitly; never trust arbitrary `X-Forwarded-For` values.
5. Load secrets from a managed secret store. Never place secret values in source control, logs, deployment output, or incident reports.

## 2. Required configuration

Set and validate all of the following before process start:

- `NODE_ENV=production`
- `MONGO_URI` for the isolated/new production database endpoint and least-privilege application account.
- `JWT_SECRET`: independently generated, high-entropy value of at least 32 random bytes. Do not restore any incident-compromised or historically reused value.
- `JWT_ISSUER` and `JWT_AUDIENCE`: stable application-specific values matching the frontend/API trust boundary.
- `THEME_CODE_PEPPER`: independent high-entropy value, distinct from `JWT_SECRET` and all encryption keys.
- `JWT_EXPIRES_IN=15m` unless security approves a shorter access lifetime; do not use a multi-day access token lifetime.
- `PROVIDER_CREDENTIAL_ENCRYPTION_KEY`: independently generated 32 random bytes, base64 encoded. It must never equal or derive from `JWT_SECRET`.
- `TRUSTED_PROVIDER_HOSTS`: exact comma-separated hostnames approved by supplier owners; no wildcard entries, private IPs, or unreviewed aliases.
- `FINANCIAL_EXECUTION_ENABLED=false` for initial recovery and verification.
- `FRONTEND_URL`, `FRONTEND_VERIFY_REDIRECT_URL`, and `ALLOWED_ORIGINS`: exact HTTPS frontend origins; verify cross-origin cookie exchange behavior.
- Google OAuth client ID/secret and callback URL only after OAuth state/CSRF, account-linking, and MFA controls are approved.

The application must fail before listening if a required production secret is absent or weak. Verify the process startup output contains no secret material.

## 3. Freeze and revoke sessions

1. Keep `FINANCIAL_EXECUTION_ENABLED=false`; pause scheduled order fulfillment/provider sync and keep supplier egress blocked at the firewall during initial startup.
2. Rotate `JWT_SECRET` to a fresh unrelated value. This invalidates existing signed tokens. Never put the retired value in the environment to recover access.
3. Apply a reviewed database migration that increments `sessionVersion` for every account. Preserve an encrypted pre-migration snapshot and record counts/results without logging personal data.
4. Force password resets for affected administrative identities and review MFA enrollment independently. Suspend isolated accounts until incident response approves reactivation.
5. Validate login, pending MFA, expired token, revoked session, suspended account, and role/permission changes against a staging copy.

## 4. Database readiness and supplier replacement

1. Restore or clone only into isolated staging first. Verify indexes and schema readiness checks there; never point test runners at production MongoDB.
2. Inventory provider records and compare them with incident evidence and supplier owner records. Treat every supplier credential as compromised.
3. Contact supplier owners through the organization's approved incident channel, rotate/reissue each supplier credential, and revoke historical tokens at the supplier.
4. Approve exact supplier hostnames out-of-band. Add only approved hosts to `TRUSTED_PROVIDER_HOSTS`, review public DNS answers, and test certificate name validation in staging.
5. Replace provider credentials through the protected application path so the model encrypts and binds the new token to the exact approved host. Existing provider records without `credentialHost` must remain disabled until this is complete.
6. Verify provider API list/get/create/update responses, audit rows, errors, and application logs contain no plaintext credentials. Never serialize raw database rows to logs.
7. Confirm no production credential depended on a retired JWT secret. Do not attempt unaudited bulk decryption or restore the previous key.

## 5. Isolated verification and read-only window

1. Use an isolated MongoDB database and supplier mocks/sandboxes only. Run `npm ci` in the clean build environment, then `npm test -- --silent` and the targeted security suites. Record exact command, commit, counts, environment class, and failures.
2. Test DNS rebinding, prohibited IPv4/IPv6 ranges, redirects, proxy settings, malformed URLs, credential host mismatch, TLS failure, response/timeout bounds, and emergency mode against controlled local fixtures.
3. Test ADMIN, SUPERVISOR, and CUSTOMER permissions per route; include target accounts with equal and higher privilege. Verify audits use the actual authenticated actor and role.
4. Keep execution disabled. Read-only APIs that remain available include health, catalog/product reads, account/session-authenticated reads, order history, wallet/transaction history, provider metadata reads, maintenance status, and audit review, subject to normal authorization. Supplier balance/catalog/test calls are outbound and remain blocked. All order creation/retry, wallet debit/credit/refund/adjustment, deposit approval/recovery, and automated fulfillment are blocked.
5. Confirm workers report skipped work and do not create balances, orders, refunds, or supplier requests while the switch is off.

## 6. Staged recovery

1. Security and incident response sign off on evidence preservation, account inventory, supplier credential replacement, authorization tests, OAuth integration, and dependency review.
2. Enable supplier connectivity only for approved sandbox/low-risk suppliers while keeping financial execution disabled. Verify audit events, destination binding, DNS/TLS, and reconciliation.
3. Enable financial execution for a tightly monitored, low-volume cohort only after the provider owner and finance owner confirm supplier-side idempotency and refunds. Monitor wallet ledger invariants, order retries, supplier transaction IDs, audit delivery, and security denials.
4. Expand cohorts in documented stages. Pause immediately on unexplained supplier calls, destination mismatch, audit failure, duplicate order, balance invariant failure, or unexpected privileged action.
5. Keep incident dashboards and supplier reconciliation active through the agreed heightened-monitoring period.

## 7. Rollback and stop procedure

- Set `FINANCIAL_EXECUTION_ENABLED=false`, block supplier egress at the network boundary, pause fulfillment/sync workers, and preserve logs/database snapshots before any repair.
- Roll back only to a separately reviewed patched artifact that retains SSRF, credential, and session controls. Never roll back to a build with unrestricted supplier URLs, plaintext credential exposure, or compromised secrets.
- Do not roll back JWT or provider encryption keys. Key rotation and session invalidation are containment controls, not application-version settings.
- Reconcile supplier-side orders and local wallet ledger from immutable records before resuming. Do not issue compensating credits/refunds automatically from unverified supplier status.

## 8. Post-deployment verification

- Confirm startup secret validation, TLS and exact supplier host configuration, egress controls, and no proxy bypass.
- Confirm all old user sessions fail and new sessions honor MFA, issuer/audience, short expiry, active status, and session version.
- Confirm no query-string OAuth bearer token is emitted and frontend cookie exchange works only from the configured Origin.
- Confirm supplier API responses contain no credential fields; verify credential host binding and supplier-side token rotation.
- Confirm emergency mode blocks HTTP, administrative, worker, retry, recovery, and supplier execution paths.
- Confirm immutable audit attribution, critical audit-write behavior, wallet/order reconciliation, and incident monitoring.
- Record explicit unresolved findings and secure sign-off before classifying production recovery as ready.
