# Security Incident Remediation Report

## Implementation summary

Implemented on the local `oscar-backend-release-apply` checkout only. No production systems were contacted. Detailed evidence and unresolved findings are in [SECURITY_INCIDENT_AUDIT.md](SECURITY_INCIDENT_AUDIT.md).

## Release classification

**NOT READY** — production credential replacement/rebinding, isolated staging network and OAuth verification, authorization and audit durability work, and dependency advisory review remain incomplete. Keep supplier and financial execution disabled until the deployment runbook gates are satisfied.

## Continuation from `efeeeb4`

Work continued on `codex/security-incident-remediation-20261126`; the existing branch history was preserved. This continuation adds OAuth state validation, verified Google email checks, one-time/attempt-limited email OTP verification with an independent production pepper, cookie-only OAuth handoff and frontend handling, global fail-closed audit records for privileged mutations, tighter ADMIN-only supplier credential changes/password resets, and production-default financial stop. Supplier client configuration now rejects absolute-URL overrides, redirects and proxies while requiring TLS verification and validated DNS. A default-dry-run provider migration utility has a staging-only gate and encrypted external rollback file. Frontend changes are in the same-named branch in the separate frontend repository.

These local changes do not establish that the real incident is contained: exposed supplier tokens and user sessions still need revocation; OAuth needs real configured-origin browser verification; production provider records need rotated credentials; and dependency findings and operational state need security approval. The release remains **NOT READY**.

### Supplier request boundary and credential handling

- Added `src/shared/security/providerHttp.js` and routed Royal Crown, Toros, Alkasr, and Ibra adapters through one Axios client factory. The policy requires HTTPS, exact configured supplier hostnames, port 443, no URL user-info/fragments/IP literals, safe DNS answers across A and AAAA records, socket lookup pinning, TLS verification, no redirects, no proxy environment routing, bounded timeouts and response sizes.
- Added supplier credential host binding. Missing or mismatched host binding prevents adapters from resolving a token. Both ordinary provider update services reject `baseUrl` changes; new host trust and destination replacement are operational/out-of-band.
- Added `src/shared/security/providerCredentials.js` with AES-256-GCM `enc:v1` ciphertext and an independent `PROVIDER_CREDENTIAL_ENCRYPTION_KEY`. Provider API JSON/object serialization omits `apiToken` and legacy `apiKey`; audit snapshots therefore omit plaintext credentials.
- Added direct `ipaddr.js` dependency for special-use IPv4/IPv6 classification.

### Authentication and emergency controls

- JWT access lifetime defaults to 15 minutes. Production configuration rejects weak signing secrets, requires the independent provider encryption key and explicit `TRUSTED_PROVIDER_HOSTS`, and uses configured issuer/audience with HS256-only verification.
- Added `sessionVersion` and invalidate prior tokens on document-saved password, role, status, permission, and 2FA changes. Middleware checks current version and active account status.
- Removed the production fallback coupling between theme activation-code HMAC and JWT secrets; production now requires an independent `THEME_CODE_PEPPER`.
- Google OAuth honors application MFA and no longer returns an access token in a redirect URL. Added short-lived HttpOnly handoff cookies and an Origin-checked exchange endpoint.
- Added `FINANCIAL_EXECUTION_ENABLED=false` gate to wallet operation entry points, order creation, admin retries, deposit credits/recovery, and supplier HTTP creation. Recovery workers stop rather than mutating balances during the stop.
- Fixed provider service updates to save documents through model hooks instead of using an unsafe direct update path.
- Added provider create/update/delete audit events with authenticated actor, role, request IP/user-agent, provider identity, safe before/after metadata, and detached-product counts. Credential fields remain excluded by provider serialization.

## Changed files

- Configuration and environment example: `.env.example`, `src/config/config.js`, `package.json`, `package-lock.json`.
- Security primitives: `src/shared/security/executionGate.js`, `providerHttp.js`, `providerCredentials.js`.
- Auth/session: `src/modules/auth/auth.controller.js`, `auth.routes.js`, `auth.service.js`, `src/modules/users/user.model.js`, `src/shared/middlewares/authenticate.js`, `maintenanceGate.js`.
- Supplier code: `src/modules/providers/provider.model.js`, `provider.service.js`, `provider.controller.js`, `src/modules/admin/admin.providers.service.js`, all four adapters, and `base.adapter.js`.
- Financial gates: `src/modules/wallet/wallet.service.js`, `walletOperation.service.js`, `src/modules/orders/order.service.js`, `src/modules/admin/admin.orders.service.js`, `src/modules/deposits/deposit.service.js`.
- Tests: `src/tests/securityHardening.test.js`, `src/tests/adapters.test.js`, `src/tests/maintenance.test.js`, `src/tests/walletRecoveryHttp.test.js`, `src/tests/theme.test.js`, `src/tests/provider.test.js`.
- Work tracking: `SECURITY_PROGRESS.md` and the required incident deliverables.

## Frontend OAuth changes implemented locally

Google OAuth no longer redirects with `?token=`. After the browser returns to `/auth?status=complete`, the frontend must call `POST /api/auth/oauth-session` with `credentials: 'include'`, receive the token from the no-store JSON response, and keep using it as its bearer token. If status is `requires-2fa`, post the entered code to `/api/auth/verify-2fa` with `credentials: 'include'`; the server reads the pending challenge from an HttpOnly cookie. Configure the frontend origin exactly in `FRONTEND_URL`/allowed CORS origins and test cookies over the real HTTPS deployment domains. Existing `?token=` parsing should be removed.

## Database and supplier credential migration

No database was contacted and no migration was run. A default-dry-run script, staging safeguards, and encrypted rollback artifact have been added. Existing provider documents have no trusted host binding and credentials may be plaintext or encrypted under a retired JWT-derived key. Operators must:

1. Approve each supplier host independently and set `TRUSTED_PROVIDER_HOSTS` to exact hostnames.
2. Rotate/reissue supplier credentials directly with each supplier; do not attempt to recover credentials using a rotated or compromised JWT secret.
3. Submit the replacement credential through the protected provider update operation so it is encrypted under the new independent key and bound to the approved hostname.
4. Confirm provider reads omit both token fields and conduct mocked/isolated connection tests before enabling execution.
5. Retain the prior database snapshot and incident evidence under the organization's evidence retention process; do not destroy it during migration.

The `enc:v1` format has no key identifier or online key rotation utility. Rotating its encryption key requires a controlled re-encryption/replacement plan; because this incident may have exposed keys, supplier-side credential replacement is preferred.

## Architectural decisions and limitations

- Trust is an exact host allowlist controlled outside ordinary supplier CRUD. This introduces an operational onboarding step by design.
- The DNS check rejects the request if any resolved address is prohibited and pins the chosen validated address at connection time. Staging must exercise the deployed Node/Axios agent behavior and DNS resolver, not only the pure unit tests.
- Emergency mode is configured by environment variable; infrastructure must provide a reliable controlled update/restart and keep it disabled until recovery is approved.
- This patch does not implement role step-up/recent-auth policy, supplier-side idempotency proof, or a fully exercised authorization matrix. Audit mutation records have request IDs, but end-to-end correlation with upstream logs remains unverified.
- Full OS/network/database privilege, all upload/input abuse classes, exchange-rate URL policy, browser/staging verification, and remaining dependency advisories remain open.
