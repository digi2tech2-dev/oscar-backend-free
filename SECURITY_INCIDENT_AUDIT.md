# MS Store Backend Security Incident Audit

## Scope and evidence

This is a repository-code audit of the clean `oscar-backend-release-apply` checkout at commit `d9cdda1`. `oscar-backend-main` was kept read-only. The incident observations in the supplied brief are treated as incident intelligence, not independently verified production evidence. No production server, production database, supplier endpoint, real financial operation, or external service was contacted. Local Git history was inspected by commit subject only; historical secret values were not displayed.

Repository mapping covered `src/server.js`, `src/app.js`, configuration and deployment files, authentication/OAuth, middleware and permissions, provider models/services/adapters, product and order flows, wallet and deposit workflows, scheduled jobs, audit services, and the Jest/MongoDB-memory-server suites. A repository search found supplier Axios requests only in the four concrete provider adapters; other network use is exchange-rate and email infrastructure. No webhook module was found in the scanned backend source. Direct balance mutation paths also exist in deposit and order workflows, in addition to wallet services.

## Findings

### F-01 — Supplier URL controlled by ordinary provider configuration enabled SSRF

- **Severity:** Critical (P0). **Status:** Confirmed in the original code; primary remediation implemented, staging verification pending.
- **Affected code:** `src/modules/admin/admin.providers.service.js` `updateProvider`; `src/modules/providers/provider.service.js` `updateProvider`; `src/modules/providers/adapters/{royalCrown,toros,alkasr,ibra}.adapter.js` client builders; `src/modules/providers/provider.model.js`.
- **Root cause:** Provider `baseUrl` was accepted from ordinary API configuration and passed directly into independent Axios clients. The original clients followed default redirect behavior, used environment proxy settings, and did not validate DNS answers or destination networks.
- **Impact / incident relationship:** An authorized or compromised supplier manager could point requests at loopback, private, link-local, metadata, Docker, or internal services; any attached supplier token could be exposed. This directly matches the reported destination changes and attempted SSRF. Successful internal access or credential receipt remains unverified.
- **Remediation:** Added `src/shared/security/providerHttp.js`, routed all four adapters through it, required exact `TRUSTED_PROVIDER_HOSTS` entries outside tests, require HTTPS and standard port, reject credentials/fragment/IP-literal URLs, reject any non-public DNS answer, pin the selected validated DNS answer through the socket lookup, disable redirects and proxy environment use, verify TLS, and cap request/response sizes and timeouts. Routine provider updates can no longer change `baseUrl`; destination changes require an out-of-band trust and credential replacement procedure. Missing/mismatched `credentialHost` prevents adapters from resolving credentials.
- **Verification:** Security unit tests cover approved host, malformed/unsafe URLs, local/reserved addresses, mixed public/private DNS answers (rebinding defense), and credential host mismatch. Adapter tests confirm shared client adoption. Real DNS/socket behavior and each supplier's API compatibility still require isolated staging tests.

### F-02 — Supplier API credentials were stored and serialized as plaintext

- **Severity:** Critical (P0). **Status:** Confirmed in original schema; new credential writes encrypted; legacy migration is a release blocker.
- **Affected code:** `src/modules/providers/provider.model.js`; admin provider CRUD and serialization; concrete adapters.
- **Root cause:** The schema explicitly stored `apiToken`/legacy `apiKey` in plaintext and returned provider documents to API callers; audit snapshots could serialize complete provider objects. The supplied brief also reports key derivation tied to JWT secrets in a prior implementation; this checkout's provider schema has no encryption layer.
- **Impact / incident relationship:** Database, API, audit, or debug exposure could reveal supplier credentials. The incident's destination manipulation makes credential exposure especially consequential; actual exfiltration is not established.
- **Remediation:** Added AES-256-GCM credential encryption with `enc:v1` ciphertext, independent `PROVIDER_CREDENTIAL_ENCRYPTION_KEY`, no production fallback, and API `toJSON`/`toObject` omission of both token fields. Provider audit snapshots no longer include token plaintext. Test connection output remains token-free by serialization.
- **Verification:** Round-trip/randomization test passes. No full legacy-cipher migration tool is included. Existing plaintext or ciphertext encrypted under an unavailable old key must be replaced and rotated with suppliers. Production must not start without an independent 32-byte base64 key.

### F-03 — Long-lived JWTs lacked reliable revocation and production secret strength checks

- **Severity:** Critical (P0). **Status:** Original weaknesses confirmed; primary code fix implemented, full end-to-end revocation testing pending.
- **Affected code:** `src/config/config.js`, `.env.example`, `src/modules/auth/auth.service.js`, `src/modules/users/user.model.js`, `src/shared/middlewares/authenticate.js`, `src/shared/middlewares/maintenanceGate.js`.
- **Root cause:** The configured access lifetime defaulted to seven days; JWT verification did not constrain algorithm, issuer, audience, or session generation; password/role/status/MFA changes did not invalidate issued tokens. The checked-in environment example supplied a predictable placeholder.
- **Impact / incident relationship:** Forged, stolen, or otherwise compromised tokens could retain privileged access after account changes. JWT forgery/token compromise remains a strong hypothesis from the supplied incident report, not a proven entry path.
- **Remediation:** Default access lifetime is 15 minutes; production startup rejects weak/placeholder secrets and requires JWT issuer/audience; signing and verification restrict HS256 and enforce issuer/audience. Added `sessionVersion`, included it in access and pending-MFA tokens, and increment it on password, role, status, permissions, and 2FA changes. Authentication and maintenance authorization reject stale session versions. `.env.example` no longer contains a JWT signing value.
- **Verification:** A child-process test confirms a weak production JWT secret fails before startup; existing auth/activation tests passed. Dedicated HTTP integration tests for revocation after each change are still required before staging approval.

### F-04 — Google OAuth could bypass application MFA and put bearer tokens in redirect URLs

- **Severity:** Critical (P0). **Status:** Original behavior confirmed; partial remediation implemented; OAuth state/account-linking and frontend handoff verification remain blockers.
- **Affected code:** `src/modules/auth/auth.routes.js`, `src/modules/auth/auth.controller.js`, `src/modules/auth/auth.service.js`, `src/config/google.strategy.js`.
- **Root cause:** OAuth callback issued a full JWT without checking application 2FA and returned it in a query parameter. No explicit state validation was configured in the inspected route/strategy.
- **Impact / incident relationship:** Privileged Google identities with configured application MFA could obtain sessions without completing that MFA; query tokens could be copied into browser history, referrer, proxy, or access logs. This aligns with the reported OAuth/session concerns.
- **Remediation:** Google login now creates and emails the same short-lived pending-MFA challenge when the account has MFA enabled. OAuth callback no longer redirects with a token; it places a short-lived HttpOnly cookie and redirects with status only. Added a one-time POST exchange guarded by configured frontend Origin; the MFA flow uses a separate HttpOnly pending cookie.
- **Verification / unresolved:** No OAuth provider integration test was executed. Frontend must POST to `/api/auth/oauth-session` with credentials, use the returned token as its bearer token, and POST the MFA code to `/api/auth/verify-2fa` with credentials. Explicit OAuth state/CSRF protection, existing-account linking policy, and cookie domain/SameSite behavior require review and integration verification. OAuth use is not release-ready until those controls are proven.

### F-05 — Supplier destination updates and credentials were not bound together

- **Severity:** Critical (P0). **Status:** Primary fail-closed binding implemented; existing records need migration.
- **Affected code:** Provider model, admin provider service, base adapter, provider service.
- **Root cause:** Changing `baseUrl` did not require replacement or reapproval of the credentials already attached to the provider.
- **Impact:** Stored supplier secrets could be sent to a newly configured host. This maps directly to the reported temporary redirection of legitimate suppliers.
- **Remediation:** Each new provider or credential update records the canonical credential host; adapters refuse to return credentials when the destination host differs. Ordinary update APIs reject base URL changes. An out-of-band approved-host update and supplier credential replacement are required to change destinations.
- **Verification / unresolved:** Unit test checks host mismatch. Existing providers lacking `credentialHost` intentionally stop supplier calls until they are re-bound and have credentials rotated. A controlled migration run against a scrubbed isolated database remains necessary.

### F-06 — Emergency financial execution stop was absent and recovery paths were separate

- **Severity:** Critical (P0). **Status:** Central gate implemented for main financial and provider paths; full coverage not yet proven.
- **Affected code:** `src/shared/security/executionGate.js`, wallet services/operation service, order service, admin retry, deposit approval and recovery, provider HTTP client.
- **Root cause:** No shared incident switch controlled all wallet mutations and supplier execution; some deposit credit/recovery paths update balances directly.
- **Impact:** During an incident, endpoint disablement or cron shutdown alone could still permit financial changes or supplier calls from other routes/workers.
- **Remediation:** `FINANCIAL_EXECUTION_ENABLED=false` blocks centralized wallet operations, new orders, deposit approval/recovery, admin order retries, and all supplier HTTP clients. Wallet/deposit recovery workers report skipped while disabled.
- **Verification / unresolved:** A unit test verifies the shared gate, and the full financial regression suite is running. Dedicated HTTP + background worker emergency-mode integration tests and a static review of all direct mutation paths remain required. This flag is environment-driven; a managed runtime configuration and operator procedure must be validated.

### F-07 — Privileged authorization was present on product publishing; incident activity does not prove a route bypass

- **Severity:** High, investigation finding. **Status:** Existing route protection confirmed; incident mechanism unverified.
- **Affected code:** `src/modules/providers/provider.routes.js` and route middleware; `src/modules/products/product.routes.js`; `src/shared/middlewares/authenticate.js`, `authorize.js`, `requirePermission.js`.
- **Evidence:** The provider router applies authentication, ADMIN/SUPERVISOR role checks, and `MANAGE_SUPPLIERS` to all routes before declaring publish. The supplied incident says `/api/products/publish` declared `authenticate`, `authorize('ADMIN','SUPERVISOR')`, and `MANAGE_PRODUCTS`; local review found equivalent privileged gating on publishing routes. A successful request therefore does not, by itself, prove missing route authorization.
- **Impact / incident relationship:** A compromised privileged identity/token, unexpectedly granted permission, middleware defect, or different endpoint/version may explain the action. The incident brief notes multiple admin identities and activity without matching initial login events; those facts cannot be verified from this checkout.
- **Remediation:** JWT validity and revocation checks were strengthened. No blanket route removal was made. Full role/permission and target-account escalation review is still required, including production permission snapshots from incident evidence.
- **Verification:** Existing route-level tests do not cover the complete ADMIN/SUPERVISOR matrix for publishing and supplier modifications; required authorization integration tests remain release blockers.

### F-08 — Audit identity and durability are inconsistent across administrative workflows

- **Severity:** High. **Status:** Confirmed in code; partial.
- **Affected code:** `src/modules/admin/admin.providers.service.js`, `src/modules/admin/admin.routes.js`, admin user/wallet services, audit service/outbox.
- **Root cause:** Several service paths hardcode `actorRole: ADMIN`, even though some routes accept supervisors; some audits are fire-and-forget while wallet operations use a durable outbox. Correlation IDs and trusted IP provenance are not consistently recorded.
- **Impact / incident relationship:** Audit records can misattribute the actor role, lose failed security attempts, or be incomplete when writes fail, complicating reconstruction of the hundreds of reported supplier mutations.
- **Remediation:** Provider create/update/delete now emit audit events with the authenticated actor and role, request IP/user-agent, provider identity, safe before/after metadata, and deletion detach count; provider credential fields are omitted from snapshots. The existing wallet audit outbox remains in use. Broader actor-role/context propagation, correlation IDs, and critical audit-write failure policy have not been completed.
- **Verification:** Provider suite passed 56/56 and full regression passed 25 suites / 759 tests after adding these events. No fault-injection coverage was added for supplier/admin critical audit writes.

### F-09 — Supplier retry and execution idempotency need external-side-effect verification

- **Severity:** High. **Status:** Probable risk; not proven exploitable from this code review.
- **Affected code:** `src/modules/admin/admin.orders.service.js`, provider adapters, order fulfillment and retry workers.
- **Root cause:** Local idempotency and refund guards exist, but local state alone cannot prove the supplier honored stable idempotency keys or that every external retry is de-duplicated.
- **Impact / incident relationship:** Duplicate supplier-side transactions may occur even where local order state is failed/refunded, consistent with customer reports in the incident brief. Local tests cannot establish supplier-side state.
- **Remediation:** Emergency stop blocks retries and supplier calls; existing order idempotency behavior retained. Provider-specific idempotency contracts and reconciliation are not verified.
- **Verification:** Existing retry and refund regression suites plus supplier sandbox contract tests and post-incident supplier reconciliation are required.

### F-10 — Theme activation-code HMAC reused the JWT signing secret

- **Severity:** High. **Status:** Confirmed in original code; independent secret requirement implemented.
- **Affected code:** `src/modules/theme/manualPayment.service.js`, `src/config/config.js`, `.env.example`.
- **Root cause:** The theme activation-code HMAC pepper fell back to `JWT_SECRET`, coupling unrelated security domains and making JWT rotation alter activation-code verification behavior.
- **Impact:** Compromise or rotation of the JWT signing key affected the trust and continuity of theme activation codes. This is separate from supplier encryption but was found during secret dependency review.
- **Remediation:** Production startup now requires a separate high-entropy `THEME_CODE_PEPPER` that differs from `JWT_SECRET`; the runtime fallback remains only for isolated tests. The example documents a separately configured key.
- **Verification:** A child-process production startup test rejects a shared key; focused security suite execution is recorded in `SECURITY_TEST_REPORT.md`.

## Additional review notes

- No webhook handler was identified in the scanned source. If webhook functionality exists in another service/repository, its signature, replay and authorization controls were outside this checkout.
- `src/services/exchangeRateSync.service.js` performs non-supplier outbound HTTP and is configurable independently; it was not integrated into the supplier SSRF client and requires separate destination policy review if operators can alter its URL.
- The repository dependency install reported 48 advisories (1 low, 20 moderate, 25 high, 2 critical). No automated dependency upgrades were applied. A detailed `npm audit` review and safe upgrade plan remain outstanding.
- File-upload, NoSQL injection, CORS, proxy trust, application-wide IDOR/mass-assignment, supervisor target restrictions, deployment OS/database least privilege, and full source/history review remain incomplete. Do not infer that these are clean from the fixes above.

## Release blockers

1. Replace or migrate all legacy supplier credentials and establish the independent production encryption key; never restore a compromised JWT secret.
2. Populate the exact supplier hostname allowlist and validate DNS/TLS behavior using isolated staging mocks/supplier sandboxes.
3. Complete OAuth state/CSRF and account-linking review; deploy the documented frontend cookie exchange changes and verify across actual frontend/backend origins.
4. Run complete authorization matrix tests, emergency-switch integration tests, direct balance mutation review, and remaining backend regression tests.
5. Review dependency advisories and resolve critical/high findings through controlled upgrades.
6. Preserve and correlate production incident evidence separately; this local repository audit cannot prove initial access, internal service reachability, credential receipt, or supplier-side transaction state.
