# Security Test Report

## Environment and scope

Tests ran only in the local backend checkout using the repository Jest configuration and isolated `mongodb-memory-server` databases/mocked provider adapters. No production MongoDB, production server, real supplier, payment API, or real financial operation was used. The checked-in test helpers set `NODE_ENV=test` and a test-only JWT secret.

Dependency installation: `npm install` initially failed because Puppeteer's optional Chrome postinstall could not find its cached executable. `npm install --ignore-scripts` then completed successfully and installed 633 packages. npm reported 48 advisories: 1 low, 20 moderate, 25 high, 2 critical. Browser-dependent Puppeteer install scripts were not run. No dependency audit fix was applied.

## Executed commands and results

| Command | Result |
|---|---|
| `node --check src\shared\security\providerHttp.js` | Passed |
| `node --check src\shared\security\providerCredentials.js` | Passed |
| `node --check src\modules\auth\auth.service.js` | Passed |
| `node --check src\modules\auth\auth.controller.js` | Passed |
| `node --check src\modules\providers\provider.model.js` | Passed |
| `npm test -- --runTestsByPath src/tests/securityHardening.test.js src/tests/adapters.test.js src/tests/orderPolling.test.js --silent` | 3 suites passed, 128 tests passed |
| `npm test -- --runTestsByPath src/tests/securityHardening.test.js src/tests/adapters.test.js src/tests/auth.test.js src/tests/activation.test.js src/tests/admin.test.js --silent` | 5 suites passed, 194 tests passed |
| `npm test -- --runTestsByPath src/tests/walletRecoveryHttp.test.js src/tests/maintenance.test.js src/tests/theme.test.js --silent` | 2 suites passed, 38 tests passed; maintenance initially had 2 failures due a session-version projection bug |
| `npm test -- --runTestsByPath src/tests/maintenance.test.js --silent` | 1 suite passed, 3 tests passed after the projection fix |
| `npm test -- --runTestsByPath src/tests/walletRecoveryHttp.test.js src/tests/maintenance.test.js src/tests/theme.test.js --silent` (rerun after test-token fixes and maintenance projection fix) | 3 suites passed, 40 tests passed |
| `npm test -- --silent` (final tree) | 25 suites passed, 759 tests passed, 0 failed (351.924 seconds) |
| `npm test -- --runTestsByPath src/tests/provider.test.js --silent` (after provider CRUD audit events) | 1 suite passed, 56 tests passed |
| `npm test -- --silent` (rerun after provider CRUD audit events) | 25 suites passed, 759 tests passed, 0 failed (306.36 seconds) |
| `npm test -- --runTestsByPath src/tests/securityHardening.test.js --silent` (after adding the production JWT lifetime cap) | 1 suite passed, 14 tests passed |
| `npm test -- --runTestsByPath src/tests/securityHardening.test.js src/tests/theme.test.js --silent` (after requiring independent `THEME_CODE_PEPPER` and adding credential serialization coverage) | 2 suites passed, 46 tests passed |
| `node --check src\config\config.js` | Passed |
| `node --check src\modules\theme\manualPayment.service.js` | Passed |
| `git diff --check` | Passed |

The first whole-suite execution completed with 22 of 25 suites passing and 727 of 756 tests passing; three suites/29 tests failed. The failures exposed outdated test tokens lacking issuer/audience/session-version claims and the maintenance-gate session-version projection. Test helpers were updated and the projection was fixed. The complete suite then passed with 25 suites and 759 tests, and passed again after provider CRUD audit events were added. The security/theme targeted rerun also passed 46/46.

## Whole regression suite

The final-tree full regression suite passed with 25 suites and 759 tests in 306.36 seconds after the provider CRUD audit change. `finalReleaseGate.test.js` took 201.422 seconds in the isolated test environment. The provider suite passed 56 tests, and the separate security/theme targeted run passed 46 tests.

## Coverage added

`src/tests/securityHardening.test.js` exercises explicitly approved supplier URL acceptance; unsafe protocol, credentials, port, fragment and IP literal rejection; prohibited IPv4/IPv6 ranges; mixed public/private DNS rejection; credential host mismatch; versioned randomized AES-GCM credential round-trip; emergency mode; and production weak-secret startup failure. Existing adapter, auth, wallet recovery, maintenance, theme, order, deposit and standalone wallet recovery suites provide regression coverage.

## Not executed / release blockers

- OAuth integration with Google, OAuth state/CSRF, cookie exchange across actual frontend/backend origins, and browser tests.
- Actual Node/Axios socket pinning against a controlled DNS rebinding server, TLS failure, redirect, proxy environment, timeout, and response-size fixtures.
- Full ADMIN/SUPERVISOR/CUSTOMER route permission matrix, recent-auth checks, horizontal/vertical privilege tests, and account-target restrictions.
- Emergency mode integration across all direct balance mutation paths, every HTTP route, every recovery worker, and every scheduler.
- Legacy provider credential migration/replacement and ciphertext key rotation against a scrubbed staging database.
- Supplier sandbox idempotency, supplier-side order reconciliation, and webhooks (none found in the scanned backend source).
- Detailed `npm audit` advisory review, critical/high dependency upgrades, production deployment configuration validation, and network egress/TLS policy verification.

These missing integration and operational checks block staging/production readiness even if the whole Jest suite passes.
