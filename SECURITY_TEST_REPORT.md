# Security Test Report

## Continuation verification from `efeeeb4`

- Final local backend regression: 25 suites passed, 769 tests passed, 0 failed. Test databases used `mongodb-memory-server`; no production database, external supplier, email provider, payment service, or live financial transaction was used.
- Targeted `securityHardening.test.js`: 1 suite, 26 tests passed. It covers trusted-host enforcement, invalid supplier URLs and address ranges, mixed and rebinding DNS responses, redirect/proxy/TLS agent configuration, migration planning, encrypted rollback authenticity, production database rejection, and execution-stop behavior.
- Frontend: `npm run build` passed; `npm run lint` (`tsc --noEmit`) passed.
- Syntax checks passed for edited backend JavaScript files; `git diff --check` passed.
- Dependency audit after compatible updates: 34 total (23 moderate, 11 high, 0 critical); production-only 17 (6 moderate, 11 high, 0 critical). The two prior critical findings are no longer reported. Remaining production high findings are in the WhatsApp/Puppeteer dependency tree; no force downgrade was applied.
- The credential migration CLI default mode was designed to print a dry-run/no-connection notice. No staging database dry run or apply/rollback operation was run in this session.
- Redirect and TLS verification was checked through the configured Axios options in isolated tests, and DNS rebinding through a deterministic fake resolver. No live TLS handshake or real DNS rebinding server test was run; that remains a Staging gate.

### Dependency impact review

| Package group | Remediation and production relevance |
|---|---|
| `express` / `proxy-addr`, `mongoose` | Safe lockfile-compatible updates removed the two critical findings. The app uses Express and Mongoose on live request paths; the fixed versions are installed. |
| `axios`, `joi`, `multer` and related transitive packages | Compatible upgrades reduced known vulnerable ranges without `--force`; these packages remain in the application request/input paths. |
| `sharp` | Updated to `0.35.5`; source use is limited to image metadata and resizing, and the code uses still-supported calls. Node 22.22.2 was used for local verification; verify the deployed runtime meets the package engine requirement. |
| `nodemailer` | Updated to `10.6.1`. Source uses only `createTransport` and `sendMail`; no removed legacy API was found, and the full backend regression passed. SMTP delivery still needs a Staging-only test. |
| `whatsapp-web.js` / Puppeteer dependency tree | **Residual high risk.** `npm audit` reports 11 production high findings (including transitive Puppeteer, proxy-agent, and archive/extract dependencies); server startup initializes this integration by default. This makes the dependency group production-reachable, but does not prove an exploit occurred or that every advisory input is attacker-controlled. `npm audit fix` offered a forced downgrade of `whatsapp-web.js` to `1.34.6` from `1.34.8`; this downgrade was not applied because it may regress the WhatsApp integration. Replace with a reviewed upstream-compatible dependency fix or isolate/disable the WhatsApp worker before production recovery. |

The audit count moved from 48 (1 low, 20 moderate, 25 high, 2 critical) at the starting lockfile to 34 (0 low, 23 moderate, 11 high, 0 critical); production-only is 17 (6 moderate, 11 high, 0 critical). Counts can change as the registry advisory database changes. Review `npm audit --json` against the exact release lockfile immediately before deployment.

The earlier baseline results below are retained as historical evidence and do not replace the final continuation results above.

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
