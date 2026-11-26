# Security Incident Work Checklist

Target: `oscar-backend-release-apply` (clean detached checkout at start).
Scope: local repository only; no production access, real suppliers, or financial actions.

## Phase A — forensic audit
- [x] Map primary entry points, middleware, auth/OAuth/MFA, permissions, models, services, jobs, APIs, deployment and tests; remaining repository-wide review is documented as incomplete in the audit.
- [x] Search direct outbound clients and alternate supplier execution paths; found all four provider Axios adapters and non-supplier exchange-rate HTTP path.
- [x] Inspect local Git history commit subjects without exposing historical secret values.
- [x] Record findings with severity, confidence, root cause, impact, evidence relationship, remediation and verification in `SECURITY_INCIDENT_AUDIT.md`.

## Phase B — supplier SSRF and credentials (P0)
- [x] Centralize trusted outbound policy and enforce DNS/address, redirect, timeout, TLS and response limits.
- [x] Route all four provider adapters through the policy; staging socket/provider compatibility remains unverified.
- [x] Bind credentials to trusted destinations; ordinary API destination edits are denied.
- [x] Use independent versioned credential encryption and document replacement; legacy migration/rotation remains a blocker.

## Phase C — authentication and sessions (P0)
- [x] Harden production secrets and JWT validation/scope/lifetime.
- [x] Revoke sessions after document-saved credential, role, status, permission and MFA changes; full revocation integration coverage remains required.
- [x] Ensure OAuth respects configured MFA and removes tokens from redirect URLs; state/CSRF and browser handoff remain blockers.
- [ ] Review rate limits, proxy/IP trust and authentication audit coverage (partial review only).

## Phase D — authorization (P0)
- [ ] Review role/permission boundaries, IDOR, mass assignment and critical operations (publish chain verified; matrix incomplete).
- [ ] Add step-up/recent-auth controls where supported and protect higher-privilege targets.

## Phase E — financial integrity and emergency control (P0)
- [x] Trace main wallet/order/refund/retry/recovery paths; webhook module not found; full direct-mutation review remains open.
- [x] Add an emergency execution gate to wallet services, new orders, retries, deposit approval/recovery, and supplier calls; integration coverage remains open.

## Phase F — auditability (P0)
- [ ] Verify actor attribution, sanitized records, critical audit durability and coverage (provider CRUD events now pass actor/context and safe metadata; broader role/correlation/durability work remains open).

## Phase G — additional review
- [ ] Review input handling, uploads, CORS/headers, error paths, dependencies, secrets and deployment defaults (partial; dependency advisories recorded).

## Phase H — verification and deliverables
- [x] Add isolated automated security tests with mocked external services.
- [x] Execute full regression and targeted security suites; see exact results and blockers in `SECURITY_TEST_REPORT.md`.
- [x] Create audit, remediation, test, deployment and cross-project reports.
- [x] Record remaining blockers below.

## Initial observations
- Workspace root is a container of multiple projects, not itself a Git checkout.
- `oscar-backend-release-apply` started clean at detached HEAD; `oscar-backend-main` is a separate clean tracking checkout and was treated as read-only.
- No production credentials or service access have been used.

## Current results and next actions

- Full Jest regression after the provider audit change: 25 suites, 759 tests passed, 0 failed in 306.36 seconds. Provider suite: 56 tests passed. Security/theme targeted run: 46 tests passed.
- Critical unresolved release blockers: OAuth state/CSRF and frontend browser integration; legacy supplier credential replacement and independent production key provisioning; production exact-host allowlist and socket/DNS staging test; authorization matrix/step-up checks; comprehensive emergency stop coverage; dependency advisory review; production infrastructure/evidence verification.
- Next action: complete the missing staging/integration review with approved test infrastructure and supplier sandbox credentials; do not classify this checkout for staging or production recovery until then.

## Continuation from efeeeb4

- Continued on `codex/security-incident-remediation-20261126`; no reset or main-branch merge.
- Added OAuth state validation, verified-email account linking requirements, single-use/attempt-limited OTP verification, independent production OTP key, and frontend cookie handoff/2FA integration.
- Added fail-closed audit records on privileged mutating routes and restricted provider credential changes and admin password resets to ADMIN.
- Enforced exact provider origin on Axios calls, disabled redirects/proxies, retained pinned safe DNS and TLS verification; added DNS-rebinding and client policy tests.
- Added default-dry-run provider credential migration and an encrypted rollback artifact guarded against production targets. No database was connected.
- Applied compatible dependency remediations without `--force`; sharp and nodemailer upgraded after source/API use review. Remaining audit findings are recorded in the test report.
- Financial execution defaults off in production and accepts only explicit truthy enable values; confirmation is needed in isolated staging before enabling.
- Current classification remains NOT READY. The final full-test counts will be appended after the last run.
