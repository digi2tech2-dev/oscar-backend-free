# Cross-Project Backend Security Checklist

Reusable for Oscar, Kanz Coins, Ibra, KA, Winnie, Rosetta, and related services. Treat each repository and deployment as independent; do not assume a fix or secret rotation propagated across projects.

## Repository and secrets

- [ ] Record repository, commit, branch, clean/dirty status, runtime, entry points, deployment topology, database and background workers.
- [ ] Search current files and local history for committed credentials without printing secret values.
- [ ] Confirm production startup fails for missing/weak JWT, encryption, OAuth, webhook, and database secrets.
- [ ] Ensure authentication keys, data-encryption keys, HMAC keys, and supplier credentials are independent and rotated separately.
- [ ] Remove secret-looking defaults from tracked examples; use documented generation instructions.
- [ ] Review lockfile advisories and maintain a supported dependency upgrade process.

## Authentication and session lifecycle

- [ ] Restrict JWT algorithms; validate issuer, audience, expiry, token purpose, and service scope.
- [ ] Use short-lived access tokens and reliable session revocation/versioning.
- [ ] Revoke sessions on password reset/change, role/permission change, account suspension, MFA change, and account recovery.
- [ ] Ensure pending-MFA tokens cannot access business routes and resist brute force.
- [ ] Verify OAuth state/CSRF, verified-email policy, account linking, privileged account protections, MFA enforcement, and no bearer tokens in URLs.
- [ ] Require HTTPS, secure cookie attributes, and explicit trusted origins for handoff flows.
- [ ] Rate-limit login, reset, verification, and MFA challenges; validate trusted proxy/IP configuration.

## Authorization and data access

- [ ] Apply server-side authentication, role, and permission checks to every route and alternate execution path.
- [ ] Test CUSTOMER, lower-privileged admin, supervisor, and administrator access for each critical operation.
- [ ] Check BOLA/IDOR, target-account role boundaries, self-escalation, mass assignment, and nested ownership.
- [ ] Require recent authentication/step-up controls for role, supplier destination/credential, wallet, refund, publishing, and security-setting changes.
- [ ] Check query construction against NoSQL injection and prototype-pollution payloads.
- [ ] Return explicit DTOs; never expose password hashes, tokens, API keys, encrypted/raw provider records, or internal error stacks.

## Supplier and outbound network access

- [ ] Inventory Axios/fetch/HTTP clients, redirects, proxies, DNS resolution, adapters, jobs, retries, and legacy clients.
- [ ] Require exact trusted hostnames, HTTPS, approved ports, canonical URL parsing, and no embedded credentials.
- [ ] Reject loopback/private/link-local/reserved/multicast/metadata ranges across IPv4 and IPv6.
- [ ] Validate all DNS answers and pin the connected address to prevent DNS rebinding/TOCTOU.
- [ ] Disable redirects or validate every hop; disable unsafe proxy-environment behavior; verify TLS certificates.
- [ ] Bound timeouts, request/response sizes, concurrency, and retries.
- [ ] Bind credentials to a reviewed destination; require explicit supplier credential replacement on host changes.
- [ ] Encrypt supplier secrets with independent versioned AEAD keys; test key rotation and data migration.
- [ ] Verify every supplier communication path uses the shared control, including connection tests, balance, catalog, import, orders, retries, sync, polling, and worker jobs.
- [ ] Enforce network egress allowlists and metadata-service blocks outside the application.

## Financial integrity and incident stop

- [ ] Trace wallet/order/deposit/refund/payment/reconciliation paths and every direct database balance mutation.
- [ ] Require atomic balance checks, unique idempotency keys, concurrency safety, immutable ledger entries, and valid state transitions.
- [ ] Verify duplicate order/retry behavior against supplier idempotency contracts and reconcile supplier-side state.
- [ ] Authenticate webhook signatures, bind payloads to expected entities, and prevent replay.
- [ ] Require authorization, reason, limits, and durable audit for administrative balance changes.
- [ ] Implement one emergency switch checked by HTTP, APIs, workers, recovery, scheduled jobs, order retries, refunds, credits/debits, and all supplier calls.
- [ ] Test that emergency mode leaves only an explicitly documented read-only surface.

## Audit, deployment, and tests

- [ ] Record true actor ID/role, target, action, outcome, timestamp, trusted client IP, correlation ID, and sanitized before/after values.
- [ ] Define durable audit behavior for critical operations and failure handling; test audit-store outages.
- [ ] Review uploads, path traversal, file type/size limits, CORS, security headers, error handling, debug routes, OS identity, database roles, and resource limits.
- [ ] Use isolated test databases and mocked supplier/payment/email services; never run real financial actions in tests.
- [ ] Add negative security tests that exercise actual middleware/transport, not mocks that bypass the control.
- [ ] Run existing regression tests and capture exact commands, counts, failures, and unexecuted blockers.
- [ ] Rehearse a clean deployment, key/session rotation, migration, supplier credential replacement, rollback, and staged recovery.
- [ ] Verify controls independently in every related project and environment; do not copy secrets between projects.
