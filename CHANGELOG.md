# Changelog

All notable changes to `axis-registry` (the Cloudflare Workers + D1 implementation deployed at `registry.axisprime.ai`). Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

This worker does not follow strict semver — the wire-protocol contract is owned by the [AXIS Protocol Spec](https://github.com/MachinesOfDesire/axis-protocol). Versions on this changelog track deployable revisions of the worker code, not protocol revisions.

## [Unreleased]

### Fixed

- **`migrations/0003_api_key_hash_constraint.sql` replay safety.** The migration as merged contained `BEGIN TRANSACTION` / `COMMIT` (D1 rejects) and a positional `INSERT ... SELECT *` (mismaps because `role` was appended by migration 0001 to position 10 in the live table, not position 7 as in the rebuild target). Live D1 was migrated on 2026-05-11 using a corrected variant; this commit aligns the file in the repo with what actually ran so future replays / forks work.

### Security

- **H7 — `target_registrar_id` column on `audit_log` + widened `GET /audit` filter.** Previously `GET /audit` filtered by `registrar_id = caller.id`. Break-glass `/admin/force-*` writes the super_admin's id as `registrar_id`, so the owning registrar could not see force-deactivations of their own resources through the standard `/audit` endpoint. Migration `0004_audit_target_registrar_id.sql` adds a parallel `target_registrar_id` column; both force-* paths pre-lookup the target's owning registrar (404 before audit if missing) and record it; `logAudit` accepts and binds it; `GET /audit` now filters `WHERE registrar_id = ? OR target_registrar_id = ?`. Existing pre-migration force-* rows stay `target_registrar_id = NULL` (one-time historical gap; optional backfill snippet documented in the migration header).
- **H6 — structured `AUDIT_WRITE_FAILED` log line on normal-path audit failures.** `logAudit` is invoked via `ctx.waitUntil` AFTER the mutation on `/register` and `DELETE /agents`, so an audit insert failure cannot abort the mutation (audit-first ordering on every normal-path mutation would surface transient D1 hiccups as user-visible 500s — that tradeoff is reserved for the rare break-glass paths). Instead, the catch block now emits a structured JSON line with `tag: "AUDIT_WRITE_FAILED"` containing the would-have-been-written fields (action, actor, target, registrar_id, target_registrar_id, ip_address; `details` omitted to avoid logging user-supplied content). Logpush / Tail can filter on the tag to detect gaps and alert. The two `/admin/force-*` paths use the same structured tag in their own catch blocks for consistency.
- **H4 — `/admin/agents` static prepared statements + status allowlist.** Previously the handler concatenated an optional `WHERE status = ?` fragment into the query string. The bind was parameterized so this was not SQL injection in practice, but the dynamic-string-build pattern is a footgun and tripped review. Refactored to two static prepared statements (with-status / without-status) selected by branch, and an explicit allowlist (`['active', 'suspended', 'revoked', 'deactivated']`) that returns 400 `invalid_request` for unknown status values instead of silently running a query that matches zero rows.
- **H5 — `LIMIT` floor on pagination.** `clampPaginationInt` previously demoted `NaN` / negative values but accepted `0`, which D1 honors as "return zero rows." Added a `min` parameter (default 0 for offsets, 1 for limits) so `?limit=0` now falls back to the default page size. All five `LIMIT` call sites pass `min=1`; `OFFSET` call sites keep the default. No wire-protocol change.
- **H3 — schema CHECK constraint on `api_key_hash` + Bearer-length validation in middleware.** Closes the finding from the [2026-05-08 security review](https://www.notion.so/d2f90b6b9d384973abfbb25b17592d20) (axis-registry H3) and the corresponding [Coordination item](https://www.notion.so/35df359483b281518a85d8eb04068f92). An empty `api_key_hash` on a seeded row would otherwise let `Authorization: Bearer ` (empty) authenticate via SHA-256(""). Production seed has always set a real hash; this commit makes drift impossible going forward.
  - `schema.sql`: added `CHECK(length(api_key_hash) = 64 AND api_key_hash <> '')` inline on the `registrars` table. Fresh databases created from `schema.sql` reject bad hashes at insert.
  - `migrations/0003_api_key_hash_constraint.sql`: SQLite table-rebuild pattern applies the same CHECK to existing databases. Pre-flight check documented inline (`SELECT id, length(api_key_hash) FROM registrars WHERE api_key_hash = '' OR length(api_key_hash) <> 64` should return zero rows before applying).
  - `src/middleware/auth.js`: rejects any Bearer credential shorter than 32 chars before hashing. Defense-in-depth — the schema CHECK already prevents the drift; this prevents the auth attempt from consuming compute and provides a fast no-op reject for accidentally-truncated or empty values.

## [0.1.2] — 2026-05-10

Foundation cleanup ahead of public-launch sprint. Architecturally significant — splits the canonical AXIS registry from Kipple Labs extension services so the canonical implementation stays conformance-clean, foundation-ready, and forkable as a working AXIS without Kipple specifics. Decisions logged 2026-05-10 in [📋 AXIS Decisions Log](https://www.notion.so/34cf359483b2815eb4fcf3c98ecbf238).

### Removed

- **`trust_attestations` table + indexes from `schema.sql`.** Per the canonical spec (`SPEC.md` v0.1.1, axisprime.ai), Trust Attestations are advisory and *"stored by the issuer, not the registry."* The table had been defined since the initial commit but never wired to a route handler — pure schema drift. Removed; affects fresh deployments only.
- **`content_provenance_attestations` table + indexes from `schema.sql`.** Same reasoning; same status (defined but never used).

Existing live databases keep these tables as empty no-ops until a follow-up migration drops them. No data migration is required because no data was ever written to them.

### Added

- **`schema.sql` header comment** documenting Layer 1 + Layer 2 scope and the canonical/extensions architectural separation.
- **`wrangler.toml.example`**: added an optional `EXTENSIONS` D1 binding block (commented out by default). Forks running their own canonical registry can ignore the binding entirely; registrars running Layer 3 services on top can uncomment and point at their own extension database.
- **`README.md` Scope section** explaining the L1+L2 commitment and the canonical / extensions split. Forkers know up front what's in this repo and what isn't.

### Provisioned

- **`kipple-extensions` D1 database** (`7245f283-82c1-4529-bdb0-b36a353b6c83`) on the Kipple Labs Cloudflare account. Initially empty. Will host Kipple Labs L3 services as they come online (trust attestations, content provenance attestations, compliance kit bundles). Cross-references to canonical data are by `agent_id` / `operator_id` strings, never SQL JOINs across the boundary.

### Out of scope (deferred)

- Migration to drop the inert L3 tables from existing live databases. Low priority; tables are empty no-ops. Will land when a follow-up migration is convenient.
- Wiring any L3 service to the new `EXTENSIONS` binding. None exist yet; the binding is in place as architectural commitment, not because any code uses it today.

## [0.1.1] — 2026-05-09

First tagged release. The repo was made public on 2026-05-08; this release captures the full state of `main` as of the public-readiness pass plus the post-public hardening pass on 2026-05-09.

### Authorization model (already deployed; first formal release tag)

- **Three-role RBAC**: `registrar` (default), `admin` (cross-tenant read), `super_admin` (admin + break-glass mutations). Role lives in the `registrars.role` column. Server is the source of truth — the SDK does not predict role locally.
- **BOLA enforcement** on normal-path mutations: every mutating endpoint checks that `operator.registrar_id == caller.registrar_id` (or that caller has admin+ role on a read path).
- **Break-glass endpoints**: `POST /admin/force-deactivate-agent/:id` and `POST /admin/force-revoke-delegation/:id`. Both write an audit row *before* the mutation; mutation aborts if the audit write fails. Reason is required and validated (non-empty string).
- **Opaque PII-free operator IDs** (`op-` prefix slugs) for email-tier operators. Domain-tier operators continue to use the domain slug. Stops leaking email local-parts into public records.

Migrations `0001_registrar_roles.sql` and `0002_opaque_email_tier_operator_ids.sql` are applied in production via `wrangler d1 execute --file`. The `d1_migrations` tracker has been backfilled.

### Spec alignment

- `POST /delegations` accepts the canonical `expires` field (per AXIS Protocol Spec v0.1 §4.4); the legacy `expires_at` alias was dropped earlier.
- `POST /register` response includes `operator_id` at the top level (additive, backwards-compatible).
- `GET /verify` returns the canonical `operator_id` from the agent row (not from the AIT payload, which the SDK never writes). Closes the bug where every comment row was stored with `axis_operator_id: null`.

### Public-readiness

- Repo flipped public on 2026-05-08.
- Added `LICENSE` (Apache 2.0), `CONTRIBUTING.md`, `SECURITY.md`, `DEPLOYMENT.md`, `wrangler.toml.example`.
- Real `wrangler.toml` is now git-ignored; deployers copy `wrangler.toml.example` and fill in their own `account_id` / `database_id`. Earlier commits still contain the previous values in git history (identifiers, not secrets — same exposure as any Cloudflare worker example on GitHub).
- README rewritten to match the deployed reality (correct URL, three-role authz model, migration + tracker-backfill flow, prereqs bumped to Node 20+ / wrangler 4+).

### Hardening pass (2026-05-09)

- **Stale fallback URLs**: `env.REGISTRY_BASE_URL || 'https://axis-registry.editor-9a4.workers.dev'` in `src/index.js` (lines 43, 127) and `src/routes/resolve.js` (line 139). The fallback URL is dead. In production the env var is set so the fallback never fires, but a fork/local-dev without the var would emit broken `registry_url`/`revocation_url` fields on agent records. Fallback now `https://registry.axisprime.ai`.
- **Pagination unbounded + NaN-fragile**: `/admin/operators`, `/admin/agents`, `/admin/audit` accepted any limit value, and non-integer query strings parsed to `NaN` and bound into D1 unpredictably. Added `clampPaginationInt` helper that caps at 500, demotes `NaN`/negative to the default. Existing `/operators` and `/audit` (which used ad-hoc `Math.min(...,500)`) updated to use the same helper for consistency.
- **First unit tests**: `test/unit.test.js` covers `hashApiKey` (including explicit trailing-whitespace sensitivity — closes the CRLF-from-PowerShell-pipe bug class that bit `ADMIN_PASSWORD` rotation on 2026-05-08), the role helpers (`isAdmin`, `isSuperAdmin`, requirements), and the gate response shapes (`requireAdmin`, `requireSuperAdmin`, `notYourResource`). 19 tests, all pure-function, no D1 needed. `npm test` wired up.

### Known gaps (not in this release)

- `PATCH /agents/:id` returns 501 — implementation deferred.
- Route-level integration tests need a Wrangler/Miniflare harness — currently covered only by the unit tests + the live-traffic conformance suite at `MachinesOfDesire/axis-conformance`.
- `/verify/signature` accepts arbitrary message size; consider adding a payload-size cap to avoid CPU DoS.
- `Access-Control-Allow-Origin: *` is unconditional; acceptable for a public read API but worth a review pass at launch.

### Pending (separate `security-hardening-2026-05-08` branch)

A side branch carries additional hardening that is **not** in this release:

- `migrations/0003_api_key_hash_constraint.sql` adding `CHECK(length(api_key_hash) = 64 AND api_key_hash <> '')` to the `registrars` table (closes finding H3 — empty `api_key_hash` row would have allowed authenticating with `Bearer ` against the SHA-256 of empty string; production seed has a real hash so this is hardening, not a live exploit).
- Inline `CHECK` in `schema.sql` for fresh databases.
- `test/crypto.test.js` — 20 unit tests for `src/utils/crypto.js` (`deriveAgentId`, `verifyEd25519Signature`, codec roundtrips).

Branch is awaiting review. Will release as 0.1.2 if accepted.
