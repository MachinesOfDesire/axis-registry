# Changelog

All notable changes to `axis-registry` (the Cloudflare Workers + D1 implementation deployed at `registry.axisprime.ai`). Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

This worker does not follow strict semver — the wire-protocol contract is owned by the [AXIS Protocol Spec](https://github.com/MachinesOfDesire/axis-protocol). Versions on this changelog track deployable revisions of the worker code, not protocol revisions.

## [Unreleased]

### Tests

- **Comprehensive integration-test coverage — `test/integration/` (51 new tests across 5 files).** Resolves the entire [axis-registry test-gap Coordination item](https://www.notion.so/35df359483b28188b260c8d41fbf366b) in one PR — all five queued matrices ship together rather than as a sequence of small follow-on PRs. Builds on the Miniflare harness from PR #14. Test count: 40 unit + 5 C2 slot-race + 51 new = 96/96 pass.
  - **BOLA matrix — `bola.test.js` (15 tests).** Per-route ownership gates on every mutating + scoped-read path: `POST /register`, `DELETE /agents/:id`, `GET /agents?operator_id=` (cross-tenant + unauthed-401-before-BOLA), `GET /operators` and `GET /audit` (self-scoped), `/admin/*` role gate, `/admin/force-deactivate-agent` + `/admin/force-revoke-delegation` super_admin gate, super_admin positive control, plus the previously-deferred `POST /delegations` (cross-tenant issue + cross-tenant parent-chain), `DELETE /delegations/:id`, and `POST /operators/verify-domain` + `/check` cross-registrar domain-claim paths.
  - **Presentation-layer matrix — `presentation-layer.test.js` (9 tests).** `GET /agents/:id` field-gating across the unlock conditions: unauthenticated → public layer only; owning registrar / admin / super_admin Bearer → unlocked; non-owning plain registrar → public layer only; valid AIT in Authorization → unlocked; AIT with missing `aud` (H1 silent fail) / bad signature / oversized 5 KB token (M2 cap) → public layer only.
  - **Audit-before-mutate — `audit-before-mutate.test.js` (6 tests).** Break-glass `/admin/force-*` paths: success writes audit row with `target_registrar_id` matching the owning registrar (H7 hardening); missing target returns 404 BEFORE any audit row is written; missing `reason` returns 400 BEFORE any lookup or audit row.
  - **Delegation chain matrix — `delegation-chain.test.js` (10 tests).** Happy path + child attenuation (subset scope passes; wider scope → 400 `delegation_chain_invalid`); `root_operator` mismatch with parent; `max_sub_delegation_depth=0` blocks further chaining; M5 expires-horizon (>90 days → `expires_too_far`; past/malformed → `invalid_request`); DELETE cascade through 3-level chain (cascadeRevoked=2); M3 depth cap (18-deep direct-DB chain, root DELETE stops cascade at CASCADE_MAX_DEPTH=16, beyond-cap delegation stays active).
  - **AIT verification matrix — `ait-verify.test.js` (11 tests).** `GET /verify?token=` failure paths: malformed token → 400; wrong `typ` / wrong `alg` → 400; H1 `aud` enforcement (missing / empty / whitespace-only → 400 `missing_aud`); unknown `iss` → 404; bad signature → 200 `valid:false` reason="Invalid signature"; expired-but-validly-signed → 200 `valid:false` reason="Token expired"; deactivated agent → 200 `valid:false` reason starts with "Agent status:"; happy path positive control returning `valid:true` with operator_id in canonical `axis:<slug>:operator` form.
  - Shared helpers in `test/integration/_helpers.js`: real Ed25519 keypairs via Node Web Crypto, signed-AIT mint, `registerRealAgent()` for tests that need verifiable signatures.

### Security

- **L3 — `seed-key.sql` no longer committed

### Security

- **L3 — `seed-key.sql` no longer committed; `.example` placeholder shipped instead.** The live production registrar API key hash was previously committed in the public repo. SHA-256 is one-way, but publishing the live hash removed a layer of obscurity (offline brute-force on the plaintext, algorithm confirmation) for zero operational benefit. `seed-key.sql` is now gitignored alongside `wrangler.toml`; `seed-key.sql.example` documents the workflow (generate Bearer client-side, compute SHA-256, paste, apply, delete local copy). `seed-demo-agents.sql` gets a prominent DEV-ONLY warning header — the rows it seeds are intentional public demo state on `registry.axisprime.ai`, not a leak, but a third-party deployer running this file would inherit the demo's keypair-authentication path. The H3 schema CHECK constraint (PR #2) already prevents an empty seed row from drifting back in.
- **L4 — error messages no longer echo caller-supplied identifiers.** `404` / `400` / `409` responses that previously interpolated the requested `agent_id` / `delegation_id` / `operator_id` / DID into the message body now return fixed strings (`"Agent not found"`, `"Delegation not found"`, etc.). Mild enumeration-aid before — the same 404 vs 200 distinction reveals existence, but the echoed identifier confirms the exact form the caller used reached the lookup. Error codes (semantic routing for clients) are unchanged; only the human-readable `message` field was scrubbed. Also scrubbed: `err.message` leak in `register.js` (`"Failed to process public key: ${err.message}"` → `"Failed to process public key"`) and `verify.js` (`"Failed to decode token: ${err.message}"` → `"Failed to decode token"`). The full error remains in server-side `console.error` for forensics.
- **M8 — `cors.js` documents why wildcard origin + `Authorization` in `Allow-Headers` is safe.** Bearer auth flows are server-to-server (SDK, curl, registrar workers) — CORS doesn't apply. For browser-side foreign-origin code, the wildcard origin paired with the deliberate absence of `Access-Control-Allow-Credentials: true` means the browser refuses to send a foreign-origin Authorization header. Net effect: any origin can read public responses (verification widgets work anywhere), no origin can smuggle Bearer credentials into the registry from a browser context. Documented intent; no behavioural change. M4 (chain signature verification) parked until L1 (RFC 8785 JCS) lands.
- **C1 phase 1 — operator-namespaced DIDs (spec v0.2 §10.3).** Closes the DID name-squatting finding by structurally requiring verification of an operator namespace before claiming any agent slug inside it. Implementation is additive only — no migration in this phase.
  - **`src/utils/operator-slug.js`** — tier-driven operator-slug derivation (`domain` → verified domain root with TLD stripped; `email` / `kyb_individual` → opaque `op-<24hex>`; `kyb_organization` → domain if present else opaque). Slug is derived from verification proof, never caller-chosen — that's what kills squatting at the protocol level.
  - **`src/utils/did.js`** — `parseAxisDid` accepts both v0.1 (`did:axis:prime:<agent>`) and v0.2 (`did:axis:prime:<operator>:<agent>`) canonical forms; `buildAxisDidV2` emits the v0.2 form.
  - **`src/routes/register.js`** — newly-registered agents get the v0.2 DID form via `buildAxisDidV2`.
  - **`src/routes/operators.js`** — newly-created operators get the v0.2 slug via `deriveOperatorSlug`. Previously domain-tier operators got `<domain>.replace(/\./g, '-')` (e.g. `kipple-labs-com`); they now get `<domain-root>` (e.g. `kipple-labs`). Existing operator records keep their old-form id until the Phase 2 migration.
  - **`src/routes/resolve.js findAgent`** — cross-form DID tolerance per spec §10.3 ("Resolvers MUST accept both v0.1 and v0.2 DID forms"). Caller can pass either form; the resolver tries the literal stored DID first, then falls back to parsing the input and matching by agent slug (operator-scoped where possible).
  - **`test/c1.test.js`** — 17 unit tests covering slug derivation, opacity invariants for the floor tier, DID parsing, and v0.1 / v0.2 round-trips. 36/36 tests pass.
  - **Phase 2 (separate PR):** re-issue DIDs and operator slugs for the existing ~25 production agents at cutover. No legacy-alias period per the 2026-05-11 locked decision (almost entirely Josh's test data).
  - **PSL gap:** multi-label TLDs (`example.co.uk`) currently collapse via dot→dash (`example-co`) rather than PSL-aware stripping (`example`). Tracked as a follow-up; not blocking ccTLD launch but should land before scale.



### Security

- **C3 — application-level rate limiting via Cloudflare Workers Rate Limiting bindings.** Four tiers (`RL_PUBLIC_READ`, `RL_PUBLIC_VERIFY_SIG`, `RL_REGISTRAR`, `RL_AUTH_FAIL`) with sensible defaults sized to absorb the chatty-platform AI-comment-verification flow without throttling legitimate traffic. Auth-fail tier (30 req/min per IP on mutating requests with no/invalid Bearer) is the credential-stuffing brake. Each tier hit emits a structured `RATE_LIMIT_HIT` log line (key prefix, tier, URL, method, `cf-ray`) for Logpush filtering. If a binding is unset (local dev / minimal fork) the helper is a no-op, so test environments are unaffected. 429 responses include `Retry-After: 60`. Tier values + Logpush + WAF dashboard handoff documented in `DEPLOYMENT.md`. No wire-protocol change.



### Fixed

- **`migrations/0003_api_key_hash_constraint.sql` replay safety.** The migration as merged contained `BEGIN TRANSACTION` / `COMMIT` (D1 rejects) and a positional `INSERT ... SELECT *` (mismaps because `role` was appended by migration 0001 to position 10 in the live table, not position 7 as in the rebuild target). Live D1 was migrated on 2026-05-11 using a corrected variant; this commit aligns the file in the repo with what actually ran so future replays / forks work.

### Security

- **H7 — `target_registrar_id` column on `audit_log` + widened `GET /audit` filter.** Previously `GET /audit` filtered by `registrar_id = caller.id`. Break-glass `/admin/force-*` writes the super_admin's id as `registrar_id`, so the owning registrar could not see force-deactivations of their own resources through the standard `/audit` endpoint. Migration `0004_audit_target_registrar_id.sql` adds a parallel `target_registrar_id` column; both force-* paths pre-lookup the target's owning registrar (404 before audit if missing) and record it; `logAudit` accepts and binds it; `GET /audit` now filters `WHERE registrar_id = ? OR target_registrar_id = ?`. Existing pre-migration force-* rows stay `target_registrar_id = NULL` (one-time historical gap; optional backfill snippet documented in the migration header).
- **H6 — structured `AUDIT_WRITE_FAILED` log line on normal-path audit failures.** `logAudit` is invoked via `ctx.waitUntil` AFTER the mutation on `/register` and `DELETE /agents`, so an audit insert failure cannot abort the mutation (audit-first ordering on every normal-path mutation would surface transient D1 hiccups as user-visible 500s — that tradeoff is reserved for the rare break-glass paths). Instead, the catch block now emits a structured JSON line with `tag: "AUDIT_WRITE_FAILED"` containing the would-have-been-written fields (action, actor, target, registrar_id, target_registrar_id, ip_address; `details` omitted to avoid logging user-supplied content). Logpush / Tail can filter on the tag to detect gaps and alert. The two `/admin/force-*` paths use the same structured tag in their own catch blocks for consistency.
- **M1 — empty string → NULL on operator lookup binds.** `POST /register` and `POST /operators/verify-domain` bound missing `domain` / `email` as `''` instead of `null`. Querying `WHERE domain = '' OR email = ''` against a row whose corresponding field was `''` (drift) would silently match the wrong operator; binding `NULL` makes the predicate cleanly unknown and surfaces the missing-operator case as a 404. Behavioural change is invisible on clean data; defense-in-depth against schema drift.
- **M2 — 4 KB raw-token cap in `extractPresentationContext` before `atob`.** Bearer / `?ait=` tokens of arbitrary size were base64-decoded before any size check, giving an attacker an amplification / CPU-burn vector on every public read. Tokens larger than 4 KB now short-circuit as "no presentation context" (the function intentionally never rejects the request — it falls back to the public layer instead).
- **M3 — `cascadeRevoke` depth cap (16) + visited Set.** The recursive delegation-cascade walker had neither bound. Added shared `visited` Set + `depth` parameter; depth-cap exhaustion logs a structured `CASCADE_DEPTH_CAP_HIT` line so we'll notice if any legitimate chain ever approaches the limit (in practice chains are 2-4 deep).
- **M5 — 90-day max horizon on delegation `expires`.** `POST /delegations` accepted any future timestamp, letting callers mint effectively immortal delegations and defeating revocation hygiene. Also added explicit checks for "is a valid ISO-8601 string" and "is in the future" (both previously implicit). Tier-aware ceilings (e.g. 365 days for KYB) deferred to a follow-up; one number for launch.
- **M6 — domain shape regex + 5s `AbortController` timeout on `verifyDNS` / `verifyHTTP`.** Operator-supplied `domain` values were interpolated into outbound URLs without shape validation, and fetches had no timeout. RFC1918 / link-local are already blocked by the Workers runtime; this is defense-in-depth on shape (RFC 1035/1123 hostname) and on hung-target liveness. Shape validation also closes the path where a junk value (`example.com/?nope=`) would have produced a deformed DoH query URL.
- **M7 — 400 `invalid_encoding` instead of 500 on malformed `decodeURIComponent` input.** All 14 `decodeURIComponent` call sites parse user-controlled URL path segments. Bad percent-encoding currently throws `URIError`, which the outer catch surfaces as 500. Added a `URIError` branch to the outer catch so the entire surface returns 400 `invalid_encoding` without 14 inline try/catch wrappers.
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
