# Changelog

All notable changes to `axis-registry`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

This is the production AXIS registry deployed at `registry.axisprime.ai`. It does not follow strict semver — the wire-protocol contract is owned by the [AXIS Protocol Spec](https://github.com/MachinesOfDesire/axis-protocol). The version on this changelog tracks deployable revisions of the worker code, not protocol revisions.

## [Unreleased]

Branch: `security-hardening-2026-05-08`. Items below are merged into `main` and deployed when verified.

### Added

- `migrations/0003_api_key_hash_constraint.sql` — adds `CHECK(length(api_key_hash) = 64 AND api_key_hash <> '')` to the `registrars` table. Closes finding H3 from the 2026-05-08 security review (an empty `api_key_hash` row would have allowed authenticating with `Authorization: Bearer ` against the SHA-256 of empty string). Production seed has a real hash so this is hardening, not a live exploit. Pre-flight check documented inline.
- `test/crypto.test.js` — 20 unit tests for `src/utils/crypto.js`, covering `deriveAgentId` determinism, `verifyEd25519Signature` accept/reject paths, base58/base64url codec roundtrips, and the multibase `z` prefix path. Combined with the existing `test/unit.test.js` (middleware/auth) the registry now has 39 unit tests, all pure-function (no Workers binding required). Route-level coverage is still TODO; needs a Wrangler/Miniflare harness for the BOLA matrix and AIT verification matrix.

### Changed

- `schema.sql`: inline the H3 CHECK constraint on `api_key_hash` so fresh databases don't need migration 0003 to be safe.
- `README.md`: deploy section now lists migration 0003 in the fresh-database sequence.

### Pending decisions

- C1 (DID name squatting): operator-namespaced DIDs. Wire-protocol-touching change → AXIS spec v0.2 candidate.
- C2 (slot accounting race): `env.DB.batch([...])` atomic + conditional UPDATE.
- C3 (no rate limiting): Cloudflare RateLimit binding, per-IP for public endpoints + per-API-key for authenticated.
- H1 (no `aud` enforcement on AITs): server-side check against platform identifier. Wire-protocol-touching → coordinated with AXIS spec v0.2.
- See `Kipple Labs Branding/security-review-2026-05-08/SECURITY-REVIEW.md` for full list.

## 2026-05-08 — pagination + URL hardening

(Pre-CHANGELOG commits, captured retroactively. Commit `e75b1cd`.)

- Replaced stale `*.workers.dev` fallback URLs in route handlers — `REGISTRY_BASE_URL` from env is now authoritative.
- Pagination clamping in admin list endpoints: `limit` is now clamped to `[1, 500]` and `offset` to `[0, ∞)` with `parseInt` fallbacks. Closes finding H5 (negative `LIMIT` was treated as unlimited by SQLite).
- Additional unit tests in `test/unit.test.js`.

## 2026-05-04 — RBAC + opaque operator IDs (production cutover)

(Pre-CHANGELOG; commit `8b6f31e` plus `bee826a` seed-key alignment, `e0d7f00` OSS readiness, `73d4bda` gitignore wrangler.toml.)

- Three-role authorization model: `registrar`, `admin`, `super_admin` enforced server-side. BOLA constraints on every mutation route. Break-glass force-* endpoints require non-empty `reason` and audit-row-before-mutate semantics.
- Migration 0001: registrar roles.
- Migration 0002: opaque `op-{random}` operator IDs replacing email-tier IDs (closes the email-as-PII-in-identifier issue captured in `registry-conformance-v0.1.md` §8.1.1).
- `seed-key.sql` aligned with rotated production hash.
- OSS readiness files (`SECURITY.md`, `CONTRIBUTING.md`).

## 2026-04 — initial public push

Repo went public at `MachinesOfDesire/axis-registry` with the v0.1 surface
(`/register`, `/agents/:id`, `/verify`, `/delegations`, `/operators/verify-domain`, etc.). Schema versioned at 0.1.0.
