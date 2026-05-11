-- Migration 0003: harden api_key_hash column
-- Per 2026-05-08 security review (H3): an empty `api_key_hash` would let
-- `Authorization: Bearer ` (empty) authenticate via the SHA-256-of-empty
-- hash. Production seed sets a real hash, but no schema constraint prevents
-- future drift, and a row created without `api_key_hash` (NULL → empty) would
-- be a vulnerability.
--
-- D1 (SQLite) does not support adding a CHECK constraint to an existing
-- column directly. We rebuild the table with the constraint, copy data, and
-- swap. Standard SQLite ALTER pattern.
--
-- IMPORTANT: this migration was applied to live D1 on 2026-05-11. The committed
-- form below is the one that successfully ran. Two things differ from a naive
-- table-rebuild template:
--   1) NO `BEGIN TRANSACTION` / `COMMIT` block — D1 rejects explicit transaction
--      statements (`To execute a transaction, please use state.storage.transaction()`).
--      D1 stops on first error, so on failure the partially-completed steps
--      stay (CREATE TABLE registrars_new survives; data table untouched). Re-running
--      requires `DROP TABLE registrars_new` first.
--   2) Explicit column list on the INSERT. The live `registrars` table has
--      `role` at column position 10 because migration 0001 appended it via
--      `ALTER TABLE ADD COLUMN`. `SELECT *` returns columns in that order, so a
--      positional INSERT would mismap. The schema.sql column order (with role
--      at position 7) only applies to fresh databases created from schema.sql,
--      not to existing prod.
--
-- Apply via:
--   wrangler d1 execute axis-registry-db --remote --file=migrations/0003_api_key_hash_constraint.sql
--   wrangler d1 execute axis-registry-db --remote --command \
--     "INSERT INTO d1_migrations (name) VALUES ('0003_api_key_hash_constraint.sql')"
--
-- Pre-flight check (must return zero rows):
--   SELECT id, length(api_key_hash) FROM registrars
--   WHERE api_key_hash = '' OR length(api_key_hash) <> 64;

PRAGMA foreign_keys = OFF;

-- 1) Create the new table with the hardened constraint.
--    Column order matches the live prod table (role appended last by ALTER TABLE
--    in migration 0001). For fresh databases the schema.sql order is different
--    but the schema is logically equivalent; SQLite does not enforce column order
--    for query semantics.
CREATE TABLE registrars_new (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('connected', 'private', 'root')),
  api_key_hash TEXT NOT NULL CHECK(length(api_key_hash) = 64 AND api_key_hash <> ''),
  domain TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  metadata TEXT,
  role TEXT NOT NULL DEFAULT 'registrar' CHECK(role IN ('registrar', 'admin', 'super_admin'))
);

-- 2) Copy rows with explicit column list. If any existing row has
--    api_key_hash = '' or length != 64, the INSERT fails with the CHECK
--    violation — fix the row before applying this migration (see pre-flight).
INSERT INTO registrars_new (id, name, type, api_key_hash, domain, status, created_at, updated_at, metadata, role)
  SELECT id, name, type, api_key_hash, domain, status, created_at, updated_at, metadata, role FROM registrars;

-- 3) Swap.
DROP TABLE registrars;
ALTER TABLE registrars_new RENAME TO registrars;

PRAGMA foreign_keys = ON;
