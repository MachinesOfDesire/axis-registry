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
-- Apply via:
--   wrangler d1 execute axis-registry-db --remote --file=migrations/0003_api_key_hash_constraint.sql
--   wrangler d1 execute axis-registry-db --remote --command \
--     "INSERT INTO d1_migrations (name) VALUES ('0003_api_key_hash_constraint.sql')"

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

-- 1) Create the new table with the hardened constraint.
CREATE TABLE registrars_new (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('connected', 'private', 'root')),
  api_key_hash TEXT NOT NULL CHECK(length(api_key_hash) = 64 AND api_key_hash <> ''),
  domain TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked')),
  role TEXT NOT NULL DEFAULT 'registrar' CHECK(role IN ('registrar', 'admin', 'super_admin')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  metadata TEXT
);

-- 2) Copy rows. If any existing row has api_key_hash = '' or length != 64,
--    the INSERT will fail with the CHECK violation. That's the point — fix
--    the row before applying this migration. Run a pre-flight check first:
--      SELECT id, length(api_key_hash) FROM registrars
--      WHERE api_key_hash = '' OR length(api_key_hash) <> 64;
--    Should return zero rows.
INSERT INTO registrars_new SELECT * FROM registrars;

-- 3) Swap.
DROP TABLE registrars;
ALTER TABLE registrars_new RENAME TO registrars;

COMMIT;

PRAGMA foreign_keys = ON;
