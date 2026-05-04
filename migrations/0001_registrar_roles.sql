-- Migration 0001: Registrar roles for BOLA authorization fix
--
-- Introduces a three-role model on the registrars table:
--   'registrar'    (default) — can only touch resources where registrar_id = me.id
--   'admin'                   — full READ across tenants; MUTATIONS still scoped to own registrar_id
--   'super_admin'             — admin + break-glass /admin/force-* endpoints (audit-required)
--
-- SQLite/D1 does not support adding a CHECK constraint via ALTER TABLE, so we enforce
-- the allowed values in application code (middleware/auth.js) and default at the column
-- level here. Existing rows get the default 'registrar' role.

ALTER TABLE registrars
  ADD COLUMN role TEXT NOT NULL DEFAULT 'registrar';

CREATE INDEX IF NOT EXISTS idx_registrars_role ON registrars(role);

-- Elevate the Kipple Labs seed registrar (the row whose API key is used by
-- the registrar-app via REGISTRY_API_KEY) to super_admin. This is the only
-- row bootstrapped by schema.sql / seed-key.sql.
UPDATE registrars SET role = 'super_admin' WHERE id = 'kipple-labs';
