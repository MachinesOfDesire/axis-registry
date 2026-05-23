-- Migration: 0006_parent_operator_id.sql
--
-- Add nullable `parent_operator_id` column to operators table, enabling
-- a three-level principal hierarchy (organization → user → agent) without
-- breaking the existing two-level model.
--
-- Spec: docs/specs/axis-registry-v0.x-changes-spec.md, Change 1.
-- Companion: Kipple Governor v0.1 depends on this column.
--
-- Note on migration number: spec text says "0003_parent_operator_id.sql"
-- but 0003 is already taken (api_key_hash_constraint). This file is the
-- next available number (0006). Filename adjusted accordingly; the spec's
-- intent — "the next migration" — is honored.
--
-- Semantics:
--   parent_operator_id IS NULL → top-level entity (organization, free-
--                                standing individual operator). Existing
--                                rows retain NULL and behave identically.
--   parent_operator_id IS NOT NULL → child of the referenced operator
--                                    (a user under an organization).
--
-- D1/SQLite does not support adding a FOREIGN KEY constraint via ALTER
-- TABLE. FK semantics are enforced at the application layer for existing
-- deployments. Fresh deploys (via schema.sql) carry the FK inline.
--
-- Backward-compatibility: the column is nullable. Any client that doesn't
-- supply parent_operator_id on POST creates a top-level operator (current
-- behavior). Existing rows are untouched.

ALTER TABLE operators ADD COLUMN parent_operator_id TEXT;

-- Index supports GET /operators/:id/children lookups by parent.
CREATE INDEX IF NOT EXISTS idx_operators_parent ON operators(parent_operator_id);
