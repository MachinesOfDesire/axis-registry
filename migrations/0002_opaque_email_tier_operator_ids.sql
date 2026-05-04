-- Migration 0002: opaque operator ids for legacy email-leaking rows
--
-- Pre-April-23 operator-id derivation leaked the email local-part into a
-- publicly-enumerable identifier (e.g. `josh.ashcroft+test3-23f67f61`). The
-- derivation has been fixed in code (routes/operators.js and routes/register.js,
-- April 23 2026) to use `op-` + 12 random hex chars. This migration renames
-- existing rows that carry the legacy format.
--
-- Mechanics: operators.id is referenced by agent_slots.operator_id (FK
-- without ON UPDATE CASCADE), so an UPDATE on operators.id fails with a
-- FK constraint. We use the insert-new / migrate-references / delete-old
-- pattern. At the moment of DELETE there are no remaining referrers.
--
-- No agents exist under any of the three rows touched here (verified before
-- writing), so only agent_slots need to move.

-- ── Row 1: josh.ashcroft-55df8002  ->  op-8f3998c35292 ─────────────────────
INSERT INTO operators (id, email, domain, verification_tier, domain_verified, domain_verified_at, domain_verification_token, domain_verification_expires, domain_verification_method, public_key, status, registrar_id, created_at, updated_at)
SELECT 'op-8f3998c35292', email, domain, verification_tier, domain_verified, domain_verified_at, domain_verification_token, domain_verification_expires, domain_verification_method, public_key, status, registrar_id, created_at, datetime('now')
  FROM operators WHERE id = 'josh.ashcroft-55df8002';
UPDATE agent_slots SET operator_id = 'op-8f3998c35292' WHERE operator_id = 'josh.ashcroft-55df8002';
DELETE FROM operators WHERE id = 'josh.ashcroft-55df8002';

-- ── Row 2: josh.ashcroft+axistest-105de4ca  ->  op-4451d99ee158 ────────────
INSERT INTO operators (id, email, domain, verification_tier, domain_verified, domain_verified_at, domain_verification_token, domain_verification_expires, domain_verification_method, public_key, status, registrar_id, created_at, updated_at)
SELECT 'op-4451d99ee158', email, domain, verification_tier, domain_verified, domain_verified_at, domain_verification_token, domain_verification_expires, domain_verification_method, public_key, status, registrar_id, created_at, datetime('now')
  FROM operators WHERE id = 'josh.ashcroft+axistest-105de4ca';
UPDATE agent_slots SET operator_id = 'op-4451d99ee158' WHERE operator_id = 'josh.ashcroft+axistest-105de4ca';
DELETE FROM operators WHERE id = 'josh.ashcroft+axistest-105de4ca';

-- ── Row 3: josh.ashcroft+test3-23f67f61  ->  op-44e7a1fcb7da ──────────────
-- This row already got a partial migration: the registrar-app accounts row
-- carries 'op-44e7a1fcb7da'. Realign registry to that same id so the two
-- databases stay consistent.
INSERT INTO operators (id, email, domain, verification_tier, domain_verified, domain_verified_at, domain_verification_token, domain_verification_expires, domain_verification_method, public_key, status, registrar_id, created_at, updated_at)
SELECT 'op-44e7a1fcb7da', email, domain, verification_tier, domain_verified, domain_verified_at, domain_verification_token, domain_verification_expires, domain_verification_method, public_key, status, registrar_id, created_at, datetime('now')
  FROM operators WHERE id = 'josh.ashcroft+test3-23f67f61';
UPDATE agent_slots SET operator_id = 'op-44e7a1fcb7da' WHERE operator_id = 'josh.ashcroft+test3-23f67f61';
DELETE FROM operators WHERE id = 'josh.ashcroft+test3-23f67f61';
