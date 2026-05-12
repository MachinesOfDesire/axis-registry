-- Migration 0005: C1 / spec v0.2 §10.3 — re-issue existing agent DIDs in
-- the operator-namespaced v0.2 form.
--
-- Phase 1 (PR #8) made *new* registrations emit v0.2 DIDs. This migration
-- is Phase 2: it brings the existing rows (25 agents on prod at cutover
-- time, all of which were registered before Phase 1) to the same form.
--
-- Strategy: leave operator_id strings alone, just re-derive each agent's
-- DID as `did:axis:prime:<operator_id>:<agent_id>`. The operator slug is
-- still derived from verification proof (that's how it ended up in
-- operators.id in the first place), it's just historically transformed
-- differently than the v0.2 helper would emit for a brand-new operator.
-- For new operators registered after Phase 1, operators.id already uses
-- the cleaner shape via deriveOperatorSlug().
--
-- Per the 2026-05-11 locked decision (Cross-Project Coordination C1):
-- "Re-issue DIDs for existing 25 agents at cutover — no legacy alias
-- period needed since it's almost entirely Josh's test data."
--
-- Pre-flight check (must return non-zero v0_1_count before this is useful):
--   SELECT COUNT(*) AS total,
--          SUM(CASE WHEN length(did) - length(replace(did, ':', '')) = 3 THEN 1 ELSE 0 END) AS v0_1_count,
--          SUM(CASE WHEN length(did) - length(replace(did, ':', '')) = 4 THEN 1 ELSE 0 END) AS v0_2_count
--     FROM agents;
--
-- Apply via:
--   wrangler d1 execute axis-registry-db --remote --file=migrations/0005_c1_v0_2_did_cutover.sql
--   wrangler d1 execute axis-registry-db --remote --command \
--     "INSERT INTO d1_migrations (name) VALUES ('0005_c1_v0_2_did_cutover.sql')"
--
-- Post-flight check (should report v0_1_count = 0):
--   (same SELECT as pre-flight)
--
-- Rollback strategy: there's no automated rollback for this migration
-- since the v0.1 DID is fully derivable from the v0.2 form (drop the
-- third colon-segment). If a rollback is needed, run:
--   UPDATE agents
--      SET did = 'did:axis:prime:' || id,
--          updated_at = datetime('now')
--    WHERE length(did) - length(replace(did, ':', '')) = 4
--      AND did LIKE 'did:axis:prime:%';

UPDATE agents
   SET did = 'did:axis:prime:' || operator_id || ':' || id,
       updated_at = datetime('now')
 WHERE length(did) - length(replace(did, ':', '')) = 3
   AND did LIKE 'did:axis:prime:%';
