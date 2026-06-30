-- Migration 0007: enforce operator identity at the database layer.
--
-- Background: the 2026-06-29 email-tier signup incident (and the no-clobber
-- follow-up) both traced to one root cause — `handleVerifyDomain` upheld the
-- "one operator per email" invariant only in application code: SELECT by
-- (email OR domain), then branch INSERT-vs-UPDATE. That is a TOCTOU race and,
-- more importantly, a rule a human has to remember and re-implement correctly
-- every time. Nothing stopped two rows sharing an email, and a speculative
-- (random) operator id could be returned that was never persisted.
--
-- This migration makes the natural keys UNIQUE so the database itself refuses
-- a duplicate operator. Combined with the upsert + RETURNING rewrite of
-- handleVerifyDomain (same PR), "return the persisted id", "never create a
-- duplicate operator", and "an absent value can't clobber an existing one"
-- stop being remembered rules and become properties the code cannot violate.
--
-- email:  UNIQUE — one operator per email address.
-- domain: UNIQUE, PARTIAL (WHERE domain IS NOT NULL) — a verified domain
--         belongs to exactly one operator, while the many email-tier
--         operators that have domain=NULL do not collide. (SQLite already
--         treats NULLs as distinct under a UNIQUE index, but the partial
--         predicate makes the intent explicit and keeps NULLs out of the index.)
--
-- The old non-unique idx_operators_email / idx_operators_domain are dropped and
-- replaced; a UNIQUE index serves the same lookups, so no read path regresses.
--
-- PRE-FLIGHT — this migration FAILS if any duplicates already exist. Both
-- queries MUST return zero rows before applying:
--   SELECT email, COUNT(*) n FROM operators GROUP BY email HAVING n > 1;
--   SELECT domain, COUNT(*) n FROM operators WHERE domain IS NOT NULL GROUP BY domain HAVING n > 1;
-- Verified clean on prod (axis-registry-db) at authoring time: 11 operators,
-- 0 duplicate emails (incl. case-insensitive), 0 duplicate domains.
--
-- Apply via:
--   wrangler d1 execute axis-registry-db --remote --file=migrations/0007_operator_unique_constraints.sql
--   wrangler d1 execute axis-registry-db --remote --command \
--     "INSERT INTO d1_migrations (name) VALUES ('0007_operator_unique_constraints.sql')"

DROP INDEX IF EXISTS idx_operators_email;
DROP INDEX IF EXISTS idx_operators_domain;

CREATE UNIQUE INDEX idx_operators_email ON operators(email);
CREATE UNIQUE INDEX idx_operators_domain ON operators(domain) WHERE domain IS NOT NULL;
