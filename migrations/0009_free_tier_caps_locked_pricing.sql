-- Migration 0009: reconcile free-tier agent caps to the locked pricing model.
--
-- Background: the decoupled pricing model (2026-07-04; supersedes the earlier
-- 2026-06-16 10/100 figures) defines free-tier agent caps as HARD caps with no
-- per-agent fees and no unlimited fallthrough:
--
--   Single Operator (email-verified)  → 25 agents
--   Team (domain-verified)            → 250 agents
--   Verified (registrar quota push)   → 1000 agents
--
-- The code previously created: email tier free_slots_total=0 / max_agents=5,
-- domain tier free_slots_total=3 / max_agents=NULL (unlimited — agents beyond
-- the free count silently tallied as paid_agents with no billing behind it).
-- The same PR fixes the creation path (src/routes/operators.js TIER_CAPS);
-- this migration upgrades EXISTING rows.
--
-- Rules (idempotent — every UPDATE is a raise-only reconcile, so re-running
-- is a no-op once rows conform):
--   * domain tier: free_slots_total → 250 and max_agents → 250, but NEVER
--     lower an existing value that is already >= the target (e.g. a
--     registrar-pushed max_agents=1000 stays 1000). max_agents NULL → 250 is
--     an intentional LOWERING from unlimited: the hard-cap model has no
--     unlimited free tier.
--   * email tier: free_slots_total → 25, max_agents 5 → 25, same raise-only
--     guard. An email-tier max_agents that is NULL (should not exist; only a
--     manual grant could produce it) is left untouched — this migration only
--     removes the unlimited default at the DOMAIN tier, it does not claw back
--     an explicit grant.
--   * KYB / verified tiers: untouched. Their caps come from the registrar's
--     verification push (POST /operators/:id/verification), which is correct
--     as-is.
--
-- Apply via:
--   wrangler d1 execute axis-registry-db --remote --file=migrations/0009_free_tier_caps_locked_pricing.sql
--   wrangler d1 execute axis-registry-db --remote --command \
--     "INSERT INTO d1_migrations (name) VALUES ('0009_free_tier_caps_locked_pricing.sql')"

-- Domain (Team) tier: free slots 3 → 250 (raise-only).
UPDATE agent_slots
   SET free_slots_total = 250
 WHERE free_slots_total < 250
   AND operator_id IN (
     SELECT id FROM operators WHERE verification_tier = 'domain'
   );

-- Domain (Team) tier: max_agents NULL → 250 (kill the unlimited fallthrough)
-- and raise anything below 250; never lower a cap already >= 250.
UPDATE agent_slots
   SET max_agents = 250
 WHERE (max_agents IS NULL OR max_agents < 250)
   AND operator_id IN (
     SELECT id FROM operators WHERE verification_tier = 'domain'
   );

-- Email (Single Operator) tier: free slots 0 → 25 (raise-only).
UPDATE agent_slots
   SET free_slots_total = 25
 WHERE free_slots_total < 25
   AND operator_id IN (
     SELECT id FROM operators WHERE verification_tier = 'email'
   );

-- Email (Single Operator) tier: max_agents 5 → 25 (raise-only; NULL left
-- alone per the note above).
UPDATE agent_slots
   SET max_agents = 25
 WHERE max_agents IS NOT NULL
   AND max_agents < 25
   AND operator_id IN (
     SELECT id FROM operators WHERE verification_tier = 'email'
   );
