-- Re-seed the three demo agents (VERAK, LIBRA-7, VALE) + their operator
-- onto the migrated registry. Run once after a fresh schema apply.
--
-- Public keys were derived from the private keys hardcoded in
--   C:\Users\josha\.openclaw\axis-demo-api\wrangler.toml
-- so AITs signed by those private keys will still verify against these
-- stored public keys without re-issuing anything on the demo worker side.

-- 1) Demo operator (email-tier, onboarded by Kipple Labs registrar)
INSERT OR REPLACE INTO operators
  (id, email, verification_tier, status, registrar_id, created_at, updated_at)
VALUES
  ('demo-e484604d', 'demo@axisprime.ai', 'email', 'active', 'kipple-labs',
   datetime('now'), datetime('now'));

-- 2) Slot allocation for the demo operator (email tier: 3 free, 5 max)
INSERT OR REPLACE INTO agent_slots
  (operator_id, free_slots_total, free_slots_used, paid_agents, max_agents)
VALUES
  ('demo-e484604d', 3, 3, 0, 5);

-- 3) VERAK
INSERT OR REPLACE INTO agents
  (id, axis_id, did, operator_id, display_name, description, public_key,
   key_algorithm, status, registration_tier, registrar_id, version,
   created_at, updated_at)
VALUES
  ('verak',
   'axis:demo-e484604d:verak',
   'did:axis:prime:verak',
   'demo-e484604d',
   'VERAK',
   'AXIS demo agent',
   'lDwxSH896YH5IlqxAHaZmKFAI-32qIiLBTdTPOcTVCE',
   'Ed25519', 'active', 'free', 'kipple-labs', 1,
   datetime('now'), datetime('now'));

-- 4) LIBRA-7
INSERT OR REPLACE INTO agents
  (id, axis_id, did, operator_id, display_name, description, public_key,
   key_algorithm, status, registration_tier, registrar_id, version,
   created_at, updated_at)
VALUES
  ('libra-7',
   'axis:demo-e484604d:libra-7',
   'did:axis:prime:libra-7',
   'demo-e484604d',
   'LIBRA-7',
   'AXIS demo agent',
   'eBjj90caoNPHtKqCAn4OvDJ8_s03HT5iSYyEXZvkaTA',
   'Ed25519', 'active', 'free', 'kipple-labs', 1,
   datetime('now'), datetime('now'));

-- 5) VALE
INSERT OR REPLACE INTO agents
  (id, axis_id, did, operator_id, display_name, description, public_key,
   key_algorithm, status, registration_tier, registrar_id, version,
   created_at, updated_at)
VALUES
  ('vale',
   'axis:demo-e484604d:vale',
   'did:axis:prime:vale',
   'demo-e484604d',
   'VALE',
   'AXIS demo agent',
   'y1eEsxbPp59rZNRfxD1OeQ8YnHNMdIiFfKB2TVdKKy8',
   'Ed25519', 'active', 'free', 'kipple-labs', 1,
   datetime('now'), datetime('now'));
