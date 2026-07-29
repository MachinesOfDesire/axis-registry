-- Migration 0011: verification-tier vocabulary correction — email | domain | kyc | kyb.
--
-- Pre-v0.3-ratification vocabulary correction (protocol CHANGELOG, Unreleased):
-- KYC always verifies a natural person and KYB always verifies a registered
-- legal entity, so the _individual/_business suffixes carried no information.
-- The canonical ladder becomes four bare method names, totally ordered:
--   email < domain < kyc < kyb
-- Mapping applied to existing rows:
--   kyb_individual   → kyc
--   kyb_organization → kyb
-- Entity categories (education/nonprofit/etc.) are NOT tiers; if needed later
-- they become an attested org_category attribute from the KYB result.
--
-- SQLite cannot ALTER a CHECK constraint, so this is a table rebuild. Because
-- `agents` and `agent_slots` hold FOREIGN KEYs into `operators`, the rebuild
-- must also rebuild BOTH child tables: dropping a referenced parent registers
-- deferred FK violations for every child row, and SQLite's deferred-violation
-- counter is bookkeeping, not a commit-time re-scan — renaming a replacement
-- table into place does NOT retroactively clear the counter, so the naive
-- parent-only rebuild fails at commit with `FOREIGN KEY constraint failed`
-- (observed against prod D1, 2026-07-29; D1 rolled back cleanly).
--
-- The order below never leaves an FK-violating window:
--   1. build operators_new (corrected CHECK) and copy rows (tiers rewritten);
--   2. build agents_new / agent_slots_new REFERENCING operators_new, copy rows;
--   3. drop the OLD children (nothing references them — clean);
--   4. drop the OLD operators (nothing references it anymore — clean);
--   5. rename operators_new → operators (SQLite rewrites the new children's
--      FK clauses from operators_new to operators), then rename the children;
--   6. recreate all indexes (the old ones died with their tables).
--
-- PRE-FLIGHT — run against prod before applying:
--   1. Confirm the live DDL of operators, agents, agent_slots matches the
--      rebuild column lists below:
--        SELECT sql FROM sqlite_master WHERE type='table'
--         AND name IN ('operators','agents','agent_slots');
--   2. Record the tier distribution being rewritten:
--        SELECT verification_tier, COUNT(*) FROM operators GROUP BY verification_tier;
--   3. Confirm no orphaned child rows (a pre-existing orphan fails the rebuild):
--        SELECT COUNT(*) FROM agents WHERE operator_id NOT IN (SELECT id FROM operators);
--        SELECT COUNT(*) FROM agent_slots WHERE operator_id NOT IN (SELECT id FROM operators);
--
-- Apply via:
--   wrangler d1 migrations apply axis-registry-db --remote

PRAGMA defer_foreign_keys = true;

-- 1. Rebuild parent with the corrected CHECK.
CREATE TABLE operators_new (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  domain TEXT,
  domain_verified INTEGER NOT NULL DEFAULT 0,
  domain_verified_at TEXT,
  domain_verification_method TEXT CHECK(domain_verification_method IN ('dns_txt', 'http_file', NULL)),
  domain_verification_token TEXT,
  domain_verification_expires TEXT,
  verification_tier TEXT NOT NULL DEFAULT 'email' CHECK(verification_tier IN ('email', 'domain', 'kyc', 'kyb')),
  kyb_verified INTEGER NOT NULL DEFAULT 0,
  kyb_verified_at TEXT,
  kyb_provider TEXT,
  operator_did TEXT,
  public_key TEXT,
  stripe_customer_id TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deactivated')),
  registrar_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (registrar_id) REFERENCES registrars(id)
);

INSERT INTO operators_new (
  id, email, domain, domain_verified, domain_verified_at,
  domain_verification_method, domain_verification_token, domain_verification_expires,
  verification_tier, kyb_verified, kyb_verified_at, kyb_provider,
  operator_did, public_key, stripe_customer_id, status, registrar_id,
  created_at, updated_at
)
SELECT
  id, email, domain, domain_verified, domain_verified_at,
  domain_verification_method, domain_verification_token, domain_verification_expires,
  CASE verification_tier
    WHEN 'kyb_individual'   THEN 'kyc'
    WHEN 'kyb_organization' THEN 'kyb'
    ELSE verification_tier
  END,
  kyb_verified, kyb_verified_at, kyb_provider,
  operator_did, public_key, stripe_customer_id, status, registrar_id,
  created_at, updated_at
FROM operators;

-- 2. Rebuild children against operators_new (rows unchanged).
CREATE TABLE agents_new (
  id TEXT PRIMARY KEY,
  axis_id TEXT NOT NULL UNIQUE,
  did TEXT NOT NULL UNIQUE,
  operator_id TEXT NOT NULL,
  display_name TEXT,
  description TEXT,
  public_key TEXT NOT NULL,
  key_algorithm TEXT NOT NULL DEFAULT 'Ed25519',
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked', 'deactivated')),
  revoked_at TEXT,
  revocation_reason TEXT,
  registration_tier TEXT NOT NULL CHECK(registration_tier IN ('free', 'paid', 'kyb')),
  registrar_id TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  service_endpoints TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (operator_id) REFERENCES operators_new(id),
  FOREIGN KEY (registrar_id) REFERENCES registrars(id)
);

INSERT INTO agents_new (
  id, axis_id, did, operator_id, display_name, description, public_key,
  key_algorithm, status, revoked_at, revocation_reason, registration_tier,
  registrar_id, version, service_endpoints, created_at, updated_at
)
SELECT
  id, axis_id, did, operator_id, display_name, description, public_key,
  key_algorithm, status, revoked_at, revocation_reason, registration_tier,
  registrar_id, version, service_endpoints, created_at, updated_at
FROM agents;

CREATE TABLE agent_slots_new (
  operator_id TEXT PRIMARY KEY,
  free_slots_total INTEGER NOT NULL DEFAULT 3,
  free_slots_used INTEGER NOT NULL DEFAULT 0,
  paid_agents INTEGER NOT NULL DEFAULT 0,
  max_agents INTEGER,
  FOREIGN KEY (operator_id) REFERENCES operators_new(id)
);

INSERT INTO agent_slots_new (operator_id, free_slots_total, free_slots_used, paid_agents, max_agents)
SELECT operator_id, free_slots_total, free_slots_used, paid_agents, max_agents
FROM agent_slots;

-- 3. Drop old children (nothing references them), then the old parent
--    (nothing references it anymore).
DROP TABLE agents;
DROP TABLE agent_slots;
DROP TABLE operators;

-- 4. Swap names. Renaming operators_new rewrites the new children's FK
--    clauses to reference "operators".
ALTER TABLE operators_new RENAME TO operators;
ALTER TABLE agents_new RENAME TO agents;
ALTER TABLE agent_slots_new RENAME TO agent_slots;

-- 5. Recreate indexes (0007's UNIQUE semantics preserved exactly).
CREATE UNIQUE INDEX idx_operators_email ON operators(email);
CREATE UNIQUE INDEX idx_operators_domain ON operators(domain) WHERE domain IS NOT NULL;
CREATE INDEX idx_operators_stripe ON operators(stripe_customer_id);
CREATE INDEX idx_agents_operator ON agents(operator_id);
CREATE INDEX idx_agents_axis_id ON agents(axis_id);
CREATE INDEX idx_agents_did ON agents(did);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_public_key ON agents(public_key);

-- Telemetry hygiene: verify_events.operator_tier snapshots the operator's tier
-- at verify time, so historical rows carry the old strings. Rewrite them so
-- tier-distribution queries read one vocabulary. (No 'verified' rows can
-- exist — the operators CHECK never permitted that value and no writer
-- recorded it; the 0008 header comment that listed it was stale.)
UPDATE verify_events SET operator_tier = 'kyc' WHERE operator_tier = 'kyb_individual';
UPDATE verify_events SET operator_tier = 'kyb' WHERE operator_tier = 'kyb_organization';
