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
-- SQLite cannot ALTER a CHECK constraint, so this is a standard table rebuild:
-- create the replacement table with the corrected CHECK, copy every row
-- (rewriting the two renamed tier values), swap, and recreate the operators
-- indexes (0007's UNIQUE semantics preserved exactly).
--
-- PRE-FLIGHT — both checks MUST be run against prod before applying:
--   1. Confirm the live operators DDL matches this rebuild's column list
--      (no drift — no migration has ever added a column to operators):
--        SELECT sql FROM sqlite_master WHERE type='table' AND name='operators';
--   2. Record the tier distribution being rewritten:
--        SELECT verification_tier, COUNT(*) FROM operators GROUP BY verification_tier;
--
-- Apply via:
--   wrangler d1 migrations apply axis-registry-db --remote

PRAGMA defer_foreign_keys = true;

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

DROP TABLE operators;
ALTER TABLE operators_new RENAME TO operators;

CREATE UNIQUE INDEX idx_operators_email ON operators(email);
CREATE UNIQUE INDEX idx_operators_domain ON operators(domain) WHERE domain IS NOT NULL;
CREATE INDEX idx_operators_stripe ON operators(stripe_customer_id);

-- Telemetry hygiene: verify_events.operator_tier snapshots the operator's tier
-- at verify time, so historical rows carry the old strings. Rewrite them so
-- tier-distribution queries read one vocabulary. (No 'verified' rows can
-- exist — the operators CHECK never permitted that value and no writer
-- recorded it; the 0008 header comment that listed it was stale.)
UPDATE verify_events SET operator_tier = 'kyc' WHERE operator_tier = 'kyb_individual';
UPDATE verify_events SET operator_tier = 'kyb' WHERE operator_tier = 'kyb_organization';
