-- AXIS Registry D1 Schema
-- Version: 0.1.0
-- Database: Cloudflare D1 (SQLite)

-- ============================================
-- REGISTRARS
-- Authorized parties that can submit registrations
-- Kipple Labs is the first registrar
-- ============================================
CREATE TABLE IF NOT EXISTS registrars (
  id TEXT PRIMARY KEY,                          -- e.g., "kipple-labs"
  name TEXT NOT NULL,                           -- "Kipple Labs"
  type TEXT NOT NULL CHECK(type IN ('connected', 'private', 'root')),
  api_key_hash TEXT NOT NULL CHECK(length(api_key_hash) = 64 AND api_key_hash <> ''),  -- SHA-256 hash of API key (must be 64 hex chars; closes 2026-05-08 finding H3)
  domain TEXT,                                  -- registrar's domain
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  metadata TEXT                                 -- JSON blob for extra info
);

-- ============================================
-- OPERATORS
-- Organizations or individuals that control agents
-- ============================================
CREATE TABLE IF NOT EXISTS operators (
  id TEXT PRIMARY KEY,                          -- e.g., "offworld" (namespace)
  email TEXT NOT NULL,
  domain TEXT,                                  -- verified domain (nullable for email-only)
  domain_verified INTEGER NOT NULL DEFAULT 0,
  domain_verified_at TEXT,
  domain_verification_method TEXT CHECK(domain_verification_method IN ('dns_txt', 'http_file', NULL)),
  domain_verification_token TEXT,               -- pending verification token
  domain_verification_expires TEXT,             -- token expiry
  verification_tier TEXT NOT NULL DEFAULT 'email' CHECK(verification_tier IN ('email', 'domain', 'kyb_individual', 'kyb_organization')),
  kyb_verified INTEGER NOT NULL DEFAULT 0,
  kyb_verified_at TEXT,
  kyb_provider TEXT,                            -- third-party KYB provider name
  operator_did TEXT,                            -- did:axis:prime:op:{domain} (if Operator Identity purchased)
  public_key TEXT,                              -- Ed25519 public key (base64url) for operator signing
  stripe_customer_id TEXT,                      -- Stripe customer ID
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deactivated')),
  registrar_id TEXT NOT NULL,                   -- which registrar onboarded this operator
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (registrar_id) REFERENCES registrars(id)
);

CREATE INDEX IF NOT EXISTS idx_operators_email ON operators(email);
CREATE INDEX IF NOT EXISTS idx_operators_domain ON operators(domain);
CREATE INDEX IF NOT EXISTS idx_operators_stripe ON operators(stripe_customer_id);

-- ============================================
-- AGENTS
-- Registered agent identities
-- ============================================
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,                          -- agent ID (e.g., "mira-voss" or key-derived hash)
  axis_id TEXT NOT NULL UNIQUE,                 -- full AXIS ID: axis:{operator}:{name}
  did TEXT NOT NULL UNIQUE,                     -- full DID: did:axis:prime:{id}
  operator_id TEXT NOT NULL,
  display_name TEXT,
  description TEXT,
  public_key TEXT NOT NULL,                     -- Ed25519 public key (base64url)
  key_algorithm TEXT NOT NULL DEFAULT 'Ed25519',
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked', 'deactivated')),
  revoked_at TEXT,
  revocation_reason TEXT,
  registration_tier TEXT NOT NULL CHECK(registration_tier IN ('free', 'paid', 'kyb')),
  registrar_id TEXT NOT NULL,                   -- registrar that submitted this registration
  version INTEGER NOT NULL DEFAULT 1,           -- DID Document version
  service_endpoints TEXT,                       -- JSON array of service endpoints
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (operator_id) REFERENCES operators(id),
  FOREIGN KEY (registrar_id) REFERENCES registrars(id)
);

CREATE INDEX IF NOT EXISTS idx_agents_operator ON agents(operator_id);
CREATE INDEX IF NOT EXISTS idx_agents_axis_id ON agents(axis_id);
CREATE INDEX IF NOT EXISTS idx_agents_did ON agents(did);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_public_key ON agents(public_key);

-- ============================================
-- DELEGATION CREDENTIALS
-- Scoped authority grants between agents/operators
-- ============================================
CREATE TABLE IF NOT EXISTS delegations (
  id TEXT PRIMARY KEY,                          -- dc:{namespace}:{id}
  issued_by TEXT NOT NULL,                      -- AXIS ID or DID of delegator
  issued_to TEXT NOT NULL,                      -- AXIS ID, DID, or foreign DID of delegatee
  root_operator TEXT NOT NULL,                  -- must be identical across chain
  parent_credential_id TEXT,                    -- null for root delegations
  scope TEXT NOT NULL,                          -- JSON array of scope strings
  constraints TEXT,                             -- JSON object of constraints
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  revocable INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
  revoked_at TEXT,
  revocation_reason TEXT,
  proof TEXT NOT NULL,                          -- JSON proof object (signature)
  registrar_id TEXT NOT NULL,
  FOREIGN KEY (parent_credential_id) REFERENCES delegations(id),
  FOREIGN KEY (registrar_id) REFERENCES registrars(id)
);

CREATE INDEX IF NOT EXISTS idx_delegations_issued_by ON delegations(issued_by);
CREATE INDEX IF NOT EXISTS idx_delegations_issued_to ON delegations(issued_to);
CREATE INDEX IF NOT EXISTS idx_delegations_root_operator ON delegations(root_operator);
CREATE INDEX IF NOT EXISTS idx_delegations_parent ON delegations(parent_credential_id);
CREATE INDEX IF NOT EXISTS idx_delegations_status ON delegations(status);

-- ============================================
-- TRUST ATTESTATIONS
-- Reputation layer (Layer 3)
-- ============================================
CREATE TABLE IF NOT EXISTS trust_attestations (
  id TEXT PRIMARY KEY,                          -- ta:{namespace}:{id}
  issued_by TEXT NOT NULL,                      -- AXIS ID or DID of attester
  subject TEXT NOT NULL,                        -- AXIS ID or DID of subject
  scope TEXT NOT NULL,                          -- domain of trust (e.g., "editorial:research")
  level INTEGER NOT NULL CHECK(level >= 1 AND level <= 5),
  statement TEXT,
  evidence TEXT,                                -- JSON array of evidence objects
  signature TEXT NOT NULL,                      -- Ed25519 signature
  issued_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
  registrar_id TEXT NOT NULL,
  FOREIGN KEY (registrar_id) REFERENCES registrars(id)
);

CREATE INDEX IF NOT EXISTS idx_ta_subject ON trust_attestations(subject);
CREATE INDEX IF NOT EXISTS idx_ta_issued_by ON trust_attestations(issued_by);

-- ============================================
-- CONTENT PROVENANCE ATTESTATIONS
-- Content governance chain (Layer 3)
-- ============================================
CREATE TABLE IF NOT EXISTS content_provenance_attestations (
  id TEXT PRIMARY KEY,                          -- cpa:{namespace}:{id}
  content_id TEXT NOT NULL,                     -- URI of the content
  content_hash_algorithm TEXT,                  -- sha-256, sha-384, sha-512
  content_hash_value TEXT,                      -- hex-encoded hash
  produced_by TEXT NOT NULL,                    -- AXIS ID or DID
  produced_under_credential TEXT NOT NULL,      -- delegation credential ID
  reviewed_by TEXT NOT NULL,                    -- AXIS ID or DID
  approved_at TEXT NOT NULL,
  root_operator TEXT NOT NULL,
  metadata TEXT,                                -- JSON object (content_type, title, tags)
  signature TEXT NOT NULL,                      -- Ed25519 signature
  registrar_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (produced_under_credential) REFERENCES delegations(id),
  FOREIGN KEY (registrar_id) REFERENCES registrars(id)
);

CREATE INDEX IF NOT EXISTS idx_cpa_content ON content_provenance_attestations(content_id);
CREATE INDEX IF NOT EXISTS idx_cpa_produced_by ON content_provenance_attestations(produced_by);

-- ============================================
-- AGENT SLOTS
-- Tracks free/paid agent allocation per operator
-- ============================================
CREATE TABLE IF NOT EXISTS agent_slots (
  operator_id TEXT PRIMARY KEY,
  free_slots_total INTEGER NOT NULL DEFAULT 3,  -- 3 for domain verified, 0 for email/KYB
  free_slots_used INTEGER NOT NULL DEFAULT 0,
  paid_agents INTEGER NOT NULL DEFAULT 0,
  max_agents INTEGER,                           -- null = unlimited (for KYB tiers), 5 for email tier
  FOREIGN KEY (operator_id) REFERENCES operators(id)
);

-- ============================================
-- AUDIT LOG
-- Immutable log of all registry operations
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  action TEXT NOT NULL,                         -- register_agent, revoke_agent, create_delegation, etc.
  actor TEXT NOT NULL,                          -- registrar ID or system
  target TEXT,                                  -- agent ID, delegation ID, etc.
  operator_id TEXT,
  registrar_id TEXT,
  details TEXT,                                 -- JSON blob with action-specific data
  ip_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_log(operator_id);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);

-- ============================================
-- SEED DATA
-- Kipple Labs as the root registrar
-- ============================================
INSERT OR IGNORE INTO registrars (id, name, type, api_key_hash, domain, status)
VALUES ('kipple-labs', 'Kipple Labs', 'root', '', 'kipple-labs.com', 'active');
