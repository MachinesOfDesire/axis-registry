-- AXIS Registry D1 Schema
-- Version: 0.1.0
-- Database: Cloudflare D1 (SQLite)
--
-- SCOPE: Canonical AXIS registry stores Layer 1 (Identity) + Layer 2 (Authorization) only.
-- Per the canonical spec (https://github.com/MachinesOfDesire/axis-protocol SPEC.md v0.1.1
-- and axisprime.ai): "Layers 1 and 2 are mandatory for any verification. Layer 3 is advisory."
-- Trust Attestations are explicitly "stored by the issuer, not the registry."
--
-- Layer 3 artifacts (Trust Attestations, Content Provenance Attestations) live in
-- separate Kipple Labs extension databases, NOT in this canonical registry. This
-- separation keeps the canonical registry implementation conformance-clean and
-- foundation-ready.

-- ============================================
-- REGISTRARS
-- Authorized parties that can submit registrations
-- Kipple Labs is the first registrar
-- ============================================
CREATE TABLE IF NOT EXISTS registrars (
  id TEXT PRIMARY KEY,                          -- e.g., "kipple-labs"
  name TEXT NOT NULL,                           -- "Kipple Labs"
  type TEXT NOT NULL CHECK(type IN ('connected', 'private', 'root')),
  api_key_hash TEXT NOT NULL                    -- SHA-256 hash of API key
    CHECK(length(api_key_hash) = 64 AND api_key_hash <> ''),
                                                -- H3 hardening: hash must be a
                                                -- real 64-char SHA-256. An empty
                                                -- string would let `Bearer ` (empty)
                                                -- authenticate via SHA-256("") matched
                                                -- against a seeded '' row. Per the
                                                -- 2026-05-08 security review,
                                                -- axis-registry H3. Live databases
                                                -- inherit this via migration 0003.
  domain TEXT,                                  -- registrar's domain
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'revoked')),
  role TEXT NOT NULL DEFAULT 'registrar'        -- 'registrar' | 'admin' | 'super_admin'
    CHECK(role IN ('registrar', 'admin', 'super_admin')),
                                                -- Added via migration 0001 on live
                                                -- databases; included here so fresh
                                                -- deploys carry it from the start.
                                                -- Three-role RBAC: registrar (default,
                                                -- self-scoped), admin (cross-tenant read),
                                                -- super_admin (admin + break-glass).
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  metadata TEXT                                 -- JSON blob for extra info
);

CREATE INDEX IF NOT EXISTS idx_registrars_role ON registrars(role);

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

-- An operator is identified by its natural keys: one operator per email, and a
-- verified domain belongs to exactly one operator. These are UNIQUE (not plain)
-- indexes so the database itself refuses a duplicate operator — the
-- "one operator per email" invariant is enforced by construction, not by the
-- handler remembering to look before it inserts. The domain index is partial
-- (WHERE domain IS NOT NULL) so the many email-tier operators with NULL domain
-- don't collide. See migrations/0007_operator_unique_constraints.sql.
CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_email ON operators(email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_domain ON operators(domain) WHERE domain IS NOT NULL;
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
  signed_document TEXT,                         -- raw issuer-signed DC doc (Option A, v0.2 §4.4); null for legacy/unsigned rows
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
-- (Layer 3 tables removed 2026-05-10)
-- Trust Attestations and Content Provenance Attestations are NOT canonical
-- registry primitives per the AXIS spec. They are advisory artifacts stored
-- by the issuer (typically Kipple Labs as a service operator, or the
-- platform that produced the content). Removed because they were defined
-- here but never wired up to any route handler — pure schema drift.
-- See AXIS Decisions Log entry 2026-05-10.
-- ============================================

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
  ip_address TEXT,
  target_registrar_id TEXT                      -- owning registrar of the targeted resource (H7); NULL for older rows and non-mutation actions
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_log(operator_id);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);
CREATE INDEX IF NOT EXISTS idx_audit_target_registrar ON audit_log(target_registrar_id);

-- ============================================
-- SEED DATA
-- Kipple Labs as the root registrar
-- ============================================
INSERT OR IGNORE INTO registrars (id, name, type, api_key_hash, domain, status)
VALUES ('kipple-labs', 'Kipple Labs', 'root', '', 'kipple-labs.com', 'active');
