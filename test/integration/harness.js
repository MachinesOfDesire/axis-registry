/**
 * Miniflare integration-test harness for axis-registry.
 *
 * Purpose: every route-level test (BOLA matrix, AIT verification matrix,
 * audit-before-mutate, slot-race, etc.) needs a worker + D1 spun up with
 * a known fixture state. This module is the foundation; tests import it.
 *
 * Pattern:
 *
 *     import { createHarness } from './harness.js';
 *
 *     test('something', async (t) => {
 *       const harness = await createHarness();
 *       t.after(() => harness.dispose());
 *
 *       const registrar = await harness.createRegistrar({ role: 'admin' });
 *       const operator  = await harness.createOperator({
 *         tier: 'domain', registrar_id: registrar.id,
 *         free_slots_total: 3, max_agents: null,
 *       });
 *
 *       const res = await harness.fetch('/register', {
 *         method: 'POST',
 *         headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
 *         body: JSON.stringify({ publicKey: '...', operator: { domain: ... } }),
 *       });
 *
 *       assert.equal(res.status, 201);
 *     });
 *
 * Design notes:
 *
 *   - Each createHarness() call gets a fresh isolated worker + D1. Tests
 *     don't share state. Slower but correct; if a test mutates DB state
 *     no other test sees it.
 *
 *   - Schema is applied from the real `schema.sql`. If the schema drifts
 *     between tests and prod, integration tests catch it immediately.
 *
 *   - `harness.createRegistrar()` returns a synthetic API key whose hash
 *     is inserted into the registrars table. The plaintext is held only
 *     in memory and returned to the caller for use in test requests.
 *
 *   - Rate-limit bindings are deliberately NOT configured. The middleware
 *     no-ops when bindings are absent, so route logic runs unrated. Add
 *     a separate harness profile if/when we want to test rate limits.
 */

import { Miniflare } from 'miniflare';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..');

let cachedSchema = null;
async function loadSchema() {
  if (!cachedSchema) {
    cachedSchema = await readFile(join(REPO_ROOT, 'schema.sql'), 'utf8');
  }
  return cachedSchema;
}

/**
 * SHA-256 helper that matches src/middleware/auth.js exactly.
 * Used to insert API key hashes when creating test registrars.
 */
async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Spin up a fresh worker + D1 with schema applied. The seed row from
 * schema.sql (kipple-labs registrar with empty hash) is removed so tests
 * start from a known-clean state.
 *
 * @returns {Promise<Harness>}
 */
export async function createHarness() {
  const schema = await loadSchema();

  const mf = new Miniflare({
    modules: true,
    scriptPath: join(REPO_ROOT, 'src', 'index.js'),
    modulesRules: [{ type: 'ESModule', include: ['**/*.js'] }],
    compatibilityDate: '2026-04-11',
    d1Databases: { DB: 'axis-registry-test' },
    bindings: {
      REGISTRY_BASE_URL: 'http://localhost',
    },
    // Rate-limit bindings deliberately omitted; the middleware no-ops.
  });

  const db = await mf.getD1Database('DB');

  // Apply schema. D1's exec() accepts multi-statement input but requires
  // it on a single line (or escapes newlines weirdly), so we collapse
  // comments + whitespace before passing it through. Then delete the
  // schema's `INSERT OR IGNORE INTO registrars` seed row for kipple-labs
  // so tests start from a fully clean state.
  // Strip line comments FIRST, then split on `;`. Doing it in the other
  // order breaks on lines like `target_registrar_id TEXT  -- comment );`
  // where the `;` inside the comment is treated as a statement boundary
  // and produces "incomplete input" SQL errors.
  const cleaned = schema
    .replace(/--[^\n]*/g, '')   // strip line comments
    .replace(/\s+/g, ' ')        // collapse whitespace
    .trim();
  const statements = cleaned
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const stmt of statements) {
    await db.exec(stmt);
  }
  await db.prepare("DELETE FROM registrars WHERE id = 'kipple-labs'").run();

  return new Harness(mf, db);
}

class Harness {
  constructor(mf, db) {
    this.mf = mf;
    this.db = db;
  }

  /**
   * Make a request against the worker. Path is relative; we prepend a
   * dummy origin. Returns the standard `Response` object.
   */
  async fetch(path, init = {}) {
    const url = new URL(path, 'http://localhost').toString();
    return this.mf.dispatchFetch(url, init);
  }

  /**
   * Create a test registrar row. Returns the inserted row plus the
   * plaintext apiKey (only available in memory; the row stores the hash).
   *
   *   opts.id      — registrar id (default: generated)
   *   opts.name    — display name (default: 'Test Registrar')
   *   opts.type    — 'connected' | 'private' | 'root' (default: 'connected')
   *   opts.role    — 'registrar' | 'admin' | 'super_admin' (default: 'registrar')
   *   opts.domain  — string (default: 'test.example.com')
   */
  async createRegistrar(opts = {}) {
    const id = opts.id || `reg-${randomSuffix()}`;
    const apiKey = `test-key-${randomSuffix(32)}`;
    const apiKeyHash = await sha256Hex(apiKey);
    await this.db.prepare(
      `INSERT INTO registrars (id, name, type, api_key_hash, domain, status, role)
       VALUES (?, ?, ?, ?, ?, 'active', ?)`
    ).bind(
      id,
      opts.name || 'Test Registrar',
      opts.type || 'connected',
      apiKeyHash,
      opts.domain || 'test.example.com',
      opts.role || 'registrar'
    ).run();
    return { id, apiKey, role: opts.role || 'registrar' };
  }

  /**
   * Create a test operator + matching agent_slots row.
   *
   *   opts.id                — operator id (default: generated)
   *   opts.email             — required-ish; default 'test+<suffix>@example.com'
   *   opts.domain            — optional
   *   opts.tier              — 'email' | 'domain' | 'kyb_individual' | 'kyb_organization'
   *   opts.registrar_id      — required; the registrar that owns this operator
   *   opts.free_slots_total  — default: 3
   *   opts.max_agents        — default: null (unlimited paid)
   *   opts.domain_verified   — default: tier === 'domain' or 'kyb_organization'
   */
  async createOperator(opts) {
    if (!opts.registrar_id) throw new Error('createOperator: registrar_id required');
    const tier = opts.tier || 'email';
    const id = opts.id || (tier === 'domain' && opts.domain
      ? opts.domain.split('.').slice(0, -1).join('-')
      : `op-${randomSuffix(24)}`);
    const email = opts.email || `test+${randomSuffix(8)}@example.com`;
    const domainVerified = opts.domain_verified ?? (tier === 'domain' || tier === 'kyb_organization');

    await this.db.prepare(
      `INSERT INTO operators (id, email, domain, verification_tier, domain_verified, registrar_id, status)
       VALUES (?, ?, ?, ?, ?, ?, 'active')`
    ).bind(
      id,
      email,
      opts.domain || null,
      tier,
      domainVerified ? 1 : 0,
      opts.registrar_id
    ).run();

    await this.db.prepare(
      `INSERT INTO agent_slots (operator_id, free_slots_total, free_slots_used, paid_agents, max_agents)
       VALUES (?, ?, 0, 0, ?)`
    ).bind(
      id,
      opts.free_slots_total ?? 3,
      opts.max_agents ?? null
    ).run();

    return { id, email, domain: opts.domain || null, tier };
  }

  /**
   * Generate a random Ed25519-shaped public key for tests that don't care
   * about cryptographic validity (just need the field populated). For
   * proof-verifying tests use a real keypair via @noble/ed25519 or similar.
   */
  generateFakePublicKey() {
    // 32 random bytes → base64url. Server-side this won't validate any
    // proof, but for slot-race / BOLA tests we don't supply a proof.
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Buffer.from(bytes)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  /**
   * Pull current agent_slots row for verification.
   */
  async getSlots(operatorId) {
    return this.db
      .prepare('SELECT * FROM agent_slots WHERE operator_id = ?')
      .bind(operatorId)
      .first();
  }

  /**
   * Pull all agents under an operator for verification.
   */
  async getAgentsForOperator(operatorId) {
    const result = await this.db
      .prepare('SELECT id, axis_id, did, registration_tier FROM agents WHERE operator_id = ?')
      .bind(operatorId)
      .all();
    return result.results || [];
  }

  async dispose() {
    await this.mf.dispose();
  }
}

function randomSuffix(len = 12) {
  const bytes = new Uint8Array(Math.ceil(len / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, len);
}
