/**
 * Free-tier agent caps — decoupled pricing model (2026-07-04; supersedes the
 * earlier 2026-06-16 10/100 figures):
 *
 *   Single Operator (email-verified)  → 25 agents (hard cap)
 *   Team (domain-verified)            → 250 agents (hard cap)
 *   Verified (registrar quota push)   → 1000 agents (default)
 *
 * Hard caps == free caps at both free tiers: no per-agent fees, no unlimited
 * paid fallthrough. Tier upgrade is the only path to more agents.
 *
 * Covers:
 *   - POST /operators/verify-domain (the only operator-creation path) writes
 *     the new agent_slots values: email 25/25, domain 250/250.
 *   - A repeat signup never disturbs an existing slots row (in particular a
 *     registrar-pushed max_agents=1000 is not lowered).
 *   - POST /operators/:id/verification still defaults max_agents to 1000 and
 *     preserves free_slots_total.
 *   - Migration 0009 upgrades legacy rows (domain 3/NULL → 250/250, email
 *     0/5 → 25/25), never lowers an existing higher cap, and is idempotent.
 *
 * Handlers: src/routes/operators.js (TIER_CAPS is the single source of truth)
 * Migration: migrations/0009_free_tier_caps_locked_pricing.sql
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createHarness } from './harness.js';
import { TIER_CAPS, VERIFIED_DEFAULT_MAX_AGENTS } from '../../src/routes/operators.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATION_PATH = join(
  HERE, '..', '..', 'migrations', '0009_free_tier_caps_locked_pricing.sql'
);

async function verifyDomain(harness, registrar, body) {
  const res = await harness.fetch('/operators/verify-domain', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function getSlots(harness, operatorId) {
  return harness.db
    .prepare('SELECT free_slots_total, free_slots_used, paid_agents, max_agents FROM agent_slots WHERE operator_id = ?')
    .bind(operatorId)
    .first();
}

/** Run migration 0009 against the harness DB (same comment-stripping the harness uses for schema.sql). */
async function applyMigration0009(harness) {
  const sql = await readFile(MIGRATION_PATH, 'utf8');
  const statements = sql
    .replace(/--[^\n]*/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const stmt of statements) {
    await harness.db.prepare(stmt).run();
  }
}

// ---------------------------------------------------------------------------
// Sanity: the constants themselves encode the locked pricing model.
// ---------------------------------------------------------------------------

test('caps: TIER_CAPS matches the locked pricing model (25/250 hard caps, 1000 verified default)', () => {
  assert.deepEqual(TIER_CAPS.email, { freeSlots: 25, maxAgents: 25 });
  assert.deepEqual(TIER_CAPS.domain, { freeSlots: 250, maxAgents: 250 });
  assert.equal(VERIFIED_DEFAULT_MAX_AGENTS, 1000);
  // Hard cap == free cap at both free tiers: no paid fallthrough headroom.
  assert.equal(TIER_CAPS.email.freeSlots, TIER_CAPS.email.maxAgents);
  assert.equal(TIER_CAPS.domain.freeSlots, TIER_CAPS.domain.maxAgents);
});

// ---------------------------------------------------------------------------
// Creation path (POST /operators/verify-domain)
// ---------------------------------------------------------------------------

test('caps: new email-tier operator gets free_slots_total=25, max_agents=25', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const res = await verifyDomain(harness, reg, { email: 'solo@example.com' });
  assert.equal(res.status, 200);

  const slots = await getSlots(harness, res.body.operator_id);
  assert.ok(slots, 'an agent_slots row must be created');
  assert.equal(slots.free_slots_total, 25, 'email tier: 25 free slots');
  assert.equal(slots.max_agents, 25, 'email tier: hard cap 25 (== free cap, no fallthrough)');
  assert.equal(slots.free_slots_used, 0);
  assert.equal(slots.paid_agents, 0);
});

test('caps: new domain-tier operator gets free_slots_total=250, max_agents=250 (no unlimited)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const res = await verifyDomain(harness, reg, {
    email: 'team@widget-corp.example.com',
    domain: 'widget-corp.example.com',
    method: 'dns_txt',
  });
  assert.equal(res.status, 200);

  const slots = await getSlots(harness, res.body.operator_id);
  assert.ok(slots, 'an agent_slots row must be created');
  assert.equal(slots.free_slots_total, 250, 'domain tier: 250 free slots');
  assert.equal(slots.max_agents, 250, 'domain tier: hard cap 250, NOT NULL/unlimited');
});

test('caps: repeat signup does not disturb an existing slots row (registrar-pushed 1000 preserved)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const first = await verifyDomain(harness, reg, { email: 'repeat@example.com' });
  assert.equal(first.status, 200);
  const opId = first.body.operator_id;

  // Simulate a registrar verification push having raised the cap, plus usage.
  await harness.db
    .prepare('UPDATE agent_slots SET max_agents = 1000, free_slots_used = 4 WHERE operator_id = ?')
    .bind(opId)
    .run();

  const second = await verifyDomain(harness, reg, { email: 'repeat@example.com' });
  assert.equal(second.status, 200);
  assert.equal(second.body.operator_id, opId);

  const slots = await getSlots(harness, opId);
  assert.equal(slots.max_agents, 1000, 'repeat signup must never lower a pushed cap');
  assert.equal(slots.free_slots_used, 4, 'repeat signup must not reset usage counters');
  assert.equal(slots.free_slots_total, 25, 'free slot total untouched');
});

// ---------------------------------------------------------------------------
// Registrar verification push (POST /operators/:id/verification)
// ---------------------------------------------------------------------------

test('caps: verification push defaults max_agents to 1000 and preserves free slots (domain-created operator)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const created = await verifyDomain(harness, reg, {
    email: 'upgrade@corp.example.com',
    domain: 'corp.example.com',
  });
  assert.equal(created.status, 200);
  const opId = created.body.operator_id;

  const res = await harness.fetch(`/operators/${encodeURIComponent(opId)}/verification`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${reg.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.max_agents, 1000);

  const slots = await getSlots(harness, opId);
  assert.equal(slots.max_agents, 1000, 'push raises the enforced cap to 1000');
  assert.equal(slots.free_slots_total, 250, 'push preserves the domain-tier free slot count');
});

// ---------------------------------------------------------------------------
// Migration 0009 (legacy row reconcile)
// ---------------------------------------------------------------------------

test('migration 0009: upgrades legacy rows, never lowers higher caps, idempotent', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });

  // Legacy world: values as the OLD code wrote them.
  const legacyDomain = await harness.createOperator({
    registrar_id: reg.id, tier: 'domain', domain: 'legacy-team.example.com',
    free_slots_total: 3, max_agents: null,
  });
  const legacyEmail = await harness.createOperator({
    registrar_id: reg.id, tier: 'email',
    free_slots_total: 0, max_agents: 5,
  });
  // Domain-tier operator whose cap was registrar-pushed to 1000 — must NOT be lowered.
  const pushedDomain = await harness.createOperator({
    registrar_id: reg.id, tier: 'domain', domain: 'pushed.example.com',
    free_slots_total: 3, max_agents: 1000,
  });
  // Email-tier anomaly with an explicit unlimited grant — left untouched.
  const emailNullCap = await harness.createOperator({
    registrar_id: reg.id, tier: 'email',
    free_slots_total: 0, max_agents: null,
  });
  // KYB tier — untouched by the migration.
  const kyb = await harness.createOperator({
    registrar_id: reg.id, tier: 'kyb_individual',
    free_slots_total: 0, max_agents: 1000,
  });

  await applyMigration0009(harness);

  let slots = await getSlots(harness, legacyDomain.id);
  assert.equal(slots.free_slots_total, 250, 'legacy domain: free 3 → 250');
  assert.equal(slots.max_agents, 250, 'legacy domain: max NULL → 250 (unlimited fallthrough removed)');

  slots = await getSlots(harness, legacyEmail.id);
  assert.equal(slots.free_slots_total, 25, 'legacy email: free 0 → 25');
  assert.equal(slots.max_agents, 25, 'legacy email: max 5 → 25');

  slots = await getSlots(harness, pushedDomain.id);
  assert.equal(slots.free_slots_total, 250, 'pushed domain: free still upgraded to 250');
  assert.equal(slots.max_agents, 1000, 'pushed domain: max_agents 1000 must NOT be lowered');

  slots = await getSlots(harness, emailNullCap.id);
  assert.equal(slots.free_slots_total, 25, 'email NULL-cap: free still upgraded to 25');
  assert.equal(slots.max_agents, null, 'email NULL-cap: explicit unlimited grant left untouched');

  slots = await getSlots(harness, kyb.id);
  assert.equal(slots.free_slots_total, 0, 'kyb tier untouched');
  assert.equal(slots.max_agents, 1000, 'kyb tier untouched');

  // Idempotency: a second run must change nothing.
  await applyMigration0009(harness);

  slots = await getSlots(harness, legacyDomain.id);
  assert.equal(slots.free_slots_total, 250);
  assert.equal(slots.max_agents, 250);
  slots = await getSlots(harness, pushedDomain.id);
  assert.equal(slots.max_agents, 1000, 'second run must not lower the pushed cap');
  slots = await getSlots(harness, emailNullCap.id);
  assert.equal(slots.max_agents, null, 'second run must not touch the explicit unlimited grant');
});
