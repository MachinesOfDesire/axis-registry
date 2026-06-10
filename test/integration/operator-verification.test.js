/**
 * POST /operators/:id/verification — registrar-attested Verified Identity.
 *
 * The registrar (e.g. kipple-registrar / AXIS Prime signup) calls this after
 * an operator completes the Verified Identity flow on its side (one-time
 * payment + Stripe Identity KYC). The registry records the verified tier and
 * raises the enforced agent cap (POST /register reads agent_slots.max_agents).
 *
 * Handler: src/routes/operators.js → handleSetOperatorVerification
 * Route:   src/index.js (POST /operators/:id/verification)
 *
 * Coverage:
 *   - Unauthenticated (no Bearer) → 401
 *   - Operator not found → 404
 *   - BOLA: registrar may only attest its OWN operators → 403 not_your_resource
 *   - Happy path (default cap) → 200, tier=kyb_individual, kyb_verified, max_agents=1000
 *   - Custom max_agents → 200, cap set, free/used slots preserved
 *   - max_agents: null (unlimited) → 200, max_agents NULL
 *   - max_agents out of range → clamped to [1, 1_000_000]
 *   - max_agents wrong type → 400 invalid_request
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

const PATH = (id) => `/operators/${encodeURIComponent(id)}/verification`;

async function getOperator(harness, id) {
  return harness.db
    .prepare('SELECT id, verification_tier, kyb_verified, kyb_provider FROM operators WHERE id = ?')
    .bind(id)
    .first();
}

test('verification: no Bearer → 401 unauthorized', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const op = await harness.createOperator({ registrar_id: reg.id, tier: 'domain', domain: 'a.example.com' });

  const res = await harness.fetch(PATH(op.id), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(res.status, 401);
});

test('verification: unknown operator → 404 not_found', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });

  const res = await harness.fetch(PATH('op-does-not-exist'), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${reg.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.error?.code, 'not_found');
});

test('verification: BOLA — registrar cannot attest another registrar\'s operator → 403', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const regA = await harness.createRegistrar({ id: 'reg-a' });
  const regB = await harness.createRegistrar({ id: 'reg-b' });
  // Operator owned by reg-a; reg-b tries to attest it.
  const op = await harness.createOperator({ registrar_id: regA.id, tier: 'domain', domain: 'a.example.com' });

  const res = await harness.fetch(PATH(op.id), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${regB.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource');

  // And nothing changed on the operator.
  const after = await getOperator(harness, op.id);
  assert.equal(after.verification_tier, 'domain');
  assert.equal(after.kyb_verified, 0);
});

test('verification: happy path — default cap raises to 1000, tier=kyb_individual', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const op = await harness.createOperator({
    registrar_id: reg.id, tier: 'domain', domain: 'a.example.com',
    free_slots_total: 3, max_agents: null,
  });

  const res = await harness.fetch(PATH(op.id), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${reg.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.verification_tier, 'kyb_individual');
  assert.equal(body.kyb_verified, true);
  assert.equal(body.max_agents, 1000);
  assert.equal(body.provider, 'stripe_identity');

  const after = await getOperator(harness, op.id);
  assert.equal(after.verification_tier, 'kyb_individual');
  assert.equal(after.kyb_verified, 1);
  assert.equal(after.kyb_provider, 'stripe_identity');

  // Cap raised; free slots preserved (upsert touches only max_agents).
  const slots = await harness.getSlots(op.id);
  assert.equal(slots.max_agents, 1000);
  assert.equal(slots.free_slots_total, 3);
  assert.equal(slots.free_slots_used, 0);
});

test('verification: custom max_agents + provider, preserves free/used slots', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const op = await harness.createOperator({
    registrar_id: reg.id, tier: 'domain', domain: 'a.example.com',
    free_slots_total: 3, max_agents: 7,
  });

  const res = await harness.fetch(PATH(op.id), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${reg.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ max_agents: 5000, provider: 'manual_review' }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.max_agents, 5000);
  assert.equal(body.provider, 'manual_review');

  const slots = await harness.getSlots(op.id);
  assert.equal(slots.max_agents, 5000);
  assert.equal(slots.free_slots_total, 3);
});

test('verification: max_agents null → unlimited (NULL in DB)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const op = await harness.createOperator({ registrar_id: reg.id, tier: 'domain', domain: 'a.example.com' });

  const res = await harness.fetch(PATH(op.id), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${reg.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ max_agents: null }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.max_agents, null);

  const slots = await harness.getSlots(op.id);
  assert.equal(slots.max_agents, null);
});

test('verification: max_agents above ceiling is clamped to 1_000_000', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const op = await harness.createOperator({ registrar_id: reg.id, tier: 'domain', domain: 'a.example.com' });

  const res = await harness.fetch(PATH(op.id), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${reg.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ max_agents: 999999999 }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.max_agents, 1000000);
});

test('verification: non-numeric max_agents → 400 invalid_request', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const op = await harness.createOperator({ registrar_id: reg.id, tier: 'domain', domain: 'a.example.com' });

  const res = await harness.fetch(PATH(op.id), {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${reg.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ max_agents: 'lots' }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');
});
