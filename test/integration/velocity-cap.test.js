/**
 * Velocity cap (Pre-Launch Engineering Brief §3.4):
 *
 * No operator may register more than VELOCITY_LIMIT agents in any
 * rolling VELOCITY_WINDOW_HOURS-hour window, independent of tier. This
 * is a soft brake on bulk-pump abuse — the primary defense is the
 * atomic per-tier slot cap (C2), and the velocity cap intentionally
 * sits on top of it as a per-operator rate.
 *
 * Coverage:
 *   1. 10 sequential registers under one operator → all succeed
 *   2. 11th register → 429 velocity_limit_reached + Retry-After header
 *   3. Per-operator isolation: operator A at cap doesn't block operator B
 *   4. Rolling-window: back-dating one of the 10 to >24h ago allows an
 *      11th register (proves the window is truly rolling, not session-
 *      lifetime or daily-reset)
 *
 * Slot allocation is deliberately set well above the velocity cap in
 * setup (free_slots_total: 100, max_agents: null) so the slot cap
 * doesn't fire before the velocity cap.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

const VELOCITY_LIMIT = 10;
const WINDOW_HOURS = 24;

async function register(harness, registrar, operator, name) {
  return harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { domain: operator.domain },
      metadata: { name },
    }),
  });
}

async function setupOperator(harness, registrar, opts = {}) {
  return harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain',
    domain: opts.domain || `op-${Math.random().toString(36).slice(2, 10)}.example.com`,
    free_slots_total: 100,     // well above VELOCITY_LIMIT
    max_agents: null,           // unlimited paid (so slot cap never fires)
    ...opts,
  });
}

test('Velocity cap: 10 sequential registers under one operator all succeed', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await setupOperator(harness, registrar);

  for (let i = 0; i < VELOCITY_LIMIT; i++) {
    const res = await register(harness, registrar, operator, `agent-${i}`);
    assert.equal(res.status, 201, `register ${i} should succeed (within velocity cap)`);
  }

  const agents = await harness.getAgentsForOperator(operator.id);
  assert.equal(agents.length, VELOCITY_LIMIT, 'all 10 agents created');
});

test('Velocity cap: 11th register returns 429 velocity_limit_reached + Retry-After header', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await setupOperator(harness, registrar);

  // Burn the velocity allowance.
  for (let i = 0; i < VELOCITY_LIMIT; i++) {
    const res = await register(harness, registrar, operator, `agent-${i}`);
    assert.equal(res.status, 201, `setup register ${i} should succeed`);
  }

  // 11th request.
  const res = await register(harness, registrar, operator, 'agent-11');
  assert.equal(res.status, 429, '11th register must hit velocity cap');

  const body = await res.json();
  assert.equal(body.error?.code, 'velocity_limit_reached', 'expected velocity_limit_reached code');

  const retryAfter = res.headers.get('Retry-After');
  assert.ok(retryAfter, 'Retry-After header must be present');
  const retrySec = parseInt(retryAfter, 10);
  assert.ok(Number.isFinite(retrySec), 'Retry-After must be a valid integer');
  assert.ok(retrySec >= 60, 'Retry-After respects 60s floor');
  assert.ok(retrySec <= WINDOW_HOURS * 3600, `Retry-After capped at window (${WINDOW_HOURS}h)`);

  // No 11th agent in DB — velocity check fires BEFORE slot allocation
  // and BEFORE the INSERT.
  const agents = await harness.getAgentsForOperator(operator.id);
  assert.equal(agents.length, VELOCITY_LIMIT, 'no agent row created on velocity rejection');

  // Slot counters untouched (velocity fires before slot allocation).
  const slots = await harness.getSlots(operator.id);
  assert.equal(slots.free_slots_used, VELOCITY_LIMIT, 'free slots reflect only successful registers');
  assert.equal(slots.paid_agents, 0, 'no paid allocation on velocity rejection');
});

test('Velocity cap: per-operator isolation — A at cap does not affect B', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'reg' });
  const opA = await setupOperator(harness, registrar, { domain: 'op-a.example.com' });
  const opB = await setupOperator(harness, registrar, { domain: 'op-b.example.com' });

  // Cap operator A.
  for (let i = 0; i < VELOCITY_LIMIT; i++) {
    const res = await register(harness, registrar, opA, `a-${i}`);
    assert.equal(res.status, 201);
  }
  const capRes = await register(harness, registrar, opA, 'a-overflow');
  assert.equal(capRes.status, 429, 'operator A is velocity-capped');

  // Operator B should be unaffected.
  for (let i = 0; i < VELOCITY_LIMIT; i++) {
    const res = await register(harness, registrar, opB, `b-${i}`);
    assert.equal(res.status, 201, `operator B register ${i} must succeed (independent counter)`);
  }

  const agentsA = await harness.getAgentsForOperator(opA.id);
  const agentsB = await harness.getAgentsForOperator(opB.id);
  assert.equal(agentsA.length, VELOCITY_LIMIT, 'A has exactly VELOCITY_LIMIT agents');
  assert.equal(agentsB.length, VELOCITY_LIMIT, 'B has exactly VELOCITY_LIMIT agents');
});

test('Velocity cap: rolling window — back-dating one register to >24h ago allows an 11th', async (t) => {
  // Proves the window is truly rolling (not session-lifetime or
  // calendar-day-reset). After the cap fires, back-date one of the 10
  // in-window registrations to BEFORE the 24h window — that agent stops
  // counting toward velocity, leaving 9 in-window. An 11th register
  // should then succeed.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await setupOperator(harness, registrar);

  for (let i = 0; i < VELOCITY_LIMIT; i++) {
    const res = await register(harness, registrar, operator, `agent-${i}`);
    assert.equal(res.status, 201);
  }

  // Confirm we are velocity-capped.
  const cappedRes = await register(harness, registrar, operator, 'pre-shift-overflow');
  assert.equal(cappedRes.status, 429, 'expected velocity cap to fire pre-shift');

  // Back-date one agent's created_at to 25h ago — moves it outside the
  // rolling 24h window, dropping the in-window count to 9.
  //
  // SQLite supports UPDATE ... ORDER BY ... LIMIT only when compiled with
  // SQLITE_ENABLE_UPDATE_DELETE_LIMIT — D1 / Miniflare doesn't enable that
  // flag. SELECT-then-UPDATE-by-id is the portable form.
  const farPast = new Date(Date.now() - 25 * 3600 * 1000).toISOString();
  const oldestRow = await harness.db.prepare(
    'SELECT id FROM agents WHERE operator_id = ? ORDER BY created_at ASC LIMIT 1'
  ).bind(operator.id).first();
  assert.ok(oldestRow, 'setup: must have an agent to back-date');
  const updated = await harness.db.prepare(
    'UPDATE agents SET created_at = ? WHERE id = ?'
  ).bind(farPast, oldestRow.id).run();
  assert.equal(updated.meta.changes, 1, 'exactly one row back-dated');

  // Sanity-check that the back-date actually persisted.
  const verifyRow = await harness.db.prepare(
    'SELECT created_at FROM agents WHERE id = ?'
  ).bind(oldestRow.id).first();
  assert.equal(verifyRow.created_at, farPast, 'created_at was actually updated');

  // 11th register should now succeed (only 9 are in the rolling window).
  const res = await register(harness, registrar, operator, 'after-shift');
  assert.equal(res.status, 201, 'register must succeed after window roll');

  const agents = await harness.getAgentsForOperator(operator.id);
  assert.equal(agents.length, VELOCITY_LIMIT + 1, '11 total agents (one is outside the window)');
});
