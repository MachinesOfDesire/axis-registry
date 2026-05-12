/**
 * C2 — slot-count race regression test.
 *
 * Bug shape (pre-fix): POST /register did a Read→Check→Increment sequence
 * with no atomicity. Two concurrent registrations against an operator at
 * their slot limit could both pass the cap check and both succeed.
 * Operator ends up with `max_agents + 1` rows.
 *
 * Fix shape: slot allocation is now a single UPDATE-with-predicate that
 * SQLite serializes within a row. The predicate is the cap check; the
 * UPDATE either succeeds (1 row affected) or doesn't (0 rows affected,
 * meaning we lost the race to a concurrent request).
 *
 * Test strategy: create an operator with N free slots, fire 2N parallel
 * POST /register requests. Assert exactly N return 201 and exactly N
 * return 403 slot_limit_reached, and the DB final state matches.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

test('C2: concurrent registrations cannot over-allocate slots when capped (domain tier with max_agents)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'test-registrar' });

  // Domain-tier operator with 3 free slots AND total cap of 3.
  // This is the canonical C2 scenario: an operator at their slot cap,
  // multiple concurrent registers, no over-allocation allowed.
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain',
    domain: 'example.com',
    free_slots_total: 3,
    max_agents: 3,
  });

  // Fire 2 * max_agents = 6 parallel registrations.
  const N = 6;
  const requests = Array.from({ length: N }, (_, i) => harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { domain: operator.domain },
      metadata: { name: `racer-${i}` },
    }),
  }));

  const responses = await Promise.all(requests);
  const statuses = responses.map((r) => r.status);
  const succeeded = statuses.filter((s) => s === 201).length;
  const quotaExhausted = statuses.filter((s) => s === 403).length;

  // Race-safe invariants under the cap:
  //   1. Every request gets a response (no 500s, no surprise statuses)
  //   2. Exactly max_agents succeed (3)
  //   3. Remaining N - max_agents return 403 slot_limit_reached (3)
  assert.equal(responses.length, N, 'every request gets a response');
  assert.equal(succeeded, 3, 'exactly max_agents succeed');
  assert.equal(quotaExhausted, 3, 'remaining requests get slot_limit_reached');
  assert.equal(
    succeeded + quotaExhausted,
    N,
    'every response is either 201 or 403; no 500s, no surprise statuses'
  );

  // Verify error code on the 403s.
  const quotaResponses = await Promise.all(
    responses.filter((r) => r.status === 403).map((r) => r.json())
  );
  for (const body of quotaResponses) {
    assert.equal(body.error?.code, 'slot_limit_reached', 'expected slot_limit_reached error code');
  }

  // DB state: free_slots_used + paid_agents must equal max_agents.
  const slots = await harness.getSlots(operator.id);
  assert.equal(
    slots.free_slots_used + slots.paid_agents,
    3,
    'total slot allocation matches successful registrations; no over-allocation under contention'
  );

  // Agent count matches successful response count.
  const agents = await harness.getAgentsForOperator(operator.id);
  assert.equal(agents.length, 3, 'agent rows count matches successful registrations');
});

test('C2: concurrent registrations with unlimited paid still cap free correctly (domain tier, no max_agents)', async (t) => {
  // Variant: domain operator with 3 free slots and unlimited paid. All
  // 6 registrations should succeed (3 free + 3 paid), but free_slots_used
  // must be exactly 3 (no over-allocation of the free tier). Catches the
  // race where two concurrent requests both think they got "the last
  // free slot" and increment past free_slots_total.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'test-registrar' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain',
    domain: 'example.com',
    free_slots_total: 3,
    max_agents: null,
  });

  const N = 6;
  const requests = Array.from({ length: N }, (_, i) => harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { domain: operator.domain },
      metadata: { name: `racer-${i}` },
    }),
  }));

  const responses = await Promise.all(requests);
  const succeeded = responses.filter((r) => r.status === 201).length;
  assert.equal(succeeded, 6, 'all 6 succeed because paid is unlimited');

  const slots = await harness.getSlots(operator.id);
  assert.equal(
    slots.free_slots_used, 3,
    'free_slots_used MUST equal free_slots_total exactly; no over-allocation under contention'
  );
  assert.equal(slots.paid_agents, 3, 'remaining 3 go to paid (unlimited)');

  const agents = await harness.getAgentsForOperator(operator.id);
  assert.equal(agents.length, 6, 'all 6 registrations produce agent rows');
  const freeCount = agents.filter((a) => a.registration_tier === 'free').length;
  const paidCount = agents.filter((a) => a.registration_tier === 'paid').length;
  assert.equal(freeCount, 3, 'exactly 3 agents tagged free');
  assert.equal(paidCount, 3, 'exactly 3 agents tagged paid');
});

test('C2: concurrent registrations cannot over-allocate slots (email tier with max_agents)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'test-registrar' });

  // Email-tier operator: 0 free slots, max 5 total (all paid).
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'email',
    free_slots_total: 0,
    max_agents: 5,
  });

  const N = 10;
  const requests = Array.from({ length: N }, (_, i) => harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { email: operator.email },
      metadata: { name: `racer-${i}` },
    }),
  }));

  const responses = await Promise.all(requests);
  const statuses = responses.map((r) => r.status);
  const succeeded = statuses.filter((s) => s === 201).length;
  const quotaExhausted = statuses.filter((s) => s === 403).length;

  assert.equal(succeeded, 5, 'exactly max_agents succeed');
  assert.equal(quotaExhausted, 5, 'remaining requests get slot_limit_reached');

  const slots = await harness.getSlots(operator.id);
  // free_slots_total is 0, so all successful allocations went to paid.
  assert.equal(slots.paid_agents, 5, 'paid_agents reflects exactly the successful registrations');
  assert.equal(slots.free_slots_used, 0, 'no free slots used (email tier has none)');

  const agents = await harness.getAgentsForOperator(operator.id);
  assert.equal(agents.length, 5, 'agent rows count matches max_agents');
});

test('C2: sequential registrations still work normally (no false-positive lockout)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'test-registrar' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain',
    domain: 'example.com',
    free_slots_total: 3,
    max_agents: null,
  });

  // Three sequential registrations should all succeed.
  for (let i = 0; i < 3; i++) {
    const res = await harness.fetch('/register', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${registrar.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        publicKey: harness.generateFakePublicKey(),
        operator: { domain: operator.domain },
        metadata: { name: `agent-${i}` },
      }),
    });
    assert.equal(res.status, 201, `registration ${i} should succeed`);
  }

  const slots = await harness.getSlots(operator.id);
  assert.equal(slots.free_slots_used, 3, 'all three slots used');
});

test('C2: 4th registration past free quota with null max_agents goes to paid tier', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'test-registrar' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain',
    domain: 'example.com',
    free_slots_total: 3,
    max_agents: null, // unlimited paid
  });

  // Register 4 sequentially. First 3 free, 4th paid.
  for (let i = 0; i < 4; i++) {
    const res = await harness.fetch('/register', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${registrar.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        publicKey: harness.generateFakePublicKey(),
        operator: { domain: operator.domain },
        metadata: { name: `agent-${i}` },
      }),
    });
    assert.equal(res.status, 201, `registration ${i} should succeed`);
  }

  const slots = await harness.getSlots(operator.id);
  assert.equal(slots.free_slots_used, 3, '3 free slots used');
  assert.equal(slots.paid_agents, 1, '1 paid slot used');

  const agents = await harness.getAgentsForOperator(operator.id);
  const freeCount = agents.filter((a) => a.registration_tier === 'free').length;
  const paidCount = agents.filter((a) => a.registration_tier === 'paid').length;
  assert.equal(freeCount, 3, '3 agents tagged free');
  assert.equal(paidCount, 1, '1 agent tagged paid');
});
