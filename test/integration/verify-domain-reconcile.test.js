/**
 * POST /operators/verify-domain — the operator_id the registry returns MUST
 * resolve via GET /operators/:id.
 *
 * Regression for the 2026-06-29 email-tier signup incident: a repeat email
 * signup for an address that already had an operator hit the existing-operator
 * branch of handleVerifyDomain, which UPDATEd the persisted row but RETURNED a
 * freshly-minted opaque slug that was never written. The registrar stored that
 * phantom id; GET /operators/<phantom> → 404. Root cause was returning the
 * newly-generated `operatorId` instead of the persisted `operator.id`.
 *
 * Handler: src/routes/operators.js → handleVerifyDomain
 * Route:   src/index.js (POST /operators/verify-domain)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

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

async function getOperator(harness, registrar, id) {
  const res = await harness.fetch(`/operators/${encodeURIComponent(id)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  return { status: res.status, body: await res.json() };
}

test('verify-domain: first email signup returns a resolvable operator_id', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });

  const create = await verifyDomain(harness, reg, { email: 'new-user@gmail.com' });
  assert.equal(create.status, 200, 'first signup must succeed');
  assert.ok(create.body.operator_id, 'response must carry an operator_id');

  const got = await getOperator(harness, reg, create.body.operator_id);
  assert.equal(got.status, 200, 'the returned operator_id must resolve via GET /operators/:id');
  assert.equal(got.body.operator_id, create.body.operator_id);
});

test('verify-domain: repeat email signup returns the SAME persisted, resolvable operator_id', async (t) => {
  // This is the incident path. The first call creates the operator. The
  // second call (same email) must reconcile to the existing row and return
  // its id — NOT a freshly-minted phantom id that was never persisted.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });

  const first = await verifyDomain(harness, reg, { email: 'repeat-user@gmail.com' });
  assert.equal(first.status, 200);
  const firstId = first.body.operator_id;
  assert.ok(firstId);

  const second = await verifyDomain(harness, reg, { email: 'repeat-user@gmail.com' });
  assert.equal(second.status, 200, 'repeat signup must succeed');

  assert.equal(
    second.body.operator_id,
    firstId,
    'repeat signup must return the same persisted operator_id, not a phantom new one'
  );

  // The crux: whatever id the registry hands back MUST resolve. Before the
  // fix this GET 404'd because the returned id was never written.
  const got = await getOperator(harness, reg, second.body.operator_id);
  assert.equal(got.status, 200, 'the operator_id from a repeat signup must resolve');

  // And there must be exactly one operator row for that email — no orphan.
  const count = await harness.db
    .prepare('SELECT COUNT(*) AS n FROM operators WHERE email = ?')
    .bind('repeat-user@gmail.com')
    .first();
  assert.equal(count.n, 1, 'repeat signup must not create a duplicate operator row');
});

test('verify-domain: repeat signup against a pre-existing operator row resolves', async (t) => {
  // Mirrors production: an operator created by an EARLIER signup already
  // exists (here seeded directly), then the user signs up again. The id
  // returned must be the seeded operator's id and must resolve.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const reg = await harness.createRegistrar({ id: 'reg-a' });
  const seeded = await harness.createOperator({
    registrar_id: reg.id,
    tier: 'email',
    email: 'seeded-user@gmail.com',
    free_slots_total: 0,
    max_agents: 5,
  });

  const res = await verifyDomain(harness, reg, { email: 'seeded-user@gmail.com' });
  assert.equal(res.status, 200);
  assert.equal(res.body.operator_id, seeded.id, 'must return the seeded operator id');

  const got = await getOperator(harness, reg, res.body.operator_id);
  assert.equal(got.status, 200, 'returned operator_id must resolve');
});
