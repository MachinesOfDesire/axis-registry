/**
 * Delegation chain matrix — attenuation, max-sub-depth, M3 cycle/depth
 * cap, M5 expires-horizon, cascade revocation.
 *
 * The delegations route enforces several invariants on chain construction.
 * This file is the regression suite that locks them in.
 *
 * Coverage:
 *
 *   POST /delegations (no parent)
 *     - happy path → 201
 *
 *   POST /delegations (with parent)
 *     - scope subset → 201
 *     - scope wider than parent → 400 delegation_chain_invalid
 *     - root_operator mismatch with parent → 400 delegation_chain_invalid
 *     - parent with max_sub_delegation_depth=0 → 400 delegation_chain_invalid
 *
 *   M5 horizon (expires)
 *     - expires >90 days from now → 400 expires_too_far
 *     - expires in the past → 400 invalid_request
 *     - malformed ISO-8601 expires → 400 invalid_request
 *
 *   DELETE /delegations/:id
 *     - cascade revokes child delegations recursively (3-level chain)
 *
 *   M3 cascade cap
 *     - direct-DB chain of 18 levels; root revoke halts at depth 16
 *       (16 children revoked, 2 left untouched)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

const DAY_MS = 24 * 60 * 60 * 1000;

async function setup(harness) {
  const registrar = await harness.createRegistrar({ id: 'test-reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain', domain: 'chain.example.com', free_slots_total: 3,
  });
  const regRes = await harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { domain: operator.domain },
      metadata: { name: 'issuer' },
    }),
  });
  assert.equal(regRes.status, 201);
  const agent = await regRes.json();
  return { registrar, operator, agent };
}

async function createDelegation(harness, registrar, params) {
  const res = await harness.fetch('/delegations', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(params),
  });
  return res;
}

test('Delegations: happy path no parent → 201', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a', 'scope:b'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  assert.equal(res.status, 201);
  const body = await res.json();
  assert.equal(body.status, 'active');
  assert.deepEqual(body.scope, ['scope:a', 'scope:b']);
});

test('Delegations: child with subset scope → 201 (attenuation respected)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const parentRes = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a', 'scope:b', 'scope:c'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  assert.equal(parentRes.status, 201);
  const parent = await parentRes.json();

  const childRes = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:2',
    root_operator: `axis:${operator.id}:operator`,
    parent_credential_id: parent.id,
    scope: ['scope:a', 'scope:b'],  // subset of parent
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  assert.equal(childRes.status, 201, 'child with subset scope must succeed');
});

test('Delegations: child with wider scope → 400 delegation_chain_invalid (attenuation enforced)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const parentRes = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  const parent = await parentRes.json();

  const res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:2',
    root_operator: `axis:${operator.id}:operator`,
    parent_credential_id: parent.id,
    scope: ['scope:a', 'scope:b'],  // wider than parent
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'delegation_chain_invalid');
});

test('Delegations: child with root_operator mismatch → 400 delegation_chain_invalid', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const parentRes = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  const parent = await parentRes.json();

  const res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:2',
    root_operator: 'axis:wrong-operator:operator',  // mismatch
    parent_credential_id: parent.id,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'delegation_chain_invalid');
});

test('Delegations: parent with max_sub_delegation_depth=0 → 400 (no further sub-delegation)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const parentRes = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
    constraints: { max_sub_delegation_depth: 0 },
  });
  const parent = await parentRes.json();

  const res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:2',
    root_operator: `axis:${operator.id}:operator`,
    parent_credential_id: parent.id,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'delegation_chain_invalid');
});

test('Delegations: M5 — expires more than 90 days out → 400 expires_too_far', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 91 * DAY_MS).toISOString(),  // >90 days
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'expires_too_far');
});

test('Delegations: M5 — expires in the past → 400 invalid_request', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a'],
    expires: new Date(Date.now() - DAY_MS).toISOString(),  // in the past
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');
});

test('Delegations: M5 — malformed ISO expires → 400 invalid_request', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  const res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:1',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a'],
    expires: 'not-a-real-date',
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');
});

test('Delegations: DELETE root cascades revoke through 3-level child chain', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, agent } = await setup(harness);

  // Build a 3-deep chain: root → c1 → c2
  const rootRes = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:root',
    root_operator: `axis:${operator.id}:operator`,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  const root = await rootRes.json();

  const c1Res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:c1',
    root_operator: `axis:${operator.id}:operator`,
    parent_credential_id: root.id,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  const c1 = await c1Res.json();

  const c2Res = await createDelegation(harness, registrar, {
    issued_by: agent.axis_id,
    issued_to: 'axis:downstream:c2',
    root_operator: `axis:${operator.id}:operator`,
    parent_credential_id: c1.id,
    scope: ['scope:a'],
    expires: new Date(Date.now() + 30 * DAY_MS).toISOString(),
  });
  const c2 = await c2Res.json();

  // Revoke root.
  const delRes = await harness.fetch(`/delegations/${encodeURIComponent(root.id)}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'test' }),
  });
  assert.equal(delRes.status, 200);
  const delBody = await delRes.json();
  assert.equal(delBody.status, 'revoked');
  assert.equal(delBody.cascadeRevoked, 2, 'cascade revokes both children');

  // Verify DB state: all three are revoked.
  for (const id of [root.id, c1.id, c2.id]) {
    const row = await harness.db.prepare(
      'SELECT status FROM delegations WHERE id = ?'
    ).bind(id).first();
    assert.equal(row.status, 'revoked', `delegation ${id} must be revoked`);
  }
});

test('Delegations: M3 cascade depth cap — 18-deep chain, root revoke halts at depth 16', async (t) => {
  // Build the chain via direct DB insert to bypass route-level validation
  // (no need for real proofs / valid expires-in-window for each link).
  // Then revoke the top via the route and confirm cascadeRevoke stops at
  // CASCADE_MAX_DEPTH (16). Children at depth 1..16 should be revoked;
  // children at depth 17+ stay active.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator } = await setup(harness);
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + 30 * DAY_MS).toISOString();
  const chainLength = 18;
  const ids = Array.from({ length: chainLength }, (_, i) => `dc-chain-${i}`);

  for (let i = 0; i < chainLength; i++) {
    await harness.db.prepare(
      `INSERT INTO delegations (id, issued_by, issued_to, root_operator, parent_credential_id,
                                scope, constraints, created_at, expires_at, revocable, status, proof, registrar_id)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, 1, 'active', '{}', ?)`
    ).bind(
      ids[i],
      `axis:${operator.id}:operator`,
      `axis:downstream:${i}`,
      `axis:${operator.id}:operator`,
      i === 0 ? null : ids[i - 1],
      JSON.stringify(['scope:a']),
      now,
      expires,
      registrar.id,
    ).run();
  }

  // Revoke the top.
  const res = await harness.fetch(`/delegations/${encodeURIComponent(ids[0])}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'depth-cap-test' }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  // cascadeRevoke starts recursing with depth=0 against the first child;
  // it halts when its OWN depth counter reaches CASCADE_MAX_DEPTH (16).
  // So children at chain index 1..16 get revoked (16 children), and 17 stays active.
  assert.equal(body.cascadeRevoked, 16, 'cascade revokes exactly CASCADE_MAX_DEPTH = 16 children');

  // Verify: ids[0..16] revoked; ids[17] still active.
  for (let i = 0; i <= 16; i++) {
    const row = await harness.db.prepare('SELECT status FROM delegations WHERE id = ?').bind(ids[i]).first();
    assert.equal(row.status, 'revoked', `index ${i} must be revoked`);
  }
  const deepest = await harness.db.prepare('SELECT status FROM delegations WHERE id = ?').bind(ids[17]).first();
  assert.equal(deepest.status, 'active', 'beyond-cap delegation must remain active (depth cap held)');
});
