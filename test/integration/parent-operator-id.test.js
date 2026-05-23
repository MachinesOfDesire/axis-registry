/**
 * parent_operator_id (v0.x Change 1) — integration matrix.
 *
 * Covers the schema + endpoint changes from
 * docs/specs/axis-registry-v0.x-changes-spec.md:
 *
 *   1. POST /operators/verify-domain
 *        - Accepts and persists optional parent_operator_id (happy path)
 *        - parent_operator_id = null/omitted → top-level operator (existing behavior preserved)
 *        - parent that doesn't exist → 400 invalid_parent_operator
 *        - parent owned by a different registrar → 403 parent_operator_cross_registrar (BOLA)
 *
 *   2. GET /operators/:id
 *        - Returns parent_operator_id when set + presentation context unlocked
 *        - Omits parent_operator_id when NULL (don't emit empty field)
 *
 *   3. PATCH /operators/:id
 *        - Sets parent_operator_id (happy path)
 *        - Clears parent_operator_id via explicit null
 *        - 404 when operator doesn't exist
 *        - 403 when caller doesn't own the operator (BOLA)
 *        - 403 when proposed parent belongs to a different registrar (BOLA)
 *        - 400 when self-loop (operator IS the proposed parent)
 *        - 400 when proposed parent doesn't exist
 *        - 400 when body has unknown fields (tight surface for v0.x)
 *        - Audit row written with both previous and new parent ids
 *
 *   4. GET /operators/:id/children
 *        - Returns paginated list of children owned by the calling registrar
 *        - Empty list when no children
 *        - 403 when caller doesn't own the parent (and is not admin+)
 *        - 404 when parent doesn't exist
 *        - admin+ sees children across registrars
 *
 * Spec acceptance criteria not covered here:
 *
 *   - "A delegation issued from a parent operator to a child operator is
 *     accepted, stored, and verifiable via the existing chain-walk logic."
 *     The existing operator-to-operator delegation pipeline is already
 *     covered by test/integration/delegation-chain.test.js. parent_operator_id
 *     is a structural hint at the principal hierarchy; it does not alter
 *     how the chain-walker walks. Adding parent_operator_id awareness to
 *     chain-walking would be a normative protocol change and is explicitly
 *     out of scope for v0.x.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

// ---------- POST /operators/verify-domain ----------

test('verify-domain: accepts parent_operator_id when parent exists + same registrar', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const parent = await harness.createOperator({
    tier: 'domain', registrar_id: registrar.id, domain: 'parent-org.example',
  });

  const res = await harness.fetch('/operators/verify-domain', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'child-user@parent-org.example', parent_operator_id: parent.id }),
  });

  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.operator_id, 'response includes operator_id');

  const row = await harness.db.prepare('SELECT parent_operator_id FROM operators WHERE id = ?')
    .bind(body.operator_id).first();
  assert.equal(row.parent_operator_id, parent.id, 'parent_operator_id persisted');
});

test('verify-domain: omitting parent_operator_id creates a top-level operator (existing behavior)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();

  const res = await harness.fetch('/operators/verify-domain', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'solo@example.com' }),
  });

  assert.equal(res.status, 200);
  const body = await res.json();
  const row = await harness.db.prepare('SELECT parent_operator_id FROM operators WHERE id = ?')
    .bind(body.operator_id).first();
  assert.equal(row.parent_operator_id, null, 'parent_operator_id NULL when omitted');
});

test('verify-domain: rejects parent_operator_id that does not exist', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();

  const res = await harness.fetch('/operators/verify-domain', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'orphan@example.com', parent_operator_id: 'op-does-not-exist' }),
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error.code, 'invalid_parent_operator');
});

test('verify-domain: rejects parent_operator_id owned by different registrar (BOLA)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar();
  const registrarB = await harness.createRegistrar();
  const parentUnderA = await harness.createOperator({
    tier: 'domain', registrar_id: registrarA.id, domain: 'org-a.example',
  });

  // Registrar B attempts to plant a child under A's parent.
  const res = await harness.fetch('/operators/verify-domain', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${registrarB.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'leak@b.example', parent_operator_id: parentUnderA.id }),
  });

  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error.code, 'parent_operator_cross_registrar');
});

// ---------- GET /operators/:id ----------

test('GET /operators/:id: returns parent_operator_id when set (owner context)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const parent = await harness.createOperator({
    tier: 'domain', registrar_id: registrar.id, domain: 'parent.example',
  });
  const child = await harness.createOperator({ registrar_id: registrar.id, email: 'c@parent.example' });
  await harness.db.prepare('UPDATE operators SET parent_operator_id = ? WHERE id = ?')
    .bind(parent.id, child.id).run();

  const res = await harness.fetch(`/operators/${encodeURIComponent(child.id)}`, {
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.parent_operator_id, parent.id, 'response includes parent_operator_id');
});

test('GET /operators/:id: omits parent_operator_id when NULL', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const topLevel = await harness.createOperator({ registrar_id: registrar.id, email: 't@example.com' });

  const res = await harness.fetch(`/operators/${encodeURIComponent(topLevel.id)}`, {
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(!('parent_operator_id' in body), 'parent_operator_id field absent when NULL');
});

// ---------- PATCH /operators/:id ----------

test('PATCH /operators/:id: sets parent_operator_id (happy path) + writes audit row', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const parent = await harness.createOperator({
    tier: 'domain', registrar_id: registrar.id, domain: 'parent.example',
  });
  const child = await harness.createOperator({ registrar_id: registrar.id, email: 'c@parent.example' });

  const res = await harness.fetch(`/operators/${encodeURIComponent(child.id)}`, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: parent.id }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.parent_operator_id, parent.id);
  assert.equal(body.updated, true);

  // Persisted?
  const row = await harness.db.prepare('SELECT parent_operator_id FROM operators WHERE id = ?')
    .bind(child.id).first();
  assert.equal(row.parent_operator_id, parent.id);

  // ctx.waitUntil resolves before the worker finishes the response in
  // Miniflare; the audit row should be present by the time fetch resolves.
  // Allow a brief tick just in case.
  await new Promise((r) => setTimeout(r, 50));
  const audit = await harness.db.prepare(
    'SELECT action, actor, target, details FROM audit_log WHERE action = ? AND target = ?'
  ).bind('update_operator_parent', child.id).first();
  assert.ok(audit, 'audit row written');
  const details = JSON.parse(audit.details);
  assert.equal(details.previous_parent_operator_id, null);
  assert.equal(details.new_parent_operator_id, parent.id);
});

test('PATCH /operators/:id: clears parent_operator_id via explicit null', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const parent = await harness.createOperator({
    tier: 'domain', registrar_id: registrar.id, domain: 'parent.example',
  });
  const child = await harness.createOperator({ registrar_id: registrar.id, email: 'c@parent.example' });
  await harness.db.prepare('UPDATE operators SET parent_operator_id = ? WHERE id = ?')
    .bind(parent.id, child.id).run();

  const res = await harness.fetch(`/operators/${encodeURIComponent(child.id)}`, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: null }),
  });
  assert.equal(res.status, 200);
  const row = await harness.db.prepare('SELECT parent_operator_id FROM operators WHERE id = ?')
    .bind(child.id).first();
  assert.equal(row.parent_operator_id, null);
});

test('PATCH /operators/:id: 404 when operator does not exist', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const res = await harness.fetch('/operators/op-ghost-id', {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: null }),
  });
  assert.equal(res.status, 404);
});

test('PATCH /operators/:id: 403 when caller does not own the operator (BOLA)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar();
  const registrarB = await harness.createRegistrar();
  const operatorUnderA = await harness.createOperator({ registrar_id: registrarA.id, email: 'a@x.example' });

  const res = await harness.fetch(`/operators/${encodeURIComponent(operatorUnderA.id)}`, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrarB.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: null }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error.code, 'not_your_resource');
});

test('PATCH /operators/:id: 403 when proposed parent belongs to different registrar (BOLA)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar();
  const registrarB = await harness.createRegistrar();
  const parentUnderA = await harness.createOperator({
    tier: 'domain', registrar_id: registrarA.id, domain: 'a.example',
  });
  const childUnderB = await harness.createOperator({ registrar_id: registrarB.id, email: 'b@x.example' });

  const res = await harness.fetch(`/operators/${encodeURIComponent(childUnderB.id)}`, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrarB.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: parentUnderA.id }),
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error.code, 'parent_operator_cross_registrar');
});

test('PATCH /operators/:id: 400 self-loop (parent === id)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const operator = await harness.createOperator({ registrar_id: registrar.id, email: 's@x.example' });

  const res = await harness.fetch(`/operators/${encodeURIComponent(operator.id)}`, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: operator.id }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error.code, 'invalid_parent_operator');
});

test('PATCH /operators/:id: 400 when parent does not exist', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const child = await harness.createOperator({ registrar_id: registrar.id, email: 'c@x.example' });

  const res = await harness.fetch(`/operators/${encodeURIComponent(child.id)}`, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: 'op-ghost' }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error.code, 'invalid_parent_operator');
});

test('PATCH /operators/:id: 400 on unknown body fields (tight v0.x surface)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const operator = await harness.createOperator({ registrar_id: registrar.id, email: 'x@x.example' });

  const res = await harness.fetch(`/operators/${encodeURIComponent(operator.id)}`, {
    method: 'PATCH',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ parent_operator_id: null, status: 'suspended' }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error.code, 'invalid_request');
});

// ---------- GET /operators/:id/children ----------

test('GET /operators/:id/children: returns paginated children for the owning registrar', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const parent = await harness.createOperator({
    tier: 'domain', registrar_id: registrar.id, domain: 'parent.example',
  });

  // Three children under the parent.
  const childIds = [];
  for (let i = 0; i < 3; i++) {
    const c = await harness.createOperator({ registrar_id: registrar.id, email: `c${i}@parent.example` });
    await harness.db.prepare('UPDATE operators SET parent_operator_id = ? WHERE id = ?')
      .bind(parent.id, c.id).run();
    childIds.push(c.id);
  }

  const res = await harness.fetch(`/operators/${encodeURIComponent(parent.id)}/children`, {
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.total, 3);
  assert.equal(body.children.length, 3);
  for (const id of childIds) {
    assert.ok(body.children.some((c) => c.id === id), `child ${id} appears in response`);
  }
});

test('GET /operators/:id/children: empty list when parent has no children', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const parent = await harness.createOperator({
    tier: 'domain', registrar_id: registrar.id, domain: 'parent.example',
  });

  const res = await harness.fetch(`/operators/${encodeURIComponent(parent.id)}/children`, {
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.total, 0);
  assert.deepEqual(body.children, []);
});

test('GET /operators/:id/children: 404 when parent does not exist', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar();
  const res = await harness.fetch('/operators/op-ghost-id/children', {
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  assert.equal(res.status, 404);
});

test('GET /operators/:id/children: 403 when caller does not own the parent (and is not admin+)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar();
  const registrarB = await harness.createRegistrar();
  const parentUnderA = await harness.createOperator({
    tier: 'domain', registrar_id: registrarA.id, domain: 'a.example',
  });

  const res = await harness.fetch(`/operators/${encodeURIComponent(parentUnderA.id)}/children`, {
    headers: { 'Authorization': `Bearer ${registrarB.apiKey}` },
  });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error.code, 'not_your_resource');
});

test('GET /operators/:id/children: admin sees children across registrars', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar();
  const registrarB = await harness.createRegistrar();
  const adminRegistrar = await harness.createRegistrar({ role: 'admin' });

  const parentUnderA = await harness.createOperator({
    tier: 'domain', registrar_id: registrarA.id, domain: 'a.example',
  });
  // Children under DIFFERENT registrars sharing the same parent. (Unusual
  // but the model permits it: registrar identifies who onboarded each row.)
  const childUnderA = await harness.createOperator({ registrar_id: registrarA.id, email: 'a-child@x.example' });
  const childUnderB = await harness.createOperator({ registrar_id: registrarB.id, email: 'b-child@x.example' });
  await harness.db.prepare('UPDATE operators SET parent_operator_id = ? WHERE id = ?').bind(parentUnderA.id, childUnderA.id).run();
  await harness.db.prepare('UPDATE operators SET parent_operator_id = ? WHERE id = ?').bind(parentUnderA.id, childUnderB.id).run();

  const res = await harness.fetch(`/operators/${encodeURIComponent(parentUnderA.id)}/children`, {
    headers: { 'Authorization': `Bearer ${adminRegistrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.total, 2, 'admin sees children regardless of registrar');
});
