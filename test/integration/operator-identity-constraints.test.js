/**
 * Operator identity is enforced at the DATABASE layer (migration 0007 +
 * schema.sql): UNIQUE(email) and partial UNIQUE(domain) WHERE domain IS NOT
 * NULL. These tests assert the invariants hold by construction — i.e. the DB
 * itself refuses a duplicate operator — not merely because handleVerifyDomain
 * remembers to look before it writes.
 *
 * Paired with the upsert + RETURNING rewrite of handleVerifyDomain, this is the
 * structural close-out of the 2026-06-29 email-tier signup incident class.
 *
 * Handler: src/routes/operators.js → handleVerifyDomain
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

test('schema: a second operator with a duplicate email is rejected by the DB', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });

  await harness.createOperator({ registrar_id: reg.id, tier: 'email', email: 'dup@example.com' });

  await assert.rejects(
    () => harness.createOperator({ registrar_id: reg.id, tier: 'email', email: 'dup@example.com' }),
    /UNIQUE/i,
    'the DB must refuse a second operator row sharing an email',
  );
});

test('schema: duplicate non-null domain rejected; multiple NULL domains allowed', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });

  await harness.createOperator({
    registrar_id: reg.id, tier: 'domain', domain: 'acme.example.com', email: 'a@acme.example.com',
  });
  await assert.rejects(
    () => harness.createOperator({
      registrar_id: reg.id, tier: 'domain', domain: 'acme.example.com', email: 'b@acme.example.com',
    }),
    /UNIQUE/i,
    'a verified domain belongs to exactly one operator',
  );

  // Two email-tier operators both have domain=NULL — these must NOT collide
  // (partial index / NULLs distinct), or every email signup after the first
  // would fail.
  await harness.createOperator({ registrar_id: reg.id, tier: 'email', email: 'e1@example.com' });
  await assert.doesNotReject(
    () => harness.createOperator({ registrar_id: reg.id, tier: 'email', email: 'e2@example.com' }),
    'multiple email-tier operators with NULL domain must be allowed',
  );
});

test('verify-domain: claiming a domain already verified by another operator → 409', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });

  // Operator A owns acme.example.com (verified) under this registrar.
  await harness.createOperator({
    registrar_id: reg.id, tier: 'domain', domain: 'acme.example.com',
    email: 'owner-a@acme.example.com', domain_verified: true,
  });

  // A different operator (different email, same registrar) tries to claim it.
  const res = await verifyDomain(harness, reg, { email: 'intruder@other.example.com', domain: 'acme.example.com' });
  assert.equal(res.status, 409, 'cross-operator domain claim must be rejected');
  assert.equal(res.body.error.code, 'domain_taken');

  // And the failed claim must not have created an orphan operator row.
  const orphan = await harness.db
    .prepare('SELECT COUNT(*) AS n FROM operators WHERE email = ?')
    .bind('intruder@other.example.com')
    .first();
  assert.equal(orphan.n, 0, 'a rejected domain claim must not leave a half-created operator');
});

test('verify-domain: an operator re-initiating verification for its OWN domain is not a conflict', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const reg = await harness.createRegistrar({ id: 'reg-a' });

  const op = await harness.createOperator({
    registrar_id: reg.id, tier: 'domain', domain: 'mine.example.com',
    email: 'owner@mine.example.com', domain_verified: true,
  });

  const res = await verifyDomain(harness, reg, { email: 'owner@mine.example.com', domain: 'mine.example.com' });
  assert.equal(res.status, 200, 're-initiating verification for your own domain must succeed');
  assert.equal(res.body.operator_id, op.id);
  assert.ok(res.body.token, 'a fresh verification token is issued');
});
