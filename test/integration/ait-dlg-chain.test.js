/**
 * P0-2 (second half): GET /verify resolves the AIT's `dlg` chain to root and
 * returns the trustworthy effective scope (§4.3, §8 Step 3) — additively. Top-
 * level `valid` stays the AIT-identity assertion; `delegation_valid` carries
 * the chain's trustworthiness, and `effective_scope` is the intersected scope.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';
import { registerRealAgent, buildSignedDelegation, signAIT } from './_helpers.js';

const now = () => Math.floor(Date.now() / 1000);
const futureISO = (d = 30) => new Date(Date.now() + d * 86400_000).toISOString();
const nowISO = () => new Date().toISOString();

async function setup(opts = {}) {
  const harness = await createHarness(opts);
  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id, tier: 'domain', domain: 'widget-corp.com', free_slots_total: 5,
  });
  const issuer = await registerRealAgent(harness, registrar, operator, 'editor');
  const delegate = await registerRealAgent(harness, registrar, operator, 'researcher');
  return { harness, registrar, operator, issuer, delegate };
}

const postDelegation = (harness, registrar, body) => harness.fetch('/delegations', {
  method: 'POST',
  headers: { Authorization: `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

function dcDoc({ issuer, delegate, operator, scope }) {
  return {
    axis_version: '0.2', type: 'DelegationCredential',
    id: `dc:${operator.id}:chain-${Math.floor(Date.now() / 1000)}-${Math.random().toString(36).slice(2, 8)}`,
    issued_by: issuer.axisId, issued_to: delegate.axisId, root_operator: operator.id,
    scope, created: nowISO(), expires: futureISO(30), revocable: true,
  };
}

async function verifyToken(harness, keypair, claims) {
  const token = await signAIT(keypair, { aud: 'widget-corp.com', iat: now(), exp: now() + 600, ...claims });
  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  return res.json();
}

test('P0-2: resolves a signed dlg chain and returns effective scope', async (t) => {
  const { harness, registrar, operator, issuer, delegate } = await setup();
  t.after(() => harness.dispose());

  const doc = dcDoc({ issuer, delegate, operator, scope: ['x-test:article:draft'] });
  const r = await postDelegation(harness, registrar, await buildSignedDelegation(issuer.keypair, doc));
  assert.equal(r.status, 201, await r.text());

  const body = await verifyToken(harness, delegate.keypair, { iss: delegate.axisId, sub: delegate.axisId, dlg: doc.id });
  assert.equal(body.valid, true, JSON.stringify(body));
  assert.equal(body.delegation_resolved, true);
  assert.equal(body.delegation_valid, true);
  assert.equal(body.delegation_bound_to_agent, true);
  assert.equal(body.delegation_depth, 1);
  assert.deepEqual(body.effective_scope, ['x-test:article:draft']);
});

test('P0-2: a legacy unsigned dlg still resolves (enforcement off): valid chain, effective scope', async (t) => {
  const { harness, registrar, operator, issuer, delegate } = await setup();
  t.after(() => harness.dispose());

  // Legacy create (no proof) — issued_to the delegate.
  const r = await postDelegation(harness, registrar, {
    issued_by: issuer.axisId, issued_to: delegate.axisId, root_operator: operator.id,
    scope: ['x-test:article:draft'], expires: futureISO(30),
  });
  const created = await r.json();
  assert.equal(r.status, 201, JSON.stringify(created));

  const body = await verifyToken(harness, delegate.keypair, { iss: delegate.axisId, sub: delegate.axisId, dlg: created.id });
  assert.equal(body.delegation_resolved, true);
  assert.equal(body.delegation_valid, true); // enforcement off → proof not required
  assert.deepEqual(body.effective_scope, ['x-test:article:draft']);
});

test('P0-2: a chain whose leaf is issued to a different agent is not bound', async (t) => {
  const { harness, registrar, operator, issuer, delegate } = await setup();
  t.after(() => harness.dispose());

  const doc = dcDoc({ issuer, delegate, operator, scope: ['x-test:article:draft'] });
  await postDelegation(harness, registrar, await buildSignedDelegation(issuer.keypair, doc));

  // The ISSUER presents an AIT claiming the DC that was issued to the DELEGATE.
  const body = await verifyToken(harness, issuer.keypair, { iss: issuer.axisId, sub: issuer.axisId, dlg: doc.id });
  assert.equal(body.delegation_resolved, true);
  assert.equal(body.delegation_bound_to_agent, false);
  assert.equal(body.delegation_valid, false);
});

test('P0-2: a nonexistent dlg resolves to nothing', async (t) => {
  const { harness, registrar, delegate } = await setup();
  t.after(() => harness.dispose());

  const body = await verifyToken(harness, delegate.keypair, { iss: delegate.axisId, sub: delegate.axisId, dlg: 'dc:nope:does-not-exist' });
  assert.equal(body.valid, true); // AIT identity still valid
  assert.equal(body.delegation_resolved, false);
  assert.equal(body.delegation_valid, false);
});

test('P0-2: effective scope is the chain intersection (wildcard parent narrows to child)', async (t) => {
  const { harness, registrar, operator, issuer, delegate } = await setup({ });
  t.after(() => harness.dispose());

  // Parent: operator -> issuer with a wildcard scope. Child: issuer -> delegate, concrete subset.
  const parent = {
    axis_version: '0.2', type: 'DelegationCredential',
    id: `dc:${operator.id}:parent-${Math.floor(Date.now() / 1000)}`,
    issued_by: `axis:${operator.id}:operator`, issued_to: issuer.axisId, root_operator: operator.id,
    scope: ['x-test:article:*'], created: nowISO(), expires: futureISO(30), revocable: true,
  };
  // Parent is issued BY the operator; the operator has no registered key here,
  // so it resolves unsigned/legacy. Use the legacy create path for the parent.
  const rp = await postDelegation(harness, registrar, {
    issued_by: parent.issued_by, issued_to: parent.issued_to, root_operator: parent.root_operator,
    scope: parent.scope, expires: parent.expires,
  });
  const parentCreated = await rp.json();
  assert.equal(rp.status, 201, JSON.stringify(parentCreated));

  const child = dcDoc({ issuer, delegate, operator, scope: ['x-test:article:draft'] });
  child.parent_credential_id = parentCreated.id;
  const rc = await postDelegation(harness, registrar, await buildSignedDelegation(issuer.keypair, child));
  const childCreated = await rc.json();
  assert.equal(rc.status, 201, JSON.stringify(childCreated));

  const body = await verifyToken(harness, delegate.keypair, { iss: delegate.axisId, sub: delegate.axisId, dlg: child.id });
  assert.equal(body.delegation_depth, 2);
  assert.deepEqual(body.effective_scope, ['x-test:article:draft']); // x-test:article:* ∩ x-test:article:draft
});
