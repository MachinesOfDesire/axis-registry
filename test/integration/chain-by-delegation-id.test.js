/**
 * GET /delegations/:id/chain — dual-mode :id (agent identifier OR delegation
 * credential id).
 *
 * A verifier holding an AIT carries the specific delegation the token was
 * issued under in the `dlg` claim (§4.3). Passing that credential id to the
 * chain endpoint must resolve THAT delegation's chain and pin the verdict to
 * it — otherwise the effective authority silently becomes the union of all
 * the agent's delegations and the `dlg` claim is ignored.
 *
 * Coverage:
 *   - delegation-id form (`dc:` prefix) returns the chain pinned to the named
 *     credential, including when the agent holds multiple delegations
 *   - agent-identifier form is unchanged (no pinning block, walks the agent's
 *     newest active delegation)
 *   - unknown `dc:` id → 404 delegation_not_found; unknown agent identifier
 *     → 404 agent_not_found (distinguishable codes)
 *   - a revoked delegation id resolves but reports chainValid:false
 *   - an expired delegation id resolves but reports chainValid:false
 *   - an issuer-chosen id without the `dc:` prefix (signed submission) still
 *     resolves via the delegations-table fallback
 *   - multi-link chain resolves upward through parent_credential_id with the
 *     intersected effective_scope
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';
import { registerRealAgent, buildSignedDelegation } from './_helpers.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const futureISO = (d = 30) => new Date(Date.now() + d * DAY_MS).toISOString();

async function setup(harness) {
  const registrar = await harness.createRegistrar({ id: 'chain-mode-reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id, tier: 'domain', domain: 'chain-mode.example.com', free_slots_total: 5,
  });

  async function registerAgent(name) {
    const res = await harness.fetch('/register', {
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
    assert.equal(res.status, 201);
    return res.json();
  }

  const issuer = await registerAgent('issuer');
  const delegate = await registerAgent('delegate');
  return { registrar, operator, issuer, delegate };
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
  assert.equal(res.status, 201, await res.clone().text());
  return res.json();
}

const getChain = (harness, id) =>
  harness.fetch(`/delegations/${encodeURIComponent(id)}/chain`);

test('Chain by delegation id: pins to the named credential when the agent holds multiple delegations', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, issuer, delegate } = await setup(harness);
  const root = `axis:${operator.id}:operator`;

  // Two independent delegations to the SAME delegatee with different scopes.
  const dcA = await createDelegation(harness, registrar, {
    issued_by: issuer.axis_id, issued_to: delegate.axis_id, root_operator: root,
    scope: ['x-test:article:draft'], expires: futureISO(30),
  });
  const dcB = await createDelegation(harness, registrar, {
    issued_by: issuer.axis_id, issued_to: delegate.axis_id, root_operator: root,
    scope: ['x-test:article:publish'], expires: futureISO(30),
  });

  for (const [dc, scope] of [[dcA, ['x-test:article:draft']], [dcB, ['x-test:article:publish']]]) {
    const res = await getChain(harness, dc.id);
    assert.equal(res.status, 200);
    const body = await res.json();

    // Pinned to exactly the named credential, regardless of the sibling.
    assert.equal(body.delegation.id, dc.id);
    assert.deepEqual(body.delegation.scope, scope);
    assert.deepEqual(body.effective_scope, scope);
    assert.equal(body.chainValid, true);
    assert.equal(body.chainDepth, 1);
    assert.equal(body.chain[0].delegation, dc.id);
    assert.deepEqual(body.chain[0].scope, scope);

    // Agent-form parity fields still present.
    assert.equal(body.agent, delegate.did);
    assert.equal(body.axis_id, delegate.axis_id);
    assert.equal(typeof body.verifiedAt, 'string');
  }
});

test('Chain by agent identifier: original behavior unchanged (no pinning block)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, issuer, delegate } = await setup(harness);

  await createDelegation(harness, registrar, {
    issued_by: issuer.axis_id, issued_to: delegate.axis_id,
    root_operator: `axis:${operator.id}:operator`,
    scope: ['x-test:article:draft'], expires: futureISO(30),
  });

  const res = await getChain(harness, delegate.axis_id);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.agent, delegate.did);
  assert.equal(body.axis_id, delegate.axis_id);
  assert.equal(body.chainValid, true);
  assert.equal(body.chainDepth, 1);
  assert.equal(body.delegation, undefined, 'agent form must not carry the pinning block');
});

test('Chain 404s distinguish delegation_not_found from agent_not_found', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  await setup(harness);

  const dcRes = await getChain(harness, 'dc:nope:does-not-exist');
  assert.equal(dcRes.status, 404);
  assert.equal((await dcRes.json()).error?.code, 'delegation_not_found');

  const agentRes = await getChain(harness, 'axis:nope:no-such-agent');
  assert.equal(agentRes.status, 404);
  assert.equal((await agentRes.json()).error?.code, 'agent_not_found');
});

test('Chain by delegation id: revoked credential resolves but reports invalid', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, issuer, delegate } = await setup(harness);

  const dc = await createDelegation(harness, registrar, {
    issued_by: issuer.axis_id, issued_to: delegate.axis_id,
    root_operator: `axis:${operator.id}:operator`,
    scope: ['x-test:article:draft'], expires: futureISO(30),
  });

  const del = await harness.fetch(`/delegations/${encodeURIComponent(dc.id)}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'test' }),
  });
  assert.equal(del.status, 200);

  const res = await getChain(harness, dc.id);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.delegation.id, dc.id);
  assert.equal(body.delegation.status, 'revoked');
  assert.equal(body.chainValid, false, 'revoked credential must fail the pinned chain');
});

test('Chain by delegation id: expired credential resolves but reports invalid', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, issuer, delegate } = await setup(harness);

  // The create route rejects past `expires`, so seed the expired row directly.
  const id = 'dc:chain-mode:expired-1';
  await harness.db.prepare(
    `INSERT INTO delegations (id, issued_by, issued_to, root_operator, parent_credential_id,
                              scope, constraints, created_at, expires_at, revocable, status, proof, registrar_id)
     VALUES (?, ?, ?, ?, NULL, ?, NULL, ?, ?, 1, 'active', '{}', ?)`
  ).bind(
    id, issuer.axis_id, delegate.axis_id, `axis:${operator.id}:operator`,
    JSON.stringify(['x-test:article:draft']),
    new Date(Date.now() - 2 * DAY_MS).toISOString(),
    new Date(Date.now() - DAY_MS).toISOString(),
    registrar.id,
  ).run();

  const res = await getChain(harness, id);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.delegation.id, id);
  assert.equal(body.chainValid, false, 'expired credential must fail the pinned chain');
  assert.equal(body.chain[0].expired, true);
});

test('Chain by delegation id: issuer-chosen id without dc: prefix resolves via table fallback', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrar = await harness.createRegistrar({ id: 'chain-signed-reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id, tier: 'domain', domain: 'chain-signed.example.com', free_slots_total: 5,
  });
  const issuer = await registerRealAgent(harness, registrar, operator, 'signer');
  const delegate = await registerRealAgent(harness, registrar, operator, 'holder');

  // Signed submission (§4.4 Option A): the issuer chooses the credential id.
  const doc = {
    axis_version: '0.2', type: 'DelegationCredential',
    id: 'urn:example:pinned-credential-1',
    issued_by: issuer.axisId, issued_to: delegate.axisId, root_operator: operator.id,
    scope: ['x-test:article:draft'], created: new Date().toISOString(),
    expires: futureISO(30), revocable: true,
  };
  const post = await harness.fetch('/delegations', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(await buildSignedDelegation(issuer.keypair, doc)),
  });
  assert.equal(post.status, 201, await post.clone().text());

  const res = await getChain(harness, doc.id);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.delegation.id, doc.id);
  assert.deepEqual(body.delegation.scope, ['x-test:article:draft']);
  assert.equal(body.chainValid, true);
  assert.equal(body.chain[0].signatureValid, true, 'signed credential proof must verify');
});

test('Chain by delegation id: multi-link chain walks parents with intersected effective scope', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator, issuer, delegate } = await setup(harness);
  const root = `axis:${operator.id}:operator`;

  const parent = await createDelegation(harness, registrar, {
    issued_by: issuer.axis_id, issued_to: delegate.axis_id, root_operator: root,
    scope: ['x-test:article:draft', 'x-test:article:publish'], expires: futureISO(30),
  });
  const child = await createDelegation(harness, registrar, {
    issued_by: issuer.axis_id, issued_to: 'axis:downstream:sub', root_operator: root,
    parent_credential_id: parent.id,
    scope: ['x-test:article:draft'], expires: futureISO(30),
  });

  const res = await getChain(harness, child.id);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.delegation.id, child.id);
  assert.equal(body.chainDepth, 2);
  assert.equal(body.chain[0].delegation, child.id, 'chain is leaf-first');
  assert.equal(body.chain[1].delegation, parent.id);
  assert.deepEqual(body.effective_scope, ['x-test:article:draft']);
  assert.equal(body.chainValid, true);

  // Delegatee of the pinned credential is not a registered agent — the raw
  // identifier is surfaced instead.
  assert.equal(body.agent, 'axis:downstream:sub');
  assert.equal(body.axis_id, null);
});
