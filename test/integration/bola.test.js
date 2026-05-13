/**
 * BOLA matrix — every mutating route, registrar A's key MUST NOT touch
 * registrar B's resources.
 *
 * BOLA = Broken Object Level Authorization. The vulnerability class where
 * the auth gate confirms "is a valid registrar logged in?" but doesn't
 * confirm "is THIS resource THEIRS to act on?" The second check is per-route
 * business logic. This file is the regression suite that locks it in.
 *
 * Pre-launch this is the highest-leverage integration coverage we have.
 * Every gate here was already in code (per src/middleware/auth.js and the
 * inline checks in each route handler) — the tests stop a future refactor
 * from silently regressing the ownership semantics.
 *
 * Routes covered (highest-leverage pre-launch surface):
 *
 *   1. POST /register
 *        - Registrar B → 403 not_your_resource when targeting A's operator
 *
 *   2. DELETE /agents/:id
 *        - Registrar B → 403 not_your_resource when targeting A's agent
 *
 *   3. GET /agents?operator_id=
 *        - Registrar B → 403 not_your_resource when listing A's operator's
 *          agents (the operator_id-drift fix shipped 2026-05-12 in PR #13
 *          added this gate; this test locks it in)
 *        - Unauthed caller → 401 (defense-in-depth before the BOLA check)
 *
 *   4. GET /operators
 *        - Scoped self-list: B's response MUST NOT include A's operators
 *
 *   5. GET /audit
 *        - Scoped self-list: B's response MUST NOT include audit rows for
 *          A's actions (cross-tenant audit lives at /admin/audit, admin+ only)
 *
 *   6. /admin/* — plain registrar role
 *        - 403 forbidden when caller role is 'registrar'
 *
 *   7. /admin/force-deactivate-agent — admin role
 *        - 403 forbidden when caller role is 'admin' (super_admin required)
 *
 *   8. /admin/force-revoke-delegation — admin role
 *        - 403 forbidden when caller role is 'admin' (super_admin required)
 *
 *   9. /admin/* — super_admin positive control
 *        - 200 when caller is super_admin (so the matrix isn't asserting on
 *          a universal denial)
 *
 * Out of scope for this initial matrix (queued for follow-up PR per
 * test/integration/README.md "pending" list):
 *
 *  10. POST /delegations
 *        - Registrar B → 403 not_your_resource when issuing on behalf of A's agent
 *
 *  11. POST /delegations with parent_credential_id
 *        - Registrar B → 403 not_your_resource when chaining onto A's parent
 *
 *  12. DELETE /delegations/:id
 *        - Registrar B → 403 not_your_resource when revoking A's delegation
 *
 *  13. POST /operators/verify-domain
 *        - Registrar B → 403 not_your_resource when claiming A's existing operator
 *
 *  14. POST /operators/verify-domain/check
 *        - Registrar B → 403 not_your_resource when checking A's operator's token
 *
 * The harness's createRegistrar defaults role='registrar', so most tests
 * use that. Admin/super_admin tests pass role explicitly.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

/**
 * Helper: pre-seed an agent under (registrar, operator) by hitting POST
 * /register. Returns the parsed response body. Asserts that the seeded
 * registration succeeded — if this fails the test is broken at setup, not
 * the gate under test.
 */
async function seedAgentForRegistrar(harness, registrar, operator, name = 'victim-agent') {
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
  assert.equal(
    res.status, 201,
    `pre-test setup: owner-side registration must succeed (status was ${res.status})`,
  );
  return res.json();
}

test('BOLA: POST /register — registrar B cannot register under registrar A\'s operator', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain',
    domain: 'company-a.example.com',
    free_slots_total: 3,
  });

  const res = await harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrarB.apiKey}`,   // B's key
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { domain: operatorA.domain },           // A's operator
      metadata: { name: 'malicious-agent' },
    }),
  });

  assert.equal(res.status, 403, 'cross-tenant register must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');

  // Defense-in-depth: nothing should have been created.
  const agents = await harness.getAgentsForOperator(operatorA.id);
  assert.equal(agents.length, 0, 'no agents should be created under A\'s operator');

  // The BOLA check fires BEFORE slot allocation, so slot counts must be
  // untouched. This catches any future refactor that accidentally moves
  // the BOLA check after the slot UPDATE.
  const slots = await harness.getSlots(operatorA.id);
  assert.equal(slots.free_slots_used, 0, 'no slot allocation on a denied register');
  assert.equal(slots.paid_agents, 0, 'no paid allocation on a denied register');
});

test('BOLA: DELETE /agents/:id — registrar B cannot deactivate registrar A\'s agent', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain',
    domain: 'company-a.example.com',
    free_slots_total: 3,
  });

  const registered = await seedAgentForRegistrar(harness, registrarA, operatorA);
  const targetAxisId = registered.axis_id;

  const res = await harness.fetch(`/agents/${encodeURIComponent(targetAxisId)}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${registrarB.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'malicious' }),
  });

  assert.equal(res.status, 403, 'cross-tenant deactivate must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');

  // Agent should still be active in the DB.
  const agents = await harness.getAgentsForOperator(operatorA.id);
  assert.equal(agents.length, 1, 'agent still exists after denied deactivation');
});

test('BOLA: GET /agents?operator_id= — registrar B cannot list registrar A\'s agents', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain',
    domain: 'company-a.example.com',
    free_slots_total: 3,
  });
  await seedAgentForRegistrar(harness, registrarA, operatorA);

  const res = await harness.fetch(`/agents?operator_id=${encodeURIComponent(operatorA.id)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${registrarB.apiKey}` },
  });

  assert.equal(res.status, 403, 'cross-tenant list must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');
});

test('BOLA: GET /agents?operator_id= — unauthed caller rejected with 401 before BOLA check', async (t) => {
  // Defense-in-depth: the auth gate must reject before the BOLA logic runs.
  // The standard HTTP distinction matters: 401 (no credentials) vs 403
  // (credentials but wrong owner). Conformance tools key off the code.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain',
    domain: 'company-a.example.com',
    free_slots_total: 3,
  });

  const res = await harness.fetch(`/agents?operator_id=${encodeURIComponent(operatorA.id)}`, {
    method: 'GET',
    // no Authorization header
  });

  assert.equal(res.status, 401, 'unauthenticated GET /agents must be 401');
  const body = await res.json();
  assert.equal(body.error?.code, 'unauthorized', 'expected unauthorized code');
});

test('BOLA: GET /operators — scoped to caller; B does NOT see A\'s operators', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  await harness.createOperator({
    registrar_id: registrarA.id, id: 'op-a',
    tier: 'domain', domain: 'a.example.com', free_slots_total: 3,
  });
  await harness.createOperator({
    registrar_id: registrarB.id, id: 'op-b',
    tier: 'domain', domain: 'b.example.com', free_slots_total: 3,
  });

  const res = await harness.fetch('/operators', {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${registrarB.apiKey}` },
  });

  assert.equal(res.status, 200, 'authed self-list returns 200');
  const body = await res.json();
  const returnedIds = (body.operators || []).map((op) => op.id);
  assert.ok(returnedIds.includes('op-b'), 'B sees their own operator');
  assert.ok(!returnedIds.includes('op-a'), 'B does NOT see A\'s operator');
  assert.equal(body.total, 1, 'total count reflects only B\'s operators');
});

test('BOLA: GET /audit — scoped to caller; B does NOT see A\'s audit rows', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain', domain: 'a.example.com', free_slots_total: 3,
  });

  // Seed an audit row by registering as A. POST /register writes an audit
  // row with registrar_id = A.id via ctx.waitUntil; we read /audit as B
  // and assert no A-actor or A-target rows leak.
  await seedAgentForRegistrar(harness, registrarA, operatorA);

  const res = await harness.fetch('/audit', {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${registrarB.apiKey}` },
  });

  assert.equal(res.status, 200, 'self-audit returns 200 even when empty');
  const body = await res.json();
  const logs = body.logs || [];
  // B should see zero A-related rows. (B may have zero rows total, which is
  // also fine; we assert the negative property.)
  for (const log of logs) {
    assert.notEqual(log.registrar_id, registrarA.id, 'B audit must not contain A-actor rows');
    assert.notEqual(log.target_registrar_id, registrarA.id, 'B audit must not contain A-target rows');
  }
});

test('BOLA: /admin/* — plain registrar role is denied (403 forbidden)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  // Explicit role to make the assertion unambiguous.
  const plainRegistrar = await harness.createRegistrar({ id: 'plain', role: 'registrar' });

  // GET /admin/operators is the simplest admin-only endpoint to probe.
  const res = await harness.fetch('/admin/operators', {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${plainRegistrar.apiKey}` },
  });

  assert.equal(res.status, 403, 'plain registrar must be 403 on /admin/*');
  const body = await res.json();
  assert.equal(body.error?.code, 'forbidden', 'expected forbidden code');
});

test('BOLA: POST /admin/force-deactivate-agent — admin role denied (super_admin required)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const admin = await harness.createRegistrar({ id: 'admin', role: 'admin' });

  // Target ID can be anything; the role gate fires first and short-circuits
  // before any agent lookup happens.
  const res = await harness.fetch('/admin/force-deactivate-agent/some-axis-id', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${admin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'test' }),
  });

  assert.equal(res.status, 403, 'admin (not super_admin) must be 403 on force-deactivate');
  const body = await res.json();
  assert.equal(body.error?.code, 'forbidden', 'expected forbidden code');
});

test('BOLA: POST /admin/force-revoke-delegation — admin role denied (super_admin required)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const admin = await harness.createRegistrar({ id: 'admin', role: 'admin' });

  const res = await harness.fetch('/admin/force-revoke-delegation/some-delegation-id', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${admin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'test' }),
  });

  assert.equal(res.status, 403, 'admin (not super_admin) must be 403 on force-revoke-delegation');
  const body = await res.json();
  assert.equal(body.error?.code, 'forbidden', 'expected forbidden code');
});

test('BOLA positive control: super_admin CAN access /admin/operators (so matrix isn\'t a universal deny)', async (t) => {
  // The negative matrix above is only meaningful if the gates DO let the
  // right role through. This positive control prevents false-passes where
  // a misconfigured harness denies every request.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  const res = await harness.fetch('/admin/operators', {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${superAdmin.apiKey}` },
  });

  assert.equal(res.status, 200, 'super_admin must access /admin/operators');
});

// =====================================================================
// Delegation + verify-domain BOLA paths (deferred from initial matrix
// pending a read of the route code; now covered).
// =====================================================================

test('BOLA: POST /delegations — registrar B cannot issue delegation on behalf of A\'s agent', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain', domain: 'company-a.example.com', free_slots_total: 3,
  });
  const agentA = await seedAgentForRegistrar(harness, registrarA, operatorA, 'agent-a');

  const res = await harness.fetch('/delegations', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrarB.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      issued_by: agentA.axis_id,                  // A's agent
      issued_to: 'axis:somewhere:downstream',
      root_operator: `axis:${operatorA.id}:operator`,
      scope: ['scope:test'],
      expires: new Date(Date.now() + 3600 * 1000).toISOString(),
    }),
  });

  assert.equal(res.status, 403, 'cross-tenant delegation issue must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');
});

test('BOLA: POST /delegations with parent_credential_id — registrar B cannot chain onto A\'s parent', async (t) => {
  // The check has two halves: (1) issued_by ownership and (2) parent
  // credential ownership. Here we set issued_by to B's own agent (so the
  // first half passes) but parent_credential_id to A's delegation. B
  // should still be denied with 403 not_your_resource on the parent.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain', domain: 'company-a.example.com', free_slots_total: 3,
  });
  const operatorB = await harness.createOperator({
    registrar_id: registrarB.id,
    tier: 'domain', domain: 'company-b.example.com', free_slots_total: 3,
  });
  const agentA = await seedAgentForRegistrar(harness, registrarA, operatorA, 'agent-a');
  const agentB = await seedAgentForRegistrar(harness, registrarB, operatorB, 'agent-b');

  // A creates a delegation (the future parent).
  const parentRes = await harness.fetch('/delegations', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrarA.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      issued_by: agentA.axis_id,
      issued_to: 'axis:downstream:1',
      root_operator: `axis:${operatorA.id}:operator`,
      scope: ['scope:a'],
      expires: new Date(Date.now() + 3600 * 1000).toISOString(),
    }),
  });
  assert.equal(parentRes.status, 201, 'A-side parent delegation must succeed');
  const parent = await parentRes.json();

  // B tries to attach a child credential to A's parent. issued_by points
  // at B's own agent so the first BOLA check passes; the parent check
  // must catch the cross-tenant chain.
  const res = await harness.fetch('/delegations', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrarB.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      issued_by: agentB.axis_id,
      issued_to: 'axis:downstream:2',
      root_operator: `axis:${operatorA.id}:operator`,
      parent_credential_id: parent.id,
      scope: ['scope:a'],
      expires: new Date(Date.now() + 3600 * 1000).toISOString(),
    }),
  });

  assert.equal(res.status, 403, 'cross-tenant parent chain must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');
});

test('BOLA: DELETE /delegations/:id — registrar B cannot revoke registrar A\'s delegation', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain', domain: 'company-a.example.com', free_slots_total: 3,
  });
  const agentA = await seedAgentForRegistrar(harness, registrarA, operatorA, 'agent-a');

  // A creates the delegation.
  const createRes = await harness.fetch('/delegations', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrarA.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      issued_by: agentA.axis_id,
      issued_to: 'axis:downstream:1',
      root_operator: `axis:${operatorA.id}:operator`,
      scope: ['scope:a'],
      expires: new Date(Date.now() + 3600 * 1000).toISOString(),
    }),
  });
  assert.equal(createRes.status, 201, 'A-side delegation must succeed');
  const delegation = await createRes.json();

  // B tries to revoke.
  const res = await harness.fetch(`/delegations/${encodeURIComponent(delegation.id)}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${registrarB.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'malicious' }),
  });

  assert.equal(res.status, 403, 'cross-tenant revoke must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');

  // Delegation should still be active.
  const getRes = await harness.fetch(`/delegations/${encodeURIComponent(delegation.id)}`, {
    method: 'GET',
  });
  const stillThere = await getRes.json();
  assert.equal(stillThere.status, 'active', 'delegation must remain active after denied revoke');
});

test('BOLA: POST /operators/verify-domain — registrar B cannot claim A\'s existing operator', async (t) => {
  // Setup creates A's operator with a known domain. B then calls
  // verify-domain with the same domain — handler must catch the existing
  // operator's registrar_id mismatch and return 403, NOT silently update
  // the row's token (or worse, the registrar_id).
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain', domain: 'shared.example.com', free_slots_total: 3,
  });

  const res = await harness.fetch('/operators/verify-domain', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrarB.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      domain: 'shared.example.com',                          // A's domain
      email: 'b-claimant@elsewhere.example.com',
      method: 'dns_txt',
    }),
  });

  assert.equal(res.status, 403, 'cross-tenant claim must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');
});

test('BOLA: POST /operators/verify-domain/check — registrar B cannot check A\'s pending verification', async (t) => {
  // Edge case: B somehow learns A's verification token. The route must
  // still 403 on the registrar_id mismatch. Setup directly inserts the
  // token into A's operator row so B can attempt the check with a known
  // value.
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const registrarA = await harness.createRegistrar({ id: 'registrar-a' });
  const registrarB = await harness.createRegistrar({ id: 'registrar-b' });
  const operatorA = await harness.createOperator({
    registrar_id: registrarA.id,
    tier: 'domain', domain: 'shared2.example.com', free_slots_total: 3,
  });
  const sharedToken = 'fake-token-known-to-b';
  const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  await harness.db.prepare(
    `UPDATE operators
       SET domain_verification_token = ?, domain_verification_expires = ?, domain_verification_method = 'dns_txt'
       WHERE id = ?`
  ).bind(sharedToken, future, operatorA.id).run();

  const res = await harness.fetch('/operators/verify-domain/check', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrarB.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      domain: 'shared2.example.com',
      token: sharedToken,
    }),
  });

  assert.equal(res.status, 403, 'cross-tenant check must be 403');
  const body = await res.json();
  assert.equal(body.error?.code, 'not_your_resource', 'expected not_your_resource code');
});
