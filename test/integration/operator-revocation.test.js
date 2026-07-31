/**
 * Operator-level revocation (B1) — the operator kill switch.
 *
 * Routes under test:
 *
 *   POST /operators/:id/status                  (registrar-authed writer)
 *   POST /admin/force-deactivate-operator/:id   (break-glass, super_admin)
 *   GET  /revocation/operator/:id               (public revocation check —
 *                                                the URL GET /operators/:id
 *                                                advertises as revocation_url)
 *   GET  /verify?token=<AIT>                    (operator-status join)
 *   GET  /verify/:did                           (operator-status join)
 *
 * Enforcement model: no cascade. The /verify paths join operators.status on
 * every decision, so a status flip propagates NEXT REQUEST in both
 * directions — suspend denies, reactivate restores — without touching agent
 * rows. Verify/revocation responses carry no Cache-Control.
 *
 * Coverage:
 *   - Status writer: 401 unauth, 403 cross-registrar (BOLA), 400 bad value,
 *     404 unknown operator, 200 happy path + audit row (waitUntil).
 *   - Operator suspended → AIT verify + /verify/:did deny operator_revoked;
 *     reactivated → allowed next request; deactivated → denied again.
 *   - revocation_url from GET /operators/:id resolves (no more 404) and
 *     reflects status flips; never cached.
 *   - Break-glass: admin role 403, missing reason 400 (no audit row),
 *     success audits BEFORE mutation with target_registrar_id (H7),
 *     already-deactivated 400.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';
import { registerRealAgent, signAIT } from './_helpers.js';

async function setup() {
  const harness = await createHarness();
  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain', domain: 'opkill.example.com', free_slots_total: 3,
  });
  const real = await registerRealAgent(harness, registrar, operator, 'op-kill-agent');
  return { harness, registrar, operator, real };
}

function freshAIT(real) {
  const now = Math.floor(Date.now() / 1000);
  return signAIT(real.keypair, {
    iss: real.axisId, aud: 'platform', iat: now, exp: now + 600,
  });
}

async function setStatus(harness, apiKey, operatorId, body) {
  const res = await harness.fetch(`/operators/${encodeURIComponent(operatorId)}/status`, {
    method: 'POST',
    headers: {
      ...(apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function verifyAIT(harness, token) {
  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  return { status: res.status, body: await res.json(), headers: res.headers };
}

/**
 * Normal-path audit rows are written via ctx.waitUntil AFTER the response;
 * poll briefly so the assertion doesn't race the background write.
 */
async function waitForAuditRow(harness, action, tries = 40) {
  for (let i = 0; i < tries; i++) {
    const row = await harness.db.prepare(
      'SELECT * FROM audit_log WHERE action = ? ORDER BY timestamp DESC LIMIT 1'
    ).bind(action).first();
    if (row) return row;
    await new Promise((r) => setTimeout(r, 25));
  }
  return null;
}

// ---------------------------------------------------------------------------
// Status writer — auth + validation
// ---------------------------------------------------------------------------

test('operator status: unauthenticated POST → 401', async (t) => {
  const { harness, operator } = await setup();
  t.after(() => harness.dispose());

  const res = await setStatus(harness, null, operator.id, { status: 'suspended' });
  assert.equal(res.status, 401);
  assert.equal(res.body.error?.code, 'unauthorized');
});

test('operator status: cross-registrar caller → 403 not_your_resource (BOLA)', async (t) => {
  const { harness, operator } = await setup();
  t.after(() => harness.dispose());

  const other = await harness.createRegistrar({ id: 'other-reg' });
  const res = await setStatus(harness, other.apiKey, operator.id, { status: 'suspended' });
  assert.equal(res.status, 403);
  assert.equal(res.body.error?.code, 'not_your_resource');
});

test('operator status: invalid status value → 400', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const res = await setStatus(harness, registrar.apiKey, operator.id, { status: 'revoked' });
  assert.equal(res.status, 400, 'operators.status has no revoked value; schema CHECK is the vocabulary');
  assert.equal(res.body.error?.code, 'invalid_request');
});

test('operator status: unknown operator → 404', async (t) => {
  const { harness, registrar } = await setup();
  t.after(() => harness.dispose());

  const res = await setStatus(harness, registrar.apiKey, 'op-does-not-exist', { status: 'suspended' });
  assert.equal(res.status, 404);
  assert.equal(res.body.error?.code, 'operator_not_found');
});

test('operator status: owning registrar suspends → 200 + audit row', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const res = await setStatus(harness, registrar.apiKey, operator.id, {
    status: 'suspended', reason: 'compromise investigation',
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'suspended');
  assert.equal(res.body.previous_status, 'active');
  assert.equal(res.body.operator_id, operator.id);

  const row = await waitForAuditRow(harness, 'set_operator_status');
  assert.ok(row, 'set_operator_status audit row must be written');
  assert.equal(row.actor, registrar.id);
  assert.equal(row.target, operator.id);
  assert.equal(row.target_registrar_id, registrar.id);
  const details = JSON.parse(row.details);
  assert.equal(details.from, 'active');
  assert.equal(details.to, 'suspended');
  assert.equal(details.reason, 'compromise investigation');
});

// ---------------------------------------------------------------------------
// Verify joins — the kill switch actually kills (and un-kills)
// ---------------------------------------------------------------------------

test('operator revoked ⇒ AIT verify denied with operator_revoked; reactivated ⇒ allowed next request', async (t) => {
  const { harness, registrar, operator, real } = await setup();
  t.after(() => harness.dispose());

  const token = await freshAIT(real);

  // Baseline: active operator, valid AIT.
  let v = await verifyAIT(harness, token);
  assert.equal(v.status, 200);
  assert.equal(v.body.valid, true, 'baseline verify must pass before the flip');

  // Suspend the operator → deny, next request, reserved code.
  await setStatus(harness, registrar.apiKey, operator.id, { status: 'suspended' });
  v = await verifyAIT(harness, token);
  assert.equal(v.status, 200);
  assert.equal(v.body.valid, false);
  assert.equal(v.body.code, 'operator_revoked');
  assert.equal(v.body.agent_id, real.axisId);
  assert.equal(v.body.operator_status, 'suspended');
  assert.equal(
    v.headers.get('Cache-Control'), null,
    'verify decision path must never carry Cache-Control',
  );

  // Reactivate → allowed on the very next request (no cache in the way).
  await setStatus(harness, registrar.apiKey, operator.id, { status: 'active' });
  v = await verifyAIT(harness, token);
  assert.equal(v.body.valid, true, 'reactivated operator must verify next request');

  // Deactivate → denied again with the same reserved code.
  await setStatus(harness, registrar.apiKey, operator.id, { status: 'deactivated' });
  v = await verifyAIT(harness, token);
  assert.equal(v.body.valid, false);
  assert.equal(v.body.code, 'operator_revoked');
  assert.equal(v.body.operator_status, 'deactivated');
});

test('operator revoked ⇒ GET /verify/:did denied with operator_revoked; agent status untouched', async (t) => {
  const { harness, registrar, operator, real } = await setup();
  t.after(() => harness.dispose());

  await setStatus(harness, registrar.apiKey, operator.id, { status: 'suspended' });

  const res = await harness.fetch(`/verify/${encodeURIComponent(real.did)}`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.verified, false);
  assert.equal(body.code, 'operator_revoked');
  assert.equal(body.status, 'active', 'agent row must NOT be cascaded — enforcement is the join');
  assert.equal(body.operator.status, 'suspended');
  assert.equal(
    res.headers.get('Cache-Control'), null,
    'verify decision path must never carry Cache-Control',
  );

  // Reactivate → verified again next request, and no agent state was lost.
  await setStatus(harness, registrar.apiKey, operator.id, { status: 'active' });
  const res2 = await harness.fetch(`/verify/${encodeURIComponent(real.did)}`);
  const body2 = await res2.json();
  assert.equal(body2.verified, true);
  assert.equal(body2.code, undefined, 'no deny code on the allowed path');
});

// ---------------------------------------------------------------------------
// revocation_url — the advertised URL must actually resolve
// ---------------------------------------------------------------------------

test('advertised operator revocation_url resolves and reflects status flips', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  // Read the advertised URL from GET /operators/:id (the record readers see).
  const opRes = await harness.fetch(`/operators/${encodeURIComponent(operator.id)}`);
  assert.equal(opRes.status, 200);
  const opBody = await opRes.json();
  assert.ok(opBody.revocation_url, 'operator record must advertise a revocation_url');
  const revPath = new URL(opBody.revocation_url).pathname;

  // Active operator: resolves (this 404'd before B1), not revoked.
  let res = await harness.fetch(revPath);
  assert.equal(res.status, 200, `advertised revocation_url must resolve (path: ${revPath})`);
  let body = await res.json();
  assert.equal(body.operator_id, operator.id);
  assert.equal(body.revoked, false);
  assert.equal(body.status, 'active');
  assert.equal(
    res.headers.get('Cache-Control'), null,
    'revocation check must never carry Cache-Control',
  );

  // Suspend → revoked:true on the same URL, next request.
  await setStatus(harness, registrar.apiKey, operator.id, { status: 'suspended' });
  res = await harness.fetch(revPath);
  body = await res.json();
  assert.equal(body.revoked, true, 'any non-active status counts as revoked, agreeing with /verify');
  assert.equal(body.status, 'suspended');
});

test('GET /revocation/operator/:id for unknown operator → 404 operator_not_found', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/revocation/operator/op-ghost');
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.error?.code, 'operator_not_found');
});

// ---------------------------------------------------------------------------
// Break-glass — /admin/force-deactivate-operator/:id
// ---------------------------------------------------------------------------

async function forceDeactivate(harness, apiKey, operatorId, body) {
  const res = await harness.fetch(`/admin/force-deactivate-operator/${encodeURIComponent(operatorId)}`, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  return { status: res.status, body: await res.json() };
}

test('break-glass operator deactivation: admin role is NOT enough → 403', async (t) => {
  const { harness, operator } = await setup();
  t.after(() => harness.dispose());

  const admin = await harness.createRegistrar({ id: 'admin-reg', role: 'admin' });
  const res = await forceDeactivate(harness, admin.apiKey, operator.id, { reason: 'nope' });
  assert.equal(res.status, 403);
  assert.equal(res.body.error?.code, 'forbidden');
});

test('break-glass operator deactivation: missing reason → 400, no audit row', async (t) => {
  const { harness, operator } = await setup();
  t.after(() => harness.dispose());

  const superAdmin = await harness.createRegistrar({ id: 'super-reg', role: 'super_admin' });
  const res = await forceDeactivate(harness, superAdmin.apiKey, operator.id, {});
  assert.equal(res.status, 400);
  assert.equal(res.body.error?.code, 'invalid_request');

  const count = await harness.db.prepare(
    "SELECT COUNT(*) as n FROM audit_log WHERE action = 'force_deactivate_operator'"
  ).first();
  assert.equal(count.n, 0, 'a rejected break-glass call must not write an audit row');
});

test('break-glass operator deactivation: success audits with target_registrar_id and kills verify', async (t) => {
  const { harness, registrar, operator, real } = await setup();
  t.after(() => harness.dispose());

  const superAdmin = await harness.createRegistrar({ id: 'super-reg', role: 'super_admin' });
  const res = await forceDeactivate(harness, superAdmin.apiKey, operator.id, {
    reason: 'terms violation',
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'deactivated');
  assert.equal(res.body.forced, true);

  // Break-glass writes the audit row inline BEFORE the mutation — no polling
  // needed, it must already be there.
  const row = await harness.db.prepare(
    "SELECT * FROM audit_log WHERE action = 'force_deactivate_operator' ORDER BY timestamp DESC LIMIT 1"
  ).first();
  assert.ok(row, 'break-glass must write an audit row');
  assert.equal(row.actor, superAdmin.id);
  assert.equal(row.target, operator.id);
  assert.equal(row.registrar_id, superAdmin.id);
  assert.equal(row.target_registrar_id, registrar.id, 'H7: owning registrar recorded as target');
  assert.equal(JSON.parse(row.details).reason, 'terms violation');

  // The kill switch kills: agent verify denied next request.
  const token = await freshAIT(real);
  const v = await verifyAIT(harness, token);
  assert.equal(v.body.valid, false);
  assert.equal(v.body.code, 'operator_revoked');

  // Repeat break-glass on an already-deactivated operator → 400.
  const again = await forceDeactivate(harness, superAdmin.apiKey, operator.id, { reason: 'again' });
  assert.equal(again.status, 400);
  assert.equal(again.body.error?.code, 'operator_deactivated');
});

test('break-glass operator deactivation: unknown operator → 404 before audit', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const superAdmin = await harness.createRegistrar({ id: 'super-reg', role: 'super_admin' });
  const res = await forceDeactivate(harness, superAdmin.apiKey, 'op-ghost', { reason: 'x' });
  assert.equal(res.status, 404);

  const count = await harness.db.prepare(
    "SELECT COUNT(*) as n FROM audit_log WHERE action = 'force_deactivate_operator'"
  ).first();
  assert.equal(count.n, 0, 'no-op break-glass on a missing resource is not worth a row');
});
