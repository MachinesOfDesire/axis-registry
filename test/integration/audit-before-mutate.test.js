/**
 * Audit-before-mutate matrix — break-glass /admin/force-* endpoints must
 * write the audit row BEFORE performing the mutation, and must abort the
 * mutation if the audit insert fails.
 *
 * Background: normal-path mutations (POST /register, DELETE /agents) write
 * audit rows via `ctx.waitUntil` AFTER the mutation succeeds — this is
 * deliberate (audit-first ordering on hot paths would surface transient
 * D1 hiccups as user-visible 500s). The audit-first ordering is reserved
 * for the break-glass /admin/force-* paths where audit completeness is
 * critical and 500-on-D1-hiccup is acceptable.
 *
 * Coverage:
 *
 *   POST /admin/force-deactivate-agent/:axisId
 *     - Success: audit row inserted with action='force_deactivate_agent',
 *       actor=super_admin.id, target=axisId, registrar_id=super_admin.id,
 *       target_registrar_id=<owning registrar> (H7 hardening).
 *     - Missing target: 404 BEFORE audit row (no-op break-glass not worth
 *       a row).
 *     - Missing reason: 400 BEFORE target lookup or audit row.
 *
 *   POST /admin/force-revoke-delegation/:delegationId
 *     - Success: audit row with action='force_revoke_delegation',
 *       target_registrar_id=<owning registrar>.
 *     - Missing target: 404 BEFORE audit row.
 *     - Missing reason: 400 BEFORE audit row.
 *
 * Audit-write-failure path (force returns 500 audit_write_failed and skips
 * mutation) is not testable without dependency injection on the DB; the
 * pattern is locked into the route handlers by inspection.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

async function countAuditRows(harness, action) {
  const r = await harness.db.prepare(
    'SELECT COUNT(*) as n FROM audit_log WHERE action = ?'
  ).bind(action).first();
  return r?.n || 0;
}

async function getAuditRow(harness, action) {
  return harness.db.prepare(
    'SELECT * FROM audit_log WHERE action = ? ORDER BY timestamp DESC LIMIT 1'
  ).bind(action).first();
}

async function seedAgent(harness, registrar, operator, name = 'victim') {
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
  assert.equal(res.status, 201, 'seed registration must succeed');
  return res.json();
}

async function seedDelegation(harness, registrar, operator, issuedByAxisId) {
  const res = await harness.fetch('/delegations', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      issued_by: issuedByAxisId,
      issued_to: 'axis:downstream:1',
      root_operator: `axis:${operator.id}:operator`,
      scope: ['scope:a'],
      expires: new Date(Date.now() + 3600 * 1000).toISOString(),
    }),
  });
  assert.equal(res.status, 201, 'seed delegation must succeed');
  return res.json();
}

test('Audit: force-deactivate-agent writes audit row with target_registrar_id (H7) on success', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const ownerRegistrar = await harness.createRegistrar({ id: 'owner', role: 'registrar' });
  const operatorA = await harness.createOperator({
    registrar_id: ownerRegistrar.id,
    tier: 'domain', domain: 'company.example.com', free_slots_total: 3,
  });
  const agent = await seedAgent(harness, ownerRegistrar, operatorA);

  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  // Pre-count to assert the row was inserted by THIS call (not by the
  // seeded registration which uses a different action).
  const before = await countAuditRows(harness, 'force_deactivate_agent');

  const res = await harness.fetch(`/admin/force-deactivate-agent/${encodeURIComponent(agent.axis_id)}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${superAdmin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'pre-launch test sweep' }),
  });

  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, 'deactivated');
  assert.equal(body.forced, true);

  // Audit row should be inserted exactly once.
  const after = await countAuditRows(harness, 'force_deactivate_agent');
  assert.equal(after - before, 1, 'exactly one force_deactivate_agent audit row added');

  const auditRow = await getAuditRow(harness, 'force_deactivate_agent');
  assert.equal(auditRow.actor, superAdmin.id, 'actor is the super_admin');
  assert.equal(auditRow.target, agent.axis_id, 'target is the agent axis_id');
  assert.equal(auditRow.registrar_id, superAdmin.id, 'registrar_id is the super_admin');
  assert.equal(
    auditRow.target_registrar_id, ownerRegistrar.id,
    'target_registrar_id matches the owning registrar (H7)',
  );
});

test('Audit: force-deactivate-agent on missing target returns 404 WITHOUT writing audit row', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  const before = await countAuditRows(harness, 'force_deactivate_agent');

  const res = await harness.fetch('/admin/force-deactivate-agent/axis%3Aghost%3Anone', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${superAdmin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'test' }),
  });

  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.error?.code, 'agent_not_found');

  const after = await countAuditRows(harness, 'force_deactivate_agent');
  assert.equal(after, before, 'no audit row written for missing target');
});

test('Audit: force-deactivate-agent missing reason returns 400 BEFORE any lookup or audit', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const ownerRegistrar = await harness.createRegistrar({ id: 'owner', role: 'registrar' });
  const operatorA = await harness.createOperator({
    registrar_id: ownerRegistrar.id,
    tier: 'domain', domain: 'company.example.com', free_slots_total: 3,
  });
  const agent = await seedAgent(harness, ownerRegistrar, operatorA);
  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  const before = await countAuditRows(harness, 'force_deactivate_agent');

  const res = await harness.fetch(`/admin/force-deactivate-agent/${encodeURIComponent(agent.axis_id)}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${superAdmin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),  // no reason
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');

  const after = await countAuditRows(harness, 'force_deactivate_agent');
  assert.equal(after, before, 'no audit row written when reason is missing');
});

test('Audit: force-revoke-delegation writes audit row with target_registrar_id on success', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const ownerRegistrar = await harness.createRegistrar({ id: 'owner', role: 'registrar' });
  const operatorA = await harness.createOperator({
    registrar_id: ownerRegistrar.id,
    tier: 'domain', domain: 'company.example.com', free_slots_total: 3,
  });
  const agent = await seedAgent(harness, ownerRegistrar, operatorA);
  const delegation = await seedDelegation(harness, ownerRegistrar, operatorA, agent.axis_id);

  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  const before = await countAuditRows(harness, 'force_revoke_delegation');

  const res = await harness.fetch(`/admin/force-revoke-delegation/${encodeURIComponent(delegation.id)}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${superAdmin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'spec sweep' }),
  });

  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, 'revoked');
  assert.equal(body.forced, true);

  const after = await countAuditRows(harness, 'force_revoke_delegation');
  assert.equal(after - before, 1, 'exactly one force_revoke_delegation audit row added');

  const auditRow = await getAuditRow(harness, 'force_revoke_delegation');
  assert.equal(auditRow.actor, superAdmin.id);
  assert.equal(auditRow.target, delegation.id);
  assert.equal(auditRow.registrar_id, superAdmin.id);
  assert.equal(
    auditRow.target_registrar_id, ownerRegistrar.id,
    'target_registrar_id matches the owning registrar (H7)',
  );
});

test('Audit: force-revoke-delegation on missing target returns 404 WITHOUT writing audit row', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  const before = await countAuditRows(harness, 'force_revoke_delegation');

  const res = await harness.fetch('/admin/force-revoke-delegation/dc-ghost-none', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${superAdmin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'test' }),
  });

  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.error?.code, 'delegation_not_found');

  const after = await countAuditRows(harness, 'force_revoke_delegation');
  assert.equal(after, before, 'no audit row written for missing target');
});

test('Audit: force-revoke-delegation missing reason returns 400 BEFORE any lookup or audit', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const ownerRegistrar = await harness.createRegistrar({ id: 'owner', role: 'registrar' });
  const operatorA = await harness.createOperator({
    registrar_id: ownerRegistrar.id,
    tier: 'domain', domain: 'company.example.com', free_slots_total: 3,
  });
  const agent = await seedAgent(harness, ownerRegistrar, operatorA);
  const delegation = await seedDelegation(harness, ownerRegistrar, operatorA, agent.axis_id);
  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  const before = await countAuditRows(harness, 'force_revoke_delegation');

  const res = await harness.fetch(`/admin/force-revoke-delegation/${encodeURIComponent(delegation.id)}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${superAdmin.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({}),  // no reason
  });

  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');

  const after = await countAuditRows(harness, 'force_revoke_delegation');
  assert.equal(after, before, 'no audit row written when reason is missing');
});
