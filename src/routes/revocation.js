/**
 * Revocation Endpoints
 *
 * GET /revocation/:agent_id — Public revocation check (agents)
 * GET /revocation/operator/:operator_id — Public revocation check (operators)
 * DELETE /agents/:agent_id — Deactivate agent (registrar auth required)
 * POST /operators/:id/status — Operator status write / kill switch (registrar auth required)
 * POST /admin/force-deactivate-operator/:id — break-glass operator deactivation (super_admin)
 */

import { findAgent } from './resolve.js';

// operators.status CHECK values (schema.sql). The single source of truth is
// the schema; this mirror exists so the status writer can 400 on anything
// else before touching the database.
const OPERATOR_STATUS_VALUES = ['active', 'suspended', 'deactivated'];

export async function handleRevocation(agentId, env) {
  const agent = await findAgent(agentId, env);
  if (!agent) {
    return {
      status: 404,
      body: { error: { code: 'agent_not_found', message: 'Agent not found' } }
    };
  }

  const revoked = ['revoked', 'deactivated'].includes(agent.status);

  const result = {
    agent_id: agent.axis_id,
    revoked,
    status: agent.status
  };

  if (revoked) {
    result.revoked_at = agent.revoked_at;
    result.reason = agent.revocation_reason;
  }

  return { status: 200, body: result };
}

/**
 * GET /revocation/operator/:operator_id — public operator revocation check.
 *
 * This is the route GET /operators/:id has always advertised as the operator
 * `revocation_url`; before this handler existed the URL fell through into the
 * agent-revocation matcher and 404'd for every operator.
 *
 * `revoked` is true for ANY non-active status, agreeing with the /verify
 * paths (which deny with `operator_revoked` for any non-active operator).
 * Never cached — like the agent revocation check, callers must see status
 * flips on the next request.
 */
export async function handleOperatorRevocation(operatorId, env) {
  const operator = await env.DB.prepare(
    'SELECT id, status, updated_at FROM operators WHERE id = ?'
  ).bind(operatorId).first();
  if (!operator) {
    return {
      status: 404,
      body: { error: { code: 'operator_not_found', message: 'Operator not found' } }
    };
  }

  const revoked = operator.status !== 'active';

  const result = {
    operator_id: operator.id,
    revoked,
    status: operator.status
  };

  if (revoked) {
    // Operators carry no revoked_at/revocation_reason columns (deliberately —
    // no schema change; the audit log is the record of who flipped the status
    // and why). updated_at is the closest persisted signal for "when".
    result.status_changed_at = operator.updated_at;
  }

  return { status: 200, body: result };
}

/**
 * POST /operators/:id/status — the operator kill switch (B1).
 *
 * Registrar-authenticated, BOLA-scoped to the calling registrar's own
 * operators (mirroring DELETE /agents/:id); cross-tenant deactivation is the
 * break-glass POST /admin/force-deactivate-operator/:id. Audited by the
 * caller (index.js) via ctx.waitUntil, matching the normal-path pattern.
 *
 * Enforcement model: no cascade. The /verify paths join operators.status on
 * every decision, so setting a non-active status denies every agent under
 * the operator on the NEXT request, and setting 'active' restores them just
 * as fast. Agent rows are never touched, which is what makes
 * suspend → reactivate lossless.
 *
 * Idempotent by design: re-submitting the current status succeeds (200). A
 * kill switch must never error on a repeat pull.
 */
export async function handleSetOperatorStatus(operatorId, body, registrar, env) {
  if (!registrar) {
    return { status: 401, body: { error: { code: 'unauthorized', message: 'Valid registrar API key required' } } };
  }
  if (!body || !OPERATOR_STATUS_VALUES.includes(body.status)) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: `status must be one of: ${OPERATOR_STATUS_VALUES.join(', ')}` } }
    };
  }

  const operator = await env.DB.prepare(
    'SELECT id, registrar_id, status FROM operators WHERE id = ?'
  ).bind(operatorId).first();
  if (!operator) {
    return { status: 404, body: { error: { code: 'operator_not_found', message: 'Operator not found' } } };
  }
  // BOLA: normal-path mutation is scoped to the caller's own registrar_id,
  // regardless of admin role — same rule as DELETE /agents/:id.
  if (operator.registrar_id !== registrar.id) {
    return { status: 403, body: { error: { code: 'not_your_resource', message: 'Operator belongs to a different registrar' } } };
  }

  const now = new Date().toISOString();
  await env.DB.prepare(
    'UPDATE operators SET status = ?, updated_at = ? WHERE id = ?'
  ).bind(body.status, now, operator.id).run();

  return {
    status: 200,
    body: {
      operator_id: operator.id,
      status: body.status,
      previous_status: operator.status,
      updated_at: now,
      reason: (typeof body.reason === 'string' && body.reason.trim()) ? body.reason : null
    }
  };
}

/**
 * Break-glass: deactivate an operator regardless of ownership. Caller must
 * already have been verified as super_admin, and an audit row must have been
 * written BEFORE calling this (see index.js). Mirrors forceDeactivateAgent.
 *
 * Like the normal-path status writer, there is no cascade: enforcement comes
 * from the /verify operator-status join, next request.
 */
export async function forceDeactivateOperator(operatorId, body, env) {
  const operator = await env.DB.prepare(
    'SELECT id, status FROM operators WHERE id = ?'
  ).bind(operatorId).first();
  if (!operator) {
    return {
      status: 404,
      body: { error: { code: 'operator_not_found', message: 'Operator not found' } }
    };
  }

  if (operator.status === 'deactivated') {
    return {
      status: 400,
      body: { error: { code: 'operator_deactivated', message: 'Operator is already deactivated' } }
    };
  }

  const reason = body.reason || 'admin_force';
  const now = new Date().toISOString();

  await env.DB.prepare(
    'UPDATE operators SET status = ?, updated_at = ? WHERE id = ?'
  ).bind('deactivated', now, operator.id).run();

  return {
    status: 200,
    body: {
      operator_id: operator.id,
      status: 'deactivated',
      previous_status: operator.status,
      deactivatedAt: now,
      forced: true,
      reason
    }
  };
}

export async function handleDeactivateAgent(agentId, body, registrar, env) {
  const agent = await findAgent(agentId, env);
  if (!agent) {
    return {
      status: 404,
      body: { error: { code: 'agent_not_found', message: 'Agent not found' } }
    };
  }

  // BOLA: normal-path mutation MUST be scoped to the caller's own registrar_id,
  // regardless of admin role. Admin+ callers wanting cross-tenant deactivation
  // must use POST /admin/force-deactivate-agent/:agentId (which audits).
  if (agent.registrar_id !== registrar.id) {
    return {
      status: 403,
      body: { error: { code: 'not_your_resource', message: 'Agent belongs to a different registrar' } }
    };
  }

  if (agent.status === 'deactivated') {
    return {
      status: 400,
      body: { error: { code: 'agent_deactivated', message: 'Agent is already deactivated' } }
    };
  }

  const reason = body.reason || 'operator_request';
  const now = new Date().toISOString();

  // Deactivate the agent
  await env.DB.prepare(
    `UPDATE agents SET status = 'deactivated', revoked_at = ?, revocation_reason = ?, updated_at = ?
     WHERE id = ?`
  ).bind(now, reason, now, agent.id).run();

  // Revoke all active delegations from this agent
  const cascadeResult = await env.DB.prepare(
    `UPDATE delegations SET status = 'revoked', revoked_at = ?, revocation_reason = 'agent_deactivated'
     WHERE (issued_by = ? OR issued_by = ?) AND status = 'active'`
  ).bind(now, agent.axis_id, agent.did).run();

  // Update agent slots
  const slotUpdate = agent.registration_tier === 'free'
    ? `UPDATE agent_slots SET free_slots_used = MAX(0, free_slots_used - 1) WHERE operator_id = ?`
    : `UPDATE agent_slots SET paid_agents = MAX(0, paid_agents - 1) WHERE operator_id = ?`;
  await env.DB.prepare(slotUpdate).bind(agent.operator_id).run();

  return {
    status: 200,
    body: {
      did: agent.did,
      axis_id: agent.axis_id,
      status: 'deactivated',
      deactivatedAt: now,
      delegationsRevoked: cascadeResult.meta?.changes || 0
    }
  };
}

/**
 * Break-glass: deactivate an agent regardless of ownership. Caller must
 * already have been verified as super_admin, and an audit row must have
 * been written BEFORE calling this. Skips the ownership check only.
 */
export async function forceDeactivateAgent(agentId, body, env) {
  const agent = await findAgent(agentId, env);
  if (!agent) {
    return {
      status: 404,
      body: { error: { code: 'agent_not_found', message: 'Agent not found' } }
    };
  }

  if (agent.status === 'deactivated') {
    return {
      status: 400,
      body: { error: { code: 'agent_deactivated', message: 'Agent is already deactivated' } }
    };
  }

  const reason = body.reason || 'admin_force';
  const now = new Date().toISOString();

  await env.DB.prepare(
    `UPDATE agents SET status = 'deactivated', revoked_at = ?, revocation_reason = ?, updated_at = ?
     WHERE id = ?`
  ).bind(now, reason, now, agent.id).run();

  const cascadeResult = await env.DB.prepare(
    `UPDATE delegations SET status = 'revoked', revoked_at = ?, revocation_reason = 'agent_deactivated'
     WHERE (issued_by = ? OR issued_by = ?) AND status = 'active'`
  ).bind(now, agent.axis_id, agent.did).run();

  const slotUpdate = agent.registration_tier === 'free'
    ? `UPDATE agent_slots SET free_slots_used = MAX(0, free_slots_used - 1) WHERE operator_id = ?`
    : `UPDATE agent_slots SET paid_agents = MAX(0, paid_agents - 1) WHERE operator_id = ?`;
  await env.DB.prepare(slotUpdate).bind(agent.operator_id).run();

  return {
    status: 200,
    body: {
      did: agent.did,
      axis_id: agent.axis_id,
      status: 'deactivated',
      deactivatedAt: now,
      delegationsRevoked: cascadeResult.meta?.changes || 0,
      forced: true,
      reason
    }
  };
}
