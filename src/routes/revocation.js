/**
 * Revocation Endpoints
 *
 * GET /revocation/:agent_id — Public revocation check
 * DELETE /agents/:agent_id — Deactivate agent (registrar auth required)
 */

import { findAgent } from './resolve.js';

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
