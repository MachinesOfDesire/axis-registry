/**
 * Delegation Endpoints
 *
 * GET /delegations/:id — Public, get a delegation record
 * GET /delegations/:agent_id/chain — Public, verify delegation chain
 * POST /delegations — Registrar-authenticated, create delegation
 * DELETE /delegations/:id — Registrar-authenticated, revoke delegation
 */

import { findAgent } from './resolve.js';
import { generateCredentialId } from '../utils/crypto.js';

// M5: cap on how far in the future a delegation's `expires` can sit.
// Defeats the "100-year delegation" pattern that destroys revocation hygiene.
// 90 days is the launch default; once tier-aware policy lands, KYB tiers
// should be allowed a longer ceiling (e.g. 365 days). For now: one number.
const MAX_DELEGATION_HORIZON_MS = 90 * 24 * 60 * 60 * 1000;

export async function handleGetDelegation(delegationId, env) {
  const delegation = await env.DB.prepare(
    'SELECT * FROM delegations WHERE id = ?'
  ).bind(delegationId).first();

  if (!delegation) {
    return {
      status: 404,
      body: { error: { code: 'delegation_not_found', message: `Delegation not found: ${delegationId}` } }
    };
  }

  return {
    status: 200,
    body: formatDelegation(delegation)
  };
}

export async function handleVerifyChain(agentIdentifier, env) {
  // Find all delegations where this agent is the delegatee
  const agent = await findAgent(agentIdentifier, env);
  if (!agent) {
    return {
      status: 404,
      body: { error: { code: 'agent_not_found', message: `Agent not found: ${agentIdentifier}` } }
    };
  }

  // Walk the chain from this agent back to root
  const chain = [];
  let currentId = agent.axis_id;
  let currentDid = agent.did;
  let chainValid = true;
  let rootOperator = null;
  const visited = new Set();

  while (true) {
    // Find delegation where issued_to is the current agent
    const delegation = await env.DB.prepare(
      `SELECT * FROM delegations
       WHERE (issued_to = ? OR issued_to = ?) AND status = 'active'
       ORDER BY created_at DESC LIMIT 1`
    ).bind(currentId, currentDid).first();

    if (!delegation) break; // reached root or no delegations

    // Circular reference check
    if (visited.has(delegation.id)) {
      chainValid = false;
      break;
    }
    visited.add(delegation.id);

    // Check root_operator consistency
    if (rootOperator === null) {
      rootOperator = delegation.root_operator;
    } else if (delegation.root_operator !== rootOperator) {
      chainValid = false;
    }

    // Check scope attenuation (each link must be equal or narrower than parent)
    const scope = JSON.parse(delegation.scope);
    if (delegation.parent_credential_id && chain.length > 0) {
      const parentScope = JSON.parse(chain[chain.length - 1].scope);
      const scopeValid = scope.every(s => parentScope.includes(s));
      if (!scopeValid) chainValid = false;
    }

    // Check expiry
    const expired = new Date(delegation.expires_at) < new Date();
    if (expired) chainValid = false;

    // Check max_sub_delegation_depth
    const constraints = delegation.constraints ? JSON.parse(delegation.constraints) : {};
    if (constraints.max_sub_delegation_depth !== undefined && constraints.max_sub_delegation_depth < 0) {
      chainValid = false;
    }

    chain.push({
      delegation: delegation.id,
      from: delegation.issued_by,
      to: delegation.issued_to,
      scope: scope,
      signatureValid: true, // TODO: actual signature verification
      expired,
      status: delegation.status
    });

    // Move up the chain
    currentId = delegation.issued_by;
    currentDid = delegation.issued_by; // may or may not be a DID
  }

  // Get root operator info
  let rootOperatorInfo = null;
  if (rootOperator) {
    const operatorNamespace = rootOperator.replace('axis:', '').replace(':operator', '');
    const operator = await env.DB.prepare(
      'SELECT domain, domain_verified FROM operators WHERE id = ?'
    ).bind(operatorNamespace).first();
    if (operator) {
      rootOperatorInfo = { domain: operator.domain, verified: Boolean(operator.domain_verified) };
    }
  }

  return {
    status: 200,
    body: {
      agent: agent.did,
      axis_id: agent.axis_id,
      chainValid,
      chainDepth: chain.length,
      chain,
      rootOperator: rootOperatorInfo,
      verifiedAt: new Date().toISOString()
    }
  };
}

export async function handleCreateDelegation(body, registrar, env) {
  // Per AXIS Protocol Spec v0.1 §4.4, the canonical Delegation Credential
  // timestamp fields are `created` and `expires`. Maps to the `expires_at`
  // DB column.
  const { issued_by, issued_to, root_operator, parent_credential_id, scope, constraints, expires } = body;

  // Validate required fields
  if (!issued_by || !issued_to || !root_operator || !scope || !expires) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Missing required fields: issued_by, issued_to, root_operator, scope, expires' } }
    };
  }

  // M5: enforce max horizon on `expires`. Unbounded `expires` lets callers
  // mint effectively immortal delegations and defeats revocation hygiene.
  const expiresMs = Date.parse(expires);
  if (Number.isNaN(expiresMs)) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'expires must be a valid ISO-8601 datetime' } }
    };
  }
  const nowMs = Date.now();
  if (expiresMs <= nowMs) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'expires must be in the future' } }
    };
  }
  if (expiresMs - nowMs > MAX_DELEGATION_HORIZON_MS) {
    return {
      status: 400,
      body: { error: { code: 'expires_too_far', message: `expires cannot be more than ${MAX_DELEGATION_HORIZON_MS / (24 * 60 * 60 * 1000)} days in the future` } }
    };
  }

  // BOLA: the entity on whose behalf the delegation is issued must belong to
  // the calling registrar. `issued_by` can be an agent AXIS ID/DID or an
  // operator-scoped identifier (e.g. axis:{operator}:operator). Look in both
  // tables. Admin+ follows the same rule on this normal path.
  let issuerRegistrarId = null;

  const issuerAgent = await env.DB.prepare(
    'SELECT registrar_id FROM agents WHERE axis_id = ? OR did = ? OR id = ?'
  ).bind(issued_by, issued_by, issued_by).first();
  if (issuerAgent) {
    issuerRegistrarId = issuerAgent.registrar_id;
  } else {
    // Try operator lookup. Operator identifiers look like "axis:{opId}:..." —
    // fall back to matching the namespace segment against operators.id, or a
    // bare operator id.
    const parts = issued_by.split(':');
    const opCandidate = parts.length >= 2 && parts[0] === 'axis' ? parts[1] : issued_by;
    const issuerOperator = await env.DB.prepare(
      'SELECT registrar_id FROM operators WHERE id = ?'
    ).bind(opCandidate).first();
    if (issuerOperator) {
      issuerRegistrarId = issuerOperator.registrar_id;
    }
  }

  if (issuerRegistrarId === null) {
    return {
      status: 404,
      body: { error: { code: 'agent_not_found', message: `issued_by not found as agent or operator: ${issued_by}` } }
    };
  }
  if (issuerRegistrarId !== registrar.id) {
    return {
      status: 403,
      body: { error: { code: 'not_your_resource', message: 'issued_by belongs to a different registrar' } }
    };
  }

  // If there's a parent credential, the caller must also own that delegation
  // (you can't tack a child onto someone else's chain).
  if (parent_credential_id) {
    const parentOwn = await env.DB.prepare(
      'SELECT registrar_id FROM delegations WHERE id = ?'
    ).bind(parent_credential_id).first();
    if (parentOwn && parentOwn.registrar_id !== registrar.id) {
      return {
        status: 403,
        body: { error: { code: 'not_your_resource', message: 'parent_credential_id belongs to a different registrar' } }
      };
    }
  }

  // Validate scope is an array
  if (!Array.isArray(scope)) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'scope must be an array of strings' } }
    };
  }

  // If parent credential exists, validate attenuation
  if (parent_credential_id) {
    const parent = await env.DB.prepare(
      'SELECT * FROM delegations WHERE id = ? AND status = ?'
    ).bind(parent_credential_id, 'active').first();

    if (!parent) {
      return {
        status: 400,
        body: { error: { code: 'delegation_not_found', message: `Parent credential not found or not active: ${parent_credential_id}` } }
      };
    }

    // Check root_operator consistency
    if (parent.root_operator !== root_operator) {
      return {
        status: 400,
        body: { error: { code: 'delegation_chain_invalid', message: 'root_operator must be identical to parent credential' } }
      };
    }

    // Check scope attenuation
    const parentScope = JSON.parse(parent.scope);
    const scopeValid = scope.every(s => parentScope.includes(s));
    if (!scopeValid) {
      return {
        status: 400,
        body: { error: { code: 'delegation_chain_invalid', message: 'Scope must be equal to or narrower than parent credential scope (attenuation rule)' } }
      };
    }

    // Check max_sub_delegation_depth
    const parentConstraints = parent.constraints ? JSON.parse(parent.constraints) : {};
    if (parentConstraints.max_sub_delegation_depth !== undefined) {
      if (parentConstraints.max_sub_delegation_depth <= 0) {
        return {
          status: 400,
          body: { error: { code: 'delegation_chain_invalid', message: 'Parent credential does not allow further sub-delegation (max_sub_delegation_depth = 0)' } }
        };
      }
      // Decrement depth for the new credential
      if (!constraints) body.constraints = {};
      if (!constraints?.max_sub_delegation_depth) {
        body.constraints = { ...constraints, max_sub_delegation_depth: parentConstraints.max_sub_delegation_depth - 1 };
      }
    }
  }

  // Generate credential ID
  const namespace = issued_by.split(':')[1] || 'prime';
  const credentialId = generateCredentialId('dc', namespace);

  const now = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO delegations (id, issued_by, issued_to, root_operator, parent_credential_id, scope, constraints, created_at, expires_at, revocable, status, proof, registrar_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`
  ).bind(
    credentialId,
    issued_by,
    issued_to,
    root_operator,
    parent_credential_id || null,
    JSON.stringify(scope),
    constraints ? JSON.stringify(constraints) : null,
    now,
    expires,
    body.revocable !== false ? 1 : 0,
    body.proof ? JSON.stringify(body.proof) : '{}',
    registrar.id
  ).run();

  const created = await env.DB.prepare(
    'SELECT * FROM delegations WHERE id = ?'
  ).bind(credentialId).first();

  return {
    status: 201,
    body: formatDelegation(created)
  };
}

export async function handleRevokeDelegation(delegationId, body, registrar, env) {
  const delegation = await env.DB.prepare(
    'SELECT * FROM delegations WHERE id = ?'
  ).bind(delegationId).first();

  if (!delegation) {
    return {
      status: 404,
      body: { error: { code: 'delegation_not_found', message: `Delegation not found: ${delegationId}` } }
    };
  }

  // BOLA: only the owning registrar can revoke via this endpoint. Admin+
  // callers must use POST /admin/force-revoke-delegation/:delegationId.
  if (delegation.registrar_id !== registrar.id) {
    return {
      status: 403,
      body: { error: { code: 'not_your_resource', message: 'Delegation belongs to a different registrar' } }
    };
  }

  if (delegation.status === 'revoked') {
    return {
      status: 400,
      body: { error: { code: 'delegation_revoked', message: 'Delegation is already revoked' } }
    };
  }

  const now = new Date().toISOString();
  const reason = body.reason || 'operator_request';

  // Revoke this delegation
  await env.DB.prepare(
    `UPDATE delegations SET status = 'revoked', revoked_at = ?, revocation_reason = ? WHERE id = ?`
  ).bind(now, reason, delegationId).run();

  // Cascade: revoke all downstream delegations
  const cascadeResult = await cascadeRevoke(delegationId, now, reason, env);

  return {
    status: 200,
    body: {
      delegationId,
      status: 'revoked',
      revokedAt: now,
      cascadeRevoked: cascadeResult
    }
  };
}

/**
 * Break-glass: revoke a delegation regardless of ownership. Caller must
 * already be verified as super_admin and an audit row must have been
 * written BEFORE calling this. Skips the ownership check only.
 */
export async function forceRevokeDelegation(delegationId, body, env) {
  const delegation = await env.DB.prepare(
    'SELECT * FROM delegations WHERE id = ?'
  ).bind(delegationId).first();

  if (!delegation) {
    return {
      status: 404,
      body: { error: { code: 'delegation_not_found', message: `Delegation not found: ${delegationId}` } }
    };
  }

  if (delegation.status === 'revoked') {
    return {
      status: 400,
      body: { error: { code: 'delegation_revoked', message: 'Delegation is already revoked' } }
    };
  }

  const now = new Date().toISOString();
  const reason = body.reason || 'admin_force';

  await env.DB.prepare(
    `UPDATE delegations SET status = 'revoked', revoked_at = ?, revocation_reason = ? WHERE id = ?`
  ).bind(now, reason, delegationId).run();

  const cascadeResult = await cascadeRevoke(delegationId, now, reason, env);

  return {
    status: 200,
    body: {
      delegationId,
      status: 'revoked',
      revokedAt: now,
      cascadeRevoked: cascadeResult,
      forced: true,
      reason
    }
  };
}

// M3: hard cap on cascade traversal depth to bound worst-case CPU on a
// malicious or accidentally cyclic delegation graph. 16 levels is well past
// any realistic delegation chain (in practice chains are 2-4 deep).
const CASCADE_MAX_DEPTH = 16;

async function cascadeRevoke(parentId, timestamp, reason, env, visited = new Set(), depth = 0) {
  // M3: bail on depth limit. Anything deeper than CASCADE_MAX_DEPTH levels
  // gets left active — this is a defensive cap, not a correctness invariant.
  // If we ever hit this in practice we want to know, so log structured.
  if (depth >= CASCADE_MAX_DEPTH) {
    console.warn(JSON.stringify({
      tag: 'CASCADE_DEPTH_CAP_HIT',
      message: 'cascadeRevoke stopped at depth cap',
      parent_id: parentId,
      depth,
      max_depth: CASCADE_MAX_DEPTH,
    }));
    return 0;
  }

  // M3: cycle break. The delegations table has a self-referencing FK so
  // cycles shouldn't be possible via the normal /delegations create path
  // (which enforces an acyclic parent chain), but the cap defends against
  // any drift that creates a cycle.
  if (visited.has(parentId)) return 0;
  visited.add(parentId);

  // Find all active delegations that have this as parent
  const children = await env.DB.prepare(
    `SELECT id FROM delegations WHERE parent_credential_id = ? AND status = 'active'`
  ).bind(parentId).all();

  let count = 0;
  if (children.results) {
    for (const child of children.results) {
      await env.DB.prepare(
        `UPDATE delegations SET status = 'revoked', revoked_at = ?, revocation_reason = ? WHERE id = ?`
      ).bind(timestamp, `cascade:${reason}`, child.id).run();
      count++;
      // Recurse with the shared visited set + incremented depth.
      count += await cascadeRevoke(child.id, timestamp, reason, env, visited, depth + 1);
    }
  }
  return count;
}

function formatDelegation(d) {
  return {
    axis_version: '0.1',
    type: 'DelegationCredential',
    id: d.id,
    issued_by: d.issued_by,
    issued_to: d.issued_to,
    root_operator: d.root_operator,
    parent_credential_id: d.parent_credential_id,
    scope: JSON.parse(d.scope),
    constraints: d.constraints ? JSON.parse(d.constraints) : {},
    created: d.created_at,
    expires: d.expires_at,
    revocable: Boolean(d.revocable),
    status: d.status,
    proof: d.proof ? JSON.parse(d.proof) : {}
  };
}
