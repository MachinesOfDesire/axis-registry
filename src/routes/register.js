/**
 * Registration Endpoint
 * Registrar-authenticated. Registrars submit agent registrations on behalf of operators.
 *
 * POST /register
 */

import { deriveAgentId, verifyEd25519Signature, generateToken, base64urlToBytes, bytesToBase58 } from '../utils/crypto.js';

export async function handleRegister(body, registrar, env) {
  // Validate required fields
  if (!body.publicKey) {
    return { status: 400, body: { error: { code: 'invalid_request', message: 'Missing required field: publicKey' } } };
  }
  if (!body.operator || (!body.operator.domain && !body.operator.email)) {
    return { status: 400, body: { error: { code: 'invalid_request', message: 'Missing required field: operator.domain or operator.email' } } };
  }

  // Find or validate the operator
  const operatorId = body.operator.domain
    ? body.operator.domain.replace(/\./g, '-')
    : body.operator.email.split('@')[0] + '-' + generateToken(4);

  let operator = await env.DB.prepare(
    'SELECT * FROM operators WHERE id = ? OR domain = ? OR email = ?'
  ).bind(operatorId, body.operator.domain || '', body.operator.email || '').first();

  if (!operator) {
    return {
      status: 403,
      body: { error: { code: 'operator_not_found', message: 'Operator must be registered and verified before registering agents. Use /operators/verify-domain first.' } }
    };
  }

  // Check operator status
  if (operator.status !== 'active') {
    return {
      status: 403,
      body: { error: { code: 'operator_not_verified', message: `Operator status: ${operator.status}` } }
    };
  }

  // Check domain verification for domain-verified tier
  if (operator.verification_tier === 'domain' && !operator.domain_verified) {
    return {
      status: 403,
      body: { error: { code: 'domain_not_verified', message: 'Domain verification required. Complete domain verification first.' } }
    };
  }

  // Check agent slot availability
  const slots = await env.DB.prepare(
    'SELECT * FROM agent_slots WHERE operator_id = ?'
  ).bind(operator.id).first();

  if (!slots) {
    return { status: 500, body: { error: { code: 'internal_error', message: 'Agent slot record not found for operator' } } };
  }

  // Determine if this agent is free or paid
  const freeAvailable = slots.free_slots_used < slots.free_slots_total;
  const tier = freeAvailable ? 'free' : 'paid';

  // Check max agent limits (email tier: 5 max)
  if (slots.max_agents !== null) {
    const totalAgents = slots.free_slots_used + slots.paid_agents;
    if (totalAgents >= slots.max_agents) {
      return {
        status: 403,
        body: { error: { code: 'slot_limit_reached', message: `Maximum ${slots.max_agents} agents reached for this account tier` } }
      };
    }
  }

  // Derive agent ID from public key
  let agentIdHash;
  try {
    agentIdHash = await deriveAgentId(body.publicKey);
  } catch (err) {
    console.error('deriveAgentId error:', err);
    return { status: 400, body: { error: { code: 'invalid_key', message: `Failed to process public key: ${err.message}` } } };
  }
  const agentName = body.metadata?.name || agentIdHash;
  const agentId = agentName.toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const axisId = `axis:${operator.id}:${agentId}`;
  const did = `did:axis:prime:${agentId}`;

  // Check for collisions
  const existing = await env.DB.prepare(
    'SELECT id FROM agents WHERE axis_id = ? OR did = ?'
  ).bind(axisId, did).first();

  if (existing) {
    return {
      status: 409,
      body: { error: { code: 'agent_already_exists', message: `Agent ID collision: ${axisId}` } }
    };
  }

  // Verify proof of key ownership (if proof provided)
  if (body.proof) {
    // The client signs a canonical JSON of the request body (minus the proof field)
    const proofInput = { ...body };
    delete proofInput.proof;
    const canonical = JSON.stringify(proofInput, Object.keys(proofInput).sort());

    const proofValid = await verifyEd25519Signature(
      body.publicKey,
      canonical,
      body.proof.proofValue
    );

    if (!proofValid) {
      return {
        status: 400,
        body: { error: { code: 'invalid_proof', message: 'Proof of key ownership verification failed' } }
      };
    }
  }

  const now = new Date().toISOString();

  // Insert the agent
  await env.DB.prepare(
    `INSERT INTO agents (id, axis_id, did, operator_id, display_name, description, public_key, key_algorithm, status, registration_tier, registrar_id, service_endpoints, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'Ed25519', 'active', ?, ?, ?, ?, ?)`
  ).bind(
    agentId,
    axisId,
    did,
    operator.id,
    body.metadata?.name || agentId,
    body.metadata?.description || null,
    body.publicKey,
    tier,
    registrar.id,
    body.service ? JSON.stringify(body.service) : null,
    now,
    now
  ).run();

  // Update agent slots
  if (tier === 'free') {
    await env.DB.prepare(
      'UPDATE agent_slots SET free_slots_used = free_slots_used + 1 WHERE operator_id = ?'
    ).bind(operator.id).run();
  } else {
    await env.DB.prepare(
      'UPDATE agent_slots SET paid_agents = paid_agents + 1 WHERE operator_id = ?'
    ).bind(operator.id).run();
  }

  // Build response
  return {
    status: 201,
    body: {
      did,
      axis_id: axisId,
      document: {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1',
          'https://axis-protocol.org/ns/v1'
        ],
        id: did,
        controller: did,
        verificationMethod: [{
          id: `${did}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyMultibase: `z${bytesToBase58(base64urlToBytes(body.publicKey))}`
        }],
        authentication: [`${did}#key-1`],
        assertionMethod: [`${did}#key-1`],
        axisMetadata: {
          registered: now,
          registry: 'prime',
          operator: {
            id: operator.id,
            domain: operator.domain,
            verified: Boolean(operator.domain_verified)
          },
          status: 'active'
        }
      },
      registrationReceipt: {
        registry: 'prime',
        timestamp: now,
        agentSlot: {
          used: (tier === 'free' ? slots.free_slots_used + 1 : slots.free_slots_used) + (tier === 'paid' ? slots.paid_agents + 1 : slots.paid_agents),
          free: slots.free_slots_total - (tier === 'free' ? slots.free_slots_used + 1 : slots.free_slots_used),
          operator_verification_tier: operator.verification_tier
        }
      }
    }
  };
}
