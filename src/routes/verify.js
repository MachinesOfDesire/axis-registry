/**
 * Verification Endpoints
 * Public, free, unlimited, no auth required.
 *
 * GET /verify/:did — Verify agent identity
 * GET /verify?token=<AIT> — Verify AXIS Identity Token
 * POST /verify/signature — Verify a message signature
 */

import { findAgent } from './resolve.js';
import { verifyEd25519Signature } from '../utils/crypto.js';

export async function handleVerifyIdentity(identifier, env) {
  const agent = await findAgent(identifier, env);
  if (!agent) {
    return {
      status: 404,
      body: { error: { code: 'agent_not_found', message: `Agent not found: ${identifier}` } }
    };
  }

  // Get operator info
  const operator = await env.DB.prepare(
    'SELECT domain, domain_verified, operator_did FROM operators WHERE id = ?'
  ).bind(agent.operator_id).first();

  return {
    status: 200,
    body: {
      verified: agent.status === 'active',
      did: agent.did,
      axis_id: agent.axis_id,
      status: agent.status,
      operator: {
        domain: operator?.domain || null,
        verified: Boolean(operator?.domain_verified)
      },
      registered: agent.created_at,
      verifiedAt: new Date().toISOString()
    }
  };
}

export async function handleVerifyAIT(token, env) {
  try {
    // Decode JWT (header.payload.signature)
    const parts = token.split('.');
    if (parts.length !== 3) {
      return {
        status: 400,
        body: { error: { code: 'invalid_request', message: 'Invalid token format — expected JWT (header.payload.signature)' } }
      };
    }

    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    // Validate header
    if (header.typ !== 'AIT' || header.alg !== 'EdDSA') {
      return {
        status: 400,
        body: { error: { code: 'invalid_request', message: 'Token must be type AIT with EdDSA algorithm' } }
      };
    }

    // Find the agent
    const agentId = payload.iss || payload.sub;
    const agent = await findAgent(agentId, env);
    if (!agent) {
      return {
        status: 404,
        body: { error: { code: 'agent_not_found', message: `Agent not found: ${agentId}` } }
      };
    }

    // Verify signature
    const signedContent = `${parts[0]}.${parts[1]}`;
    const signatureValid = await verifyEd25519Signature(
      agent.public_key,
      signedContent,
      parts[2]
    );

    if (!signatureValid) {
      return {
        status: 200,
        body: {
          valid: false,
          agent_id: agent.axis_id,
          reason: 'Invalid signature'
        }
      };
    }

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return {
        status: 200,
        body: {
          valid: false,
          agent_id: agent.axis_id,
          reason: 'Token expired',
          expired_at: new Date(payload.exp * 1000).toISOString()
        }
      };
    }

    // Check agent status
    if (agent.status !== 'active') {
      return {
        status: 200,
        body: {
          valid: false,
          agent_id: agent.axis_id,
          reason: `Agent status: ${agent.status}`,
          status: agent.status
        }
      };
    }

    // operator_id is authoritative from the agent's row, not the AIT payload.
    // The payload's `iss` carries the agent id; the agent's operator linkage
    // is fixed at registration. Return canonical `axis:{slug}:operator` form
    // so consumers (comments workers, audit pipelines) can rely on it.
    return {
      status: 200,
      body: {
        valid: true,
        agent_id: agent.axis_id,
        operator_id: `axis:${agent.operator_id}:operator`,
        status: agent.status,
        expires_at: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
        delegation_id: payload.delegation_id || null,
        scope: payload.scope || null
      }
    };

  } catch (err) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Failed to decode token: ' + err.message } }
    };
  }
}

export async function handleVerifySignature(body, env) {
  const { did, message, signature, verificationMethod } = body;

  if (!did || !message || !signature) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Missing required fields: did, message, signature' } }
    };
  }

  const agent = await findAgent(did, env);
  if (!agent) {
    return {
      status: 404,
      body: { error: { code: 'agent_not_found', message: `Agent not found: ${did}` } }
    };
  }

  const valid = await verifyEd25519Signature(agent.public_key, message, signature);

  return {
    status: 200,
    body: {
      valid,
      did: agent.did,
      verificationMethod: verificationMethod || `${agent.did}#key-1`,
      algorithm: 'Ed25519',
      verifiedAt: new Date().toISOString()
    }
  };
}
