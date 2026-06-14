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
      body: { error: { code: 'agent_not_found', message: 'Agent not found' } }
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

    // H1 (2026-05-11 locked decision): require non-empty `aud` claim.
    // Per spec intent, an AIT proves "the agent chose to interact with
    // this platform" — without aud, a single leaked AIT becomes a
    // universal presentation-layer key until expiry. The registry now
    // refuses to validate AITs that omit aud. For v0.1.3 we accept any
    // non-empty string (platforms self-identify); registry-managed
    // platform allowlists are deferred to v0.2.
    if (!payload.aud || typeof payload.aud !== 'string' || payload.aud.trim() === '') {
      return {
        status: 400,
        body: { error: { code: 'missing_aud', message: 'AIT payload must include a non-empty `aud` (audience) claim' } }
      };
    }

    // Find the agent
    const agentId = payload.iss || payload.sub;
    const agent = await findAgent(agentId, env);
    if (!agent) {
      return {
        status: 404,
        body: { error: { code: 'agent_not_found', message: 'Agent not found' } }
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
          code: 'invalid_signature',
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
          code: 'token_expired',
          agent_id: agent.axis_id,
          reason: 'Token expired',
          expired_at: new Date(payload.exp * 1000).toISOString()
        }
      };
    }

    // Check agent status
    if (agent.status !== 'active') {
      // Map agent status to a stable error code consumers can branch on.
      // revoked / deactivated both surface as 'agent_revoked' (callers
      // treat them identically — the agent is no longer usable). suspended
      // gets its own code in case callers want to distinguish "temporary
      // hold" from "permanent revocation".
      const code = (agent.status === 'revoked' || agent.status === 'deactivated')
        ? 'agent_revoked'
        : 'agent_suspended';
      return {
        status: 200,
        body: {
          valid: false,
          code,
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
    // v0.2 §4.3: the delegation the agent is acting under is carried in the
    // `dlg` claim (credential_id). v0.1 drafts used `delegation_id`; accept it
    // as a fallback so legacy tokens still resolve. Surface both keys: `dlg`
    // is canonical, `delegation_id` is retained for existing consumers
    // (Governor, comments worker) until they migrate.
    const dlg = payload.dlg || payload.delegation_id || null;
    return {
      status: 200,
      body: {
        valid: true,
        agent_id: agent.axis_id,
        operator_id: `axis:${agent.operator_id}:operator`,
        status: agent.status,
        expires_at: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
        dlg,
        delegation_id: dlg,
        scope: payload.scope || null
      }
    };

  } catch (err) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Failed to decode token' } }
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
      body: { error: { code: 'agent_not_found', message: 'Agent not found' } }
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
