/**
 * Resolution Endpoints
 * Public, free, unlimited, no auth required.
 *
 * GET /agents/:agent_id — Resolve by AXIS ID or DID
 * GET /resolve/:did — W3C DID Resolution format
 *
 * Implements the Registry Data Visibility Model:
 * - Public layer (unauthenticated): cryptographic identifiers only
 * - Presentation layer (valid AIT in request): adds display_name, verification_tier, etc.
 * - Private layer: never exposed through API
 */

import { base64urlToBytes, bytesToBase58, verifyEd25519Signature } from '../utils/crypto.js';

/**
 * Verify an AIT from the request and return the presenting agent's info.
 * Returns null if no valid AIT is present (unauthenticated = public layer only).
 */
export async function extractPresentationContext(request, env) {
  // Check Authorization header: Bearer <AIT>
  const authHeader = request?.headers?.get('Authorization');
  let token = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }

  // Also check ?ait= query param
  if (!token && request) {
    const url = new URL(request.url);
    token = url.searchParams.get('ait');
  }

  if (!token) return null;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    if (header.typ !== 'AIT' || header.alg !== 'EdDSA') return null;

    // Find the presenting agent
    const agentId = payload.iss || payload.sub;
    const agent = await findAgent(agentId, env);
    if (!agent || agent.status !== 'active') return null;

    // Verify signature
    const signedContent = `${parts[0]}.${parts[1]}`;
    const signatureValid = await verifyEd25519Signature(
      agent.public_key,
      signedContent,
      parts[2]
    );
    if (!signatureValid) return null;

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return null;

    return { agent_id: agent.axis_id, operator_id: agent.operator_id };
  } catch (err) {
    return null;
  }
}

export async function handleGetAgent(agentId, env, request) {
  const agent = await findAgent(agentId, env);
  if (!agent) {
    return { status: 404, body: { error: { code: 'agent_not_found', message: `Agent not found: ${agentId}` } } };
  }

  // Check for presentation context (valid AIT in request)
  const presentationContext = await extractPresentationContext(request, env);

  // Look up operator verification tier (needed for presentation layer)
  const operator = presentationContext
    ? await env.DB.prepare('SELECT verification_tier, domain FROM operators WHERE id = ?').bind(agent.operator_id).first()
    : null;

  return { status: 200, body: buildAgentRecord(agent, operator, !!presentationContext, env) };
}

export async function handleResolve(did, env) {
  const agent = await findAgent(did, env);
  if (!agent) {
    return { status: 404, body: { error: { code: 'agent_not_found', message: `DID not found: ${did}` } } };
  }

  const startTime = Date.now();
  const didDocument = buildDIDDocument(agent);
  const duration = Date.now() - startTime;

  return {
    status: 200,
    body: {
      didResolutionMetadata: {
        contentType: 'application/did+ld+json',
        duration
      },
      didDocument,
      didDocumentMetadata: {
        created: agent.created_at,
        updated: agent.updated_at,
        versionId: String(agent.version),
        deactivated: agent.status === 'deactivated'
      }
    }
  };
}

// ---- Helpers ----

export async function findAgent(identifier, env) {
  // Try all identifier formats
  let agent = await env.DB.prepare(
    'SELECT * FROM agents WHERE axis_id = ? OR did = ? OR id = ?'
  ).bind(identifier, identifier, identifier).first();

  // Also try matching just the agent name part
  if (!agent && !identifier.includes(':')) {
    agent = await env.DB.prepare(
      'SELECT * FROM agents WHERE id = ?'
    ).bind(identifier).first();
  }

  return agent;
}

function buildAgentRecord(agent, operator, includePresentation, env) {
  const registryBase = (env && env.REGISTRY_BASE_URL) || 'https://axis-registry.editor-9a4.workers.dev';

  // Public layer — always returned, no authentication required.
  // Contains only what is necessary for cryptographic verification.
  const record = {
    axis_version: '0.1',
    agent_id: agent.axis_id,
    did: agent.did,
    operator_id: agent.operator_id,
    public_key: agent.public_key,
    key_algorithm: agent.key_algorithm,
    status: agent.status,
    registry_url: `${registryBase}/agents/${encodeURIComponent(agent.axis_id)}`,
    revocation_url: `${registryBase}/revocation/${encodeURIComponent(agent.axis_id)}`
  };

  // Presentation layer — only returned when a valid AIT is included in the request.
  // The agent chose to interact with this platform, so the platform sees these details.
  if (includePresentation) {
    record.display_name = agent.display_name;
    record.operator_verification_tier = operator ? operator.verification_tier : 'unknown';
    record.registered_at = agent.created_at;
    if (agent.description) record.description = agent.description;
    if (agent.service_endpoints) record.service = JSON.parse(agent.service_endpoints);
  }

  // Private layer — NEVER returned through the API.
  // Contact info, KYB docs, billing are registrar-only.

  return record;
}

export function buildDIDDocument(agent) {
  const did = agent.did;
  const doc = {
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
      publicKeyMultibase: `z${bytesToBase58(base64urlToBytes(agent.public_key))}`
    }],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
    axisMetadata: {
      registered: agent.created_at,
      registry: 'prime',
      operator: {
        id: agent.operator_id,
        // domain and verified status would come from a join, simplified here
      },
      status: agent.status
    }
  };

  if (agent.service_endpoints) {
    doc.service = JSON.parse(agent.service_endpoints);
  }

  return doc;
}
