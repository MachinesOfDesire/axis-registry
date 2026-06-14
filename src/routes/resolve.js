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
import { parseAxisDid, buildAxisDidV2 } from '../utils/did.js';

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

  // M2: cap raw token size before calling atob. AITs are short Ed25519 JWTs;
  // 4 KB is a generous ceiling (~3x the largest realistic AIT). Without a cap,
  // a multi-megabyte Bearer header would blow up atob and burn CPU for a value
  // that can never validate. Treat oversize as "no valid AIT present" rather
  // than 400 so the public-layer fallback (no presentation context) still
  // applies — this function intentionally never rejects the request itself.
  if (token.length > 4096) return null;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    if (header.typ !== 'AIT' || header.alg !== 'EdDSA') return null;

    // H1: require non-empty `aud`. Silent here — presentation-layer unlock
    // fails closed, caller falls back to the public layer. The matching
    // loud-reject path lives in routes/verify.js handleVerifyAIT.
    if (!payload.aud || typeof payload.aud !== 'string' || payload.aud.trim() === '') {
      return null;
    }

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

export async function handleGetAgent(agentId, env, request, registrar = null) {
  const agent = await findAgent(agentId, env);
  if (!agent) {
    return { status: 404, body: { error: { code: 'agent_not_found', message: 'Agent not found' } } };
  }

  // Presentation layer is unlocked by ANY of:
  //   (a) a valid AIT in the request (an agent is asking about itself or a peer)
  //   (b) the calling registrar owns the agent (registrar self-service)
  //   (c) the calling registrar has admin+ role (cross-tenant support)
  const presentationContext = await extractPresentationContext(request, env);
  const isOwner = registrar && agent.registrar_id === registrar.id;
  const isAdminPlus = registrar && (registrar.role === 'admin' || registrar.role === 'super_admin');
  const includePresentation = Boolean(presentationContext || isOwner || isAdminPlus);

  const operator = includePresentation
    ? await env.DB.prepare('SELECT verification_tier, domain FROM operators WHERE id = ?').bind(agent.operator_id).first()
    : null;

  return { status: 200, body: buildAgentRecord(agent, operator, includePresentation, env) };
}

export async function handleResolve(did, env) {
  const agent = await findAgent(did, env);
  if (!agent) {
    return { status: 404, body: { error: { code: 'agent_not_found', message: 'DID not found' } } };
  }

  const startTime = Date.now();
  const didDocument = buildDIDDocument(agent);
  const duration = Date.now() - startTime;

  // v0.3 §10.3: v0.1 DID forms (`did:axis:{registry}:{agent}`) are resolve-only
  // and deprecated — they still resolve, but new registrations only emit the
  // v0.2 operator-namespaced form. If the CALLER requested a v0.1-form DID,
  // surface a non-fatal deprecation warning in the resolution metadata so
  // consumers can migrate to the agent's canonical (v0.2) DID.
  const requestedForm = parseAxisDid(did);
  const didResolutionMetadata = {
    contentType: 'application/did+ld+json',
    duration
  };
  if (requestedForm && requestedForm.form === 'v0.1') {
    didResolutionMetadata.warnings = [{
      type: 'DEPRECATED_DID_FORM',
      message: 'v0.1 DID form is deprecated and resolve-only; use the canonical v0.2 DID returned in didDocument.id.'
    }];
  }

  return {
    status: 200,
    body: {
      // Top-level canonical operator_id, matching /verify and /agents/:id.
      // The axis-comments worker enforces operator_id agreement across
      // endpoints as defense in depth; without it here, /resolve drifts from
      // the other resolution surfaces. DB column stays bare; canonicalized at
      // the response boundary.
      operator_id: `axis:${agent.operator_id}:operator`,
      didResolutionMetadata,
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
  // Phase 1: direct match against the stored axis_id / did / id columns.
  // Covers the common case where the caller passes the exact form the
  // agent was registered with.
  let agent = await env.DB.prepare(
    'SELECT * FROM agents WHERE axis_id = ? OR did = ? OR id = ?'
  ).bind(identifier, identifier, identifier).first();
  if (agent) return agent;

  // Phase 2 (C1 / spec v0.2 §10.3): cross-form DID tolerance. Per spec,
  // resolvers MUST accept both v0.1 and v0.2 DID forms regardless of
  // which form the agent was registered with. Parse the input and try
  // the alternate form(s).
  const parsed = parseAxisDid(identifier);
  if (parsed) {
    if (parsed.form === 'v0.1') {
      // Caller sent did:axis:prime:<agent>. The agent might actually be
      // stored with a v0.2 DID. We don't know the operator slug from this
      // input, so fall back to matching by agent slug alone.
      agent = await env.DB.prepare(
        'SELECT * FROM agents WHERE id = ?'
      ).bind(parsed.agent).first();
      if (agent) return agent;
    } else if (parsed.form === 'v0.2') {
      // Caller sent did:axis:prime:<operator>:<agent>. The agent might
      // be stored with a v0.1 DID. Try the bare agent slug, scoped to
      // the operator namespace to avoid cross-operator collisions.
      agent = await env.DB.prepare(
        'SELECT * FROM agents WHERE id = ? AND operator_id = ?'
      ).bind(parsed.agent, parsed.operator).first();
      if (agent) return agent;
      // Final fallback: bare agent slug, no operator scope. Picks the
      // first match if multiple operators share an agent slug. Matches
      // the v0.1 single-namespace behavior; will be eliminated when
      // Phase 2 migration brings every stored DID to v0.2.
      agent = await env.DB.prepare(
        'SELECT * FROM agents WHERE id = ?'
      ).bind(parsed.agent).first();
      if (agent) return agent;
    }
  }

  // Bare agent slug (no colons) — keep the v0.1 lookup path for non-DID
  // identifiers (e.g. axis_id queries that happen to omit the prefix).
  if (!identifier.includes(':')) {
    agent = await env.DB.prepare(
      'SELECT * FROM agents WHERE id = ?'
    ).bind(identifier).first();
    if (agent) return agent;
  }

  return null;
}

function buildAgentRecord(agent, operator, includePresentation, env) {
  const registryBase = (env && env.REGISTRY_BASE_URL) || 'https://registry.axisprime.ai';

  // Public layer — always returned, no authentication required.
  // Contains only what is necessary for cryptographic verification.
  const record = {
    axis_version: '0.2',
    agent_id: agent.axis_id,
    did: agent.did,
    // operator_id is returned in canonical `axis:<slug>:operator` form,
    // matching what `/verify` already emits. Previously this returned the
    // bare DB-column slug (`<slug>`), which drifted from `/verify` and
    // caused the axis-comments worker's defense-in-depth check (operator_id
    // must agree across /agents/:id and /verify for the same agent) to
    // reject otherwise-valid AITs. The DB column itself stays as the bare
    // slug — normalization happens at the response boundary.
    // Coord 818d; AXIS Protocol v0.1.1 §4.1.
    operator_id: `axis:${agent.operator_id}:operator`,
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
