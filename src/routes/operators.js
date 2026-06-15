/**
 * Operator Endpoints
 * Registrar-authenticated. Registrars manage operator accounts.
 *
 * POST /operators/verify-domain — Initiate domain verification
 * POST /operators/verify-domain/check — Check verification status
 */

import { generateToken } from '../utils/crypto.js';
import { deriveOperatorSlug } from '../utils/operator-slug.js';
import { verifyCanonicalProof } from '../utils/proof.js';

export async function handleVerifyDomain(body, registrar, env) {
  const { domain, method, email } = body;

  if (!email) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Missing required field: email' } }
    };
  }

  const verificationMethod = method || 'dns_txt';
  if (!['dns_txt', 'http_file'].includes(verificationMethod)) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'method must be dns_txt or http_file' } }
    };
  }

  // Determine tier
  const tier = domain ? 'domain' : 'email';
  // C1 (spec v0.2 §10.3): operator slug is the second-to-last segment of the
  // canonical DID `did:axis:prime:<operator>:<agent>`. It must be derived
  // from verification proof, never caller-chosen, so squatting a brand-name
  // slug structurally requires verifying that brand's domain.
  //
  //   domain          → verified-domain root (TLD stripped, dots → dashes)
  //   email           → opaque "op-<12hex>"
  //   kyb_individual  → opaque
  //   kyb_organization → verified domain if present, else opaque
  //
  // See src/utils/operator-slug.js for the full tier table + rationale.
  const operatorId = deriveOperatorSlug(tier, domain);

  // Check if operator already exists.
  // M1: bind NULL (not '') when no domain is supplied — binding '' could
  // accidentally match a drifted row stored with domain=''.
  let operator = await env.DB.prepare(
    'SELECT * FROM operators WHERE domain = ? OR email = ?'
  ).bind(domain ? domain : null, email).first();

  const token = generateToken(16);
  const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString(); // 72 hours

  if (operator) {
    // BOLA: operator already exists and belongs to a different registrar.
    // A cross-registrar domain dispute/claim must go through an admin force
    // endpoint (not exposed on this normal path). Admin+ callers hit this
    // rule too on the normal path.
    if (operator.registrar_id !== registrar.id) {
      return {
        status: 403,
        body: { error: { code: 'not_your_resource', message: 'Operator already exists under a different registrar' } }
      };
    }
    // Update verification token AND persist the claimed domain.
    // Without writing `domain` here, handleCheckDomain's later WHERE domain=?
    // lookup fails for operators that were pre-created (e.g. during signup)
    // with domain=NULL and only now are claiming one.
    await env.DB.prepare(
      `UPDATE operators SET domain = ?, domain_verification_token = ?, domain_verification_expires = ?,
       domain_verification_method = ?, updated_at = datetime('now') WHERE id = ?`
    ).bind(domain || null, token, expiresAt, verificationMethod, operator.id).run();
  } else {
    // Create new operator
    await env.DB.prepare(
      `INSERT INTO operators (id, email, domain, verification_tier, domain_verification_token,
       domain_verification_expires, domain_verification_method, registrar_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(operatorId, email, domain || null, tier, token, expiresAt, domain ? verificationMethod : null, registrar.id).run();

    // Create agent slots based on tier
    const freeSlots = tier === 'domain' ? 3 : 0;
    const maxAgents = tier === 'email' ? 5 : null;
    await env.DB.prepare(
      `INSERT INTO agent_slots (operator_id, free_slots_total, max_agents)
       VALUES (?, ?, ?)`
    ).bind(operatorId, freeSlots, maxAgents).run();
  }

  // Build response based on method
  const instructions = {};

  if (domain && verificationMethod === 'dns_txt') {
    instructions.dns_txt = {
      record: `axis-verify=${token}`,
      host: `_axis-verify.${domain}`,
      type: 'TXT'
    };
  } else if (domain && verificationMethod === 'http_file') {
    instructions.http_file = {
      url: `https://${domain}/.well-known/axis-verify.json`,
      content: { 'axis-verify': token }
    };
  }

  return {
    status: 200,
    body: {
      operator_id: operatorId,
      domain: domain || null,
      email,
      tier,
      method: domain ? verificationMethod : 'email',
      token: domain ? token : undefined,
      instructions: domain ? instructions : { email: { message: 'Email-only accounts do not require domain verification. Your account is active.' } },
      expiresAt: domain ? expiresAt : undefined,
      active: !domain // email-only accounts are immediately active
    }
  };
}

export async function handleCheckDomain(body, registrar, env) {
  const { domain, token } = body;

  if (!domain || !token) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Missing required fields: domain, token' } }
    };
  }

  const operator = await env.DB.prepare(
    'SELECT * FROM operators WHERE domain = ? AND domain_verification_token = ?'
  ).bind(domain, token).first();

  if (!operator) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Invalid domain or token' } }
    };
  }

  // BOLA: operator must belong to the calling registrar.
  if (operator.registrar_id !== registrar.id) {
    return {
      status: 403,
      body: { error: { code: 'not_your_resource', message: 'Operator belongs to a different registrar' } }
    };
  }

  // Check token expiry
  if (new Date(operator.domain_verification_expires) < new Date()) {
    return {
      status: 400,
      body: { error: { code: 'invalid_request', message: 'Verification token has expired. Initiate a new verification.' } }
    };
  }

  // Actually verify the domain (DNS or HTTP)
  let verified = false;
  try {
    if (operator.domain_verification_method === 'dns_txt') {
      verified = await verifyDNS(domain, token);
    } else {
      verified = await verifyHTTP(domain, token);
    }
  } catch (err) {
    console.error('Domain verification error:', err);
  }

  if (verified) {
    const now = new Date().toISOString();
    await env.DB.prepare(
      `UPDATE operators SET domain_verified = 1, domain_verified_at = ?,
       domain_verification_token = NULL, updated_at = ? WHERE id = ?`
    ).bind(now, now, operator.id).run();

    return {
      status: 200,
      body: {
        domain,
        verified: true,
        verifiedAt: now,
        freeAgentSlots: 3,
        message: 'Domain verified successfully. You can now register up to 3 agents for free.'
      }
    };
  }

  return {
    status: 200,
    body: {
      domain,
      verified: false,
      message: `Verification record not found. Make sure you've added the ${operator.domain_verification_method === 'dns_txt' ? 'DNS TXT record' : 'HTTP file'} and try again. DNS changes can take up to 48 hours to propagate.`
    }
  };
}

/**
 * POST /operators/:id/verification — registrar-attested identity verification.
 *
 * Called by a registrar (e.g. kipple-registrar / AXIS Prime signup) after an
 * operator completes the Verified Identity flow on its side (one-time payment
 * + Stripe Identity KYC). The registrar vouches for the result; the registry
 * records the verified tier and raises the enforced agent cap. The registry is
 * where caps are actually enforced (POST /register reads agent_slots.max_agents),
 * so this is the handoff that makes a Verified Identity upgrade real.
 *
 * BOLA-scoped: a registrar may only attest verification for its own operators.
 *
 * Body: { max_agents?: number (default 1000) | null (unlimited), provider?: string }
 *
 * Vocab note: the operators.verification_tier CHECK allows
 * email|domain|kyb_individual|kyb_organization. "Verified Identity" (individual
 * KYC) maps to kyb_individual here; the registrar-side label ("verified") is a
 * separate vocabulary, and unifying the two is a tracked follow-up.
 */
export async function handleSetOperatorVerification(operatorId, body, registrar, env) {
  if (!registrar) {
    return { status: 401, body: { error: { code: 'unauthorized', message: 'Valid registrar API key required' } } };
  }

  const operator = await env.DB.prepare(
    'SELECT id, registrar_id, status FROM operators WHERE id = ?'
  ).bind(operatorId).first();
  if (!operator) {
    return { status: 404, body: { error: { code: 'not_found', message: 'Operator not found' } } };
  }
  // BOLA: a registrar may only attest verification for its own operators.
  if (operator.registrar_id !== registrar.id) {
    return { status: 403, body: { error: { code: 'not_your_resource', message: 'Operator belongs to a different registrar' } } };
  }

  // max_agents: integer in [1, 1_000_000], or null for unlimited. Default 1000
  // (the Verified Identity cap).
  let maxAgents = 1000;
  if (body && body.max_agents !== undefined) {
    if (body.max_agents === null) {
      maxAgents = null;
    } else if (typeof body.max_agents === 'number' && Number.isFinite(body.max_agents)) {
      maxAgents = Math.max(1, Math.min(Math.floor(body.max_agents), 1000000));
    } else {
      return { status: 400, body: { error: { code: 'invalid_request', message: 'max_agents must be a number or null' } } };
    }
  }
  const provider = (body && typeof body.provider === 'string') ? body.provider.slice(0, 64) : 'stripe_identity';
  const now = new Date().toISOString();

  // Mark the operator individually KYB-verified. 'kyb_individual' is the
  // registry's canonical value for a verified individual; the CHECK constraint
  // does not permit a bare 'verified'.
  await env.DB.prepare(
    `UPDATE operators
     SET verification_tier = 'kyb_individual', kyb_verified = 1, kyb_verified_at = ?,
         kyb_provider = ?, updated_at = ?
     WHERE id = ?`
  ).bind(now, provider, now, operatorId).run();

  // Raise the enforced cap. Upsert so a missing agent_slots row is created;
  // on an existing row, only max_agents changes (free/used/paid are preserved).
  await env.DB.prepare(
    `INSERT INTO agent_slots (operator_id, free_slots_total, max_agents)
     VALUES (?, 0, ?)
     ON CONFLICT(operator_id) DO UPDATE SET max_agents = excluded.max_agents`
  ).bind(operatorId, maxAgents).run();

  return {
    status: 200,
    body: {
      operator_id: operatorId,
      verification_tier: 'kyb_individual',
      kyb_verified: true,
      max_agents: maxAgents,
      provider
    }
  };
}

/**
 * POST /operators/:id/key — register (or idempotently confirm) an operator's
 * Ed25519 signing public key, with proof of key ownership.
 *
 * Why this exists (the gap it closes): an operator that issues a root
 * DelegationCredential (`issued_by: axis:{op}:operator`) signs that DC with its
 * private key. Verifying that root link's signature requires the operator's
 * PUBLIC key (resolveIssuerPublicKey, delegations.js §8 Step 3). Until this
 * endpoint, `operators.public_key` was only ever READ — there was no way to SET
 * it, so operator-rooted chains could never report `signatureValid:true` and
 * full signed-chain enforcement could never be turned on for them. The keyless
 * operator-helper demo worked precisely because no operator key existed.
 *
 * Design (mirrors POST /register's proof-of-ownership, v0.2 §6.1):
 *   - Registrar-authenticated; BOLA-scoped to the registrar's own operators.
 *   - The operator signs the JCS canonicalization of the request body MINUS
 *     `proof`, with the private key matching `publicKey`. Proof is REQUIRED here
 *     (the whole point is to prove control of the key being registered).
 *   - Additive + backward-compatible: keyless operators keep working; this only
 *     populates a previously-NULL column. Enforcement (AXIS_ENFORCE_DC_PROOFS)
 *     stays OFF and is unaffected by registering a key.
 *   - NOT key rotation. If a DIFFERENT key is already registered, returns 409 —
 *     rotation is the separate v0.3 key-rotation candidate, not this endpoint.
 *     Re-submitting the SAME key is idempotent (200).
 *
 * Body: { publicKey: string (base64url Ed25519), proof: { proofType?, proofValue } }
 */
export async function handleRegisterOperatorKey(operatorId, body, registrar, env) {
  if (!registrar) {
    return { status: 401, body: { error: { code: 'unauthorized', message: 'Valid registrar API key required' } } };
  }
  if (!body || typeof body.publicKey !== 'string' || body.publicKey.trim() === '') {
    return { status: 400, body: { error: { code: 'invalid_request', message: 'Missing required field: publicKey' } } };
  }
  if (!body.proof || typeof body.proof.proofValue !== 'string') {
    return { status: 400, body: { error: { code: 'invalid_request', message: 'Missing required field: proof.proofValue (proof of key ownership is required)' } } };
  }

  const operator = await env.DB.prepare(
    'SELECT id, registrar_id, status, public_key FROM operators WHERE id = ?'
  ).bind(operatorId).first();
  if (!operator) {
    return { status: 404, body: { error: { code: 'operator_not_found', message: 'Operator not found' } } };
  }
  // BOLA: a registrar may only register keys for its own operators.
  if (operator.registrar_id !== registrar.id) {
    return { status: 403, body: { error: { code: 'not_your_resource', message: 'Operator belongs to a different registrar' } } };
  }
  if (operator.status !== 'active') {
    return { status: 403, body: { error: { code: 'operator_not_verified', message: `Operator status: ${operator.status}` } } };
  }

  // Rotation guard: this endpoint registers a key, it does not rotate one.
  if (operator.public_key) {
    if (operator.public_key === body.publicKey) {
      // Idempotent re-registration of the same key — succeed without re-writing.
      return {
        status: 200,
        body: { operator_id: `axis:${operator.id}:operator`, public_key: operator.public_key, key_registered: true, idempotent: true },
      };
    }
    return {
      status: 409,
      body: { error: { code: 'key_already_registered', message: 'Operator already has a different signing key. Key rotation is a separate flow (v0.3 key-rotation candidate), not this endpoint.' } },
    };
  }

  // Verify proof of key ownership: the operator signs the canonical body minus
  // `proof` with the private key matching `publicKey`. Same regime as /register.
  const proofInput = { ...body };
  delete proofInput.proof;
  const result = await verifyCanonicalProof({
    payload: proofInput,
    proofValue: body.proof.proofValue,
    proofType: body.proof.proofType,
    publicKey: body.publicKey,
  });
  if (result.unsupported) {
    return { status: 400, body: { error: { code: 'unsupported_proof_type', message: `Unrecognized proof type: ${result.proofType}. Supported: jcs-eddsa-2026 (or omit proofType for legacy).` } } };
  }
  if (!result.valid) {
    return { status: 400, body: { error: { code: 'invalid_proof', message: 'Proof of key ownership verification failed' } } };
  }

  const now = new Date().toISOString();
  await env.DB.prepare(
    `UPDATE operators SET public_key = ?, updated_at = ? WHERE id = ?`
  ).bind(body.publicKey, now, operator.id).run();

  return {
    status: 200,
    body: { operator_id: `axis:${operator.id}:operator`, public_key: body.publicKey, key_registered: true },
  };
}

// M6: defense-in-depth on outbound fetches from the verifier. The Workers
// runtime already blocks RFC1918 / link-local, so SSRF blast radius is
// bounded — these checks ensure callers can't smuggle nonsense into the
// URL we construct (e.g. `evil.com/x?` segments), and that a hung target
// can't pin a worker invocation open.

// RFC 1035 + RFC 1123 hostname shape. Labels: 1-63 chars, alphanumeric or
// hyphen, must not start/end with hyphen. Total length <= 253 chars.
// Underscore labels are not strictly RFC-1035 but are allowed by some
// platforms; we reject them here because they shouldn't appear in operator
// domains and admitting them widens the validation surface.
const DOMAIN_SHAPE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const VERIFY_FETCH_TIMEOUT_MS = 5000;

function isValidDomain(domain) {
  return typeof domain === 'string' && DOMAIN_SHAPE.test(domain);
}

async function fetchWithTimeout(url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), VERIFY_FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function verifyDNS(domain, token) {
  if (!isValidDomain(domain)) return false;
  // Use Cloudflare DNS-over-HTTPS to check for the TXT record.
  // `domain` is shape-validated above, so the interpolation is safe.
  try {
    const resp = await fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=_axis-verify.${encodeURIComponent(domain)}&type=TXT`,
      { headers: { 'Accept': 'application/dns-json' } }
    );
    const data = await resp.json();
    if (data.Answer) {
      return data.Answer.some(a =>
        a.data && a.data.replace(/"/g, '').includes(`axis-verify=${token}`)
      );
    }
  } catch (err) {
    console.error('DNS verification error:', err && err.message ? err.message : err);
  }
  return false;
}

async function verifyHTTP(domain, token) {
  if (!isValidDomain(domain)) return false;
  try {
    const resp = await fetchWithTimeout(`https://${domain}/.well-known/axis-verify.json`, {
      headers: { 'Accept': 'application/json' }
    });
    if (resp.ok) {
      const data = await resp.json();
      return data['axis-verify'] === token;
    }
  } catch (err) {
    console.error('HTTP verification error:', err && err.message ? err.message : err);
  }
  return false;
}
