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

/**
 * Free-tier agent caps per the decoupled pricing model (2026-07-04; supersedes
 * the earlier 2026-06-16 10/100 figures):
 *
 *   Single Operator (email-verified)  → 25 agents
 *   Team (domain-verified)            → 250 agents
 *   Verified (registrar quota push)   → 1000 agents (VERIFIED_DEFAULT_MAX_AGENTS)
 *
 * No per-agent fees. These are HARD caps: at the free tiers max_agents equals
 * the free slot count, so there is no paid/unlimited fallthrough — upgrading
 * tier (ultimately via POST /operators/:id/verification) is the only path to
 * more agents. Migration 0009 reconciles pre-existing rows to these values.
 */
export const TIER_CAPS = {
  email: { freeSlots: 25, maxAgents: 25 },
  domain: { freeSlots: 250, maxAgents: 250 },
};

// Default enforced cap set by the registrar's Verified Identity quota push
// (POST /operators/:id/verification). Free slot counters are preserved there.
export const VERIFIED_DEFAULT_MAX_AGENTS = 1000;

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

  const token = generateToken(16);
  const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000).toISOString(); // 72 hours

  // BOLA: if an operator already exists for this email/domain under a DIFFERENT
  // registrar, refuse — a cross-registrar claim must go through an admin force
  // endpoint, not this normal path. This SELECT produces the clean 403; the
  // upsert below also carries a `WHERE ... registrar_id` guard so the protection
  // holds structurally even under a race this advisory read could miss.
  // M1: bind NULL (not '') when no domain is supplied.
  const existing = await env.DB.prepare(
    'SELECT registrar_id FROM operators WHERE domain = ? OR email = ?'
  ).bind(domain ? domain : null, email).first();
  if (existing && existing.registrar_id !== registrar.id) {
    return {
      status: 403,
      body: { error: { code: 'not_your_resource', message: 'Operator already exists under a different registrar' } }
    };
  }

  // Single idempotent upsert keyed on the operator's natural key (email). This
  // is the structural fix for the 2026-06-29 incident class — three former
  // "remember to do it right" rules are now enforced by the statement itself:
  //
  //   * ON CONFLICT(email) DO UPDATE — a repeat signup reconciles to the SAME
  //     row instead of minting a duplicate. UNIQUE(email) (migration 0007)
  //     makes a duplicate operator impossible even under a concurrent race.
  //   * COALESCE(excluded.x, operators.x) — an email-only call binds NULL for
  //     the domain/verification columns, so it can NEVER overwrite a domain or
  //     in-flight token an operator already has. Clobber is unrepresentable.
  //   * RETURNING — the row we read back IS the persisted row, so the id (and
  //     tier/domain/active) we report can't be a phantom that was never written.
  //
  // The `WHERE operators.registrar_id = excluded.registrar_id` guard makes the
  // BOLA protection structural: on a cross-registrar email conflict the DO
  // UPDATE matches no row, RETURNING is empty, and we surface 403 below. A
  // genuine cross-operator domain collision trips UNIQUE(domain) and throws —
  // caught and surfaced as 409 (anti-squatting, now DB-enforced).
  //
  // Verification columns are bound NULL unless a domain is actually being
  // claimed, which is what lets COALESCE preserve an existing operator's state
  // on an email-only call (and means email-tier rows carry no useless token).
  const insDomain = domain || null;
  const insToken = domain ? token : null;
  const insExpires = domain ? expiresAt : null;
  const insMethod = domain ? verificationMethod : null;
  let row;
  try {
    row = await env.DB.prepare(
      `INSERT INTO operators (id, email, domain, verification_tier, domain_verification_token,
         domain_verification_expires, domain_verification_method, registrar_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(email) DO UPDATE SET
         domain = COALESCE(excluded.domain, operators.domain),
         domain_verification_token = COALESCE(excluded.domain_verification_token, operators.domain_verification_token),
         domain_verification_expires = COALESCE(excluded.domain_verification_expires, operators.domain_verification_expires),
         domain_verification_method = COALESCE(excluded.domain_verification_method, operators.domain_verification_method),
         updated_at = datetime('now')
       WHERE operators.registrar_id = excluded.registrar_id
       RETURNING id, domain, verification_tier, domain_verified`
    ).bind(operatorId, email, insDomain, tier, insToken, insExpires, insMethod, registrar.id).first();
  } catch (err) {
    // UNIQUE(domain) violation: the claimed domain is verified under another
    // operator. (An email natural-key conflict is absorbed by DO UPDATE above;
    // only a domain collision reaches here.)
    if (/UNIQUE/i.test(err?.message || '') && /domain/i.test(err?.message || '')) {
      return {
        status: 409,
        body: { error: { code: 'domain_taken', message: 'Domain is already claimed by another operator' } }
      };
    }
    throw err;
  }

  // RETURNING empty ⟺ an email conflict whose row belongs to another registrar
  // (the WHERE guard suppressed the update). Race-safe backstop for the 403.
  if (!row) {
    return {
      status: 403,
      body: { error: { code: 'not_your_resource', message: 'Operator already exists under a different registrar' } }
    };
  }

  // Slots are created once per operator, keyed on the PERSISTED id (row.id, not
  // the speculative slug) and made idempotent with ON CONFLICT DO NOTHING, so a
  // reconciling repeat signup neither orphans a slot row nor disturbs existing
  // counters. agent_slots.operator_id is the PK → valid conflict target.
  // Hard caps == free caps at both free tiers (locked pricing model; see
  // TIER_CAPS above). A pre-existing operator's row is untouched (DO NOTHING),
  // so a registrar-pushed max_agents (e.g. 1000) is never lowered here. The
  // fallback covers KYB tiers reaching this path without a slots row (normally
  // created by the verification push): 0 free, verified default cap.
  const caps = TIER_CAPS[row.verification_tier]
    || { freeSlots: 0, maxAgents: VERIFIED_DEFAULT_MAX_AGENTS };
  const freeSlots = caps.freeSlots;
  const maxAgents = caps.maxAgents;
  await env.DB.prepare(
    `INSERT INTO agent_slots (operator_id, free_slots_total, max_agents)
     VALUES (?, ?, ?)
     ON CONFLICT(operator_id) DO NOTHING`
  ).bind(row.id, freeSlots, maxAgents).run();

  // Everything reported below comes from the persisted row (authoritative),
  // never the request inputs. `active` = usable now: email-tier always;
  // domain-tier once its domain is verified (a brand-new domain operator is
  // therefore inactive, pending verification).
  const responseOperatorId = row.id;
  const resolvedTier = row.verification_tier;
  const resolvedDomain = row.domain;
  const resolvedActive = row.verification_tier === 'email' ? true : Boolean(row.domain_verified);

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
      operator_id: responseOperatorId,
      domain: resolvedDomain,
      email,
      tier: resolvedTier,
      method: domain ? verificationMethod : 'email',
      token: domain ? token : undefined,
      instructions: domain ? instructions : { email: { message: 'Email-only accounts do not require domain verification. Your account is active.' } },
      expiresAt: domain ? expiresAt : undefined,
      active: resolvedActive
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
        freeAgentSlots: TIER_CAPS.domain.freeSlots,
        message: `Domain verified successfully. You can now register up to ${TIER_CAPS.domain.freeSlots} agents for free.`
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

  // max_agents: integer in [1, 1_000_000], or null for unlimited. Default
  // VERIFIED_DEFAULT_MAX_AGENTS = 1000 (the Verified Identity cap).
  let maxAgents = VERIFIED_DEFAULT_MAX_AGENTS;
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
