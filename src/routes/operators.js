/**
 * Operator Endpoints
 * Registrar-authenticated. Registrars manage operator accounts.
 *
 * POST /operators/verify-domain — Initiate domain verification
 * POST /operators/verify-domain/check — Check verification status
 */

import { generateToken } from '../utils/crypto.js';

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
  // For domain-tier operators the id is derived from the already-public domain.
  // For email-tier operators the id MUST be opaque — deriving from the email
  // local-part leaks identifiable PII into a publicly enumerable field, which
  // violates GDPR purpose-limitation and the Registry Conformance §8 rule that
  // public-layer identifiers carry no identifiable personal data.
  const operatorId = domain
    ? domain.replace(/\./g, '-')
    : 'op-' + generateToken(12);

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
