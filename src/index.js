/**
 * AXIS Registry API
 * Cloudflare Workers + D1
 *
 * This is the AXIS Prime registry — the root registry.
 * Registrars authenticate with API keys to submit registrations.
 * Public endpoints (resolve, verify, revocation) require no auth.
 */

import { handleRegister } from './routes/register.js';
import { handleResolve, handleGetAgent, extractPresentationContext } from './routes/resolve.js';
import { handleVerifyIdentity, handleVerifyAIT, handleVerifySignature } from './routes/verify.js';
import { handleRevocation, handleDeactivateAgent, forceDeactivateAgent } from './routes/revocation.js';
import { handleCreateDelegation, handleGetDelegation, handleRevokeDelegation, handleVerifyChain, forceRevokeDelegation } from './routes/delegations.js';
import { handleVerifyDomain, handleCheckDomain } from './routes/operators.js';
import { authenticateRegistrar, isAdmin, requireAdmin, requireSuperAdmin } from './middleware/auth.js';
import { corsHeaders, handleOptions } from './middleware/cors.js';
import { checkRateLimit, ipKey, RATE_LIMIT_TIERS } from './middleware/rate-limit.js';
import { logAudit } from './utils/audit.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return handleOptions(request);
    }

    try {
      // Authenticate up-front so we can gate routes by role.
      // `registrar` is null if no/invalid Bearer header was sent.
      const registrar = await authenticateRegistrar(request, env);

      // ==========================================
      // RATE LIMITING (C3)
      // Choose a tier based on (method, path, registrar) and bucket by
      // either registrar.id (authenticated) or cf-connecting-ip (public).
      // If the tier binding isn't configured (local dev / minimal fork),
      // checkRateLimit is a no-op. See middleware/rate-limit.js for the
      // tier descriptions and wrangler.toml.example for the binding shape.
      // ==========================================
      const rateLimitDecision = await pickRateLimitTier(method, path, registrar, request);
      if (rateLimitDecision) {
        const denial = await checkRateLimit(
          env,
          rateLimitDecision.tier,
          rateLimitDecision.key,
          request,
          ctx
        );
        if (denial) {
          return addCors(jsonResponse(denial.status, denial.body, denial.headers));
        }
      }

      // ==========================================
      // PUBLIC ENDPOINTS (no auth required)
      // Free, unlimited, no rate limits
      // ==========================================

      // GET /.well-known/axis-access — Platform-side access control policy
      if (method === 'GET' && path === '/.well-known/axis-access') {
        const registryBase = env.REGISTRY_BASE_URL || 'https://registry.axisprime.ai';
        const platformId = registryBase.replace(/^https?:\/\//, '').replace(/\/$/, '');
        return addCors(jsonResponse(200, {
          axis_version: '0.1',
          platform_id: platformId,
          access_policy: {
            minimum_verification_level: 'email',
            required_scopes: [],
            allow_unverified: true,
            registration_url: 'https://signup.axisprime.ai/signup'
          },
          updated_at: '2026-04-13T00:00:00Z'
        }));
      }

      // GET /agents?operator_id= — List agents for an operator.
      // AUTH REQUIRED (BOLA fix): caller must be the owning registrar or admin+.
      // Public per-agent resolve stays at GET /agents/:axisId below (no auth).
      if (method === 'GET' && path === '/agents') {
        const operatorId = url.searchParams.get('operator_id');
        if (!operatorId) {
          return addCors(jsonResponse(400, { error: { code: 'invalid_request', message: 'operator_id query parameter required' } }));
        }
        if (!registrar) {
          return addCors(jsonResponse(401, { error: { code: 'unauthorized', message: 'Valid registrar API key required' } }));
        }
        const operator = await env.DB.prepare(
          'SELECT id, registrar_id FROM operators WHERE id = ?'
        ).bind(operatorId).first();
        if (!operator) {
          return addCors(jsonResponse(404, { error: { code: 'not_found', message: `Operator not found: ${operatorId}` } }));
        }
        if (operator.registrar_id !== registrar.id && !isAdmin(registrar)) {
          return addCors(jsonResponse(403, { error: { code: 'not_your_resource', message: 'Operator belongs to a different registrar' } }));
        }
        const agents = await env.DB.prepare(
          'SELECT * FROM agents WHERE operator_id = ? ORDER BY created_at DESC'
        ).bind(operatorId).all();
        return addCors(jsonResponse(200, { agents: agents.results || [] }));
      }

      // GET /operators — List operators owned by the calling registrar.
      // Scoped self-service endpoint. For cross-tenant listing (admin+ only)
      // use GET /admin/operators.
      if (method === 'GET' && path === '/operators') {
        if (!registrar) {
          return addCors(jsonResponse(401, { error: { code: 'unauthorized', message: 'Valid registrar API key required' } }));
        }
        const limit = clampPaginationInt(url.searchParams.get('limit'), 50, 500, 1);
        const offset = clampPaginationInt(url.searchParams.get('offset'), 0, Number.MAX_SAFE_INTEGER);
        const operators = await env.DB.prepare(
          'SELECT id, email, domain, verification_tier, domain_verified, status, created_at FROM operators WHERE registrar_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
        ).bind(registrar.id, limit, offset).all();
        const count = await env.DB.prepare(
          'SELECT COUNT(*) as total FROM operators WHERE registrar_id = ?'
        ).bind(registrar.id).first();
        return addCors(jsonResponse(200, { operators: operators.results || [], total: count?.total || 0 }));
      }

      // GET /audit — Audit log for the calling registrar's own actions
      // and actions affecting their resources. Scoped self-service. For
      // cross-tenant audit (admin+ only) use GET /admin/audit.
      if (method === 'GET' && path === '/audit') {
        if (!registrar) {
          return addCors(jsonResponse(401, { error: { code: 'unauthorized', message: 'Valid registrar API key required' } }));
        }
        const limit = clampPaginationInt(url.searchParams.get('limit'), 100, 500, 1);
        const offset = clampPaginationInt(url.searchParams.get('offset'), 0, Number.MAX_SAFE_INTEGER);
        // H7: also surface rows where the caller is the *target* registrar,
        // not just the actor. /admin/force-* writes the super_admin's id as
        // registrar_id; target_registrar_id captures the owning registrar
        // so they can see force-deactivations of their own resources here.
        const logs = await env.DB.prepare(
          'SELECT * FROM audit_log WHERE registrar_id = ? OR target_registrar_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        ).bind(registrar.id, registrar.id, limit, offset).all();
        return addCors(jsonResponse(200, { logs: logs.results || [] }));
      }

      // GET /operators/:id — Get operator info.
      // Presentation layer is unlocked by: valid AIT, owning registrar,
      // or admin+ role.
      if (method === 'GET' && path.match(/^\/operators\/([^/]+)$/)) {
        const opId = decodeURIComponent(path.match(/^\/operators\/([^/]+)$/)[1]);
        const operator = await env.DB.prepare('SELECT * FROM operators WHERE id = ?').bind(opId).first();
        if (!operator) {
          return addCors(jsonResponse(404, { error: { code: 'not_found', message: 'Operator not found' } }));
        }

        const registryBase = env.REGISTRY_BASE_URL || 'https://registry.axisprime.ai';

        const response = {
          axis_version: '0.1',
          operator_id: operator.id,
          public_key: operator.public_key || null,
          key_algorithm: operator.public_key ? 'Ed25519' : null,
          status: operator.status,
          registry_url: `${registryBase}/operators/${encodeURIComponent(operator.id)}`,
          revocation_url: `${registryBase}/revocation/operator/${encodeURIComponent(operator.id)}`
        };

        const presentationContext = await extractPresentationContext(request, env);
        const isOwner = registrar && operator.registrar_id === registrar.id;
        const isAdminPlus = registrar && (registrar.role === 'admin' || registrar.role === 'super_admin');
        const includePresentation = Boolean(presentationContext || isOwner || isAdminPlus);

        if (includePresentation) {
          response.display_name = operator.domain || operator.id;
          response.verification_tier = operator.verification_tier;
          response.registered_at = operator.created_at;
          if (operator.domain) response.domain = operator.domain;
          if (isOwner || isAdminPlus) {
            // Owner and admin see additional fields that are not appropriate
            // for the generic presentation layer (email is PII).
            response.email = operator.email;
            response.domain_verified = Boolean(operator.domain_verified);
          }
        }

        return addCors(jsonResponse(200, response));
      }

      // GET /agents/:agent_id — Resolve agent identity record (public).
      // Presentation layer unlocked by AIT, owning registrar, or admin+.
      if (method === 'GET' && path.match(/^\/agents\/(.+)$/)) {
        const agentId = decodeURIComponent(path.split('/agents/')[1]);
        const result = await handleGetAgent(agentId, env, request, registrar);
        return addCors(jsonResponse(result.status, result.body));
      }

      // GET /resolve/:did — Resolve DID to DID Document
      if (method === 'GET' && path.match(/^\/resolve\/(.+)$/)) {
        const did = decodeURIComponent(path.split('/resolve/')[1]);
        const result = await handleResolve(did, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // GET /verify?token=<AIT>
      if (method === 'GET' && path === '/verify') {
        const token = url.searchParams.get('token');
        if (token) {
          const result = await handleVerifyAIT(token, env);
          return addCors(jsonResponse(result.status, result.body));
        }
      }

      // GET /verify/:did
      if (method === 'GET' && path.match(/^\/verify\/(.+)$/)) {
        const did = decodeURIComponent(path.split('/verify/')[1]);
        const result = await handleVerifyIdentity(did, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // POST /verify/signature
      if (method === 'POST' && path === '/verify/signature') {
        const body = await request.json();
        const result = await handleVerifySignature(body, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // GET /revocation/:agent_id
      if (method === 'GET' && path.match(/^\/revocation\/(.+)$/)) {
        const agentId = decodeURIComponent(path.split('/revocation/')[1]);
        const result = await handleRevocation(agentId, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // GET /delegations/:id/chain
      if (method === 'GET' && path.match(/^\/delegations\/(.+)\/chain$/)) {
        const agentId = decodeURIComponent(path.match(/^\/delegations\/(.+)\/chain$/)[1]);
        const result = await handleVerifyChain(agentId, env);
        return addCors(jsonResponse(result.status, result.body));
      }
      // GET /delegations/:id
      if (method === 'GET' && path.match(/^\/delegations\/(.+)$/)) {
        const delegationId = decodeURIComponent(path.split('/delegations/')[1]);
        const result = await handleGetDelegation(delegationId, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // ==========================================
      // REGISTRAR-AUTHENTICATED ENDPOINTS
      // Require valid registrar API key
      // ==========================================

      if (!registrar && ['POST', 'PATCH', 'DELETE'].includes(method)) {
        return addCors(jsonResponse(401, {
          error: { code: 'unauthorized', message: 'Valid registrar API key required' }
        }));
      }

      // ==========================================
      // BREAK-GLASS ENDPOINTS (super_admin only)
      // Every call writes an audit row BEFORE the mutation.
      // These must be matched BEFORE the generic /admin/* and DELETE
      // /delegations/:id handlers so they don't fall through.
      // ==========================================

      // POST /admin/force-deactivate-agent/:agentId
      if (method === 'POST' && path.match(/^\/admin\/force-deactivate-agent\/(.+)$/)) {
        const denial = requireSuperAdmin(registrar);
        if (denial) return addCors(jsonResponse(denial.status, denial.body));
        const targetAgentId = decodeURIComponent(path.match(/^\/admin\/force-deactivate-agent\/(.+)$/)[1]);
        let body = {};
        try { body = await request.json(); } catch(e) {}
        if (!body.reason || typeof body.reason !== 'string' || !body.reason.trim()) {
          return addCors(jsonResponse(400, { error: { code: 'invalid_request', message: 'reason (non-empty string) is required' } }));
        }
        // Pre-lookup so we can record target_registrar_id (H7) on the audit
        // row. If the agent doesn't exist, return 404 before writing audit —
        // a no-op break-glass on a missing resource is not worth a row.
        const targetAgentRow = await env.DB.prepare(
          'SELECT registrar_id FROM agents WHERE axis_id = ? OR did = ? OR id = ?'
        ).bind(targetAgentId, targetAgentId, targetAgentId).first();
        if (!targetAgentRow) {
          return addCors(jsonResponse(404, { error: { code: 'agent_not_found', message: `Agent not found: ${targetAgentId}` } }));
        }
        // Audit FIRST — abort if it fails.
        try {
          await env.DB.prepare(
            `INSERT INTO audit_log (action, actor, target, registrar_id, target_registrar_id, details, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            'force_deactivate_agent',
            registrar.id,
            targetAgentId,
            registrar.id,
            targetAgentRow.registrar_id,
            JSON.stringify({ reason: body.reason, role: registrar.role }),
            request.headers.get('cf-connecting-ip')
          ).run();
        } catch (err) {
          console.error(JSON.stringify({
            tag: 'AUDIT_WRITE_FAILED',
            message: 'force-deactivate audit insert failed; mutation aborted',
            error: err && err.message ? err.message : String(err),
            action: 'force_deactivate_agent',
            actor: registrar.id,
            target: targetAgentId,
            target_registrar_id: targetAgentRow.registrar_id,
          }));
          return addCors(jsonResponse(500, { error: { code: 'audit_write_failed', message: 'Audit record could not be written; mutation aborted' } }));
        }
        const result = await forceDeactivateAgent(targetAgentId, body, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // POST /admin/force-revoke-delegation/:delegationId
      if (method === 'POST' && path.match(/^\/admin\/force-revoke-delegation\/(.+)$/)) {
        const denial = requireSuperAdmin(registrar);
        if (denial) return addCors(jsonResponse(denial.status, denial.body));
        const targetDelegationId = decodeURIComponent(path.match(/^\/admin\/force-revoke-delegation\/(.+)$/)[1]);
        let body = {};
        try { body = await request.json(); } catch(e) {}
        if (!body.reason || typeof body.reason !== 'string' || !body.reason.trim()) {
          return addCors(jsonResponse(400, { error: { code: 'invalid_request', message: 'reason (non-empty string) is required' } }));
        }
        // Pre-lookup for target_registrar_id (H7). 404 before audit if missing.
        const targetDelegationRow = await env.DB.prepare(
          'SELECT registrar_id FROM delegations WHERE id = ?'
        ).bind(targetDelegationId).first();
        if (!targetDelegationRow) {
          return addCors(jsonResponse(404, { error: { code: 'delegation_not_found', message: `Delegation not found: ${targetDelegationId}` } }));
        }
        try {
          await env.DB.prepare(
            `INSERT INTO audit_log (action, actor, target, registrar_id, target_registrar_id, details, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            'force_revoke_delegation',
            registrar.id,
            targetDelegationId,
            registrar.id,
            targetDelegationRow.registrar_id,
            JSON.stringify({ reason: body.reason, role: registrar.role }),
            request.headers.get('cf-connecting-ip')
          ).run();
        } catch (err) {
          console.error(JSON.stringify({
            tag: 'AUDIT_WRITE_FAILED',
            message: 'force-revoke audit insert failed; mutation aborted',
            error: err && err.message ? err.message : String(err),
            action: 'force_revoke_delegation',
            actor: registrar.id,
            target: targetDelegationId,
            target_registrar_id: targetDelegationRow.registrar_id,
          }));
          return addCors(jsonResponse(500, { error: { code: 'audit_write_failed', message: 'Audit record could not be written; mutation aborted' } }));
        }
        const result = await forceRevokeDelegation(targetDelegationId, body, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // POST /register
      if (method === 'POST' && path === '/register') {
        const body = await request.json();
        const result = await handleRegister(body, registrar, env);
        if (result.status === 201) {
          ctx.waitUntil(logAudit(env, {
            action: 'register_agent',
            actor: registrar.id,
            target: body.operator?.domain || body.operator?.email,
            registrar_id: registrar.id,
            // BOLA on /register: actor IS the owning registrar.
            target_registrar_id: registrar.id,
            details: { agent_id: result.body?.did },
            ip_address: request.headers.get('cf-connecting-ip')
          }));
        }
        return addCors(jsonResponse(result.status, result.body));
      }

      // PATCH /agents/:agent_id
      if (method === 'PATCH' && path.match(/^\/agents\/(.+)$/)) {
        const agentId = decodeURIComponent(path.split('/agents/')[1]);
        const body = await request.json();
        // TODO: implement handleUpdateAgent (must enforce ownership scope when implemented).
        return addCors(jsonResponse(501, {
          error: { code: 'not_implemented', message: 'Agent updates coming soon' }
        }));
      }

      // DELETE /agents/:agent_id
      if (method === 'DELETE' && path.match(/^\/agents\/(.+)$/)) {
        const agentId = decodeURIComponent(path.split('/agents/')[1]);
        let body = {};
        try { body = await request.json(); } catch(e) {}
        const result = await handleDeactivateAgent(agentId, body, registrar, env);
        if (result.status === 200) {
          ctx.waitUntil(logAudit(env, {
            action: 'deactivate_agent',
            actor: registrar.id,
            target: agentId,
            registrar_id: registrar.id,
            // BOLA on DELETE /agents: handleDeactivateAgent enforces
            // self-scope, so actor IS the owning registrar.
            target_registrar_id: registrar.id,
            details: { reason: body.reason },
            ip_address: request.headers.get('cf-connecting-ip')
          }));
        }
        return addCors(jsonResponse(result.status, result.body));
      }

      // POST /delegations
      if (method === 'POST' && path === '/delegations') {
        const body = await request.json();
        const result = await handleCreateDelegation(body, registrar, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // DELETE /delegations/:id
      if (method === 'DELETE' && path.match(/^\/delegations\/(.+)$/)) {
        const delegationId = decodeURIComponent(path.split('/delegations/')[1]);
        let body = {};
        try { body = await request.json(); } catch(e) {}
        const result = await handleRevokeDelegation(delegationId, body, registrar, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // ==========================================
      // /admin/* — admin or super_admin role required
      // (Read-only across tenants; mutations here are the break-glass
      // force-* endpoints handled above.)
      // ==========================================

      if (path.startsWith('/admin/')) {
        const denial = requireAdmin(registrar);
        if (denial) return addCors(jsonResponse(denial.status, denial.body));
      }

      // GET /admin/operators
      if (method === 'GET' && path === '/admin/operators') {
        const limit = clampPaginationInt(url.searchParams.get('limit'), 50, 500, 1);
        const offset = clampPaginationInt(url.searchParams.get('offset'), 0, Number.MAX_SAFE_INTEGER);
        const operators = await env.DB.prepare(
          'SELECT * FROM operators ORDER BY created_at DESC LIMIT ? OFFSET ?'
        ).bind(limit, offset).all();
        const count = await env.DB.prepare('SELECT COUNT(*) as total FROM operators').first();
        return addCors(jsonResponse(200, { operators: operators.results || [], total: count?.total || 0 }));
      }

      // GET /admin/agents/:agent_id
      if (method === 'GET' && path.match(/^\/admin\/agents\/(.+)$/)) {
        const agentIdentifier = decodeURIComponent(path.match(/^\/admin\/agents\/(.+)$/)[1]);
        const agent = await env.DB.prepare(
          'SELECT * FROM agents WHERE axis_id = ? OR did = ? OR id = ?'
        ).bind(agentIdentifier, agentIdentifier, agentIdentifier).first();
        if (!agent) {
          return addCors(jsonResponse(404, { error: { code: 'agent_not_found', message: `Agent not found: ${agentIdentifier}` } }));
        }
        const operator = await env.DB.prepare(
          'SELECT verification_tier, domain FROM operators WHERE id = ?'
        ).bind(agent.operator_id).first();
        return addCors(jsonResponse(200, {
          axis_version: '0.1',
          agent_id: agent.axis_id,
          did: agent.did,
          operator_id: agent.operator_id,
          display_name: agent.display_name,
          description: agent.description,
          public_key: agent.public_key,
          key_algorithm: agent.key_algorithm,
          status: agent.status,
          registration_tier: agent.registration_tier,
          created_at: agent.created_at,
          updated_at: agent.updated_at,
          revoked_at: agent.revoked_at,
          revocation_reason: agent.revocation_reason,
          service_endpoints: agent.service_endpoints ? JSON.parse(agent.service_endpoints) : null,
          operator: {
            domain: operator?.domain || null,
            verification_tier: operator?.verification_tier || null
          }
        }));
      }

      // GET /admin/agents
      if (method === 'GET' && path === '/admin/agents') {
        const limit = clampPaginationInt(url.searchParams.get('limit'), 50, 500, 1);
        const offset = clampPaginationInt(url.searchParams.get('offset'), 0, Number.MAX_SAFE_INTEGER);
        const statusFilter = url.searchParams.get('status');
        // H4 hardening: allowlist `status` against the schema's CHECK values
        // (agents.status). Reject anything outside that set with 400 — both
        // forces the schema to be the single source of truth for valid status
        // values, and removes any future risk of a downstream SQL concat
        // around this parameter. Per the 2026-05-08 security review.
        const AGENT_STATUS_VALUES = ['active', 'suspended', 'revoked', 'deactivated'];
        if (statusFilter !== null && !AGENT_STATUS_VALUES.includes(statusFilter)) {
          return addCors(jsonResponse(400, { error: { code: 'invalid_request', message: `status must be one of: ${AGENT_STATUS_VALUES.join(', ')}` } }));
        }
        // H4 hardening: two static prepared statements rather than a dynamic
        // `query += ...` concatenation. Parameterization was correct in the
        // prior implementation, but the pattern is a footgun for future
        // contributors who may not preserve it on additions. Static SQL keeps
        // it cheap to audit and impossible to regress accidentally.
        const agents = statusFilter
          ? await env.DB.prepare(
              'SELECT * FROM agents WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
            ).bind(statusFilter, limit, offset).all()
          : await env.DB.prepare(
              'SELECT * FROM agents ORDER BY created_at DESC LIMIT ? OFFSET ?'
            ).bind(limit, offset).all();
        const countQuery = statusFilter
          ? await env.DB.prepare('SELECT COUNT(*) as total FROM agents WHERE status = ?').bind(statusFilter).first()
          : await env.DB.prepare('SELECT COUNT(*) as total FROM agents').first();
        return addCors(jsonResponse(200, { agents: agents.results || [], total: countQuery?.total || 0 }));
      }

      // GET /admin/audit
      if (method === 'GET' && path === '/admin/audit') {
        const limit = clampPaginationInt(url.searchParams.get('limit'), 100, 500, 1);
        const offset = clampPaginationInt(url.searchParams.get('offset'), 0, Number.MAX_SAFE_INTEGER);
        const logs = await env.DB.prepare(
          'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        ).bind(limit, offset).all();
        return addCors(jsonResponse(200, { logs: logs.results || [] }));
      }

      // GET /admin/stats
      if (method === 'GET' && path === '/admin/stats') {
        const [agents, operators, delegations, activeAgents] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) as total FROM agents').first(),
          env.DB.prepare('SELECT COUNT(*) as total FROM operators').first(),
          env.DB.prepare('SELECT COUNT(*) as total FROM delegations').first(),
          env.DB.prepare("SELECT COUNT(*) as total FROM agents WHERE status = 'active'").first(),
        ]);
        return addCors(jsonResponse(200, {
          total_agents: agents?.total || 0,
          active_agents: activeAgents?.total || 0,
          total_operators: operators?.total || 0,
          total_delegations: delegations?.total || 0
        }));
      }

      // POST /operators/verify-domain
      if (method === 'POST' && path === '/operators/verify-domain') {
        const body = await request.json();
        const result = await handleVerifyDomain(body, registrar, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // POST /operators/verify-domain/check
      if (method === 'POST' && path === '/operators/verify-domain/check') {
        const body = await request.json();
        const result = await handleCheckDomain(body, registrar, env);
        return addCors(jsonResponse(result.status, result.body));
      }

      // 404
      return addCors(jsonResponse(404, {
        error: { code: 'not_found', message: `No route for ${method} ${path}` }
      }));

    } catch (err) {
      // M7: decodeURIComponent on malformed percent-encoding throws URIError;
      // surface as a client-error 400 instead of a generic 500. This catches
      // every decodeURIComponent call site in the file at once without
      // requiring 14 inline try/catch wrappers.
      if (err instanceof URIError) {
        return addCors(jsonResponse(400, {
          error: { code: 'invalid_encoding', message: 'URL contains malformed percent-encoding' }
        }));
      }
      console.error('Unhandled error:', err);
      return addCors(jsonResponse(500, {
        error: { code: 'internal_error', message: 'Internal server error' }
      }));
    }
  }
};

function jsonResponse(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders }
  });
}

/**
 * Decide which rate-limit tier (if any) a given request falls under and
 * what its bucket key should be. Returns null for routes we intentionally
 * leave unrated (e.g. `OPTIONS` preflight, `/.well-known/axis-access`
 * health-style reads).
 *
 * Keep the matching loose — the tier check is defense-in-depth and we
 * don't need the bucket to be perfectly partitioned by route. Where two
 * tiers could apply (e.g. an authenticated mutation), the more specific
 * (REGISTRAR / AUTH_FAIL) wins over PUBLIC_READ.
 */
async function pickRateLimitTier(method, path, registrar, request) {
  // Skip preflights and the well-known health endpoint.
  if (method === 'OPTIONS') return null;
  if (path === '/.well-known/axis-access') return null;

  const mutating = ['POST', 'PATCH', 'DELETE'].includes(method);

  // Mutating requests without a valid Bearer = AUTH_FAIL tier (slows brute force).
  if (mutating && !registrar) {
    return { tier: RATE_LIMIT_TIERS.AUTH_FAIL, key: ipKey(request) };
  }

  // Mutating requests with a valid Bearer = REGISTRAR tier (per-key bucket).
  if (mutating && registrar) {
    return { tier: RATE_LIMIT_TIERS.REGISTRAR, key: `reg:${registrar.id}` };
  }

  // GET /verify (token mode) and POST /verify/signature are the only
  // CPU-heavy public paths. POST /verify/signature is caught by the
  // mutating-without-auth branch above when unauthed, but the GET /verify
  // path is here. Tier on the more conservative VERIFY_SIG bucket.
  if (method === 'GET' && path === '/verify') {
    return { tier: RATE_LIMIT_TIERS.PUBLIC_VERIFY_SIG, key: ipKey(request) };
  }

  // Everything else that's a read = PUBLIC_READ.
  if (method === 'GET') {
    return { tier: RATE_LIMIT_TIERS.PUBLIC_READ, key: ipKey(request) };
  }

  return null;
}

/**
 * Parse a query-string pagination integer with bounds.
 * Caps unbounded inputs (e.g. ?limit=999999), demotes NaN/negative/below-min to
 * the default, and clamps to a server-side maximum so a single request can't
 * scan the whole table.
 *
 * `min` is the smallest acceptable value (default 0 — fine for offsets).
 * Callers using this for LIMIT should pass `min = 1` so `?limit=0` (a no-op
 * query that returns zero rows) is demoted to the default. H5 hardening per
 * the 2026-05-08 security review.
 */
function clampPaginationInt(raw, defaultValue, max, min = 0) {
  if (raw === null || raw === undefined || raw === '') return defaultValue;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n < min) return defaultValue;
  return Math.min(n, max);
}

function addCors(response) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  return new Response(response.body, {
    status: response.status,
    headers
  });
}
