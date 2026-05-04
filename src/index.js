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
      // PUBLIC ENDPOINTS (no auth required)
      // Free, unlimited, no rate limits
      // ==========================================

      // GET /.well-known/axis-access — Platform-side access control policy
      if (method === 'GET' && path === '/.well-known/axis-access') {
        const registryBase = env.REGISTRY_BASE_URL || 'https://axis-registry.editor-9a4.workers.dev';
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
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 500);
        const offset = parseInt(url.searchParams.get('offset') || '0');
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
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);
        const offset = parseInt(url.searchParams.get('offset') || '0');
        const logs = await env.DB.prepare(
          'SELECT * FROM audit_log WHERE registrar_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        ).bind(registrar.id, limit, offset).all();
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

        const registryBase = env.REGISTRY_BASE_URL || 'https://axis-registry.editor-9a4.workers.dev';

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
        // Audit FIRST — abort if it fails.
        try {
          await env.DB.prepare(
            `INSERT INTO audit_log (action, actor, target, registrar_id, details, ip_address)
             VALUES (?, ?, ?, ?, ?, ?)`
          ).bind(
            'force_deactivate_agent',
            registrar.id,
            targetAgentId,
            registrar.id,
            JSON.stringify({ reason: body.reason, role: registrar.role }),
            request.headers.get('cf-connecting-ip')
          ).run();
        } catch (err) {
          console.error('Force-deactivate audit write failed:', err);
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
        try {
          await env.DB.prepare(
            `INSERT INTO audit_log (action, actor, target, registrar_id, details, ip_address)
             VALUES (?, ?, ?, ?, ?, ?)`
          ).bind(
            'force_revoke_delegation',
            registrar.id,
            targetDelegationId,
            registrar.id,
            JSON.stringify({ reason: body.reason, role: registrar.role }),
            request.headers.get('cf-connecting-ip')
          ).run();
        } catch (err) {
          console.error('Force-revoke audit write failed:', err);
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
        const limit = parseInt(url.searchParams.get('limit') || '50');
        const offset = parseInt(url.searchParams.get('offset') || '0');
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
        const limit = parseInt(url.searchParams.get('limit') || '50');
        const offset = parseInt(url.searchParams.get('offset') || '0');
        const status = url.searchParams.get('status');
        let query = 'SELECT * FROM agents';
        const params = [];
        if (status) { query += ' WHERE status = ?'; params.push(status); }
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);
        const agents = await env.DB.prepare(query).bind(...params).all();
        const countQuery = status
          ? await env.DB.prepare('SELECT COUNT(*) as total FROM agents WHERE status = ?').bind(status).first()
          : await env.DB.prepare('SELECT COUNT(*) as total FROM agents').first();
        return addCors(jsonResponse(200, { agents: agents.results || [], total: countQuery?.total || 0 }));
      }

      // GET /admin/audit
      if (method === 'GET' && path === '/admin/audit') {
        const limit = parseInt(url.searchParams.get('limit') || '100');
        const offset = parseInt(url.searchParams.get('offset') || '0');
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
      console.error('Unhandled error:', err);
      return addCors(jsonResponse(500, {
        error: { code: 'internal_error', message: 'Internal server error' }
      }));
    }
  }
};

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
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
