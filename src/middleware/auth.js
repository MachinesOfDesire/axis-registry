/**
 * Registrar Authentication Middleware
 *
 * Registrars authenticate with API keys via Bearer token.
 * The registry stores SHA-256 hashes of API keys, never the keys themselves.
 *
 * Three-role model:
 *   - 'registrar'    (default) — can only touch resources where registrar_id = self
 *   - 'admin'                   — full READ across tenants; mutations still self-scoped
 *   - 'super_admin'             — admin + break-glass /admin/force-* mutation endpoints
 */

export async function authenticateRegistrar(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const apiKey = authHeader.slice(7);
  const keyHash = await hashApiKey(apiKey);

  const registrar = await env.DB.prepare(
    'SELECT id, name, type, domain, status, role FROM registrars WHERE api_key_hash = ? AND status = ?'
  ).bind(keyHash, 'active').first();

  if (!registrar) return null;

  // Defensive default: any row without a role (e.g. pre-migration) gets the
  // least-privileged role. Unknown role values also get demoted.
  if (!registrar.role || !['registrar', 'admin', 'super_admin'].includes(registrar.role)) {
    registrar.role = 'registrar';
  }

  return registrar;
}

/**
 * True if the registrar has admin or super_admin role.
 * Admin+ roles get cross-tenant READ access; normal-path mutations remain
 * scoped to the registrar's own registrar_id (use /admin/force-* for
 * break-glass cross-tenant mutations).
 */
export function isAdmin(registrar) {
  return !!registrar && (registrar.role === 'admin' || registrar.role === 'super_admin');
}

/**
 * True only if the registrar has super_admin role.
 * Required for /admin/force-* break-glass endpoints.
 */
export function isSuperAdmin(registrar) {
  return !!registrar && registrar.role === 'super_admin';
}

/**
 * Returns a 403 response body object when caller is not admin+, otherwise null.
 * Usage:
 *   const denial = requireAdmin(registrar);
 *   if (denial) return addCors(jsonResponse(denial.status, denial.body));
 */
export function requireAdmin(registrar) {
  // Standard HTTP distinction: 401 for unauthenticated, 403 for
  // authenticated-but-insufficient-role. Returning 403 for an
  // unauthenticated caller muddles the two and breaks conformance tools
  // that key off the code.
  if (!registrar) {
    return {
      status: 401,
      body: { error: { code: 'unauthorized', message: 'Valid registrar API key required' } }
    };
  }
  if (isAdmin(registrar)) return null;
  return {
    status: 403,
    body: { error: { code: 'forbidden', message: 'Admin role required' } }
  };
}

export function requireSuperAdmin(registrar) {
  if (!registrar) {
    return {
      status: 401,
      body: { error: { code: 'unauthorized', message: 'Valid registrar API key required' } }
    };
  }
  if (isSuperAdmin(registrar)) return null;
  return {
    status: 403,
    body: { error: { code: 'forbidden', message: 'super_admin role required' } }
  };
}

/**
 * Standard BOLA denial response for normal-path mutations where caller is
 * not the owning registrar. Admin+ callers also hit this on normal paths —
 * they must use the /admin/force-* break-glass endpoints for cross-tenant
 * mutations (which write audit rows).
 */
export function notYourResource(message = 'You are not authorized to modify this resource') {
  return {
    status: 403,
    body: { error: { code: 'not_your_resource', message } }
  };
}

export async function hashApiKey(key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
