/**
 * CORS Middleware
 *
 * All endpoints are CORS-open — verification must be accessible from
 * anywhere (any website embedding an AXIS verify widget, any agent making
 * an in-browser /resolve call, etc).
 *
 * M8 (2026-05-08 security review): the wildcard `Access-Control-Allow-Origin: *`
 * combined with `Access-Control-Allow-Headers: Authorization` raises a flag
 * on review tools. This combination IS intentional and safe; the explanation:
 *
 *   1. We deliberately do NOT set `Access-Control-Allow-Credentials: true`.
 *      Per the CORS spec, wildcard origin + `Allow-Credentials: false` means
 *      the browser will refuse to send an Authorization header from a
 *      foreign-origin request. The header in `Allow-Headers` advertises
 *      support but the browser-side gating prevents abuse.
 *
 *   2. Authenticated Bearer-token traffic to the registry is server-to-server
 *      (SDK, curl, registrar workers) — not browser code. CORS doesn't apply
 *      there.
 *
 *   3. Public-layer reads (GET /agents/:id, /resolve, /verify) genuinely need
 *      to work from any origin so verification widgets embedded on any
 *      website can resolve AXIS identities without us pre-approving every
 *      consumer.
 *
 * The net effect: browser-side foreign-origin code CAN read public responses
 * (the use case we want) but CANNOT smuggle Bearer credentials into the
 * registry (the abuse we want to prevent). Documented per Cross-Project
 * Coordination M8.
 */

export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  // Intentionally NOT setting Access-Control-Allow-Credentials. See header
  // comment above — this is what makes the wildcard origin safe.
  'Access-Control-Max-Age': '86400',
};

export function handleOptions(request) {
  return new Response(null, { status: 204, headers: corsHeaders });
}
