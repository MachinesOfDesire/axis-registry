/**
 * Rate Limiting Middleware
 *
 * Wraps Cloudflare Workers' built-in `RateLimit` binding. Each tier maps to
 * a separate binding declared in `wrangler.toml` (`[[ratelimits]]`); the
 * worker code chooses a tier per request and supplies the bucket key.
 *
 * Tiers (defaults — tune in wrangler.toml):
 *
 *   RL_PUBLIC_READ         6000 req/min per IP
 *     /agents/:id, /resolve/:did, /verify/:did, /revocation/:agent_id,
 *     /delegations/:id, /delegations/:id/chain, /.well-known/axis-access
 *     — high ceiling because every AI-comment verification on a host
 *     platform translates to one read here.
 *
 *   RL_PUBLIC_VERIFY_SIG   600 req/min per IP
 *     POST /verify/signature, GET /verify?token=…
 *     — lower ceiling because Ed25519 verify is the most expensive thing
 *     a public endpoint does. Still ~10/sec; a chatty platform can
 *     comfortably exceed this and *should* be authenticated as a
 *     registrar (which puts them on the RL_REGISTRAR tier instead).
 *
 *   RL_REGISTRAR           300 req/min per registrar key
 *     POST /register, POST /delegations, DELETE /agents/*, DELETE
 *     /delegations/*, POST /operators/verify-domain, POST /operators/
 *     verify-domain/check, PATCH /agents/*, /admin/*.
 *     — keyed on registrar.id (already-authenticated). A registrar can
 *     onboard up to 5 agents/sec sustained; bursts are buffered by D1.
 *
 *   RL_AUTH_FAIL           30 req/min per IP
 *     Any mutating request that arrives without a valid Bearer.
 *     — narrow funnel; legitimate registrars never trip this. Slows
 *     brute-force.
 *
 * If a binding is unset (e.g. local dev), the helper is a no-op and
 * `success` is treated as `true`. Production deploys MUST set all four
 * bindings; the `wrangler.toml.example` block is the canonical reference.
 *
 * 429 responses include a `Retry-After: 60` header (CF Rate Limiting uses
 * 60s windows) and a JSON body with a stable error code so clients can
 * back off cleanly.
 */

const RATE_LIMIT_TIERS = {
  PUBLIC_READ: 'RL_PUBLIC_READ',
  PUBLIC_VERIFY_SIG: 'RL_PUBLIC_VERIFY_SIG',
  REGISTRAR: 'RL_REGISTRAR',
  AUTH_FAIL: 'RL_AUTH_FAIL',
};

/**
 * Check the configured tier. Returns null if the request is allowed (caller
 * proceeds), or a response object `{ status: 429, body: {...}, headers: {...} }`
 * if it should be rejected.
 *
 * @param {object} env       Worker env with rate-limit bindings.
 * @param {string} tier      One of the RATE_LIMIT_TIERS values.
 * @param {string} key       Bucket key (IP, registrar id, etc.).
 * @param {object} request   Original request (used for the structured log line).
 * @param {object} ctx       Worker context (used for log fan-out only).
 * @returns {Promise<null|{status:number, body:object, headers:object}>}
 */
export async function checkRateLimit(env, tier, key, request, ctx) {
  const binding = env[tier];
  // No binding configured — treat as no-op. Useful for local dev and for
  // forks that don't want to wire rate limiting at all.
  if (!binding || typeof binding.limit !== 'function') return null;

  // Cloudflare's API: `await binding.limit({ key })` → { success: boolean }
  let result;
  try {
    result = await binding.limit({ key });
  } catch (err) {
    // Never fail the request because rate limiting itself failed.
    // Log structured so we'd notice if the binding is misconfigured.
    console.error(JSON.stringify({
      tag: 'RATE_LIMIT_CHECK_FAILED',
      message: 'rate-limit binding threw; allowing request through',
      tier,
      key_prefix: key.slice(0, 16),
      error: err && err.message ? err.message : String(err),
    }));
    return null;
  }

  if (result && result.success === false) {
    // Structured log so Logpush can route to Discord/Slack/email.
    // `key` is left as the prefix (first 16 chars) to avoid logging full
    // API keys or full IPs at high cardinality. Cloudflare's request log
    // already has the unmasked IP if forensics are needed.
    console.warn(JSON.stringify({
      tag: 'RATE_LIMIT_HIT',
      message: 'rate-limit tier exceeded',
      tier,
      key_prefix: key.slice(0, 16),
      url: request.url,
      method: request.method,
      cf_ray: request.headers.get('cf-ray') || null,
    }));
    return {
      status: 429,
      body: {
        error: {
          code: 'rate_limit_exceeded',
          message: `Rate limit exceeded for ${tier}. Retry after 60s.`,
        },
      },
      headers: { 'Retry-After': '60' },
    };
  }

  return null;
}

/**
 * Convenience: derive the per-IP key used by the public tiers.
 * Falls back to a constant if the header is missing (local dev / unusual
 * proxy setups) so all such traffic shares one bucket — which is fine,
 * because it's not real production traffic.
 */
export function ipKey(request) {
  return request.headers.get('cf-connecting-ip') || 'no-ip';
}

export { RATE_LIMIT_TIERS };
