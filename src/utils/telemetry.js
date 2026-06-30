/**
 * Verify-event telemetry — minimal adoption/activity capture.
 *
 * One row per AIT verify, written via `ctx.waitUntil` OFF the hot path, so it
 * never adds latency to the free/unlimited verify endpoint and a write failure
 * never affects the verdict. Captures only AXIS-internal identifiers (aud /
 * agent / operator / tier / outcome) — never platform content or platform
 * users. See migrations/0008_verify_events.sql for the derived metrics.
 *
 * Scale path: at high volume, swap the D1 insert for Cloudflare Analytics
 * Engine (sampled, zero-DB) — the call site in index.js stays the same.
 */

/** Best-effort decode of the AIT's `aud` claim (the target platform). */
export function decodeAud(token) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return payload && typeof payload.aud === 'string' && payload.aud.trim() ? payload.aud : null;
  } catch {
    return null;
  }
}

/**
 * Record one verify event. Never throws — telemetry must not affect
 * verification. Call as `ctx.waitUntil(recordVerifyEvent(env, token, result))`.
 *
 * @param {object} env     Worker env (needs env.DB, a D1 binding).
 * @param {string} token   The AIT that was verified (for the `aud` claim).
 * @param {{status:number, body:object}} result  The handleVerifyAIT result.
 */
export async function recordVerifyEvent(env, token, result) {
  try {
    if (!env || !env.DB) return;
    const body = (result && result.body) || {};
    const valid = body.valid === true;
    const code = valid ? null : body.code || null;
    const aud = decodeAud(token);
    const agentId = body.agent_id || null;
    const operatorId = body.operator_id || null;

    // operator_tier is slow-changing; stamp it on the event (point-in-time)
    // rather than relying on a live lookup later. Best-effort, off the hot path.
    let operatorTier = null;
    if (operatorId) {
      const m = /^axis:(.+):operator$/.exec(operatorId);
      const slug = m ? m[1] : operatorId;
      try {
        const op = await env.DB.prepare(
          'SELECT verification_tier FROM operators WHERE id = ?'
        ).bind(slug).first();
        operatorTier = (op && op.verification_tier) || null;
      } catch {
        /* tier is best-effort; leave null */
      }
    }

    await env.DB.prepare(
      `INSERT INTO verify_events (ts, aud, agent_id, operator_id, operator_tier, valid, code)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(Date.now(), aud, agentId, operatorId, operatorTier, valid ? 1 : 0, code).run();
  } catch (err) {
    try {
      console.error(JSON.stringify({
        tag: 'VERIFY_EVENT_WRITE_FAILED',
        error: err && err.message ? err.message : String(err),
      }));
    } catch {
      /* never let telemetry surface an error */
    }
  }
}
