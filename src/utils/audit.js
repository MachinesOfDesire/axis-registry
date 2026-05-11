/**
 * Audit Logging
 * Immutable log of all registry operations.
 *
 * Failure semantics: on normal mutation paths (/register, DELETE /agents,
 * DELETE /delegations) audit is written via `ctx.waitUntil(logAudit(...))`
 * AFTER the mutation. If the audit insert fails, the mutation is already
 * committed — we cannot roll it back. Per the 2026-05-08 security review
 * (H6) we route audit failures into a structured log line tagged
 * `AUDIT_WRITE_FAILED` so Cloudflare Logpush / Tail filters can detect the
 * gap and operations can reconstruct or alert.
 *
 * Break-glass paths (/admin/force-*) do NOT use this helper — they write
 * the audit row inline BEFORE the mutation and abort with HTTP 500 if the
 * insert fails. That stricter ordering is appropriate for rare, high-blast
 * super_admin actions; on normal high-volume paths, surfacing transient D1
 * write failures as user-visible 500s would do more harm than the audit
 * gap itself.
 */

export async function logAudit(env, entry) {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_log (action, actor, target, operator_id, registrar_id, target_registrar_id, details, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      entry.action,
      entry.actor,
      entry.target || null,
      entry.operator_id || null,
      entry.registrar_id || null,
      entry.target_registrar_id || null,
      entry.details ? JSON.stringify(entry.details) : null,
      entry.ip_address || null
    ).run();
  } catch (err) {
    // Structured failure log so Logpush filters can detect missed audit rows.
    // Keep the fields aligned with the audit_log columns so the lost entry
    // can be reconstructed from the log line if needed. Don't include the
    // raw error object — that can contain stack traces with internal paths.
    console.error(JSON.stringify({
      tag: 'AUDIT_WRITE_FAILED',
      message: 'audit_log insert failed; mutation already committed',
      error: err && err.message ? err.message : String(err),
      entry: {
        action: entry.action,
        actor: entry.actor,
        target: entry.target || null,
        operator_id: entry.operator_id || null,
        registrar_id: entry.registrar_id || null,
        target_registrar_id: entry.target_registrar_id || null,
        // details intentionally omitted — may contain user-supplied content;
        // the structured tag + ids is enough to investigate and re-add if
        // the audit_log row is rebuilt.
        ip_address: entry.ip_address || null,
      },
    }));
    // Don't fail the request if audit logging fails.
  }
}
