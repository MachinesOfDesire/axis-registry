/**
 * Audit Logging
 * Immutable log of all registry operations.
 */

export async function logAudit(env, entry) {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_log (action, actor, target, operator_id, registrar_id, details, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      entry.action,
      entry.actor,
      entry.target || null,
      entry.operator_id || null,
      entry.registrar_id || null,
      entry.details ? JSON.stringify(entry.details) : null,
      entry.ip_address || null
    ).run();
  } catch (err) {
    console.error('Audit log error:', err);
    // Don't fail the request if audit logging fails
  }
}
