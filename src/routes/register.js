/**
 * Registration Endpoint
 * Registrar-authenticated. Registrars submit agent registrations on behalf of operators.
 *
 * POST /register
 */

import { deriveAgentId, verifyEd25519Signature, generateToken, base64urlToBytes, bytesToBase58 } from '../utils/crypto.js';
import { buildAxisDidV2 } from '../utils/did.js';
import { verifyCanonicalProof } from '../utils/proof.js';

export async function handleRegister(body, registrar, env) {
  // Validate required fields
  if (!body.publicKey) {
    return { status: 400, body: { error: { code: 'invalid_request', message: 'Missing required field: publicKey' } } };
  }
  if (!body.operator || (!body.operator.domain && !body.operator.email)) {
    return { status: 400, body: { error: { code: 'invalid_request', message: 'Missing required field: operator.domain or operator.email' } } };
  }

  // Find the operator by domain or email. This endpoint does NOT create
  // operators; callers must have run /operators/verify-domain first, which
  // is where the operator_id is assigned. The id is deliberately not
  // derivable from the request body here — we look up by the registered
  // domain/email and inherit whatever opaque id the create path assigned.
  // (Historical note: earlier versions derived id from email.split('@')[0],
  // which leaked PII into the public layer. Fixed April 23, 2026.)
  // M1: coerce empty/missing to NULL. Binding '' would silently match a
  // row whose domain or email was stored as the empty string (drift) and
  // would not match NULL rows in either case (since `'' = NULL` is unknown).
  // NULL bind keeps `domain = NULL` unmatched and is the correct signal for
  // "no value provided," surfacing the missing-operator case as a 404.
  const opDomain = body.operator.domain ? body.operator.domain : null;
  const opEmail = body.operator.email ? body.operator.email : null;
  let operator = await env.DB.prepare(
    'SELECT * FROM operators WHERE domain = ? OR email = ?'
  ).bind(opDomain, opEmail).first();

  if (!operator) {
    return {
      status: 403,
      body: { error: { code: 'operator_not_found', message: 'Operator must be registered and verified before registering agents. Use /operators/verify-domain first.' } }
    };
  }

  // BOLA: operator must belong to the calling registrar. Admin+ callers get
  // the same rule on the normal path — to register under another registrar's
  // operator they would need a dedicated force endpoint (not provided).
  if (operator.registrar_id !== registrar.id) {
    return {
      status: 403,
      body: { error: { code: 'not_your_resource', message: 'Operator belongs to a different registrar' } }
    };
  }

  // Check operator status
  if (operator.status !== 'active') {
    return {
      status: 403,
      body: { error: { code: 'operator_not_verified', message: `Operator status: ${operator.status}` } }
    };
  }

  // Check domain verification for domain-verified tier
  if (operator.verification_tier === 'domain' && !operator.domain_verified) {
    return {
      status: 403,
      body: { error: { code: 'domain_not_verified', message: 'Domain verification required. Complete domain verification first.' } }
    };
  }

  // Velocity cap (Pre-Launch Engineering Brief §3.4): no operator may
  // register more than VELOCITY_LIMIT agents in any rolling
  // VELOCITY_WINDOW_HOURS-hour window, independent of tier. Stops
  // bulk-pump abuse even when the operator is well within their per-tier
  // slot cap.
  //
  // Counts succeeded-registrations only (rows in the `agents` table),
  // so failed requests don't burn quota. The cap fires AFTER ownership +
  // operator-status + domain-verification gates but BEFORE the atomic
  // slot allocation — so a denied register here doesn't decrement the
  // operator's slot counts.
  //
  // Returns 429 with `Retry-After` computed from the 10th-most-recent
  // registration's created_at + window (when one exists) so callers
  // know exactly how long to wait. Floor of 60s on Retry-After avoids a
  // tight retry storm.
  //
  // Race semantics: COUNT-then-INSERT is not atomic. Two concurrent
  // requests at the boundary could both pass the COUNT and both INSERT,
  // yielding 11 instead of 10. Acceptable for an anti-abuse signal —
  // the per-tier slot cap (atomic) remains the primary defense and the
  // velocity cap is intentionally a soft brake on bulk-pump patterns,
  // not a hard authorization gate.
  const VELOCITY_LIMIT = 10;
  const VELOCITY_WINDOW_HOURS = 24;
  // datetime() normalization on the stored column matters: created_at is
  // written as ISO 8601 with a 'T' separator and a 'Z' suffix
  // (`new Date().toISOString()`), while SQLite's `datetime('now', ...)`
  // returns a value with a space separator. Raw string comparison would
  // sort 'T' (0x54) AFTER space (0x20), so an ISO timestamp on the same
  // calendar date as the cutoff would always compare greater, regardless
  // of actual time. Wrapping created_at in datetime() canonicalizes both
  // sides into the same format before comparison.
  const velocityCountRow = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM agents
      WHERE operator_id = ?
        AND datetime(created_at) > datetime('now', ?)`
  ).bind(operator.id, `-${VELOCITY_WINDOW_HOURS} hours`).first();
  if ((velocityCountRow?.n || 0) >= VELOCITY_LIMIT) {
    let retryAfterSec = VELOCITY_WINDOW_HOURS * 3600;
    const oldestInWindow = await env.DB.prepare(
      `SELECT created_at FROM agents
        WHERE operator_id = ?
        ORDER BY created_at DESC
        LIMIT 1 OFFSET ?`
    ).bind(operator.id, VELOCITY_LIMIT - 1).first();
    if (oldestInWindow) {
      const oldestMs = Date.parse(oldestInWindow.created_at);
      if (Number.isFinite(oldestMs)) {
        const remainingMs = oldestMs + VELOCITY_WINDOW_HOURS * 3600 * 1000 - Date.now();
        retryAfterSec = Math.max(60, Math.ceil(remainingMs / 1000));
      }
    }
    return {
      status: 429,
      body: {
        error: {
          code: 'velocity_limit_reached',
          message: `Operator has registered the maximum ${VELOCITY_LIMIT} agents in the last ${VELOCITY_WINDOW_HOURS} hours. Try again later.`,
        },
      },
      headers: { 'Retry-After': String(retryAfterSec) },
    };
  }

  // C2 (2026-05-08 security review): atomic slot allocation.
  //
  // Previously this was a three-step Read→Check→Increment sequence with
  // no atomicity between the cap check (line 87) and the eventual UPDATE
  // (line 169). Two concurrent POST /register for the same operator could
  // both pass the cap check at line 87, both INSERT, both INCREMENT —
  // operator ends up with max_agents + 1 rows.
  //
  // The fix: do the slot allocation BEFORE the INSERT, as a single
  // UPDATE-with-predicate. SQLite serializes UPDATEs within a row, so
  // two concurrent attempts at the last free slot can't both succeed.
  // The UPDATE's predicate (`free_slots_used < free_slots_total`) is
  // the cap check; meta.changes tells us whether we won the race.
  //
  // Two-tier fallback: try free first; if it didn't match, try paid
  // (with the cap baked into the predicate). Neither matches → 403.
  //
  // The INSERT happens AFTER successful slot reservation. If INSERT
  // later fails (unlikely — agent_id collision was already checked, but
  // could happen on transient D1 errors), we best-effort decrement the
  // slot in the catch block at the bottom of this handler. Minor
  // inconsistency on rare failure is better than the over-allocation
  // race we had before.

  // First: confirm the slot row exists at all. If not, surface the same
  // 500 we did before (this would be a fresh operator without an
  // agent_slots row — schema integrity issue, not a race condition).
  const slotsExists = await env.DB.prepare(
    'SELECT 1 FROM agent_slots WHERE operator_id = ?'
  ).bind(operator.id).first();
  if (!slotsExists) {
    return { status: 500, body: { error: { code: 'internal_error', message: 'Agent slot record not found for operator' } } };
  }

  // Atomic slot allocation: try free, fall through to paid.
  let tier = null;
  const freeAttempt = await env.DB.prepare(
    `UPDATE agent_slots
        SET free_slots_used = free_slots_used + 1
      WHERE operator_id = ?
        AND free_slots_used < free_slots_total`
  ).bind(operator.id).run();
  if (freeAttempt.meta?.changes === 1) {
    tier = 'free';
  } else {
    const paidAttempt = await env.DB.prepare(
      `UPDATE agent_slots
          SET paid_agents = paid_agents + 1
        WHERE operator_id = ?
          AND (max_agents IS NULL OR free_slots_used + paid_agents < max_agents)`
    ).bind(operator.id).run();
    if (paidAttempt.meta?.changes === 1) {
      tier = 'paid';
    } else {
      return {
        status: 403,
        body: { error: { code: 'slot_limit_reached', message: 'Operator agent quota exhausted' } }
      };
    }
  }

  // Derive agent ID from public key
  let agentIdHash;
  try {
    agentIdHash = await deriveAgentId(body.publicKey);
  } catch (err) {
    console.error('deriveAgentId error:', err);
    return { status: 400, body: { error: { code: 'invalid_key', message: 'Failed to process public key' } } };
  }
  const agentName = body.metadata?.name || agentIdHash;
  const agentId = agentName.toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const axisId = `axis:${operator.id}:${agentId}`;
  // C1 (spec v0.2 §10.3): v0.2 canonical DID is operator-namespaced.
  // v0.1 form `did:axis:prime:<agent>` remains resolvable for legacy rows
  // (findAgent accepts both via src/utils/did.js parseAxisDid), but every
  // newly-registered agent gets the v0.2 form.
  const did = buildAxisDidV2('prime', operator.id, agentId);

  // Check for collisions
  const existing = await env.DB.prepare(
    'SELECT id FROM agents WHERE axis_id = ? OR did = ?'
  ).bind(axisId, did).first();

  if (existing) {
    return {
      status: 409,
      body: { error: { code: 'agent_already_exists', message: 'Agent ID collision' } }
    };
  }

  // Verify proof of key ownership (if proof provided).
  //
  // v0.2 §6.1: the client signs the canonical form of the request body MINUS
  // the `proof` field. `proofType: "jcs-eddsa-2026"` ⇒ RFC 8785 JCS;
  // `proofType` absent ⇒ legacy v0.1 canonicalization (JCS attempted first,
  // legacy as fallback). Any other proofType is unrecognized and rejected.
  if (body.proof) {
    const proofInput = { ...body };
    delete proofInput.proof;

    const result = await verifyCanonicalProof({
      payload: proofInput,
      proofValue: body.proof.proofValue,
      proofType: body.proof.proofType,
      publicKey: body.publicKey,
    });

    if (result.unsupported) {
      return {
        status: 400,
        body: { error: { code: 'unsupported_proof_type', message: `Unrecognized proof type: ${result.proofType}. Supported: jcs-eddsa-2026 (or omit proofType for legacy).` } }
      };
    }

    if (!result.valid) {
      return {
        status: 400,
        body: { error: { code: 'invalid_proof', message: 'Proof of key ownership verification failed' } }
      };
    }
  }

  const now = new Date().toISOString();

  // Insert the agent. The slot was atomically reserved above, so the
  // increment is already in agent_slots. If INSERT fails here (rare —
  // we already checked for axis_id/did collision; this would be a
  // transient D1 error or a race with a competing registration for the
  // same agent_id slug), best-effort release the slot back so the
  // operator's quota isn't permanently consumed.
  try {
    await env.DB.prepare(
      `INSERT INTO agents (id, axis_id, did, operator_id, display_name, description, public_key, key_algorithm, status, registration_tier, registrar_id, service_endpoints, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'Ed25519', 'active', ?, ?, ?, ?, ?)`
    ).bind(
      agentId,
      axisId,
      did,
      operator.id,
      body.metadata?.name || agentId,
      body.metadata?.description || null,
      body.publicKey,
      tier,
      registrar.id,
      body.service ? JSON.stringify(body.service) : null,
      now,
      now
    ).run();
  } catch (err) {
    // Slot was reserved but agent INSERT failed. Best-effort decrement.
    // Structured log so we'd notice if this happens at any frequency.
    console.error(JSON.stringify({
      tag: 'AGENT_INSERT_FAILED_AFTER_SLOT_RESERVED',
      operator_id: operator.id,
      tier,
      agent_id: agentId,
      error: err && err.message ? err.message : String(err),
    }));
    try {
      const column = tier === 'free' ? 'free_slots_used' : 'paid_agents';
      await env.DB.prepare(
        `UPDATE agent_slots SET ${column} = MAX(0, ${column} - 1) WHERE operator_id = ?`
      ).bind(operator.id).run();
    } catch (rollbackErr) {
      console.error(JSON.stringify({
        tag: 'SLOT_ROLLBACK_FAILED',
        operator_id: operator.id,
        tier,
        error: rollbackErr && rollbackErr.message ? rollbackErr.message : String(rollbackErr),
      }));
    }
    throw err;
  }

  // Build response. Top-level fields mirror the AXIS Agent Identity Record
  // shape (per spec v0.1) so clients can read identity essentials without
  // digging into the DID document's axisMetadata. Nested `document` stays
  // for W3C DID Document compatibility.
  return {
    status: 201,
    body: {
      did,
      axis_id: axisId,
      operator_id: `axis:${operator.id}:operator`,
      document: {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1',
          'https://axis-protocol.org/ns/v1'
        ],
        id: did,
        controller: did,
        verificationMethod: [{
          id: `${did}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyMultibase: `z${bytesToBase58(base64urlToBytes(body.publicKey))}`
        }],
        authentication: [`${did}#key-1`],
        assertionMethod: [`${did}#key-1`],
        axisMetadata: {
          registered: now,
          registry: 'prime',
          operator: {
            id: operator.id,
            domain: operator.domain,
            verified: Boolean(operator.domain_verified)
          },
          status: 'active'
        }
      },
      registrationReceipt: {
        registry: 'prime',
        timestamp: now,
        agentSlot: await buildSlotReceipt(env, operator)
      }
    }
  };
}

/**
 * Read post-allocation slot state for the registration response. Always
 * does a fresh SELECT (after C2's atomic UPDATE, the in-memory snapshot
 * pre-allocation is stale and would mis-report counts).
 */
async function buildSlotReceipt(env, operator) {
  const slots = await env.DB.prepare(
    'SELECT free_slots_total, free_slots_used, paid_agents, max_agents FROM agent_slots WHERE operator_id = ?'
  ).bind(operator.id).first();
  if (!slots) {
    // Defensive: should never happen because the atomic UPDATE just
    // succeeded against this row. Return a coherent shape anyway.
    return {
      used: 0,
      free: 0,
      operator_verification_tier: operator.verification_tier,
    };
  }
  return {
    used: slots.free_slots_used + slots.paid_agents,
    free: Math.max(0, slots.free_slots_total - slots.free_slots_used),
    operator_verification_tier: operator.verification_tier,
  };
}

/**
 * PATCH /agents/:id — update the human-facing fields of an agent. Only
 * display_name and description are mutable; the AXIS id, DID, public key, and
 * operator binding are immutable by design. Registrar-authenticated and
 * BOLA-scoped: a registrar can only update agents it owns.
 */
export async function handleUpdateAgent(agentId, body, registrar, env) {
  const agent = await env.DB.prepare(
    'SELECT id, registrar_id FROM agents WHERE id = ? OR axis_id = ? OR did = ?'
  ).bind(agentId, agentId, agentId).first();
  if (!agent) {
    return { status: 404, body: { error: { code: 'agent_not_found', message: 'Agent not found' } } };
  }
  // BOLA: normal-path mutation is scoped to the caller's own registrar_id.
  if (agent.registrar_id !== registrar.id) {
    return { status: 403, body: { error: { code: 'not_your_resource', message: 'Agent belongs to a different registrar' } } };
  }

  const updates = [];
  const binds = [];
  if (typeof body.display_name === 'string') {
    const dn = body.display_name.trim().slice(0, 60);
    if (!dn) {
      return { status: 400, body: { error: { code: 'invalid_display_name', message: 'display_name cannot be empty' } } };
    }
    updates.push('display_name = ?'); binds.push(dn);
  }
  if (typeof body.description === 'string') {
    updates.push('description = ?'); binds.push(body.description.slice(0, 500));
  }
  if (updates.length === 0) {
    return { status: 400, body: { error: { code: 'no_updates', message: 'Provide display_name and/or description to update.' } } };
  }

  const now = new Date().toISOString();
  updates.push('updated_at = ?'); binds.push(now);
  binds.push(agent.id);
  await env.DB.prepare(`UPDATE agents SET ${updates.join(', ')} WHERE id = ?`).bind(...binds).run();

  const updated = await env.DB.prepare(
    'SELECT id, axis_id, did, display_name, description, status FROM agents WHERE id = ?'
  ).bind(agent.id).first();
  return { status: 200, body: { agent: updated } };
}
