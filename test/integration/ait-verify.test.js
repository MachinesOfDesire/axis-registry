/**
 * AIT verification matrix — GET /verify?token=<AIT> failure paths.
 *
 * The verify handler runs these checks in order (see routes/verify.js):
 *   1. Split into 3 parts (header.payload.signature)
 *   2. Decode header + payload
 *   3. Reject if header.typ !== 'AIT' or header.alg !== 'EdDSA'
 *   4. Reject if payload.aud is missing/empty/whitespace (H1)
 *   5. Look up agent by payload.iss || payload.sub (404 if missing)
 *   6. Verify Ed25519 signature against agent.public_key
 *   7. Reject if expired (payload.exp < now) — returns valid:false
 *   8. Reject if agent.status !== 'active' — returns valid:false
 *   9. Otherwise valid:true with operator_id, scope, delegation_id
 *
 * Coverage:
 *   - Malformed token (not 3 parts) → 400 invalid_request
 *   - Wrong typ → 400 invalid_request
 *   - Wrong alg → 400 invalid_request
 *   - Missing aud → 400 missing_aud
 *   - Empty-string aud → 400 missing_aud
 *   - Whitespace-only aud → 400 missing_aud
 *   - Unknown agent (iss not registered) → 404 agent_not_found
 *   - Bad signature (signed by different key) → 200 valid:false, reason='Invalid signature'
 *   - Expired token (signed by right key but exp in the past) → 200 valid:false, reason='Token expired'
 *   - Deactivated agent → 200 valid:false, reason starts with 'Agent status:'
 *   - Happy path (real sig + real agent + non-past exp) → 200 valid:true
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';
import {
  generateRealKeypair,
  signAIT,
  registerRealAgent,
  b64uEncodeJSON,
  b64uEncode,
} from './_helpers.js';

async function setup() {
  const harness = await createHarness();
  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain', domain: 'verify.example.com', free_slots_total: 3,
  });
  const real = await registerRealAgent(harness, registrar, operator, 'verifier');
  return { harness, registrar, operator, real };
}

test('AIT verify: malformed token (not 3 parts) → 400 invalid_request', async (t) => {
  const { harness } = await setup();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/verify?token=' + encodeURIComponent('not-a-jwt'));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');
});

test('AIT verify: wrong typ in header → 400 invalid_request', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, aud: 'platform', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
  }, { typ: 'JWT' });  // wrong typ

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');
});

test('AIT verify: wrong alg in header → 400 invalid_request', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, aud: 'platform', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
  }, { alg: 'RS256' });  // wrong alg

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'invalid_request');
});

test('AIT verify: missing aud → 400 missing_aud (H1 enforcement)', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'missing_aud');
});

test('AIT verify: empty-string aud → 400 missing_aud', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, aud: '', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'missing_aud');
});

test('AIT verify: whitespace-only aud → 400 missing_aud', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, aud: '   ', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error?.code, 'missing_aud');
});

test('AIT verify: iss points at unknown agent → 404 agent_not_found', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: 'axis:nowhere:ghost-agent', aud: 'platform',
    iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(body.error?.code, 'agent_not_found');
});

test('AIT verify: bad signature → 200 valid:false, reason="Invalid signature"', async (t) => {
  // Sign with a stranger keypair while claiming to be the real agent. The
  // registry looks up `real.axisId`, fetches its (different) public key,
  // and signature verification fails.
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const stranger = await generateRealKeypair();
  const token = await signAIT(stranger, {
    iss: real.axisId, aud: 'platform',
    iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 200, 'sig failure returns 200 with valid:false body, not 400');
  const body = await res.json();
  assert.equal(body.valid, false);
  assert.equal(body.reason, 'Invalid signature');
});

test('AIT verify: expired (real sig, exp in the past) → 200 valid:false, reason="Token expired"', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const nowSec = Math.floor(Date.now() / 1000);
  const token = await signAIT(real.keypair, {
    iss: real.axisId, aud: 'platform',
    iat: nowSec - 7200, exp: nowSec - 3600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.valid, false);
  assert.equal(body.reason, 'Token expired');
});

test('AIT verify: deactivated agent → 200 valid:false, reason starts with "Agent status:"', async (t) => {
  const { harness, registrar, real } = await setup();
  t.after(() => harness.dispose());

  // Deactivate the agent via the owner's DELETE /agents path.
  const deactRes = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ reason: 'test' }),
  });
  assert.equal(deactRes.status, 200, 'deactivation must succeed');

  const nowSec = Math.floor(Date.now() / 1000);
  const token = await signAIT(real.keypair, {
    iss: real.axisId, aud: 'platform',
    iat: nowSec, exp: nowSec + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.valid, false);
  assert.match(body.reason, /^Agent status:/, 'reason should report agent status');
});

test('AIT verify: happy path → 200 valid:true with operator_id', async (t) => {
  // Positive control — the matrix above must not be denying everything.
  const { harness, real, operator } = await setup();
  t.after(() => harness.dispose());

  const nowSec = Math.floor(Date.now() / 1000);
  const token = await signAIT(real.keypair, {
    iss: real.axisId, aud: 'platform-prime',
    iat: nowSec, exp: nowSec + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.valid, true);
  assert.equal(body.agent_id, real.axisId);
  assert.equal(body.operator_id, `axis:${operator.id}:operator`,
    'operator_id returned in canonical axis:<slug>:operator form');
  assert.equal(body.status, 'active');
});
