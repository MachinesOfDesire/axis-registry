/**
 * Presentation-layer field gating matrix.
 *
 * The registry exposes agent records in two layers:
 *   - Public layer: identifiers + public key + status. Always returned.
 *   - Presentation layer: display_name, description, verification_tier,
 *     service endpoints, registered_at, etc. Returned only when the caller
 *     has earned the unlock.
 *
 * The unlock is granted by ANY of three conditions (resolve.js handleGetAgent):
 *   (a) A valid AIT in the request (an agent presenting itself or asking
 *       about a peer it interacts with).
 *   (b) The calling registrar owns the agent (self-service).
 *   (c) The calling registrar has admin+ role (cross-tenant support).
 *
 * This file is the regression suite for those three conditions plus the
 * defensive cases (invalid AIT, non-owning registrar, oversized token).
 *
 * Coverage:
 *
 *   GET /agents/:id
 *     - Unauthenticated → public only
 *     - Owning registrar Bearer → presentation unlocked
 *     - Non-owning registrar Bearer (plain role) → public only
 *     - Admin registrar Bearer → presentation unlocked (cross-tenant support)
 *     - super_admin Bearer → presentation unlocked
 *     - Valid AIT in Authorization → presentation unlocked
 *     - AIT with missing aud → public only (silent fail per H1)
 *     - AIT with bad signature → public only
 *     - Oversized Bearer (>4 KB) → public only (M2 hardening)
 *
 * Field assertions are tight: presentation-layer responses must include
 * `display_name`; public-layer responses must NOT.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';
import {
  registerRealAgent,
  signAIT,
  generateRealKeypair,
  b64uEncodeJSON,
  b64uEncode,
} from './_helpers.js';

/** Common setup: registrar + operator + a real-keypair agent. */
async function setup() {
  const harness = await createHarness();
  const ownerRegistrar = await harness.createRegistrar({ id: 'owner-reg', role: 'registrar' });
  const operator = await harness.createOperator({
    registrar_id: ownerRegistrar.id,
    tier: 'domain', domain: 'company.example.com', free_slots_total: 3,
  });
  const real = await registerRealAgent(harness, ownerRegistrar, operator, 'bram');
  return { harness, ownerRegistrar, operator, real };
}

test('Presentation layer: unauthenticated GET /agents/:id returns public layer only', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, { method: 'GET' });
  assert.equal(res.status, 200);
  const body = await res.json();

  // Public fields present. The agent record uses `agent_id` (not `axis_id`)
  // per buildAgentRecord in resolve.js — the public-layer DTO key differs
  // from the DB column name. Verifying the on-wire shape, not the DB shape.
  assert.equal(body.agent_id, real.axisId, 'agent_id always returned (carries axis_id value)');
  assert.ok(body.did, 'did always returned');
  assert.ok(body.public_key, 'public_key always returned');
  assert.equal(body.status, 'active');

  // Presentation fields absent.
  assert.equal(body.display_name, undefined, 'display_name must NOT appear in public layer');
  assert.equal(body.operator_verification_tier, undefined, 'tier must NOT appear in public layer');
  assert.equal(body.registered_at, undefined, 'registered_at must NOT appear in public layer');
});

test('Presentation layer: owning registrar Bearer unlocks presentation fields', async (t) => {
  const { harness, ownerRegistrar, real } = await setup();
  t.after(() => harness.dispose());

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${ownerRegistrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.display_name, 'bram', 'display_name unlocked for owner');
  assert.ok(body.operator_verification_tier, 'tier unlocked for owner');
  assert.ok(body.registered_at, 'registered_at unlocked for owner');
});

test('Presentation layer: non-owning plain registrar Bearer does NOT unlock', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const otherRegistrar = await harness.createRegistrar({ id: 'other-reg', role: 'registrar' });

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${otherRegistrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.display_name, undefined, 'display_name must NOT appear for non-owning registrar');
  assert.equal(body.operator_verification_tier, undefined, 'tier must NOT appear for non-owning registrar');
});

test('Presentation layer: admin role Bearer unlocks presentation (cross-tenant support)', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const adminRegistrar = await harness.createRegistrar({ id: 'admin-reg', role: 'admin' });

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${adminRegistrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.display_name, 'bram', 'display_name unlocked for admin');
  assert.ok(body.operator_verification_tier, 'tier unlocked for admin');
});

test('Presentation layer: super_admin Bearer unlocks presentation', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const superAdmin = await harness.createRegistrar({ id: 'super', role: 'super_admin' });

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${superAdmin.apiKey}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.display_name, 'bram', 'display_name unlocked for super_admin');
});

test('Presentation layer: valid AIT in Authorization unlocks presentation', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const now = Math.floor(Date.now() / 1000);
  const ait = await signAIT(real.keypair, {
    iss: real.axisId,
    sub: real.axisId,
    aud: 'test-presentation-platform',
    iat: now,
    exp: now + 600,
  });

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${ait}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.display_name, 'bram', 'display_name unlocked by valid AIT');
});

test('Presentation layer: AIT with missing aud is silently rejected → public layer', async (t) => {
  // H1: missing `aud` should fail closed at the presentation-context layer
  // (silent fall back to public). The loud-reject path lives in
  // GET /verify; this is the silent-on-unlock path.
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const now = Math.floor(Date.now() / 1000);
  const ait = await signAIT(real.keypair, {
    iss: real.axisId,
    iat: now,
    exp: now + 600,
    // intentionally no aud
  });

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${ait}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.display_name, undefined, 'AIT without aud must NOT unlock presentation');
});

test('Presentation layer: AIT with bad signature is silently rejected → public layer', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  // Sign with a different keypair than the agent's. Public key the registry
  // looks up won't validate this signature.
  const stranger = await generateRealKeypair();
  const now = Math.floor(Date.now() / 1000);
  const forged = await signAIT(stranger, {
    iss: real.axisId,  // claims to be the real agent
    sub: real.axisId,
    aud: 'test-presentation-platform',
    iat: now,
    exp: now + 600,
  });

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${forged}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.display_name, undefined, 'AIT with bad sig must NOT unlock presentation');
});

test('Presentation layer: oversized Bearer token (>4 KB) is silently rejected → public layer', async (t) => {
  // M2 hardening: tokens larger than 4 KB short-circuit as "no presentation
  // context" rather than running atob on multi-megabyte input. Verifies the
  // size check fires before the JWT parse.
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  // Construct a 5 KB structurally-shaped JWT (header.payload.sig) where the
  // payload is enormous. The size check should fire before atob.
  const header = b64uEncodeJSON({ typ: 'AIT', alg: 'EdDSA' });
  const bigPayload = b64uEncode(Buffer.from('x'.repeat(5000)));
  const fakeSig = b64uEncode(Buffer.from('y'.repeat(64)));
  const giantToken = `${header}.${bigPayload}.${fakeSig}`;
  assert.ok(giantToken.length > 4096, 'test setup: token must exceed 4 KB cap');

  const res = await harness.fetch(`/agents/${encodeURIComponent(real.axisId)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${giantToken}` },
  });
  assert.equal(res.status, 200, 'oversized token must NOT cause an error response');
  const body = await res.json();

  assert.equal(body.display_name, undefined, 'oversized token must NOT unlock presentation');
});
