/**
 * P0-2 (claim-name correctness): GET /verify must read the delegation
 * reference from the canonical `dlg` claim (v0.2 §4.3), not the v0.1-draft
 * `delegation_id`. The response surfaces both keys during the transition.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';
import { registerRealAgent, signAIT } from './_helpers.js';

async function setup() {
  const harness = await createHarness();
  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain', domain: 'dlg.example.com', free_slots_total: 3,
  });
  const real = await registerRealAgent(harness, registrar, operator, 'dlg-agent');
  return { harness, real };
}

function now() { return Math.floor(Date.now() / 1000); }

test('P0-2: reads the `dlg` claim and surfaces it as both dlg and delegation_id', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, sub: real.axisId, aud: 'dlg.example.com',
    iat: now(), exp: now() + 600,
    dlg: 'dc:widget-corp:editor-2026-04',
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.valid, true, JSON.stringify(body));
  assert.equal(body.dlg, 'dc:widget-corp:editor-2026-04');
  assert.equal(body.delegation_id, 'dc:widget-corp:editor-2026-04');
});

test('P0-2: still honors legacy `delegation_id` claim as a fallback', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, sub: real.axisId, aud: 'dlg.example.com',
    iat: now(), exp: now() + 600,
    delegation_id: 'dc:legacy:claim-name',
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.valid, true, JSON.stringify(body));
  assert.equal(body.dlg, 'dc:legacy:claim-name');
  assert.equal(body.delegation_id, 'dc:legacy:claim-name');
});

test('P0-2: absent delegation claim yields null for both keys', async (t) => {
  const { harness, real } = await setup();
  t.after(() => harness.dispose());

  const token = await signAIT(real.keypair, {
    iss: real.axisId, sub: real.axisId, aud: 'dlg.example.com',
    iat: now(), exp: now() + 600,
  });

  const res = await harness.fetch('/verify?token=' + encodeURIComponent(token));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.valid, true, JSON.stringify(body));
  assert.equal(body.dlg, null);
  assert.equal(body.delegation_id, null);
});
