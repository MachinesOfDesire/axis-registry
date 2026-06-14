/**
 * Integration tests for registration proof-of-key-ownership (v0.2 §6.1) — P0-3.
 *
 * Covers the JCS proof regime, the legacy fallback, the JCS-without-proofType
 * fallback, unknown-proofType rejection, and tamper rejection — all against a
 * real Ed25519 keypair and a live miniflare worker + D1.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';
import { generateRealKeypair, signJcsProof, signLegacyProof } from './_helpers.js';

async function seed(harness) {
  const registrar = await harness.createRegistrar({ role: 'registrar' });
  const operator = await harness.createOperator({
    tier: 'domain',
    domain: 'widget-corp.com',
    registrar_id: registrar.id,
    free_slots_total: 5,
  });
  return { registrar, operator };
}

function registerReq(harness, registrar, body) {
  return harness.fetch('/register', {
    method: 'POST',
    headers: { Authorization: `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

test('P0-3: accepts a valid jcs-eddsa-2026 registration proof', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const { registrar, operator } = await seed(harness);
  const kp = await generateRealKeypair();

  const body = {
    operator: { domain: operator.domain },
    publicKey: kp.publicKeyB64u,
    metadata: { name: 'editor' },
  };
  const proofValue = await signJcsProof(kp, body); // signs body minus proof

  const res = await registerReq(harness, registrar, {
    ...body,
    proof: { proofType: 'jcs-eddsa-2026', proofValue },
  });
  assert.equal(res.status, 201, await res.text());
});

test('P0-3: accepts a legacy proof when proofType is absent (back-compat)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const { registrar, operator } = await seed(harness);
  const kp = await generateRealKeypair();

  const body = {
    operator: { domain: operator.domain },
    publicKey: kp.publicKeyB64u,
    metadata: { name: 'legacy-agent' },
  };
  const proofValue = await signLegacyProof(kp, body);

  const res = await registerReq(harness, registrar, { ...body, proof: { proofValue } });
  assert.equal(res.status, 201, await res.text());
});

test('P0-3: a JCS-signed proof verifies even when proofType is omitted (§6.1 fallback)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const { registrar, operator } = await seed(harness);
  const kp = await generateRealKeypair();

  const body = {
    operator: { domain: operator.domain },
    publicKey: kp.publicKeyB64u,
    metadata: { name: 'jcs-no-type' },
  };
  const proofValue = await signJcsProof(kp, body);

  const res = await registerReq(harness, registrar, { ...body, proof: { proofValue } });
  assert.equal(res.status, 201, await res.text());
});

test('P0-3: rejects an unrecognized proofType with unsupported_proof_type', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const { registrar, operator } = await seed(harness);
  const kp = await generateRealKeypair();

  const body = {
    operator: { domain: operator.domain },
    publicKey: kp.publicKeyB64u,
    metadata: { name: 'weird-suite' },
  };
  const proofValue = await signJcsProof(kp, body);

  const res = await registerReq(harness, registrar, {
    ...body,
    proof: { proofType: 'bls12381-2020', proofValue },
  });
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error.code, 'unsupported_proof_type');
});

test('P0-3: rejects a tampered jcs proof (signature over different bytes)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const { registrar, operator } = await seed(harness);
  const kp = await generateRealKeypair();

  const body = {
    operator: { domain: operator.domain },
    publicKey: kp.publicKeyB64u,
    metadata: { name: 'honest-name' },
  };
  const proofValue = await signJcsProof(kp, body);
  // Submit a DIFFERENT metadata.name than what was signed — must fail.
  const res = await registerReq(harness, registrar, {
    ...body,
    metadata: { name: 'tampered-name' },
    proof: { proofType: 'jcs-eddsa-2026', proofValue },
  });
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error.code, 'invalid_proof');
});
