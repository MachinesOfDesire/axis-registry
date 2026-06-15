/**
 * #2: operator public-key registration (POST /operators/:id/key).
 *
 * Closes the gap where `operators.public_key` was only ever READ
 * (resolveIssuerPublicKey, §8 Step 3) and never SET — so an operator-rooted
 * DelegationCredential (`issued_by: axis:{op}:operator`) could never have its
 * root signature verified. This suite proves:
 *   - proof-of-ownership is required + verified (mirrors POST /register, §6.1);
 *   - BOLA scoping, not-found, idempotency, and the no-rotation 409 guard;
 *   - the payoff: after the key is registered, an operator-signed root DC
 *     resolves to chain[0].signatureValid === true (was impossible before).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';
import {
  generateRealKeypair,
  registerRealAgent,
  signJcsProof,
  buildSignedDelegation,
} from './_helpers.js';

function futureISO(daysFromNow = 30) {
  return new Date(Date.now() + daysFromNow * 86400_000).toISOString();
}
function nowISO() {
  return new Date().toISOString();
}

async function setup(opts = {}) {
  const harness = await createHarness(opts);
  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id, tier: 'domain', domain: 'widget-corp.com', free_slots_total: 5,
  });
  return { harness, registrar, operator };
}

function postKey(harness, registrar, opId, body) {
  return harness.fetch(`/operators/${encodeURIComponent(opId)}/key`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

/** A valid { publicKey, proof } body: the operator signs JCS over {publicKey}. */
async function signedKeyBody(keypair) {
  const payload = { publicKey: keypair.publicKeyB64u };
  const proofValue = await signJcsProof(keypair, payload);
  return { publicKey: keypair.publicKeyB64u, proof: { proofType: 'jcs-eddsa-2026', proofValue } };
}

test('#2: registers an operator key with a valid ownership proof', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const kp = await generateRealKeypair();
  const res = await postKey(harness, registrar, operator.id, await signedKeyBody(kp));
  const json = await res.json();
  assert.equal(res.status, 200, JSON.stringify(json));
  assert.equal(json.key_registered, true);
  assert.equal(json.operator_id, `axis:${operator.id}:operator`);
  assert.equal(json.public_key, kp.publicKeyB64u);
});

test('#2: rejects a proof made by a different key (invalid_proof)', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const kp = await generateRealKeypair();
  const other = await generateRealKeypair();
  // Claim kp's public key but sign with `other`'s private key.
  const proofValue = await signJcsProof(other, { publicKey: kp.publicKeyB64u });
  const res = await postKey(harness, registrar, operator.id, {
    publicKey: kp.publicKeyB64u, proof: { proofType: 'jcs-eddsa-2026', proofValue },
  });
  const json = await res.json();
  assert.equal(res.status, 400, JSON.stringify(json));
  assert.equal(json.error.code, 'invalid_proof');
});

test('#2: requires publicKey and proof', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const noKey = await postKey(harness, registrar, operator.id, { proof: { proofValue: 'x' } });
  assert.equal(noKey.status, 400);
  assert.equal((await noKey.json()).error.code, 'invalid_request');

  const kp = await generateRealKeypair();
  const noProof = await postKey(harness, registrar, operator.id, { publicKey: kp.publicKeyB64u });
  assert.equal(noProof.status, 400);
  assert.equal((await noProof.json()).error.code, 'invalid_request');
});

test('#2: BOLA — cannot register a key for another registrar\'s operator', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const otherReg = await harness.createRegistrar({ id: 'reg-other' });
  const kp = await generateRealKeypair();
  const res = await postKey(harness, otherReg, operator.id, await signedKeyBody(kp));
  const json = await res.json();
  assert.equal(res.status, 403, JSON.stringify(json));
  assert.equal(json.error.code, 'not_your_resource');
});

test('#2: 404 for an unknown operator', async (t) => {
  const { harness, registrar } = await setup();
  t.after(() => harness.dispose());

  const kp = await generateRealKeypair();
  const res = await postKey(harness, registrar, 'op-does-not-exist', await signedKeyBody(kp));
  assert.equal(res.status, 404);
  assert.equal((await res.json()).error.code, 'operator_not_found');
});

test('#2: re-registering the SAME key is idempotent; a DIFFERENT key is a 409 (no rotation here)', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const kp = await generateRealKeypair();
  const first = await postKey(harness, registrar, operator.id, await signedKeyBody(kp));
  assert.equal(first.status, 200);

  const again = await postKey(harness, registrar, operator.id, await signedKeyBody(kp));
  const againJson = await again.json();
  assert.equal(again.status, 200, JSON.stringify(againJson));
  assert.equal(againJson.idempotent, true);

  const kp2 = await generateRealKeypair();
  const conflict = await postKey(harness, registrar, operator.id, await signedKeyBody(kp2));
  const conflictJson = await conflict.json();
  assert.equal(conflict.status, 409, JSON.stringify(conflictJson));
  assert.equal(conflictJson.error.code, 'key_already_registered');
});

test('#2 payoff: an operator-signed root DC reports signatureValid:true once the operator key is registered', async (t) => {
  const { harness, registrar, operator } = await setup();
  t.after(() => harness.dispose());

  const opKp = await generateRealKeypair();
  const agent = await registerRealAgent(harness, registrar, operator, 'editor');

  const dc = {
    axis_version: '0.2',
    type: 'DelegationCredential',
    id: `dc:${operator.id}:operator-editor-${Math.floor(Date.now() / 1000)}`,
    issued_by: `axis:${operator.id}:operator`,
    issued_to: agent.axisId,
    root_operator: operator.id,
    scope: ['article:draft'],
    created: nowISO(),
    expires: futureISO(30),
    revocable: true,
  };
  const signed = await buildSignedDelegation(opKp, dc);

  const postDC = () => harness.fetch('/delegations', {
    method: 'POST',
    headers: { Authorization: `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(signed),
  });

  // Before the operator key is registered, the root signature can't be
  // verified (issuer key unresolvable) → create rejects the signed DC with a
  // distinct issuer_key_unavailable code.
  const before = await postDC();
  const beforeJson = await before.json();
  assert.equal(before.status, 400, JSON.stringify(beforeJson));
  assert.equal(beforeJson.error.code, 'issuer_key_unavailable');

  // Register the operator's key (proof-of-ownership), then the SAME DC verifies.
  const keyRes = await postKey(harness, registrar, operator.id, await signedKeyBody(opKp));
  assert.equal(keyRes.status, 200, await keyRes.text());

  const after = await postDC();
  assert.equal(after.status, 201, await after.text());

  const chain = await (await harness.fetch('/delegations/' + encodeURIComponent(agent.axisId) + '/chain')).json();
  assert.equal(chain.chain[0].signatureValid, true, JSON.stringify(chain));
  assert.equal(chain.chainValid, true);
});
