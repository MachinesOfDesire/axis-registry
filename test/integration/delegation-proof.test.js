/**
 * P0-1: delegation-chain proof verification (v0.2 §4.4 / §8 Step 3).
 *
 * Option A: the issuer submits a complete signed DelegationCredential; the
 * registry verifies the proof against the issuer's public key at create time
 * and again during the chain walk. The hardcoded `signatureValid: true` is
 * gone — it now reflects an actual verification.
 *
 * Enforcement is gated by AXIS_ENFORCE_DC_PROOFS so legacy/unsigned
 * delegations keep resolving until the contract is enabled.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';
import { registerRealAgent, buildSignedDelegation } from './_helpers.js';

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
  const editor = await registerRealAgent(harness, registrar, operator, 'editor');
  const researcher = await registerRealAgent(harness, registrar, operator, 'researcher');
  return { harness, registrar, operator, editor, researcher };
}

function dcDoc({ editor, researcher, operator, scope = ['article:draft'] }) {
  return {
    axis_version: '0.2',
    type: 'DelegationCredential',
    id: `dc:${operator.id}:editor-researcher-${Math.floor(Date.now() / 1000)}`,
    issued_by: editor.axisId,
    issued_to: researcher.axisId,
    root_operator: operator.id,
    scope,
    created: nowISO(),
    expires: futureISO(30),
    revocable: true,
  };
}

function postDelegation(harness, registrar, body) {
  return harness.fetch('/delegations', {
    method: 'POST',
    headers: { Authorization: `Bearer ${registrar.apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

test('P0-1: accepts a valid signed delegation and the chain reports signatureValid:true', async (t) => {
  const { harness, registrar, operator, editor, researcher } = await setup();
  t.after(() => harness.dispose());

  const signed = await buildSignedDelegation(editor.keypair, dcDoc({ editor, researcher, operator }));
  const res = await postDelegation(harness, registrar, signed);
  assert.equal(res.status, 201, await res.text());

  const chainRes = await harness.fetch('/delegations/' + encodeURIComponent(researcher.axisId) + '/chain');
  assert.equal(chainRes.status, 200);
  const chain = await chainRes.json();
  assert.equal(chain.chainDepth, 1, JSON.stringify(chain));
  assert.equal(chain.chain[0].signatureValid, true);
  assert.equal(chain.chainValid, true);
});

test('P0-1: rejects a signed delegation whose proof was made by the wrong key', async (t) => {
  const { harness, registrar, operator, editor, researcher } = await setup();
  t.after(() => harness.dispose());

  // Sign with researcher's key but claim issued_by = editor → proof must fail.
  const doc = dcDoc({ editor, researcher, operator });
  const forged = await buildSignedDelegation(researcher.keypair, doc); // wrong signer
  const res = await postDelegation(harness, registrar, forged);
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error.code, 'invalid_proof');
});

test('P0-1: rejects a signed delegation tampered after signing', async (t) => {
  const { harness, registrar, operator, editor, researcher } = await setup();
  t.after(() => harness.dispose());

  const doc = dcDoc({ editor, researcher, operator, scope: ['article:draft'] });
  const signed = await buildSignedDelegation(editor.keypair, doc);
  signed.scope = ['article:draft', 'article:publish']; // widen scope after signing
  const res = await postDelegation(harness, registrar, signed);
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error.code, 'invalid_proof');
});

test('P0-1: legacy unsigned delegation still works when enforcement is OFF (chain signatureValid:false, chainValid:true)', async (t) => {
  const { harness, registrar, operator, editor, researcher } = await setup();
  t.after(() => harness.dispose());

  // No proof — legacy convenience path.
  const res = await postDelegation(harness, registrar, {
    issued_by: editor.axisId,
    issued_to: researcher.axisId,
    root_operator: operator.id,
    scope: ['article:draft'],
    expires: futureISO(30),
  });
  assert.equal(res.status, 201, await res.text());

  const chain = await (await harness.fetch('/delegations/' + encodeURIComponent(researcher.axisId) + '/chain')).json();
  assert.equal(chain.chain[0].signatureValid, false);
  assert.equal(chain.chainValid, true); // not failed: enforcement off
});

test('P0-1: with enforcement ON, an unsigned delegation is refused at create', async (t) => {
  const { harness, registrar, operator, editor, researcher } = await setup({
    bindings: { AXIS_ENFORCE_DC_PROOFS: 'true' },
  });
  t.after(() => harness.dispose());

  const res = await postDelegation(harness, registrar, {
    issued_by: editor.axisId,
    issued_to: researcher.axisId,
    root_operator: operator.id,
    scope: ['article:draft'],
    expires: futureISO(30),
  });
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.error.code, 'proof_required');
});

test('P0-1: with enforcement ON, a valid signed delegation is accepted and chain is valid', async (t) => {
  const { harness, registrar, operator, editor, researcher } = await setup({
    bindings: { AXIS_ENFORCE_DC_PROOFS: 'true' },
  });
  t.after(() => harness.dispose());

  const signed = await buildSignedDelegation(editor.keypair, dcDoc({ editor, researcher, operator }));
  const res = await postDelegation(harness, registrar, signed);
  assert.equal(res.status, 201, await res.text());

  const chain = await (await harness.fetch('/delegations/' + encodeURIComponent(researcher.axisId) + '/chain')).json();
  assert.equal(chain.chain[0].signatureValid, true);
  assert.equal(chain.chainValid, true);
});
