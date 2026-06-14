/**
 * v0.3 registry-tail bits:
 *  - #7: /.well-known/axis-access publishes the optional access-policy fields.
 *  - #9: /resolve of a v0.1-form DID returns a non-fatal deprecation warning;
 *        a v0.2-form DID does not.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';
import { registerRealAgent } from './_helpers.js';

test('#7: /.well-known/axis-access includes the v0.3 optional access-policy fields', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/.well-known/axis-access');
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.audience, body.platform_id); // v0.2 §14 still holds
  assert.ok('blocked_operators' in body.access_policy);
  assert.deepEqual(body.access_policy.blocked_operators, []);
  assert.ok('approved_operators' in body.access_policy);
  assert.ok('rate_limits' in body.access_policy);
});

async function setupAgent() {
  const harness = await createHarness();
  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id, tier: 'domain', domain: 'widget-corp.com', free_slots_total: 3,
  });
  const agent = await registerRealAgent(harness, registrar, operator, 'editor');
  return { harness, agent };
}

test('#9: resolving a v0.1-form DID returns a DEPRECATED_DID_FORM warning', async (t) => {
  const { harness, agent } = await setupAgent();
  t.after(() => harness.dispose());

  // Agent's canonical DID is v0.2 (did:axis:prime:<op>:<agent>); request the
  // legacy v0.1 form (did:axis:prime:<agent>).
  const v01 = `did:axis:prime:${agent.agent.did.split(':').pop()}`;
  const res = await harness.fetch('/resolve/' + encodeURIComponent(v01));
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));
  const warnings = body.didResolutionMetadata.warnings || [];
  assert.ok(warnings.some((w) => w.type === 'DEPRECATED_DID_FORM'), JSON.stringify(body.didResolutionMetadata));
});

test('#9: resolving the canonical v0.2 DID has no deprecation warning', async (t) => {
  const { harness, agent } = await setupAgent();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/resolve/' + encodeURIComponent(agent.did));
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.didResolutionMetadata.warnings, undefined);
  // §12.3: /resolve surfaces the canonical did at the top level (cross-form).
  assert.equal(body.did, agent.did);
});
