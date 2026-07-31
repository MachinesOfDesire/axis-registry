/**
 * Edge-cache headers on public reads (Pre-Launch Engineering Brief §3.4).
 *
 * `Cache-Control: public, max-age=60` is set on:
 *   - GET /agents/:id
 *   - GET /operators/:id
 *   - GET /resolve/:did
 *
 * TTL is 60s (was 3600s): these payloads carry `status`, and a 1-hour edge
 * cache let a freshly-revoked agent/operator look active to record readers
 * for up to an hour. See publicReadCacheHeaders in src/index.js.
 *
 * Only when (a) the response is 200 AND (b) the caller is NOT attempting
 * to unlock the presentation layer. Presentation-attempt requests carry
 * either an `Authorization` header (Bearer or AIT) or an `?ait=` query
 * param; those skip the cache header so a presentation-layer response
 * never gets shared with a later anonymous caller.
 *
 * Coverage:
 *
 *   GET /agents/:id
 *     - Unauthed 200 → Cache-Control: public, max-age=60
 *     - With Authorization header → no Cache-Control (presentation attempt)
 *     - With ?ait= query → no Cache-Control (presentation attempt)
 *     - 404 → no Cache-Control (cached 404 would mask a future registration)
 *
 *   GET /operators/:id
 *     - Unauthed 200 → Cache-Control: public, max-age=60
 *     - With Authorization → no Cache-Control
 *
 *   GET /resolve/:did
 *     - Unauthed 200 → Cache-Control: public, max-age=60
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

async function seedAgentWithOperator(harness) {
  const registrar = await harness.createRegistrar({ id: 'reg' });
  const operator = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain', domain: 'cache.example.com', free_slots_total: 3,
  });
  const res = await harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { domain: operator.domain },
      metadata: { name: 'cache-victim' },
    }),
  });
  assert.equal(res.status, 201);
  const agent = await res.json();
  return { registrar, operator, agent };
}

test('Edge cache: unauthed GET /agents/:id 200 sets Cache-Control public, max-age=60', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { agent } = await seedAgentWithOperator(harness);

  const res = await harness.fetch(`/agents/${encodeURIComponent(agent.axis_id)}`, { method: 'GET' });
  assert.equal(res.status, 200);
  assert.equal(
    res.headers.get('Cache-Control'),
    'public, max-age=60',
    'unauthed public read must set the edge cache header',
  );
});

test('Edge cache: GET /agents/:id with Authorization header skips cache (presentation attempt)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, agent } = await seedAgentWithOperator(harness);

  const res = await harness.fetch(`/agents/${encodeURIComponent(agent.axis_id)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  assert.equal(
    res.headers.get('Cache-Control'),
    null,
    'authed read MUST NOT set the edge cache header (presentation layer in response)',
  );
});

test('Edge cache: GET /agents/:id with ?ait= query skips cache (presentation attempt)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { agent } = await seedAgentWithOperator(harness);

  const res = await harness.fetch(
    `/agents/${encodeURIComponent(agent.axis_id)}?ait=fake-aits-just-mark-the-intent`,
    { method: 'GET' },
  );
  assert.equal(res.status, 200);
  assert.equal(
    res.headers.get('Cache-Control'),
    null,
    '?ait= caller MUST NOT receive a cacheable response',
  );
});

test('Edge cache: 404 on GET /agents/:id does NOT set Cache-Control (would mask future registration)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/agents/axis%3Aghost%3Anone', { method: 'GET' });
  assert.equal(res.status, 404);
  assert.equal(
    res.headers.get('Cache-Control'),
    null,
    'cached 404 would mask a freshly-registered agent for the cache lifetime',
  );
});

test('Edge cache: unauthed GET /operators/:id 200 sets Cache-Control', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { operator } = await seedAgentWithOperator(harness);

  const res = await harness.fetch(`/operators/${encodeURIComponent(operator.id)}`, { method: 'GET' });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('Cache-Control'), 'public, max-age=60');
});

test('Edge cache: GET /operators/:id with Authorization skips cache', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { registrar, operator } = await seedAgentWithOperator(harness);

  const res = await harness.fetch(`/operators/${encodeURIComponent(operator.id)}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${registrar.apiKey}` },
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('Cache-Control'), null);
});

test('Edge cache: unauthed GET /resolve/:did 200 sets Cache-Control', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const { agent } = await seedAgentWithOperator(harness);

  const res = await harness.fetch(`/resolve/${encodeURIComponent(agent.did)}`, { method: 'GET' });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('Cache-Control'), 'public, max-age=60');
});

test('Edge cache: 404 on GET /resolve/:did does NOT set Cache-Control', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/resolve/did%3Aaxis%3Aprime%3Ano%3Anone', { method: 'GET' });
  assert.equal(res.status, 404);
  assert.equal(res.headers.get('Cache-Control'), null);
});
