/**
 * GET /.well-known/axis-scopes — standard scope vocabulary discovery
 * (v0.3 §4.5 candidate). Public, no auth.
 *
 * Coverage:
 *   - 200 OK
 *   - axis_version === '0.3'
 *   - non-empty scopes array
 *   - content:comment and commerce:purchase present with standard: true
 *   - platform_id derived from REGISTRY_BASE_URL (harness sets 'localhost')
 *   - edge-cacheable for unauthed callers
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createHarness } from './harness.js';

test('well-known/axis-scopes: 200, v0.3, non-empty scopes, known scopes present', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/.well-known/axis-scopes', { method: 'GET' });
  assert.equal(res.status, 200);

  const body = await res.json();
  assert.equal(body.axis_version, '0.3');
  assert.equal(body.platform_id, 'localhost'); // from REGISTRY_BASE_URL=http://localhost
  assert.ok(Array.isArray(body.scopes), 'scopes must be an array');
  assert.ok(body.scopes.length > 0, 'scopes array must be non-empty');

  const byScope = new Map(body.scopes.map((s) => [s.scope, s]));

  const comment = byScope.get('content:comment');
  assert.ok(comment, 'content:comment must be present');
  assert.equal(comment.standard, true);
  assert.equal(typeof comment.description, 'string');
  assert.ok(comment.description.length > 0);

  const purchase = byScope.get('commerce:purchase');
  assert.ok(purchase, 'commerce:purchase must be present');
  assert.equal(purchase.standard, true);
});

test('well-known/axis-scopes: edge-cacheable for unauthed callers', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const res = await harness.fetch('/.well-known/axis-scopes', { method: 'GET' });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('Cache-Control'), 'public, max-age=3600');
});
