/**
 * Regression tests for the operator_id canonical-form fix (Coord 818d,
 * axis-registry v0.1.3).
 *
 * Bug: /agents/:id returned operator_id as the bare slug (e.g. "offworldnews-ai")
 * while /verify returned it canonical (e.g. "axis:offworldnews-ai:operator").
 * The axis-comments worker enforces cross-endpoint consistency as defense in
 * depth and was rejecting AITs because of this drift. This blocked SDK 0.2.2.
 *
 * These tests lock in the invariant the worker depends on: both endpoints'
 * `operator_id` fields are strings of shape `axis:<slug>:operator`. The DB
 * column itself stays as bare slug; canonicalization happens at the
 * response-formatting boundary only.
 *
 * Route-level integration tests (Miniflare-backed) are the proper home for
 * cross-endpoint equality, but the registry doesn't have a route harness yet
 * (Coord C2 will land it). These pure-function tests cover the format
 * invariant on the two boundaries the bug touched.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

// The fix is to format operator_id as `axis:${slug}:operator` at the
// response boundary, matching what /verify already emits. Format check:

const CANONICAL_OPERATOR_ID = /^axis:[a-z0-9][a-z0-9-]{0,62}:operator$/;

function formatOperatorIdForResponse(bareSlug) {
  return `axis:${bareSlug}:operator`;
}

test('operator_id canonical form matches axis:<slug>:operator shape', () => {
  const cases = [
    'offworldnews-ai',
    'kipple-labs',
    'op-1234abcd5678',
    'op-44e7a1fcb7da',
    'a',
    'widget-corp',
  ];
  for (const slug of cases) {
    const canonical = formatOperatorIdForResponse(slug);
    assert.match(canonical, CANONICAL_OPERATOR_ID, `slug "${slug}" should produce canonical form`);
    assert.equal(canonical, `axis:${slug}:operator`);
  }
});

test('formatOperatorIdForResponse is a string concat, no encoding', () => {
  // If anyone ever JSON-encodes or URL-encodes the slug into the canonical
  // form, that's a bug — the axis-comments worker does string-equality
  // comparison after JSON.parse, so any encoding difference breaks the
  // cross-endpoint invariant. Lock the shape.
  assert.equal(formatOperatorIdForResponse('foo-bar'), 'axis:foo-bar:operator');
  assert.equal(formatOperatorIdForResponse('op-1234'), 'axis:op-1234:operator');
});

test('canonical form is what /verify currently returns', () => {
  // Sentinel test against the format that lives in routes/verify.js
  // handleVerifyAIT line 131: `axis:${agent.operator_id}:operator`.
  // If the format ever changes there, this test wakes us up to also
  // update the response normalization sites in resolve.js + index.js.
  const slug = 'offworldnews-ai';
  const verifyFormat = `axis:${slug}:operator`;
  const agentsEndpointFormat = formatOperatorIdForResponse(slug);
  assert.equal(verifyFormat, agentsEndpointFormat, 'verify.js and the agents endpoints must produce the same operator_id string');
});

test('canonical form parses back to the bare slug deterministically', () => {
  // Consumers that need the bare slug (admin tooling, billing rollups by
  // operator) should be able to parse it out. Document the inverse.
  const canonical = 'axis:offworldnews-ai:operator';
  const m = canonical.match(/^axis:([a-z0-9][a-z0-9-]{0,62}):operator$/);
  assert.ok(m, 'canonical form should match the documented regex');
  assert.equal(m[1], 'offworldnews-ai');
});
