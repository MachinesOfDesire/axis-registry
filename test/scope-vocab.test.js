/**
 * Unit tests for the v0.3 §4.5 (candidate) standard scope vocabulary
 * (src/utils/scope-vocab.js). The vocabulary tracks an UNRATIFIED candidate;
 * these tests pin the classifier behavior, not the final canon of scopes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  STANDARD_SCOPES,
  STANDARD_DOMAINS,
  isStandardScope,
  classifyScope,
} from '../src/utils/scope-vocab.js';

test('STANDARD_SCOPES / STANDARD_DOMAINS: seed shape', () => {
  // Spot-check representative members of the seed across domains.
  assert.ok(STANDARD_SCOPES.has('content:read'));
  assert.ok(STANDARD_SCOPES.has('content:comment'));
  assert.ok(STANDARD_SCOPES.has('commerce:purchase'));
  assert.ok(STANDARD_SCOPES.has('compute:invoke'));
  assert.ok(STANDARD_DOMAINS.includes('content'));
  assert.ok(STANDARD_DOMAINS.includes('commerce'));
  // Every standard scope's first segment is a reserved domain.
  for (const scope of STANDARD_SCOPES) {
    assert.ok(
      STANDARD_DOMAINS.includes(scope.split(':')[0]),
      `${scope} first segment must be a reserved domain`,
    );
  }
});

test('isStandardScope: strict membership, no wildcard/prefix expansion', () => {
  assert.ok(isStandardScope('content:read'));
  assert.ok(isStandardScope('social:flag'));
  assert.ok(!isStandardScope('content:*'));        // wildcard is not a standard scope
  assert.ok(!isStandardScope('content'));          // bare domain is not a standard scope
  assert.ok(!isStandardScope('x-ghost:newsletter:send'));
  assert.ok(!isStandardScope(42));
});

test('classifyScope: standard layer', () => {
  assert.deepEqual(classifyScope('content:read'), { layer: 'standard' });
  assert.deepEqual(classifyScope('commerce:purchase'), { layer: 'standard' });
  assert.deepEqual(classifyScope('data:export'), { layer: 'standard' });
});

test('classifyScope: custom x- layer accepted', () => {
  assert.deepEqual(classifyScope('x-ghost:newsletter:send'), { layer: 'custom' });
  assert.deepEqual(classifyScope('x-acme:thing'), { layer: 'custom' });
  // A single-segment x- vendor scope is still grammar-valid and custom.
  assert.deepEqual(classifyScope('x-vendor'), { layer: 'custom' });
});

test('classifyScope: reserved-domain squatting is rejected', () => {
  // Grammar-valid, first segment is a reserved domain, but the full scope is
  // NOT a recognized standard scope → invalid (cannot squat the domain).
  const result = classifyScope('content:frobnicate');
  assert.equal(result.layer, 'invalid');
  assert.match(result.reason, /reserved standard domain/);
  // A wildcard under a reserved domain is also squatting, not standard.
  assert.equal(classifyScope('content:*').layer, 'invalid');
  // Bare reserved domain (no action) is not a recognized standard scope.
  assert.equal(classifyScope('commerce').layer, 'invalid');
});

test('classifyScope: malformed grammar is invalid', () => {
  assert.equal(classifyScope('a::b').layer, 'invalid');           // empty segment
  assert.equal(classifyScope('content:**').layer, 'invalid');     // multi-wildcard
  assert.equal(classifyScope('emoji:🚀').layer, 'invalid');        // bad chars
  assert.equal(classifyScope('').layer, 'invalid');
  assert.equal(classifyScope(42).layer, 'invalid');
  assert.match(classifyScope('a::b').reason, /malformed/);
});

test('classifyScope: grammar-valid but unprefixed non-standard is invalid', () => {
  // Not a reserved domain, not x- prefixed → the standard namespace is closed
  // and custom scopes must carry the x- prefix, so this is invalid.
  const result = classifyScope('ghost:newsletter:send');
  assert.equal(result.layer, 'invalid');
  assert.match(result.reason, /x-<vendor>/);
});
