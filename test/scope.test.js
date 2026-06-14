/**
 * Unit tests for the v0.2 §4.4 scope grammar + matching (src/utils/scope.js).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidScope,
  validateScopeSet,
  scopeMatches,
  isScopeSubset,
  intersectScopes,
  MAX_SCOPES_PER_SET,
  MAX_SEGMENTS_PER_SCOPE,
} from '../src/utils/scope.js';

test('isValidScope: accepts well-formed colon scopes and the single wildcard', () => {
  assert.ok(isValidScope('read:articles'));
  assert.ok(isValidScope('admin:*'));
  assert.ok(isValidScope('content'));
  assert.ok(isValidScope('a:b-c_d:e'));
});

test('isValidScope: rejects empty, bad chars, and the ** multi-wildcard', () => {
  assert.ok(!isValidScope(''));
  assert.ok(!isValidScope('a::b'));        // empty segment
  assert.ok(!isValidScope('admin:**'));    // no multi-segment wildcard
  assert.ok(!isValidScope('a:b*'));        // wildcard only as a whole segment
  assert.ok(!isValidScope('read articles'));
  assert.ok(!isValidScope('emoji:🚀'));
  assert.ok(!isValidScope(42));
});

test('isValidScope: enforces the per-scope segment cap', () => {
  const ok = Array(MAX_SEGMENTS_PER_SCOPE).fill('a').join(':');
  const tooMany = Array(MAX_SEGMENTS_PER_SCOPE + 1).fill('a').join(':');
  assert.ok(isValidScope(ok));
  assert.ok(!isValidScope(tooMany));
});

test('validateScopeSet: rejects non-arrays and oversize sets', () => {
  assert.equal(validateScopeSet('read:x').valid, false);
  assert.equal(validateScopeSet(Array(MAX_SCOPES_PER_SET + 1).fill('a')).valid, false);
  assert.equal(validateScopeSet(['read:x', 'write:y']).valid, true);
  assert.equal(validateScopeSet(['read:x', 'bad seg']).valid, false);
});

test('scopeMatches: identical and wildcard-single-segment', () => {
  assert.ok(scopeMatches('read:articles', 'read:articles'));
  assert.ok(scopeMatches('admin:*', 'admin:users'));
  assert.ok(scopeMatches('admin:*', 'admin:roles'));
  assert.ok(scopeMatches('*:articles', 'read:articles'));
});

test('scopeMatches: wildcard does NOT span multiple segments', () => {
  assert.ok(!scopeMatches('admin:*', 'admin:users:delete'));
  assert.ok(!scopeMatches('admin:*', 'admin'));
  assert.ok(!scopeMatches('read:articles', 'read:drafts'));
});

test('isScopeSubset: attenuation rule', () => {
  // child ⊆ parent
  assert.ok(isScopeSubset(['admin:users'], ['admin:*']));
  assert.ok(isScopeSubset(['read:x', 'write:y'], ['read:x', 'write:y', 'delete:z']));
  // exact-match case (no wildcards) behaves like the old array-includes check
  assert.ok(isScopeSubset(['read:x'], ['read:x']));
  // escalation is rejected
  assert.ok(!isScopeSubset(['admin:users:delete'], ['admin:*']));
  assert.ok(!isScopeSubset(['delete:z'], ['read:x', 'write:y']));
  assert.ok(!isScopeSubset(['admin:*'], ['admin:users'])); // child broader than parent
});

test('intersectScopes: chain effective scope', () => {
  assert.deepEqual(intersectScopes(['admin:*'], ['admin:users', 'admin:roles']), [
    'admin:users',
    'admin:roles',
  ]);
  assert.deepEqual(intersectScopes(['read:x'], ['read:x', 'write:y']), ['read:x']);
  assert.deepEqual(intersectScopes(['read:x'], ['delete:z']), []);
});
