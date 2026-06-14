/**
 * Unit tests for the RFC 8785 JCS canonicalizer (src/utils/jcs.js).
 *
 * These pin the exact byte output for cases that can be computed by hand with
 * confidence, plus the key regression that motivated v0.2: the v0.1
 * canonicalization stripped nested keys whose names didn't appear at the top
 * level. JCS must NOT do that.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jcsCanonicalize, jcsCanonicalizeBytes } from '../src/utils/jcs.js';

test('recursively sorts object keys at every nesting level', () => {
  assert.equal(
    jcsCanonicalize({ b: { d: 1, c: 2 }, a: 3 }),
    '{"a":3,"b":{"c":2,"d":1}}'
  );
});

test('REGRESSION: nested keys survive (v0.1 top-level-sort would strip them)', () => {
  // Legacy JSON.stringify(obj, Object.keys(obj).sort()) yields '{"a":1,"b":{}}'
  // because `c` is not a top-level key. JCS must keep the inner value.
  assert.equal(jcsCanonicalize({ a: 1, b: { c: 2 } }), '{"a":1,"b":{"c":2}}');
});

test('insertion order does not affect output (determinism)', () => {
  assert.equal(
    jcsCanonicalize({ a: 1, b: 2, nested: { y: 1, x: 2 } }),
    jcsCanonicalize({ nested: { x: 2, y: 1 }, b: 2, a: 1 })
  );
});

test('array element order is preserved, not sorted', () => {
  assert.equal(jcsCanonicalize({ z: [3, 1, 2] }), '{"z":[3,1,2]}');
});

test('canonicalizes a top-level array of objects', () => {
  assert.equal(jcsCanonicalize([{ b: 1, a: 2 }]), '[{"a":2,"b":1}]');
});

test('keys sort by UTF-16 code unit, not numeric value', () => {
  // "1" < "10" < "2" lexicographically. A numeric sort would give 1,2,10.
  assert.equal(jcsCanonicalize({ 10: 0, 2: 0, 1: 0 }), '{"1":0,"10":0,"2":0}');
});

test('number serialization matches ECMAScript Number::toString', () => {
  assert.equal(jcsCanonicalize({ n: 4.5 }), '{"n":4.5}');
  assert.equal(jcsCanonicalize({ n: 1e30 }), '{"n":1e+30}');
  assert.equal(jcsCanonicalize({ n: 2e-3 }), '{"n":0.002}');
  assert.equal(jcsCanonicalize({ n: 0 }), '{"n":0}');
  assert.equal(jcsCanonicalize({ n: -1 }), '{"n":-1}');
});

test('string escaping matches JSON (control chars escaped, slash not)', () => {
  assert.equal(jcsCanonicalize({ s: '\n' }), '{"s":"\\n"}');
  assert.equal(jcsCanonicalize({ s: 'a/b' }), '{"s":"a/b"}');
  assert.equal(jcsCanonicalize({ s: '"\\' }), '{"s":"\\"\\\\"}');
});

test('omits undefined-valued object members (JSON semantics)', () => {
  assert.equal(jcsCanonicalize({ a: 1, b: undefined, c: 3 }), '{"a":1,"c":3}');
});

test('preserves null in objects and arrays', () => {
  assert.equal(jcsCanonicalize({ a: null }), '{"a":null}');
  assert.equal(jcsCanonicalize([null, true, false]), '[null,true,false]');
});

test('rejects non-finite numbers (no JCS representation)', () => {
  assert.throws(() => jcsCanonicalize({ n: NaN }), TypeError);
  assert.throws(() => jcsCanonicalize({ n: Infinity }), TypeError);
  assert.throws(() => jcsCanonicalize(-Infinity), TypeError);
});

test('jcsCanonicalizeBytes returns UTF-8 bytes of the canonical string', () => {
  const bytes = jcsCanonicalizeBytes({ b: 1, a: 2 });
  assert.ok(bytes instanceof Uint8Array);
  assert.equal(new TextDecoder().decode(bytes), '{"a":2,"b":1}');
});

test('handles non-ASCII without escaping (per RFC 8785 / JSON)', () => {
  assert.equal(jcsCanonicalize({ s: '€' }), '{"s":"€"}');
});
