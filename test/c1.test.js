/**
 * Unit tests for C1 (spec v0.2 §10.3) — operator-namespaced DIDs.
 *
 * Covers the two pure helpers:
 *   - src/utils/operator-slug.js — tier-driven slug derivation
 *   - src/utils/did.js          — v0.1 / v0.2 DID parser + builder
 *
 * The route-level integration (findAgent cross-form lookup, register.js
 * v0.2 emission, operators.js v0.2 slug) is unit-testable only through
 * a Wrangler / Miniflare harness, which lives in axis-conformance. These
 * tests cover the call-site invariants the route code depends on.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { deriveDomainSlug, deriveOperatorSlug, generateOpaqueOperatorSlug } from '../src/utils/operator-slug.js';
import { parseAxisDid, buildAxisDidV2 } from '../src/utils/did.js';

// ---- operator-slug ----

test('deriveDomainSlug: strips single-label TLD', () => {
  assert.equal(deriveDomainSlug('anthropic.com'), 'anthropic');
  assert.equal(deriveDomainSlug('kipple-labs.com'), 'kipple-labs');
  assert.equal(deriveDomainSlug('widget-corp.com'), 'widget-corp');
});

test('deriveDomainSlug: collapses multi-label domains via dot→dash', () => {
  // Documented gap: PSL-unaware. example.co.uk → example-co (not example).
  assert.equal(deriveDomainSlug('example.co.uk'), 'example-co');
});

test('deriveDomainSlug: lowercases', () => {
  assert.equal(deriveDomainSlug('Anthropic.Com'), 'anthropic');
});

test('deriveDomainSlug: tolerates trailing dot (FQDN form)', () => {
  assert.equal(deriveDomainSlug('anthropic.com.'), 'anthropic');
});

test('deriveDomainSlug: returns null for non-domain inputs', () => {
  assert.equal(deriveDomainSlug(null), null);
  assert.equal(deriveDomainSlug(''), null);
  assert.equal(deriveDomainSlug('plain'), null);
  assert.equal(deriveDomainSlug('..'), null);
  assert.equal(deriveDomainSlug(123), null);
});

test('generateOpaqueOperatorSlug: matches op-<24hex> shape', () => {
  const slug = generateOpaqueOperatorSlug();
  assert.match(slug, /^op-[0-9a-f]{24}$/);
});

test('generateOpaqueOperatorSlug: not deterministic', () => {
  const a = generateOpaqueOperatorSlug();
  const b = generateOpaqueOperatorSlug();
  assert.notEqual(a, b);
});

test('deriveOperatorSlug: domain tier uses domain', () => {
  assert.equal(deriveOperatorSlug('domain', 'anthropic.com'), 'anthropic');
});

test('deriveOperatorSlug: email tier always opaque', () => {
  const slug = deriveOperatorSlug('email', null);
  assert.match(slug, /^op-[0-9a-f]{24}$/);
  // Even if a domain is somehow provided, email tier MUST stay opaque
  // (the floor tier doesn't get a brand slug).
  const slug2 = deriveOperatorSlug('email', 'anthropic.com');
  assert.match(slug2, /^op-[0-9a-f]{24}$/);
});

test('deriveOperatorSlug: kyb_individual always opaque (no leaked identity)', () => {
  const slug = deriveOperatorSlug('kyb_individual', 'doe-family.com');
  assert.match(slug, /^op-[0-9a-f]{24}$/);
});

test('deriveOperatorSlug: kyb_organization with domain uses domain', () => {
  assert.equal(deriveOperatorSlug('kyb_organization', 'widget-corp.com'), 'widget-corp');
});

test('deriveOperatorSlug: kyb_organization without domain falls back to opaque', () => {
  const slug = deriveOperatorSlug('kyb_organization', null);
  assert.match(slug, /^op-[0-9a-f]{24}$/);
});

// ---- did parser/builder ----

test('parseAxisDid: parses v0.1 form', () => {
  const r = parseAxisDid('did:axis:prime:editor');
  assert.deepEqual(r, { form: 'v0.1', registry: 'prime', operator: null, agent: 'editor' });
});

test('parseAxisDid: parses v0.2 form', () => {
  const r = parseAxisDid('did:axis:prime:widget-corp:editor');
  assert.deepEqual(r, { form: 'v0.2', registry: 'prime', operator: 'widget-corp', agent: 'editor' });
});

test('parseAxisDid: rejects non-axis DIDs', () => {
  assert.equal(parseAxisDid('did:web:example.com'), null);
  assert.equal(parseAxisDid('did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSrCY36cPdSyL3pdEgGD'), null);
});

test('parseAxisDid: rejects malformed input', () => {
  assert.equal(parseAxisDid(''), null);
  assert.equal(parseAxisDid(null), null);
  assert.equal(parseAxisDid(123), null);
  assert.equal(parseAxisDid('did:axis:prime'), null);                    // only 3 segments
  assert.equal(parseAxisDid('did:axis:prime:a:b:c'), null);              // 6 segments
  assert.equal(parseAxisDid('did:axis:prime:-bad:editor'), null);         // segment starts with hyphen
});

test('buildAxisDidV2: round-trips through parser', () => {
  const did = buildAxisDidV2('prime', 'widget-corp', 'editor');
  assert.equal(did, 'did:axis:prime:widget-corp:editor');
  const r = parseAxisDid(did);
  assert.equal(r.form, 'v0.2');
  assert.equal(r.operator, 'widget-corp');
  assert.equal(r.agent, 'editor');
});
