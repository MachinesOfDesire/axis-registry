/**
 * v0.3 candidate C §1 endpoints: /.well-known/axis-registry (self-manifest) and
 * /.well-known/axis-directory (Prime root directory). The decisive test fetches
 * BOTH from the live worker and runs them through the verifier core with the
 * pinned Prime root key — i.e. the served artifacts must actually verify.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';
import { verifyDeclaredRegistry } from '../../src/utils/registry-legitimacy.js';
import { PRIME_ROOT_PUBLIC_KEY } from '../../src/legitimacy/artifacts.js';

test('GET /.well-known/axis-registry returns the signed self-manifest', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const res = await harness.fetch('/.well-known/axis-registry');
  assert.equal(res.status, 200);
  const m = await res.json();
  assert.equal(m.axis_version, '0.3');
  assert.equal(m.registry_id, 'prime');
  assert.ok(Array.isArray(m.keys) && m.keys.length > 0);
  assert.ok(typeof m.signature === 'string' && m.signature.length > 0);
});

test('GET /.well-known/axis-directory returns the root-signed directory', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());
  const res = await harness.fetch('/.well-known/axis-directory');
  assert.equal(res.status, 200);
  const d = await res.json();
  assert.equal(d.axis_version, '0.3');
  assert.ok(Number.isInteger(d.directory_version));
  assert.ok(Array.isArray(d.registrars) && d.registrars.length > 0);
  assert.ok(typeof d.root_signature === 'string' && d.root_signature.length > 0);
});

test('the served manifest + directory verify under the pinned Prime root key', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const manifest = await (await harness.fetch('/.well-known/axis-registry')).json();
  const directory = await (await harness.fetch('/.well-known/axis-directory')).json();

  const result = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: PRIME_ROOT_PUBLIC_KEY,
    now: new Date().toISOString(),
  });
  assert.equal(result.legitimate, true, JSON.stringify(result));
});

test('verification fails under a wrong pinned root key (sanity)', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());

  const manifest = await (await harness.fetch('/.well-known/axis-registry')).json();
  const directory = await (await harness.fetch('/.well-known/axis-directory')).json();

  // A different (valid-shaped) Ed25519 public key — not the real root.
  const wrong = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  const result = await verifyDeclaredRegistry({
    manifest, directory, pinnedRootPublicKey: wrong, now: new Date().toISOString(),
  });
  assert.equal(result.legitimate, false);
});
