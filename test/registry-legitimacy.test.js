/**
 * Unit tests for the Registry Legitimacy verifier (src/utils/registry-legitimacy.js).
 *
 * AXIS Protocol v0.3 candidate C §1. These exercise the full CA-trust algorithm
 * with EPHEMERAL Ed25519 keys generated per-test via WebCrypto — no provisioned
 * production keys, no AWS, no network. Every negative case asserts both the
 * verdict AND its specific `reason`, so a regression that changes WHY something
 * fails is caught, not just THAT it fails.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { jcsCanonicalize } from '../src/utils/jcs.js';
import { bytesToBase64url, bytesToHex } from '../src/utils/crypto.js';
import {
  keyFingerprint,
  verifyRegistryManifest,
  verifyRootDirectory,
  isRegistryCertified,
  verifyDeclaredRegistry,
} from '../src/utils/registry-legitimacy.js';

// ---- ephemeral-key helpers -------------------------------------------------

/** Generate an ephemeral Ed25519 keypair; return { privateKey, publicKeyB64url }. */
async function genKeypair() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return { privateKey, publicKeyB64url: bytesToBase64url(raw) };
}

/** Sign jcsCanonicalize(obj) with privateKey; return base64url signature. */
async function signObject(privateKey, obj) {
  const msg = new TextEncoder().encode(jcsCanonicalize(obj));
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, msg));
  return bytesToBase64url(sig);
}

/** Expected fingerprint computed independently of the module under test. */
async function expectedFingerprint(publicKeyB64url) {
  const raw = new Uint8Array(
    atob(publicKeyB64url.replace(/-/g, '+').replace(/_/g, '/')).split('').map((c) => c.charCodeAt(0))
  );
  const hash = await crypto.subtle.digest('SHA-256', raw);
  return bytesToHex(new Uint8Array(hash));
}

// ---- fixture builders ------------------------------------------------------

/** Build a self-signed registry manifest from a registry keypair. */
async function buildManifest(regKey, overrides = {}) {
  const base = {
    axis_version: '0.3',
    registry_id: 'reg-acme',
    registry_url: 'https://registry.acme.example',
    keys: [
      {
        kid: 'key-1',
        alg: 'Ed25519',
        public_key: regKey.publicKeyB64url,
        status: 'active',
        not_before: '2026-01-01T00:00:00Z',
        not_after: '2027-01-01T00:00:00Z',
      },
    ],
    endpoints: { register: 'https://registry.acme.example/register' },
    directory_url: 'https://prime.axis.example/.well-known/axis-directory',
    ...overrides,
  };
  const signature = await signObject(regKey.privateKey, base);
  return { ...base, signature };
}

/**
 * Build a root directory signed by `rootKey`, certifying `regKey` under the
 * given registry_id/status.
 */
async function buildDirectory(rootKey, regKey, overrides = {}) {
  const fp = await keyFingerprint(regKey.publicKeyB64url);
  const base = {
    axis_version: '0.3',
    directory_version: 5,
    issued_at: '2026-06-01T00:00:00Z',
    expires_at: '2026-12-01T00:00:00Z',
    registrars: [
      {
        registry_id: 'reg-acme',
        registry_url: 'https://registry.acme.example',
        key_fingerprints: [fp],
        status: 'certified',
        certified_at: '2026-06-01T00:00:00Z',
      },
    ],
    ...overrides,
  };
  const root_signature = await signObject(rootKey.privateKey, base);
  return { ...base, root_signature };
}

const NOW = '2026-06-14T00:00:00Z';

// ---- keyFingerprint --------------------------------------------------------

test('keyFingerprint: deterministic 64-char hex of raw key bytes', async () => {
  const k = await genKeypair();
  const fp1 = await keyFingerprint(k.publicKeyB64url);
  const fp2 = await keyFingerprint(k.publicKeyB64url);
  assert.equal(fp1, fp2, 'same key ⇒ same fingerprint');
  assert.match(fp1, /^[0-9a-f]{64}$/, 'lowercase 64-char hex (sha256)');
  assert.equal(fp1, await expectedFingerprint(k.publicKeyB64url), 'matches independent sha256');
});

test('keyFingerprint: differs for a different key', async () => {
  const a = await genKeypair();
  const b = await genKeypair();
  assert.notEqual(await keyFingerprint(a.publicKeyB64url), await keyFingerprint(b.publicKeyB64url));
});

test('keyFingerprint: null on missing/invalid input (fail-closed)', async () => {
  assert.equal(await keyFingerprint(undefined), null);
  assert.equal(await keyFingerprint(''), null);
  assert.equal(await keyFingerprint(42), null);
});

// ---- verifyRegistryManifest ------------------------------------------------

test('verifyRegistryManifest: valid self-signed manifest ⇒ valid', async () => {
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  const res = await verifyRegistryManifest(manifest);
  assert.equal(res.valid, true);
  assert.equal(res.kid, 'key-1');
});

test('verifyRegistryManifest: tampered field ⇒ invalid signature', async () => {
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  manifest.registry_url = 'https://evil.example'; // signature no longer covers this
  const res = await verifyRegistryManifest(manifest);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'manifest_signature_invalid');
});

test('verifyRegistryManifest: missing signature ⇒ fail-closed', async () => {
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  delete manifest.signature;
  const res = await verifyRegistryManifest(manifest);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'manifest_missing_signature');
});

test('verifyRegistryManifest: no active keys ⇒ fail-closed', async () => {
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey, {
    keys: [
      {
        kid: 'key-1',
        alg: 'Ed25519',
        public_key: regKey.publicKeyB64url,
        status: 'revoked',
      },
    ],
  });
  const res = await verifyRegistryManifest(manifest);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'manifest_no_active_keys');
});

test('verifyRegistryManifest: non-object ⇒ fail-closed', async () => {
  assert.equal((await verifyRegistryManifest(null)).reason, 'manifest_not_object');
  assert.equal((await verifyRegistryManifest('x')).reason, 'manifest_not_object');
});

test('verifyRegistryManifest: multiple active keys, signed by the second ⇒ valid', async () => {
  const signKey = await genKeypair();
  const otherKey = await genKeypair();
  // Build manifest body listing otherKey first, signKey second; sign with signKey.
  const base = {
    axis_version: '0.3',
    registry_id: 'reg-acme',
    registry_url: 'https://registry.acme.example',
    keys: [
      { kid: 'other', alg: 'Ed25519', public_key: otherKey.publicKeyB64url, status: 'active' },
      { kid: 'signer', alg: 'Ed25519', public_key: signKey.publicKeyB64url, status: 'active' },
    ],
    directory_url: 'https://prime.axis.example/.well-known/axis-directory',
  };
  const signature = await signObject(signKey.privateKey, base);
  const res = await verifyRegistryManifest({ ...base, signature });
  assert.equal(res.valid, true);
  assert.equal(res.kid, 'signer');
});

// ---- verifyRootDirectory ---------------------------------------------------

test('verifyRootDirectory: valid root signature ⇒ valid', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey);
  const res = await verifyRootDirectory(directory, rootKey.publicKeyB64url, { now: NOW });
  assert.equal(res.valid, true);
});

test('verifyRootDirectory: wrong (non-pinned) signing key ⇒ invalid', async () => {
  const rootKey = await genKeypair();
  const wrongKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(wrongKey, regKey); // signed by wrong key
  const res = await verifyRootDirectory(directory, rootKey.publicKeyB64url, { now: NOW });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'root_signature_invalid');
});

test('verifyRootDirectory: expired directory ⇒ invalid', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey, { expires_at: '2026-01-01T00:00:00Z' });
  const res = await verifyRootDirectory(directory, rootKey.publicKeyB64url, { now: NOW });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'directory_expired');
});

test('verifyRootDirectory: rollback (version < lastSeen) ⇒ invalid', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey, { directory_version: 3 });
  const res = await verifyRootDirectory(directory, rootKey.publicKeyB64url, {
    now: NOW,
    lastSeenVersion: 4,
  });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'directory_rolled_back');
});

test('verifyRootDirectory: equal version (not a rollback) ⇒ valid', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey, { directory_version: 4 });
  const res = await verifyRootDirectory(directory, rootKey.publicKeyB64url, {
    now: NOW,
    lastSeenVersion: 4,
  });
  assert.equal(res.valid, true);
});

test('verifyRootDirectory: undefined lastSeenVersion skips rollback check', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey, { directory_version: 1 });
  const res = await verifyRootDirectory(directory, rootKey.publicKeyB64url, { now: NOW });
  assert.equal(res.valid, true);
});

test('verifyRootDirectory: missing pinned key ⇒ fail-closed', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey);
  const res = await verifyRootDirectory(directory, '', { now: NOW });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'no_pinned_root_key');
});

test('verifyRootDirectory: no clock provided skips expiry check', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey, { expires_at: '2000-01-01T00:00:00Z' });
  const res = await verifyRootDirectory(directory, rootKey.publicKeyB64url, {});
  assert.equal(res.valid, true, 'expired-in-the-past, but no now passed ⇒ skip expiry');
});

// ---- isRegistryCertified ---------------------------------------------------

test('isRegistryCertified: certified + matching fingerprint ⇒ certified', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey);
  const fp = await keyFingerprint(regKey.publicKeyB64url);
  const res = isRegistryCertified(directory, 'reg-acme', [fp]);
  assert.equal(res.certified, true);
});

test('isRegistryCertified: registry absent ⇒ not certified (distinct reason)', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey);
  const fp = await keyFingerprint(regKey.publicKeyB64url);
  const res = isRegistryCertified(directory, 'reg-unknown', [fp]);
  assert.equal(res.certified, false);
  assert.equal(res.reason, 'registry_not_listed');
});

test('isRegistryCertified: suspended ⇒ not certified (distinct reason)', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey, {
    registrars: [
      {
        registry_id: 'reg-acme',
        key_fingerprints: [await keyFingerprint(regKey.publicKeyB64url)],
        status: 'suspended',
      },
    ],
  });
  const fp = await keyFingerprint(regKey.publicKeyB64url);
  const res = isRegistryCertified(directory, 'reg-acme', [fp]);
  assert.equal(res.certified, false);
  assert.equal(res.reason, 'registry_suspended');
});

test('isRegistryCertified: revoked ⇒ not certified (distinct reason)', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey, {
    registrars: [
      {
        registry_id: 'reg-acme',
        key_fingerprints: [await keyFingerprint(regKey.publicKeyB64url)],
        status: 'revoked',
      },
    ],
  });
  const fp = await keyFingerprint(regKey.publicKeyB64url);
  const res = isRegistryCertified(directory, 'reg-acme', [fp]);
  assert.equal(res.certified, false);
  assert.equal(res.reason, 'registry_revoked');
});

test('isRegistryCertified: fingerprint mismatch ⇒ not certified (distinct reason)', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const directory = await buildDirectory(rootKey, regKey);
  const otherKey = await genKeypair();
  const wrongFp = await keyFingerprint(otherKey.publicKeyB64url);
  const res = isRegistryCertified(directory, 'reg-acme', [wrongFp]);
  assert.equal(res.certified, false);
  assert.equal(res.reason, 'key_fingerprint_mismatch');
});

// ---- verifyDeclaredRegistry (full algorithm) -------------------------------

test('verifyDeclaredRegistry: happy path ⇒ legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  const directory = await buildDirectory(rootKey, regKey);
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
    lastSeenVersion: 5,
  });
  assert.equal(res.legitimate, true);
});

test('verifyDeclaredRegistry: tampered manifest ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  manifest.registry_url = 'https://evil.example';
  const directory = await buildDirectory(rootKey, regKey);
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'manifest_signature_invalid');
});

test('verifyDeclaredRegistry: directory signed by wrong key ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const wrongKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  const directory = await buildDirectory(wrongKey, regKey);
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'root_signature_invalid');
});

test('verifyDeclaredRegistry: registry absent from directory ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey, { registry_id: 'reg-orphan' });
  const directory = await buildDirectory(rootKey, regKey); // lists reg-acme, not reg-orphan
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'registry_not_listed');
});

test('verifyDeclaredRegistry: suspended registry ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  const directory = await buildDirectory(rootKey, regKey, {
    registrars: [
      {
        registry_id: 'reg-acme',
        key_fingerprints: [await keyFingerprint(regKey.publicKeyB64url)],
        status: 'suspended',
      },
    ],
  });
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'registry_suspended');
});

test('verifyDeclaredRegistry: revoked registry ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  const directory = await buildDirectory(rootKey, regKey, {
    registrars: [
      {
        registry_id: 'reg-acme',
        key_fingerprints: [await keyFingerprint(regKey.publicKeyB64url)],
        status: 'revoked',
      },
    ],
  });
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'registry_revoked');
});

test('verifyDeclaredRegistry: expired directory ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  const directory = await buildDirectory(rootKey, regKey, { expires_at: '2026-01-01T00:00:00Z' });
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'directory_expired');
});

test('verifyDeclaredRegistry: rolled-back directory ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  const directory = await buildDirectory(rootKey, regKey, { directory_version: 2 });
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
    lastSeenVersion: 10,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'directory_rolled_back');
});

test('verifyDeclaredRegistry: key_fingerprints mismatch ⇒ not legitimate', async () => {
  const rootKey = await genKeypair();
  const regKey = await genKeypair();
  const otherKey = await genKeypair();
  const manifest = await buildManifest(regKey);
  // Directory lists reg-acme certified but with a DIFFERENT key's fingerprint.
  const directory = await buildDirectory(rootKey, regKey, {
    registrars: [
      {
        registry_id: 'reg-acme',
        key_fingerprints: [await keyFingerprint(otherKey.publicKeyB64url)],
        status: 'certified',
      },
    ],
  });
  const res = await verifyDeclaredRegistry({
    manifest,
    directory,
    pinnedRootPublicKey: rootKey.publicKeyB64url,
    now: NOW,
  });
  assert.equal(res.legitimate, false);
  assert.equal(res.reason, 'key_fingerprint_mismatch');
});
