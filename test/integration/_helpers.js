/**
 * Shared helpers for integration tests that need real Ed25519 keypairs +
 * signed AITs.
 *
 * The base harness deliberately exposes only synthetic random-byte public
 * keys (`generateFakePublicKey()`) because most route-level tests don't
 * need a working signature — slot-race, BOLA, audit-write paths all run
 * fine against shape-valid garbage keys. These helpers handle the cases
 * where the test DOES need verifiable signatures: AIT verification
 * matrices and presentation-layer unlock tests.
 *
 * Uses Node's Web Crypto Ed25519 (Node 20+). No third-party signing libs.
 *
 * Underscore-prefixed filename so node:test doesn't try to execute it as
 * a test file.
 */

import { Buffer } from 'node:buffer';

const { subtle } = globalThis.crypto;
const TEXT = new TextEncoder();

/** Base64url-encode a Uint8Array (no padding). */
export function b64uEncode(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Base64url-encode a JSON value as the JSON string of `value`. */
export function b64uEncodeJSON(value) {
  return b64uEncode(TEXT.encode(JSON.stringify(value)));
}

/**
 * Generate a real Ed25519 keypair. Returns:
 *   - publicKeyB64u: base64url-encoded 32-byte raw public key (the form
 *     stored in the agents.public_key column and used by the registry's
 *     verifyEd25519Signature).
 *   - privateKey: CryptoKey, used to sign AITs in tests.
 *   - keyId: a short opaque identifier suitable for AIT `kid` header.
 */
export async function generateRealKeypair() {
  const { publicKey, privateKey } = await subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  );
  const raw = new Uint8Array(await subtle.exportKey('raw', publicKey));
  return {
    publicKeyB64u: b64uEncode(raw),
    privateKey,
    keyId: `test-key-${b64uEncode(raw).slice(0, 8)}`,
  };
}

/**
 * Build an AIT (AXIS Identity Token) — JWT-shaped with EdDSA signature
 * over `header.payload`. Returns the full `header.payload.signature` token.
 *
 *   keypair  — output of generateRealKeypair()
 *   payload  — object with at minimum `iss` and `aud` (registry expects
 *              both; iss is the agent identifier the registry will look
 *              up to fetch the public key). Common fields: iss, sub, aud,
 *              exp (seconds), iat (seconds), delegation_id, scope.
 *   override — optional partial header to override `{typ:'AIT', alg:'EdDSA'}`.
 *              Used by the AIT-verify matrix to construct wrong-typ /
 *              wrong-alg tokens that the registry should reject.
 */
export async function signAIT(keypair, payload, override = {}) {
  const header = {
    typ: 'AIT',
    alg: 'EdDSA',
    kid: keypair.keyId,
    ...override,
  };
  const headerB64 = b64uEncodeJSON(header);
  const payloadB64 = b64uEncodeJSON(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sigBytes = new Uint8Array(
    await subtle.sign({ name: 'Ed25519' }, keypair.privateKey, TEXT.encode(signingInput)),
  );
  return `${signingInput}.${b64uEncode(sigBytes)}`;
}

/**
 * Variant: sign with the keypair as normal, then mutate the payload so
 * the on-the-wire payload doesn't match what was signed. Returns a token
 * with a structurally-valid-but-invalid signature — useful for testing
 * `valid: false, reason: 'Invalid signature'` paths.
 */
export async function signAITThenTamper(keypair, payload, tamperedPayload) {
  const realToken = await signAIT(keypair, payload);
  const [headerB64, , sigB64] = realToken.split('.');
  return `${headerB64}.${b64uEncodeJSON(tamperedPayload)}.${sigB64}`;
}

/**
 * Register an agent through POST /register using a real keypair. Returns
 * `{ keypair, axisId, did, operatorId, agent: <full response body> }`.
 * Most integration tests that need a "real" agent for AIT signing should
 * call this rather than seeding agents through direct DB inserts (the route
 * handler is the source of truth for axis_id / did derivation).
 */
export async function registerRealAgent(harness, registrar, operator, name = 'real-agent') {
  const keypair = await generateRealKeypair();
  const res = await harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: keypair.publicKeyB64u,
      operator: operator.domain ? { domain: operator.domain } : { email: operator.email },
      metadata: { name },
    }),
  });
  if (res.status !== 201) {
    const body = await res.text();
    throw new Error(`registerRealAgent: registration failed (status=${res.status}) body=${body}`);
  }
  const body = await res.json();
  return {
    keypair,
    axisId: body.axis_id,
    did: body.did,
    operatorId: body.operator_id,
    agent: body,
  };
}
