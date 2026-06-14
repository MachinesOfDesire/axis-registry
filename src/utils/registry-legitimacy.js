/**
 * Registry Legitimacy Verifier — AXIS Protocol v0.3 candidate C §1.
 *
 * The security-critical, key-INDEPENDENT core of "Registry Legitimacy". This
 * module answers one question: may a verifier trust records that claim to come
 * from a given registry? It implements a CA-trust pattern with AXIS Prime as
 * the root authority:
 *
 *   1. Each registry publishes a self-manifest (/.well-known/axis-registry)
 *      carrying its public keys and an Ed25519 SELF-signature over the manifest.
 *   2. AXIS Prime publishes a signed root DIRECTORY listing every certified
 *      registrar by id and key fingerprint, signed by the Prime ROOT key.
 *   3. A verifier PINS the Prime root public key out of band and trusts a
 *      registry only when ALL of these hold:
 *        - the registry's manifest self-signature verifies, AND
 *        - the directory's root_signature verifies against the pinned root key,
 *          AND
 *        - the directory is neither expired nor rolled back, AND
 *        - the registry is listed `certified` in the directory with at least one
 *          key fingerprint matching the manifest's keys.
 *
 * DESIGN INVARIANTS
 *   - FAIL-CLOSED. Every function returns a negative verdict ({ valid:false } /
 *     { certified:false } / { legitimate:false }) with a machine-readable
 *     `reason` string on ANY missing, malformed, or mistyped input, and on ANY
 *     failed cryptographic or policy check. There is no path that throws to the
 *     caller; internal throws are caught and converted to a negative verdict.
 *   - KEY-INDEPENDENT. Nothing here reads provisioned production keys, AWS, or
 *     the network. All key material is passed in by the caller, so the whole
 *     module is exercisable with ephemeral test keys.
 *   - TIME IS INJECTED. We never call Date.now() or `new Date()` with no args.
 *     The caller passes `now` (ISO string or Date); when absent we simply skip
 *     time-based checks rather than inventing a clock.
 *   - REUSE. Canonicalization is jcs.js (RFC 8785); Ed25519 + encodings are
 *     crypto.js. We do not reimplement either.
 */

import { jcsCanonicalize } from './jcs.js';
import { verifyEd25519Signature, base64urlToBytes, bytesToHex } from './crypto.js';

/**
 * keyFingerprint — the canonical fingerprint of an Ed25519 public key.
 *
 * DEFINITION: the lowercase hex encoding of SHA-256 over the RAW public-key
 * bytes (the 32 bytes that `public_key` base64url-decodes to). Equivalently:
 *
 *     keyFingerprint(pk) = hex( SHA-256( base64urlToBytes(pk) ) )
 *
 * The hash is taken over the RAW KEY BYTES, never over the base64url text, so
 * the fingerprint is independent of encoding (base64url vs. the multibase
 * base58 form crypto.js also accepts). This is the exact value that appears in
 * the directory's `key_fingerprints` arrays.
 *
 * @param {string} publicKeyB64url  base64url (or multibase) raw Ed25519 pubkey
 * @returns {Promise<string|null>}  64-char lowercase hex sha256, or null if the
 *                                  input is missing / not a string / undecodable
 */
export async function keyFingerprint(publicKeyB64url) {
  if (typeof publicKeyB64url !== 'string' || publicKeyB64url.length === 0) {
    return null;
  }
  try {
    const keyBytes = base64urlToBytes(publicKeyB64url);
    const hash = await crypto.subtle.digest('SHA-256', keyBytes);
    return bytesToHex(new Uint8Array(hash));
  } catch {
    return null;
  }
}

// ---- small structural helpers (all total, never throw) ----

function isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Parse a caller-supplied `now` (ISO string or Date) to epoch ms.
 * Returns null when `now` is absent or unparseable — callers treat null as
 * "no clock provided, skip time checks" (NOT as "now = 0").
 */
function nowToMillis(now) {
  if (now === undefined || now === null) return null;
  if (now instanceof Date) {
    const t = now.getTime();
    return Number.isFinite(t) ? t : null;
  }
  if (typeof now === 'string') {
    const t = Date.parse(now);
    return Number.isFinite(t) ? t : null;
  }
  return null;
}

/**
 * verifyRegistryManifest — verify a registry self-manifest's self-signature.
 *
 * Structural requirements: `manifest` is an object with non-empty string
 * `registry_id` and `registry_url`, a `signature` (base64url string), and a
 * non-empty `keys` array. Each candidate signing key is an entry with
 * status === 'active', alg === 'Ed25519', and a non-empty `public_key`.
 *
 * The signature is verified over jcsCanonicalize(manifest WITHOUT its
 * `signature` field). We try every active key and accept if ANY verifies
 * (key rollover: a manifest may carry several active keys). We reject if none
 * verifies.
 *
 * @param {object} manifest
 * @returns {Promise<{valid: boolean, reason?: string, kid?: string}>}
 */
export async function verifyRegistryManifest(manifest) {
  if (!isPlainObject(manifest)) {
    return { valid: false, reason: 'manifest_not_object' };
  }
  if (!isNonEmptyString(manifest.registry_id)) {
    return { valid: false, reason: 'manifest_missing_registry_id' };
  }
  if (!isNonEmptyString(manifest.registry_url)) {
    return { valid: false, reason: 'manifest_missing_registry_url' };
  }
  if (!isNonEmptyString(manifest.signature)) {
    return { valid: false, reason: 'manifest_missing_signature' };
  }
  if (!Array.isArray(manifest.keys) || manifest.keys.length === 0) {
    return { valid: false, reason: 'manifest_missing_keys' };
  }

  // Candidate signing keys: active Ed25519 keys with a public_key.
  const activeKeys = manifest.keys.filter(
    (k) =>
      isPlainObject(k) &&
      k.status === 'active' &&
      k.alg === 'Ed25519' &&
      isNonEmptyString(k.public_key)
  );
  if (activeKeys.length === 0) {
    return { valid: false, reason: 'manifest_no_active_keys' };
  }

  // Canonicalize the manifest minus the signature field.
  let signedBody;
  try {
    const { signature, ...rest } = manifest;
    void signature;
    signedBody = jcsCanonicalize(rest);
  } catch {
    return { valid: false, reason: 'manifest_not_canonicalizable' };
  }

  // Try each active key; accept on first that verifies.
  for (const key of activeKeys) {
    let ok = false;
    try {
      ok = await verifyEd25519Signature(key.public_key, signedBody, manifest.signature);
    } catch {
      ok = false;
    }
    if (ok) {
      return { valid: true, kid: isNonEmptyString(key.kid) ? key.kid : undefined };
    }
  }
  return { valid: false, reason: 'manifest_signature_invalid' };
}

/**
 * verifyRootDirectory — verify AXIS Prime's signed root directory.
 *
 * Checks, in order (all fail-closed):
 *   - structural: object with non-empty `root_signature`, integer
 *     `directory_version`, and a `registrars` array;
 *   - root_signature verifies over jcsCanonicalize(directory WITHOUT
 *     `root_signature`) against the PINNED Prime root public key;
 *   - NOT expired: when both `expires_at` and `now` are present, reject if
 *     expires_at < now. (If either is absent we skip the expiry check —
 *     time is caller-injected and optional.)
 *   - NOT rolled back: when `lastSeenVersion` is provided, reject if
 *     directory_version < lastSeenVersion. When lastSeenVersion is undefined we
 *     skip the rollback check but still perform every other check.
 *
 * @param {object} directory
 * @param {string} pinnedRootPublicKeyB64url  out-of-band-pinned Prime root key
 * @param {{now?: string|Date, lastSeenVersion?: number}} [opts]
 * @returns {Promise<{valid: boolean, reason?: string}>}
 */
export async function verifyRootDirectory(directory, pinnedRootPublicKeyB64url, opts = {}) {
  const { now, lastSeenVersion } = opts || {};

  if (!isNonEmptyString(pinnedRootPublicKeyB64url)) {
    return { valid: false, reason: 'no_pinned_root_key' };
  }
  if (!isPlainObject(directory)) {
    return { valid: false, reason: 'directory_not_object' };
  }
  if (!isNonEmptyString(directory.root_signature)) {
    return { valid: false, reason: 'directory_missing_root_signature' };
  }
  if (!Number.isInteger(directory.directory_version)) {
    return { valid: false, reason: 'directory_missing_version' };
  }
  if (!Array.isArray(directory.registrars)) {
    return { valid: false, reason: 'directory_missing_registrars' };
  }

  // Verify the root signature over the directory minus root_signature.
  let signedBody;
  try {
    const { root_signature, ...rest } = directory;
    void root_signature;
    signedBody = jcsCanonicalize(rest);
  } catch {
    return { valid: false, reason: 'directory_not_canonicalizable' };
  }

  let ok = false;
  try {
    ok = await verifyEd25519Signature(
      pinnedRootPublicKeyB64url,
      signedBody,
      directory.root_signature
    );
  } catch {
    ok = false;
  }
  if (!ok) {
    return { valid: false, reason: 'root_signature_invalid' };
  }

  // Expiry: only when both a clock and an expires_at are present.
  const nowMs = nowToMillis(now);
  if (nowMs !== null && directory.expires_at !== undefined) {
    const expMs = nowToMillis(directory.expires_at);
    if (expMs === null) {
      return { valid: false, reason: 'directory_expires_at_unparseable' };
    }
    if (expMs < nowMs) {
      return { valid: false, reason: 'directory_expired' };
    }
  }

  // Rollback protection: only when the caller supplies lastSeenVersion.
  if (lastSeenVersion !== undefined) {
    if (!Number.isInteger(lastSeenVersion)) {
      return { valid: false, reason: 'invalid_last_seen_version' };
    }
    if (directory.directory_version < lastSeenVersion) {
      return { valid: false, reason: 'directory_rolled_back' };
    }
  }

  return { valid: true };
}

/**
 * isRegistryCertified — is `registryId` certified in this directory, with a
 * key fingerprint matching one the caller derived from the registry's manifest?
 *
 * Pure policy check over an ALREADY-VERIFIED directory (call verifyRootDirectory
 * first). Distinct reasons let callers tell "not listed" from "suspended" from
 * "revoked" from "key mismatch".
 *
 * @param {object} directory
 * @param {string} registryId
 * @param {string[]} keyFingerprints  fingerprints from the registry's manifest
 * @returns {{certified: boolean, reason?: string}}
 */
export function isRegistryCertified(directory, registryId, keyFingerprints) {
  if (!isPlainObject(directory) || !Array.isArray(directory.registrars)) {
    return { certified: false, reason: 'directory_missing_registrars' };
  }
  if (!isNonEmptyString(registryId)) {
    return { certified: false, reason: 'missing_registry_id' };
  }
  if (!Array.isArray(keyFingerprints) || keyFingerprints.length === 0) {
    return { certified: false, reason: 'no_key_fingerprints_supplied' };
  }

  const entry = directory.registrars.find(
    (r) => isPlainObject(r) && r.registry_id === registryId
  );
  if (!entry) {
    return { certified: false, reason: 'registry_not_listed' };
  }
  if (entry.status === 'suspended') {
    return { certified: false, reason: 'registry_suspended' };
  }
  if (entry.status === 'revoked') {
    return { certified: false, reason: 'registry_revoked' };
  }
  if (entry.status !== 'certified') {
    return { certified: false, reason: 'registry_not_certified' };
  }

  const listedFps = Array.isArray(entry.key_fingerprints) ? entry.key_fingerprints : [];
  if (listedFps.length === 0) {
    return { certified: false, reason: 'registry_no_listed_fingerprints' };
  }

  // Constant-set membership: at least one manifest fingerprint must be listed.
  const listedSet = new Set(listedFps.filter((f) => isNonEmptyString(f)));
  const matched = keyFingerprints.some((f) => isNonEmptyString(f) && listedSet.has(f));
  if (!matched) {
    return { certified: false, reason: 'key_fingerprint_mismatch' };
  }

  return { certified: true };
}

/**
 * verifyDeclaredRegistry — full registry-legitimacy algorithm.
 *
 * Runs the whole chain and returns a single verdict:
 *   1. verifyRegistryManifest(manifest)                    — self-signature
 *   2. verifyRootDirectory(directory, pinnedRootPublicKey, {now, lastSeenVersion})
 *   3. derive manifest key fingerprints from manifest.keys (all active keys)
 *   4. isRegistryCertified(directory, manifest.registry_id, fingerprints)
 *
 * `legitimate` is true only if every step passes. The returned `reason` is the
 * reason of the first failing step.
 *
 * @param {object} args
 * @param {object} args.manifest
 * @param {object} args.directory
 * @param {string} args.pinnedRootPublicKey
 * @param {string|Date} [args.now]
 * @param {number} [args.lastSeenVersion]
 * @returns {Promise<{legitimate: boolean, reason?: string}>}
 */
export async function verifyDeclaredRegistry({
  manifest,
  directory,
  pinnedRootPublicKey,
  now,
  lastSeenVersion,
} = {}) {
  // 1. Manifest self-signature.
  const manifestResult = await verifyRegistryManifest(manifest);
  if (!manifestResult.valid) {
    return { legitimate: false, reason: manifestResult.reason };
  }

  // 2. Root directory.
  const dirResult = await verifyRootDirectory(directory, pinnedRootPublicKey, {
    now,
    lastSeenVersion,
  });
  if (!dirResult.valid) {
    return { legitimate: false, reason: dirResult.reason };
  }

  // 3. Derive fingerprints from the manifest's active keys. (Manifest validity
  //    was established in step 1, so keys is a non-empty array of objects.)
  const activeKeys = manifest.keys.filter(
    (k) => isPlainObject(k) && k.status === 'active' && isNonEmptyString(k.public_key)
  );
  const fingerprints = [];
  for (const k of activeKeys) {
    const fp = await keyFingerprint(k.public_key);
    if (fp) fingerprints.push(fp);
  }
  if (fingerprints.length === 0) {
    return { legitimate: false, reason: 'manifest_no_fingerprintable_keys' };
  }

  // 4. Certification + fingerprint match.
  const certResult = isRegistryCertified(directory, manifest.registry_id, fingerprints);
  if (!certResult.certified) {
    return { legitimate: false, reason: certResult.reason };
  }

  return { legitimate: true };
}
