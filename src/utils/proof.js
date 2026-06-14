/**
 * Canonical-proof verification for AXIS signed bodies (v0.2 §6.1).
 *
 * v0.2 makes RFC 8785 JCS the canonical encoding for every signed canonical
 * body (registration proof, delegation envelope, action envelope). Two proof
 * regimes are recognized:
 *
 *   - `proofType: "jcs-eddsa-2026"` — proofValue is the base64url Ed25519
 *     signature over the JCS canonicalization of the body MINUS its proof
 *     field. RECOMMENDED for v0.2.
 *   - `proofType` absent — legacy v0.1 canonicalization
 *     (`JSON.stringify(body, Object.keys(body).sort())`, top-level sort only).
 *     Per §6.1, verifiers SHOULD try JCS first and fall back to legacy when
 *     JCS verification fails. Deprecated; removed in v1.0.
 *
 * Any OTHER proofType is unrecognized and MUST be rejected — silently
 * accepting an unknown suite would let a future/forged suite name bypass the
 * canonicalization contract.
 */

import { jcsCanonicalize } from './jcs.js';
import { verifyEd25519Signature } from './crypto.js';

/**
 * Legacy v0.1 canonicalization. Kept ONLY for backward-compatible verification
 * of proofs minted before JCS. Do not use for new signing.
 */
function legacyCanonicalize(payload) {
  return JSON.stringify(payload, Object.keys(payload).sort());
}

/**
 * Verify a canonical proof.
 *
 * @param {object}  args
 * @param {object}  args.payload        The signed body WITH its proof field already removed.
 * @param {string}  args.proofValue     base64url Ed25519 signature.
 * @param {string} [args.proofType]     Proof suite identifier; absent ⇒ legacy.
 * @param {string}  args.publicKey      Signer's Ed25519 public key (base64url or multibase).
 * @returns {Promise<{valid: boolean, mode: 'jcs'|'legacy'|'none', unsupported?: boolean, proofType?: string}>}
 *          `unsupported: true` signals an unrecognized proofType — callers MUST reject distinctly
 *          (e.g. 400 unsupported_proof_type) rather than treating it as a plain bad signature.
 */
export async function verifyCanonicalProof({ payload, proofValue, proofType, publicKey }) {
  if (!proofValue || typeof proofValue !== 'string') {
    return { valid: false, mode: 'none' };
  }

  if (proofType === 'jcs-eddsa-2026') {
    let canonical;
    try {
      canonical = jcsCanonicalize(payload);
    } catch {
      return { valid: false, mode: 'none' };
    }
    const valid = await verifyEd25519Signature(publicKey, canonical, proofValue);
    return { valid, mode: 'jcs' };
  }

  if (proofType === undefined || proofType === null) {
    // Legacy regime. §6.1: try JCS first, fall back to legacy on failure, so a
    // JCS-signed proof that omitted proofType still verifies.
    try {
      const jcsCanonical = jcsCanonicalize(payload);
      if (await verifyEd25519Signature(publicKey, jcsCanonical, proofValue)) {
        return { valid: true, mode: 'jcs' };
      }
    } catch {
      /* fall through to legacy */
    }
    const legacyValid = await verifyEd25519Signature(publicKey, legacyCanonicalize(payload), proofValue);
    return { valid: legacyValid, mode: legacyValid ? 'legacy' : 'none' };
  }

  // Unrecognized proofType — reject distinctly.
  return { valid: false, mode: 'none', unsupported: true, proofType };
}
