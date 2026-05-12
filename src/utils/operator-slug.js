/**
 * Operator slug derivation (C1 / spec v0.2 — operator-namespaced DIDs).
 *
 * The operator slug is the second-to-last segment of the v0.2 canonical DID:
 *     did:axis:prime:<operator-slug>:<agent-slug>
 *
 * The key normative property (locked in the 2026-05-11 design decision):
 * the operator slug is DERIVED from the operator's verification proof,
 * never caller-chosen. Squatting `did:axis:prime:openai:<anything>`
 * therefore requires verifying ownership of openai.com (or KYB org with
 * openai.com as the verified domain).
 *
 * Tier table:
 *
 *   domain              verified domain root (TLD stripped, dots → dashes)
 *                       e.g. "anthropic.com"        → "anthropic"
 *                            "kipple-labs.com"      → "kipple-labs"
 *                            "example.co.uk"        → "example-co"   (PSL TODO)
 *
 *   email               opaque `op-<24hex>`
 *   kyb_individual      opaque `op-<24hex>`        (never derive from name)
 *
 *   kyb_organization    verified domain if present (same as domain tier),
 *                       else opaque `op-<24hex>`
 *
 * Public Suffix List handling is a TODO: for now, `example.co.uk` produces
 * `example-co` (strip last label only). PSL-aware stripping should land
 * before opening domain-tier registration to ccTLDs that use a 2-label
 * suffix at scale. Tracked separately.
 */

import { generateToken } from './crypto.js';

const SLUG_OK = /^[a-z0-9][a-z0-9-]{0,62}$/;

/**
 * Strip the rightmost DNS label (TLD) from a domain and normalize the
 * remainder into a slug. Returns null if the input is not a plausible
 * 2+ label domain or the resulting slug doesn't fit the constraint set.
 */
export function deriveDomainSlug(domain) {
  if (typeof domain !== 'string') return null;
  const trimmed = domain.trim().toLowerCase();
  if (!trimmed.includes('.')) return null;
  // Drop trailing dot (FQDN form) and split.
  const labels = trimmed.replace(/\.$/, '').split('.');
  if (labels.length < 2) return null;
  if (labels.some((l) => l.length === 0)) return null;
  // Strip last label (TLD). PSL-aware multi-label TLDs (.co.uk, .com.au,
  // etc.) collapse one more label than ideal — documented gap, tracked
  // for follow-up.
  const body = labels.slice(0, -1);
  const slug = body.join('-');
  if (!SLUG_OK.test(slug)) return null;
  return slug;
}

/**
 * Generate a fresh opaque operator slug (`op-` + 12 hex chars).
 * Used for email-tier, kyb_individual, and as the fallback for
 * kyb_organization when no verified domain is on file.
 */
export function generateOpaqueOperatorSlug() {
  return 'op-' + generateToken(12);
}

/**
 * Derive the canonical operator slug for a given verification tier +
 * verified domain. Returns the slug string. The caller is responsible
 * for ensuring the operator slug doesn't collide with an existing row
 * (retry the opaque path if so).
 *
 * @param {string} tier   "email" | "domain" | "kyb_individual" | "kyb_organization"
 * @param {string|null} verifiedDomain  domain that has been verified (or null)
 */
export function deriveOperatorSlug(tier, verifiedDomain) {
  if (tier === 'domain') {
    return deriveDomainSlug(verifiedDomain) || generateOpaqueOperatorSlug();
  }
  if (tier === 'kyb_organization' && verifiedDomain) {
    return deriveDomainSlug(verifiedDomain) || generateOpaqueOperatorSlug();
  }
  // email, kyb_individual, kyb_organization-without-domain
  return generateOpaqueOperatorSlug();
}
