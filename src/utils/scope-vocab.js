/**
 * AXIS standard scope VOCABULARY (v0.3 §4.5 candidate).
 *
 * v0.2 stabilized the scope GRAMMAR (src/utils/scope.js): colon-separated
 * `[a-zA-Z0-9_-]` segments plus a single-segment `*` wildcard. v0.3 layers a
 * standard VOCABULARY on top of that grammar so that interoperating parties
 * agree on the MEANING of common scopes, not just their shape.
 *
 * STATUS: this vocabulary tracks an UNRATIFIED v0.3 candidate. The seed below
 * is the filed candidate's domain/action list; it is NOT final canon and may
 * change before v0.3 ratifies. Treat it as a versioned seed, not a frozen
 * registry. Do not cite it as settled in external docs.
 *
 * Two-layer namespace (v0.3 candidate §4.5):
 *
 *   (a) STANDARD scopes carry NO vendor prefix. Their first segment is one of
 *       the reserved domains in STANDARD_DOMAINS and the whole scope is one of
 *       the recognized strings in STANDARD_SCOPES.
 *
 *   (b) CUSTOM scopes MUST be prefixed `x-<vendor>:` where `<vendor>` matches
 *       `[a-z0-9-]+` (e.g. `x-ghost:newsletter:send`). The `x-` prefix is
 *       RESERVED for custom strings so a vendor extension can never collide
 *       with a future standard domain.
 *
 * Both layers MUST still satisfy the v0.2 grammar — this module never
 * reimplements grammar checking; it delegates to scope.js `isValidScope`.
 *
 * A grammar-valid scope whose first segment IS a reserved standard domain but
 * which is NOT a recognized standard scope is INVALID: a caller cannot squat a
 * reserved domain with an unrecognized action (e.g. `content:frobnicate`).
 * This keeps the standard namespace closed so that adding a new standard
 * action is a deliberate vocabulary change, not something any caller can mint.
 */

import { isValidScope } from './scope.js';

/**
 * The standard vocabulary, keyed by reserved domain (first segment) → the
 * recognized scopes under that domain, each with a short plain-language
 * description. The description text is surfaced verbatim by the public
 * `/.well-known/axis-scopes` discovery endpoint.
 *
 * SEED — tracks the unratified v0.3 candidate; subject to change before
 * ratification. Order is preserved for stable discovery-endpoint output.
 */
export const STANDARD_VOCABULARY = {
  content: {
    'content:read': 'Read content items.',
    'content:create': 'Create new content items.',
    'content:update': 'Update existing content items.',
    'content:delete': 'Delete content items.',
    'content:comment': 'Comment on content items.',
    'content:publish': 'Publish content items.',
  },
  social: {
    'social:follow': 'Follow an account or actor.',
    'social:like': 'Like or react to an item.',
    'social:announce': 'Boost or re-share an item.',
    'social:invite': 'Invite others to a space or group.',
    'social:join': 'Join a space or group.',
    'social:leave': 'Leave a space or group.',
    'social:block': 'Block an account or actor.',
    'social:flag': 'Flag or report an item or account.',
  },
  commerce: {
    'commerce:quote': 'Request a price quote.',
    'commerce:order': 'Place an order.',
    'commerce:purchase': 'Complete a purchase.',
    'commerce:pay': 'Make a payment.',
    'commerce:sell': 'List an item or service for sale.',
    'commerce:refund': 'Issue or request a refund.',
    'commerce:offer': 'Make an offer.',
    'commerce:accept': 'Accept an offer.',
    'commerce:reject': 'Reject an offer.',
  },
  data: {
    'data:read': 'Read data records.',
    'data:export': 'Export data in bulk.',
    'data:write': 'Write new data records.',
    'data:modify': 'Modify existing data records.',
    'data:share': 'Share data with another party.',
    'data:delete': 'Delete data records.',
  },
  comms: {
    'comms:send': 'Send messages.',
    'comms:read': 'Read messages.',
  },
  account: {
    'account:read': 'Read account information.',
    'account:manage': 'Manage account settings.',
  },
  scheduling: {
    'scheduling:read': 'Read availability or bookings.',
    'scheduling:book': 'Create a booking.',
    'scheduling:cancel': 'Cancel a booking.',
  },
  compute: {
    'compute:invoke': 'Invoke a compute task or function.',
    'compute:read': 'Read compute results or status.',
  },
};

/**
 * The reserved first-segment domains. A grammar-valid scope whose first
 * segment is in this set is treated as STANDARD-namespace: it is either a
 * recognized standard scope or invalid (domain squatting is rejected).
 */
export const STANDARD_DOMAINS = Object.freeze(Object.keys(STANDARD_VOCABULARY));

/**
 * The flat set of recognized standard scope strings (e.g. `content:read`).
 * A Set for O(1) membership; frozen so callers can't mutate the vocabulary.
 */
export const STANDARD_SCOPES = Object.freeze(
  new Set(Object.values(STANDARD_VOCABULARY).flatMap((domain) => Object.keys(domain)))
);

// A custom scope's first segment: `x-` followed by a vendor of `[a-z0-9-]+`.
// Anchored to the full first segment; the rest of the scope still goes
// through the v0.2 grammar check separately.
const CUSTOM_FIRST_SEGMENT = /^x-[a-z0-9-]+$/;

/**
 * Is `scope` EXACTLY one of the recognized standard scopes? This is strict
 * string membership — no wildcard expansion, no prefix matching. `content:*`
 * is NOT a standard scope (it's a grammar-valid wildcard, classified 'invalid'
 * because `content` is a reserved domain and `content:*` isn't recognized).
 * @returns {boolean}
 */
export function isStandardScope(scope) {
  return typeof scope === 'string' && STANDARD_SCOPES.has(scope);
}

/**
 * Classify a scope into the v0.3 two-layer namespace.
 *
 * @param {string} scope
 * @returns {{ layer: 'standard' | 'custom' | 'invalid', reason?: string }}
 *
 * Rules, in order:
 *   1. Recognized standard scope            → 'standard'.
 *   2. Otherwise, malformed v0.2 grammar    → 'invalid'.
 *   3. Otherwise, first segment is a reserved standard domain (but not a
 *      recognized scope — rule 1 already failed) → 'invalid' (domain
 *      squatting: an unrecognized action under a reserved domain).
 *   4. Otherwise, first segment matches `x-<vendor>` → 'custom'.
 *   5. Otherwise (grammar-valid, neither standard-domain nor x- prefixed)
 *      → 'invalid' (unprefixed non-standard scope; the standard namespace is
 *      closed and custom scopes MUST carry the `x-` prefix).
 */
export function classifyScope(scope) {
  if (isStandardScope(scope)) {
    return { layer: 'standard' };
  }
  if (!isValidScope(scope)) {
    return { layer: 'invalid', reason: 'malformed scope grammar' };
  }
  const firstSegment = scope.split(':')[0];
  if (STANDARD_DOMAINS.includes(firstSegment)) {
    return {
      layer: 'invalid',
      reason: `'${firstSegment}' is a reserved standard domain and '${scope}' is not a recognized standard scope`,
    };
  }
  if (CUSTOM_FIRST_SEGMENT.test(firstSegment)) {
    return { layer: 'custom' };
  }
  return {
    layer: 'invalid',
    reason: 'custom scopes must be prefixed `x-<vendor>:` (vendor = [a-z0-9-]+)',
  };
}
