/**
 * AXIS scope grammar + matching (v0.2 §4.4).
 *
 * Scopes are colon-separated strings; each segment is `[a-zA-Z0-9_-]+`, OR the
 * literal single-segment wildcard `*`. A granted scope matches a requested
 * scope if, segment-by-segment, each granted segment is identical to the
 * corresponding requested segment OR the granted segment is `*`. The wildcard
 * matches EXACTLY ONE segment — `admin:*` covers `admin:users` and
 * `admin:roles` but NOT `admin:users:delete`. There is no multi-segment
 * wildcard; `**` (and any segment that is neither `[a-zA-Z0-9_-]+` nor `*`) is
 * invalid grammar and rejected.
 *
 * Attenuation (§4.4 MUST): a delegation's scope set MUST be a subset of its
 * parent's scope set under these matching rules. Effective scope across a chain
 * is the intersection, computed with the same rules.
 *
 * Defensive caps bound worst-case matching cost on adversarial input. They are
 * far above any realistic delegation (scopes are typically 2-3 segments, a
 * handful per credential).
 */

export const MAX_SCOPES_PER_SET = 256;
export const MAX_SEGMENTS_PER_SCOPE = 16;

// A single segment: a non-empty run of [a-zA-Z0-9_-], or the literal `*`.
const SEGMENT = /^(?:[a-zA-Z0-9_-]+|\*)$/;

/**
 * Validate a single scope string against the v0.2 grammar + segment cap.
 * @returns {boolean}
 */
export function isValidScope(scope) {
  if (typeof scope !== 'string' || scope.length === 0) return false;
  const segments = scope.split(':');
  if (segments.length > MAX_SEGMENTS_PER_SCOPE) return false;
  return segments.every((seg) => SEGMENT.test(seg));
}

/**
 * Validate a scope SET (array). Returns { valid, reason } so callers can emit a
 * precise error. Rejects non-arrays, oversize sets, and any malformed scope.
 */
export function validateScopeSet(scopes) {
  if (!Array.isArray(scopes)) return { valid: false, reason: 'scope must be an array of strings' };
  if (scopes.length > MAX_SCOPES_PER_SET) {
    return { valid: false, reason: `scope set exceeds ${MAX_SCOPES_PER_SET} entries` };
  }
  for (const s of scopes) {
    if (!isValidScope(s)) {
      return { valid: false, reason: `invalid scope grammar: ${typeof s === 'string' ? JSON.stringify(s) : typeof s}` };
    }
  }
  return { valid: true };
}

/**
 * Does `granted` match `requested` per §4.4 (segment-by-segment, `*` matches
 * exactly one segment)? Segment counts must be equal — the wildcard does not
 * span multiple segments.
 */
export function scopeMatches(granted, requested) {
  const g = granted.split(':');
  const r = requested.split(':');
  if (g.length !== r.length) return false;
  for (let i = 0; i < g.length; i++) {
    if (g[i] === '*') continue;
    if (g[i] !== r[i]) return false;
  }
  return true;
}

/**
 * Is `childScopes` a subset of `parentScopes` under §4.4 matching? Every child
 * scope must be matched by at least one parent scope. (Attenuation rule.)
 */
export function isScopeSubset(childScopes, parentScopes) {
  return childScopes.every((child) => parentScopes.some((parent) => scopeMatches(parent, child)));
}

/**
 * Effective scope across two levels: the child scopes permitted by the parent.
 * Folding this across a chain (parent-most → child-most) yields the chain's
 * effective scope per §4.4.
 */
export function intersectScopes(parentScopes, childScopes) {
  return childScopes.filter((child) => parentScopes.some((parent) => scopeMatches(parent, child)));
}
