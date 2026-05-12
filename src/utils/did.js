/**
 * AXIS DID parser (spec v0.2 §10.3).
 *
 * Two canonical forms accepted:
 *
 *   v0.2 (canonical):  did:axis:<registry>:<operator>:<agent>
 *   v0.1 (legacy):     did:axis:<registry>:<agent>
 *
 * Per spec §10.3, resolvers MUST accept both. The registry must therefore
 * be able to:
 *   1) Parse either form and extract the agent slug for lookup.
 *   2) Parse the v0.2 form and extract the operator slug (for scoped
 *      disambiguation when an agent slug is shared across operators).
 *
 * Returns `{ form: "v0.1" | "v0.2", registry, operator, agent }` or
 * `null` if the input is not a recognizable `did:axis:` DID.
 */

const DID_AXIS_RE = /^did:axis:[a-z0-9][a-z0-9-]{0,62}(?::[a-z0-9][a-z0-9-]{0,62}){1,2}$/i;

export function parseAxisDid(input) {
  if (typeof input !== 'string') return null;
  if (!DID_AXIS_RE.test(input)) return null;
  const parts = input.split(':');
  // parts: ['did', 'axis', '<registry>', '<seg1>', '<seg2>?']
  // v0.1: ['did','axis','<reg>','<agent>']        → length 4
  // v0.2: ['did','axis','<reg>','<op>','<agent>'] → length 5
  if (parts.length === 4) {
    return {
      form: 'v0.1',
      registry: parts[2],
      operator: null,
      agent: parts[3],
    };
  }
  if (parts.length === 5) {
    return {
      form: 'v0.2',
      registry: parts[2],
      operator: parts[3],
      agent: parts[4],
    };
  }
  return null;
}

/**
 * Build the v0.2 canonical DID. Always emits 4-segment form even for
 * legacy callers — once Phase 2 migration runs, every stored DID is
 * v0.2.
 */
export function buildAxisDidV2(registry, operator, agent) {
  return `did:axis:${registry}:${operator}:${agent}`;
}
