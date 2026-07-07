/**
 * AXIS protocol version advertised by this registry's discovery surfaces
 * (`/.well-known/axis-access`, `/.well-known/axis-scopes`).
 *
 * Single-sourced so the discovery endpoints can never drift apart — the
 * shipped feature set tracks protocol v0.3 (scope vocabulary discovery,
 * registry legitimacy artifacts, chain-by-delegation-id verification).
 *
 * NOTE: this is the PROTOCOL version the registry implements, not the
 * credential-FORMAT version. Stored/echoed credential documents (Delegation
 * Credentials, operator/agent records) carry their own `axis_version`
 * reflecting the format they were issued under (stable since v0.2) — those
 * are deliberate and must not be re-pointed at this constant.
 */
export const PROTOCOL_VERSION = '0.3';
