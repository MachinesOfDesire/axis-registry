# axis-registry v0.x Changes — Specification

**Version:** v0.x (companion to Kipple Governor v0.1)
**Owner:** Josh Ashcroft
**Status:** Draft, 2026-05-22
**Companion spec:** `kipple-governor-v0.1-spec.md`
**Target repo:** `MachinesOfDesire/axis-registry`

---

## Overview

Two changes to the canonical axis-registry to support Governor v0.1's product model. Both changes are minimal, backward-compatible, and consistent with the registry's "Layer 1 (Identity) and Layer 2 (Authorization) only" scope. Neither breaks conformance.

1. **Schema change:** add a nullable `parent_operator_id` column to the `operators` table, enabling a three-level principal hierarchy (organization → user → agent) without breaking the existing two-level model.
2. **Documentation change:** add a non-normative recommendation for scope syntax conventions, so independent gateway implementations can interoperate.

---

## Change 1: parent_operator_id column on operators table

### Problem

Governor v0.1 models a three-level principal hierarchy: `organization → user → agent`. The canonical registry currently models two levels: `operator → agent`, where "operator" is defined in the schema comments as "Organizations or individuals that control agents." There is no way to express the relationship "this user is a member of this organization" using the existing schema.

If Governor maintains the hierarchy in its own database without a corresponding registry change, the principal model and the registry drift apart. That divergence is exactly the situation the open-core architecture is meant to avoid: it forces Governor to be the source of truth for principal relationships that should be canonical in the registry.

### Solution

Add a nullable `parent_operator_id` column to the `operators` table, referencing `operators.id`. Semantics:

- An operator with `parent_operator_id IS NULL` is a top-level entity (an organization, or a free-standing individual operator, as today).
- An operator with `parent_operator_id` set is a child of the referenced operator (a user under an organization).
- Children can receive delegations from their parent using the existing delegation mechanism.
- Agents continue to belong to a single operator (which may be a parent or a child).

Single-column addition. No breaking impact. Existing operators retain `NULL` parent and behave identically. The existing delegation chain logic already supports operator-to-operator delegation, which is what makes the parent-child authority flow work end-to-end.

### Schema change

```sql
-- Migration: 0003_parent_operator_id.sql
ALTER TABLE operators ADD COLUMN parent_operator_id TEXT;
-- D1/SQLite does not support adding a FOREIGN KEY constraint after table creation
-- via ALTER, so the FK semantics are enforced at the application layer for existing
-- deployments. Fresh deploys carry the constraint via schema.sql update below.
CREATE INDEX idx_operators_parent ON operators(parent_operator_id);
```

Also update `schema.sql` for fresh deploys to include the column and FK constraint inline on the `operators` table definition.

### API surface changes

- `POST /operators` accepts an optional `parent_operator_id` parameter. If set, the value must reference an existing operator owned by the same registrar (BOLA enforcement).
- `GET /operators/:id` includes `parent_operator_id` in the response when set.
- `GET /operators/:id/children` new endpoint returning child operators (paginated). Pagination follows the same convention as other list endpoints.
- Delegation creation endpoints already accept operator-to-operator delegations; no API change needed, just documentation that parent-to-child is the canonical use case for hierarchical orgs.

### Authorization rules

- A registrar may create a child operator only if the proposed parent is owned by the same registrar.
- A registrar may not create a child operator whose parent belongs to a different registrar (prevents cross-registrar principal injection).
- `admin` and `super_admin` roles retain cross-tenant read on the parent-child relationship.

### Conformance impact

None. The column is optional. Any registry implementation that doesn't support `parent_operator_id` simply treats all operators as flat (the current behavior). The conformance suite needs no changes. A new test for parent-child semantics is additive, not breaking, and can land separately in `MachinesOfDesire/axis-conformance`.

### Acceptance criteria

- [ ] Migration `0003_parent_operator_id.sql` applies cleanly to the existing live database
- [ ] `schema.sql` updated so fresh deploys include the column
- [ ] `POST /operators` accepts and persists `parent_operator_id`
- [ ] `POST /operators` rejects a `parent_operator_id` belonging to a different registrar with a stable error code
- [ ] `GET /operators/:id` returns `parent_operator_id` when set
- [ ] `GET /operators/:id/children` returns the correct paginated list
- [ ] A delegation issued from a parent operator to a child operator is accepted, stored, and verifiable via the existing chain-walk logic
- [ ] An agent owned by a child operator can present an AIT carrying a delegation chain that traces back to the parent and the chain validates
- [ ] Existing operators with `NULL` parent continue to behave identically (no regression)
- [ ] Audit log entries for `POST /operators` and `GET /operators/:id/children` are written via the existing audit pipeline

---

## Change 2: Scope syntax recommendation in spec docs

### Problem

The registry stores scope strings as opaque text. There is no documented convention for how implementations should format scope strings. As multiple Governor-equivalent gateways emerge (including a future open-source Mayor variant), this risks fragmentation: each implementation chooses its own convention, scopes become non-portable, and the registry's role as a neutral storage layer is undermined.

### Solution

Add a non-normative recommendation to the registry spec documentation (likely a new `docs/scopes.md`, or a section inside `SPEC.md` in the `axis-protocol` repo) that recommends a layered scope syntax for interoperability.

**Recommended convention:**

- **Coarse-grained:** `service:<server>:<verb>` (e.g., `service:shopify:read`, `service:drive:write`)
- **Fine-grained:** `service:<server>:<action>` (e.g., `service:shopify:list-products`, `service:drive:create-file`)
- **Hybrid:** an implementation may use either form per scope and the registry accepts both without distinction

Where `<server>` is the MCP server (or REST API wrapped as an MCP server) and `<verb>` / `<action>` is the operation requested.

### Why non-normative

The registry's job is to store and chain scopes, not to interpret them. Gateways enforce scopes at runtime; that's where granularity decisions belong. Mandating a syntax would force every gateway implementation into a single model. Recommending one gives independent implementations a shared vocabulary while keeping the registry agnostic.

### Implementation impact

None on the registry code or schema. Documentation-only change. Could be a one-paragraph addition to `SPEC.md` or a new file under `docs/`.

### Acceptance criteria

- [ ] `SPEC.md` (or equivalent) includes a "Scope Syntax (Non-Normative)" section
- [ ] The section explicitly states that registries must accept any scope string and not validate format
- [ ] Conformance suite remains unchanged

---

## Timeline Considerations

**Change 1 (`parent_operator_id`)** must land before Governor v0.1 ships, or Governor's `organization → user → agent` schema can't be backed by the canonical registry. If the registry change is blocked for any reason, Governor v0.1 can ship with a temporary internal mapping (Governor's own database holds the parent-child relationship), but this introduces exactly the kind of drift we're trying to avoid. Strong preference: land the registry change first.

**Change 2 (scope syntax recommendation)** is documentation-only and can land any time, including after Governor v0.1. Recommend doing it as part of the same PR as Change 1 so the registry's v0.x bump is coherent.

---

## Open Questions

- **Stakeholder.** Who reviews and approves changes to the canonical registry? Internal to Kipple Labs for now, but if axis-protocol is intended to have broader community governance, the `parent_operator_id` change should be socialized accordingly before merge. Worth documenting the review path explicitly.
- **Engineering.** Is the existing migration tooling (`wrangler d1 execute --file`) sufficient for this change, or does it warrant a new entry in `migrations/` with the existing tracker backfill pattern (see migrations 0001 and 0002)?
- **Engineering.** SQLite doesn't support adding FK constraints via `ALTER TABLE`. For the live database, FK semantics are enforced at the application layer. Is that acceptable, or do we want to recreate the table to add the constraint? Recreation is heavier but matches `schema.sql`.
- **Product.** Should `agent_slots` be re-evaluated in the parent-child model? Currently slots are per-operator. In a parent-child setup, should child operators consume from the parent's pool, have their own pool, or be exempt? Probably v1.x decision, not v0.x.

---

## Definition of Done

The registry change is shippable when:

- [ ] Migration applied to staging and production D1 databases
- [ ] `schema.sql` updated and committed
- [ ] API surface changes implemented with route handlers
- [ ] Authorization rules enforced (same-registrar constraint on parent assignment)
- [ ] All acceptance criteria for Change 1 green in automated tests
- [ ] Scope syntax recommendation merged into spec documentation
- [ ] CHANGELOG entry written
- [ ] axis-conformance updated with additive parent-child tests (separate PR, can land later)
- [ ] Governor v0.1 dependency confirmed unblocked by this change
