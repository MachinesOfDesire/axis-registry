# Scope Syntax (Non-Normative)

**Status:** Recommendation, not protocol requirement.
**Spec reference:** `docs/specs/axis-registry-v0.x-changes-spec.md` Change 2.

## What the registry actually does with scopes

The AXIS Registry stores scope strings as opaque text. It does not parse, validate, or interpret scope syntax. Two delegations carrying entirely different scope grammars are equally valid in the registry — the registry's only concern is that the delegation chain is signed, unrevoked, and within its `expires_at`.

**Registries must accept any scope string and must not validate its format.** Conformance does not require any particular syntax.

## Why a recommendation exists

Gateways — the components that *do* interpret scopes at runtime — are independent implementations. Without a shared convention, two gateways looking at the same delegation can disagree about what it grants. That fragmentation is bad for both the protocol's interoperability story and for operators trying to reason about agent permissions across multiple integrations.

This file documents a non-normative convention so independent gateway implementations can share a vocabulary without the registry mandating one.

## Recommended grammar

Two complementary forms, used in either or both per delegation as the implementation prefers:

### Coarse-grained: `service:<server>:<verb>`

```
service:shopify:read
service:shopify:write
service:drive:read
service:drive:write
```

`<server>` is a short stable identifier for an upstream system (e.g. `shopify`, `drive`, `slack`, `anthropic-prod`). `<verb>` is one of `read` / `write` / `*` (wildcard).

Best for: simple bucket-level grants, lift-and-shift from existing role models, the v1 of most products.

### Fine-grained: `service:<server>:<action>`

```
service:shopify:list-products
service:shopify:update-inventory
service:drive:create-file
service:drive:download-file
```

`<action>` is a specific operation identifier — usually the operation name from the upstream API's documentation, lowercased and kebab-cased.

Best for: per-action permission enforcement, audit-friendly grants, principle-of-least-privilege deployments.

### Mixed use

A single delegation may carry both forms:

```json
{
  "scopes": [
    "service:drive:read",
    "service:shopify:list-products",
    "service:shopify:update-inventory"
  ]
}
```

The registry treats them identically — opaque strings on an unordered set. Gateways resolve their meaning per-route.

## Wildcards

Implementations that support wildcards should treat `*` as a literal segment value, not a glob. So `service:shopify:*` matches every action under `shopify`; `service:*:read` matches `read` on every server. `*:*:*` (or equivalent) should NOT be issued by any sane operator UI.

The registry does not interpret wildcards. Gateways do.

## What is intentionally NOT recommended

- **Per-resource scopes** (e.g. `service:drive:read:folder/Q3-reports`). The registry doesn't preclude them, but no gateway today implements per-resource enforcement and a recommendation here would lock in a syntax before the design surface is settled.
- **Hierarchical inheritance** (e.g. `service:drive:read` automatically granting `service:drive:list`). Implementations may choose to model this, but a registry-level recommendation would conflict with stricter enforcement models that want exact-match only.
- **ABAC / conditions in the scope string** (e.g. `service:drive:read[when=business-hours]`). Conditions belong on the delegation's `conditions` column (when added to the schema), not in the scope string.

## Conformance impact

None. Conformance for AXIS registries is defined by the wire protocol and the registry endpoints; scope-syntax conventions live above that line. A registry that accepts arbitrary scope strings and does not validate their format is conformant with or without adopting this recommendation.

This file exists so independent implementations can converge on a shared vocabulary by choice, not by requirement.
