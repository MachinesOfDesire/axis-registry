# AXIS Registry

Cloudflare Workers + D1 implementation of the **canonical** AXIS Protocol registry API.

This is the **production source** for the registry deployed at
[`registry.axisprime.ai`](https://registry.axisprime.ai). Companion projects:

- Protocol spec: [MachinesOfDesire/axis-protocol](https://github.com/MachinesOfDesire/axis-protocol)
- Conformance suite: [MachinesOfDesire/axis-conformance](https://github.com/MachinesOfDesire/axis-conformance)
- Reference SDK: [MachinesOfDesire/axis-protocol-sdk](https://github.com/MachinesOfDesire/axis-protocol-sdk)

## Scope

This implementation stores **Layer 1 (Identity)** and **Layer 2 (Authorization)** records only — registrars, operators, agents, agent slots, delegations, audit log. That's everything a verifier needs to validate an AIT or walk a delegation chain.

Layer 3 artifacts (Trust Attestations, Content Provenance Attestations) are explicitly **NOT** stored here. Per the canonical spec (`SPEC.md` v0.1.1): *"Layers 1 and 2 are mandatory for any verification. Layer 3 is advisory."* L3 records are stored by the issuer; for Kipple Labs as one issuer, those live in a separate codebase + database (`kipple-extensions`), not in this canonical registry.

This separation matters because:

1. **Conformance clarity** — anyone forking this repo gets a working AXIS implementation, not a Kipple-specific superset.
2. **Foundation readiness** — when independent governance forms (post-solvency), this canonical schema is what's handed off; no Kipple cleanup needed.
3. **Open-source path** — the canonical registry can accept community contributions without exposing extension internals.

If you fork this for your own conformant registry, you can ignore everything in this repo about `kipple-extensions`. The `axis-registry-db` binding is the only D1 that the canonical registry needs.

## Layout

```
src/
  index.js              Worker entry — route table
  routes/               Endpoint handlers (register, resolve, verify,
                        delegations, revocation, operators, admin, ...)
  middleware/           auth (three-role RBAC), cors
  utils/                crypto, audit
migrations/             D1 migrations (0001 registrar roles, 0002 opaque
                        operator IDs). Applied via `wrangler d1 execute
                        --file`; the d1_migrations tracker is backfilled
                        out-of-band.
schema.sql              D1 base schema (run first on a fresh database)
seed-key.sql            One-time registrar API-key seed (SHA-256 hash only,
                        safe to commit; the raw key lives outside git)
wrangler.toml           Worker config — D1 binding to axis-registry-db
wrangler.toml.example   Sanitized template for forks
```

## Prerequisites

- Node 20+
- `wrangler` 4+ (`npm i -g wrangler`)
- A Cloudflare account with Workers + D1 enabled

## Authorization model

Three roles, enforced server-side. The SDK does not predict role locally —
the server is the source of truth and returns `401`/`403` with stable codes
for the SDK to branch on.

| Role | Powers |
|---|---|
| `registrar` | Register / deactivate agents under operators it owns; set operator status (`POST /operators/:id/status` — the operator kill switch); create / revoke delegations issued by its agents; verify domains. |
| `admin` | Cross-tenant read on operators, agents, audit log, and stats. Same BOLA constraints as `registrar` on the normal write paths. |
| `super_admin` | Break-glass writes: `/admin/force-deactivate-agent/:id`, `/admin/force-deactivate-operator/:id`, and `/admin/force-revoke-delegation/:id`. Audit row is written *before* the mutation; aborts if the audit write fails. Reason is required. |

Bearer-token auth via `Authorization: Bearer <key>`. Each registrar's raw
key lives outside source control; only the SHA-256 hash is stored in the
`registrars` table.

## Local development

First-time setup: copy the example config, fill in your own Cloudflare
account ID and D1 database ID. The real `wrangler.toml` is git-ignored so
your environment-specific values do not get committed.

```bash
cp wrangler.toml.example wrangler.toml
# edit wrangler.toml: replace every CHANGE-ME with your value
npm install
npm run db:init        # initialize local D1 from schema.sql
npm run dev            # start local wrangler dev server
```

## Deploy

Auto-deploy on push is **disabled** (`.github/workflows/deploy.yml` keeps
`workflow_dispatch` only) until a staging environment exists. Deploy manually:

```bash
wrangler deploy
```

For a fresh remote database:

```bash
npm run db:init:remote                                    # base schema
wrangler d1 execute axis-registry-db --remote --file=migrations/0001_registrar_roles.sql
wrangler d1 execute axis-registry-db --remote --file=migrations/0002_opaque_email_tier_operator_ids.sql
# Then backfill the d1_migrations tracker so future `wrangler d1 migrations
# apply` calls don't try to re-run them:
wrangler d1 execute axis-registry-db --remote --command \
  "INSERT INTO d1_migrations (name) VALUES ('0001_registrar_roles.sql'), ('0002_opaque_email_tier_operator_ids.sql')"
```

## Secrets and configuration

Public config lives in `wrangler.toml` (D1 `database_id`, `REGISTRY_BASE_URL`).
No Worker-side secrets are required for the registry itself — registrar API
keys are stored hashed in the `registrars` table; admin/super_admin role is
elevated via the `registrars.role` column, not a separate token.

For CI (when re-enabled):
- `CLOUDFLARE_API_TOKEN` — scoped token with Workers + D1 deploy permissions
- `CLOUDFLARE_ACCOUNT_ID` — the Cloudflare account ID

## Running your own registry

If you want to fork this and run a conformant registry under your own control,
start with [DEPLOYMENT.md](./DEPLOYMENT.md). Requirements you must meet to be
called an "AXIS-conformant registry" are in
[Registry Conformance v0.1](../../registry-conformance-v0.1.md) (to be copied
into this repo as `docs/conformance.md` when published).

## What's NOT in this repo

- The AXIS Protocol specification ([MachinesOfDesire/axis-protocol](https://github.com/MachinesOfDesire/axis-protocol))
- The AXIS Protocol SDK ([axis-protocol-sdk](https://github.com/MachinesOfDesire/axis-protocol-sdk))
- The AXIS Prime dashboard / UI (separate codebase)
- The Kipple Labs registrar front-end (separate codebase)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Security reports to
`security@kipplelabs.com`; see [SECURITY.md](./SECURITY.md).

## License

Apache 2.0. See [LICENSE](./LICENSE).
