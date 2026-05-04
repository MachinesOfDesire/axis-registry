# AXIS Registry

Cloudflare Workers + D1 implementation of the AXIS Identity Protocol registry API.

This is the **production source** for the deployed registry worker at
`https://axis-registry.editor-9a4.workers.dev`.

> ⚠️ Naming note: the protocol and product names are being finalized. The
> codebase currently uses `axis-registry` / `axis:{operator}:{agent}` and
> references `AXIS Protocol` in comments. Final names (likely **AXIS Identity**
> for the protocol, **AXIS Prime** for the product, **Kipple Labs** for the
> operating company) will be applied in a naming pass once domains are locked.

## Layout

```
src/
  index.js              Worker entry — route table
  routes/               Endpoint handlers (register, resolve, verify, ...)
  middleware/           auth, cors
  utils/                crypto, audit
schema.sql              D1 schema
seed-key.sql            One-time registrar API-key seed (hashes only, safe to commit)
wrangler.toml           Worker config — D1 binding to axis-registry-db
```

## Prerequisites

- Node 18+
- `wrangler` (Cloudflare's CLI) — `npm i -g wrangler`
- A Cloudflare account with Workers + D1 enabled
- `ADMIN_TOKEN` set as a Worker secret (`wrangler secret put ADMIN_TOKEN`)

## Local development

```bash
npm install
npm run db:init        # initialize local D1 from schema.sql
npm run dev            # start local wrangler dev server
```

## Deploy

**CI-based (preferred):** push to `main` triggers the GitHub Actions workflow
at `.github/workflows/deploy.yml`, which runs `wrangler deploy`.

**Manual:**
```bash
wrangler deploy
```

Initial schema migration to remote D1 (first deploy only, or after schema
changes):
```bash
npm run db:init:remote
```

## Secrets and configuration

Worker-side secrets (set via `wrangler secret put`):
- `ADMIN_TOKEN` — bearer token for admin endpoints

GitHub Actions secrets (for CI deploy):
- `CLOUDFLARE_API_TOKEN` — scoped token with Workers + D1 deploy permissions
- `CLOUDFLARE_ACCOUNT_ID` — the Cloudflare account ID

Public config lives in `wrangler.toml` (`database_id`, etc. — not secret).

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
