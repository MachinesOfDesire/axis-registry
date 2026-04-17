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

## What's NOT in this repo

- The AXIS Protocol specification (lives separately, pending public publication)
- The AXIS Protocol SDK (`axis-protocol-sdk`)
- The AXIS Prime dashboard / UI (separate codebase)
- The Kipple Labs registrar front-end (separate codebase)

## License

TBD — aligned with the AXIS Identity Protocol licensing decision (not yet
finalized). This repo is private during the naming + licensing pass.
