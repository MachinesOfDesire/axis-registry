# Deploying your own AXIS registry

This registry is the reference implementation of the AXIS protocol (v0.1). You can fork it, run your own, and still be part of the federation — provided you meet the requirements in [Registry Conformance v0.1](https://github.com/MachinesOfDesire/axis-registry/blob/main/docs/conformance.md) (see also the copy in `docs/` of this repo once published).

This document is the minimum practical guide for getting a fork live. It assumes familiarity with Cloudflare Workers and D1. If that is not you, the reference registry at `registry.axisprime.ai` is free to use.

---

## What you need

- A Cloudflare account (Workers + D1 enabled, Paid Workers plan if you expect real traffic)
- Wrangler CLI ≥ 3 (`npm install -g wrangler`)
- A domain you control (if you want a custom hostname; optional)
- Node 20+ for local development

## Step 1 — Clone and install

```bash
git clone https://github.com/MachinesOfDesire/axis-registry.git my-registry
cd my-registry
npm install
```

## Step 2 — Configure Cloudflare resources

### Create a D1 database

```bash
wrangler d1 create my-axis-registry-db
```

Copy the returned `database_id`. You'll paste it into `wrangler.toml` in the next step.

### Copy and customize `wrangler.toml`

```bash
cp wrangler.toml.example wrangler.toml
```

Edit `wrangler.toml`:

- `name` — a unique worker name in your Cloudflare account
- `account_id` — your Cloudflare account ID (Dashboard → Workers → Overview)
- `routes` — either remove this block (to use the `*.workers.dev` URL) or set the pattern to your own domain and zone
- `[vars] REGISTRY_BASE_URL` — the canonical public URL of *your* registry (goes into every agent record)
- `[[d1_databases]] database_id` — paste the id from `wrangler d1 create`

## Step 3 — Initialize the schema

```bash
wrangler d1 execute my-axis-registry-db --remote --file=./schema.sql
wrangler d1 execute my-axis-registry-db --remote --file=./migrations/0001_registrar_roles.sql
```

Any future migrations in `migrations/` apply the same way, in numeric order.

## Step 4 — Seed a registrar key

The registry authenticates callers by a SHA-256 hashed bearer key. Generate one:

```bash
# On Linux/Mac:
RAW_KEY=$(openssl rand -hex 32)
KEY_HASH=$(echo -n "$RAW_KEY" | shasum -a 256 | cut -d' ' -f1)
echo "Raw key (store this somewhere safe; treat as a password):"
echo "$RAW_KEY"
echo "Hash (goes in the DB):"
echo "$KEY_HASH"
```

Insert into `registrars`:

```bash
wrangler d1 execute my-axis-registry-db --remote \
  --command "INSERT INTO registrars (id, name, type, api_key_hash, status, role)
             VALUES ('my-org', 'My Org', 'operator', '$KEY_HASH', 'active', 'super_admin')"
```

**Role guidance:**
- First key is typically `super_admin` so you can issue additional keys and handle break-glass.
- Service-to-service integrations should hold `registrar` role.
- Reserve `admin` / `super_admin` for named human operators.

Store the raw key in whatever secret manager you use. Never commit it.

## Step 5 — Deploy

```bash
wrangler deploy
```

That prints your worker's URL. If you configured a custom domain in `wrangler.toml`, Cloudflare provisions DNS and TLS automatically.

## Step 6 — Smoke test

```bash
# Public (no auth) — should return the access policy:
curl https://your-registry-url/.well-known/axis-access

# Authenticated — should return your stats:
curl -H "Authorization: Bearer $RAW_KEY" https://your-registry-url/admin/stats
```

## Maintaining conformance

Your registry is conformant if it behaves according to [Registry Conformance v0.1](./docs/conformance.md). Critical operational points:

- **API keys are stored as SHA-256 hashes.** Never store raw keys.
- **Break-glass endpoints require a reason string and write audit rows before mutating.** The reference implementation handles this in `src/index.js` at the `/admin/force-*` routes. Do not bypass the audit-first pattern.
- **Ownership scoping.** Every handler on an operator-owned resource checks `registrar_id` against the authenticated principal. If you add new mutating endpoints, follow the same pattern.
- **Retention.** `audit_log` records must persist at least 12 months. Do not add automatic cleanup without a 12-month floor.

## Ongoing operations

- **Rotating keys:** insert a new hash into `registrars` for a given registrar, confirm the caller has switched, then delete the old hash. There is no downtime because the registry accepts any hash matching an active registrar key.
- **Revoking keys:** `UPDATE registrars SET status = 'inactive' WHERE id = ?`. Effective immediately on the next request.
- **Reading the audit log:** `GET /admin/audit` (admin+ role). Or direct D1 query for forensics.
- **Incident response:** the break-glass endpoints (`/admin/force-deactivate-agent/:id`, `/admin/force-revoke-delegation/:id`) are for compromise events. Provide a human-readable `reason`; it goes in the permanent record.

## Operating costs

At Cloudflare's current pricing, running the registry for a small federation (thousands of operators, hundreds of thousands of agent resolutions per month) sits in the low-tens of dollars per month. The dominant cost is D1 read rows. This is a single-digit line item, not a business model driver.

## Known limitations of the reference implementation

- **Rate limiting is minimal.** Cloudflare's infrastructure provides the baseline; per-registrar application-level limits are TODO.
- **Retention enforcement is not yet automated.** Audit records persist indefinitely by default. You can enforce minimum retention manually or via scheduled Workers.
- **No built-in metrics dashboard.** `GET /admin/stats` returns counts; deeper observability is your responsibility (Cloudflare Analytics, external tooling).
- **No federation discovery.** If you run your registry, consumers must be told its URL. There is no registry-of-registries yet.

## Getting help

- Issues: [github.com/MachinesOfDesire/axis-registry/issues](https://github.com/MachinesOfDesire/axis-registry/issues)
- Protocol spec: [github.com/MachinesOfDesire/axis-protocol](https://github.com/MachinesOfDesire/axis-protocol)
- Conformance questions: open a discussion in the protocol repo

## License

Apache 2.0. See [LICENSE](./LICENSE).
