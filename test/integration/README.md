# Integration tests

Route-level tests for `axis-registry`, backed by **Miniflare** (Cloudflare's local Workers runtime emulator) + an in-memory D1.

These tests dispatch real HTTP requests at the worker entry point, exercise route handlers end-to-end, and verify both response shapes and underlying DB state. They complement the unit tests in `test/*.test.js` which cover pure helpers in isolation.

## When to write one

Open a test in this directory when the behavior you want to verify involves:

- **Cross-statement state changes** — anything that touches more than one D1 statement (slot allocation + agent insert, audit-write + mutation, delegation chain rebuild).
- **Concurrency** — race conditions, parallel writes, retry semantics.
- **Authorization gating** — BOLA matrices (registrar A's key can't touch registrar B's resources), role-aware paths (admin vs registrar vs super_admin), AIT-vs-bearer presentation-layer unlocks.
- **Wire-format round-trips** — what does the live response actually look like, not just what the route handler returns.

Keep pure-function tests (signature verification, slug derivation, DID parsing, etc.) in `test/*.test.js`. Faster, no Miniflare boot cost.

## How to write one

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHarness } from './harness.js';

test('your scenario', async (t) => {
  const harness = await createHarness();
  t.after(() => harness.dispose());        // always dispose; each test owns a worker

  const registrar = await harness.createRegistrar({ role: 'registrar' });
  const operator  = await harness.createOperator({
    registrar_id: registrar.id,
    tier: 'domain',
    domain: 'example.com',
    free_slots_total: 3,
  });

  const res = await harness.fetch('/register', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${registrar.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      publicKey: harness.generateFakePublicKey(),
      operator: { domain: operator.domain },
      metadata: { name: 'agent-1' },
    }),
  });

  assert.equal(res.status, 201);
  const slots = await harness.getSlots(operator.id);
  assert.equal(slots.free_slots_used, 1);
});
```

## Harness contract

`createHarness()` returns an object with:

| Method | Use |
|---|---|
| `fetch(path, init)` | Dispatch an HTTP request at the worker. Returns `Response`. |
| `createRegistrar({ id?, name?, type?, role?, domain? })` | Insert a registrar row. Returns `{ id, apiKey, role }`. The `apiKey` plaintext is in-memory; the DB stores its SHA-256 hash. |
| `createOperator({ registrar_id, tier?, email?, domain?, free_slots_total?, max_agents?, domain_verified? })` | Insert operator + matching `agent_slots` row. Returns `{ id, email, domain, tier }`. |
| `generateFakePublicKey()` | Random base64url 32-byte string. Field-shaped, NOT cryptographically valid — only use in tests that don't supply a proof. |
| `getSlots(operatorId)` | Read `agent_slots` row. |
| `getAgentsForOperator(operatorId)` | List agents owned by the operator. |
| `dispose()` | Tear down Miniflare. Call from `t.after()`. |

Each `createHarness()` call spins up a **fresh isolated worker + fresh D1**. Tests don't share state; you can safely run them in parallel without worrying about ordering.

## What the harness deliberately does NOT do

- **No rate-limit bindings.** The middleware no-ops when bindings are absent. Tests run unrated. Add a separate harness profile if you want to test rate-limit behavior.
- **No real Ed25519 proofs.** `generateFakePublicKey()` makes shape-valid bytes but no real keypair. Tests that submit a `proof` field need to use `@noble/ed25519` or similar to generate a real signature. Most route-level tests can skip the proof field (it's optional in `/register`).
- **No backup/restore of the seed `kipple-labs` row.** The harness deletes the schema's `INSERT OR IGNORE` seed so tests start from a known-empty `registrars` table. If a test needs that row, recreate it via `createRegistrar({ id: 'kipple-labs', ... })`.

## Running

```sh
npm test                # runs both unit + integration tests
npm run test:integration  # integration tests only
```

The integration tests are slower (Miniflare boot is a few hundred ms per `createHarness()`). For tight unit-test iteration use the unit-only script.

## Existing files

- `harness.js` — the test fixture itself
- `slot-race.test.js` — C2 regression: concurrent registrations don't over-allocate slots

## Pending — high-leverage integration tests to add next

These are flagged in the security review's "Test gap" section. Order by impact:

1. **BOLA matrix** — `test/integration/bola.test.js`: every mutating route, registrar A's key MUST NOT touch registrar B's resources. Most important pre-launch coverage.
2. **Audit-before-mutate** — `test/integration/audit.test.js`: `/admin/force-*` writes audit row BEFORE the mutation, and aborts with 500 if audit insert fails.
3. **AIT verification matrix** — `test/integration/ait-verify.test.js`: bad sig / expired / wrong typ/alg / missing iss / revoked agent / malformed b64 / missing aud (post-H1).
4. **Delegation chain attenuation** — `test/integration/delegation-chain.test.js`: child scope ⊆ parent; cycle handling; depth cap from M3.
5. **Public-vs-presentation field gating** — `test/integration/presentation-layer.test.js`: various auth states unlock the right field sets, no field leakage across layers.

Pick any one of these next; the harness is the foundation that makes them cheap.
