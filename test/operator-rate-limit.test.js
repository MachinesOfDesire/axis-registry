/**
 * RL_OPERATOR — per-operator spam brake.
 *
 * The tier sub-partitions the shared REGISTRAR bucket: a hosted console
 * funnels every one of its operators through ONE registrar key, so without
 * this a single hot operator can exhaust the registrar's budget and starve
 * its siblings. The check runs IN-ROUTE (the operator id is only known after
 * body parse + ownership resolution), which is what these tests lock in:
 *
 *   1. Middleware helper contract (no-op without binding, fail-open on
 *      binding errors, 429 shape + key format when the binding denies).
 *   2. Route wiring: handleRegister / handleCreateDelegation /
 *      handleUpdateAgent deny with 429 + Retry-After when the operator's
 *      bucket is exhausted.
 *   3. Ordering: the brake fires AFTER the BOLA gate — a cross-registrar
 *      caller sees 403, never a 429 that would leak bucket state for a
 *      resource that isn't theirs.
 *   4. Kill-switch exclusion: revocation and deactivation NEVER consult the
 *      operator bucket. An anti-spam limit must not throttle the paths that
 *      exist to stop a compromised agent.
 *
 * Handlers are exercised directly with a stubbed D1 so the tests stay in
 * the plain node:test runner (the Miniflare harness deliberately runs
 * unrated — see test/integration/harness.js).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkOperatorRateLimit, checkRateLimit, RATE_LIMIT_TIERS } from '../src/middleware/rate-limit.js';
import { handleRegister, handleUpdateAgent } from '../src/routes/register.js';
import { handleCreateDelegation, handleRevokeDelegation } from '../src/routes/delegations.js';

// ---- helpers ----

/** Rate-limit binding stub that records keys and answers per `allow`. */
function fakeBinding({ allow }) {
  const calls = [];
  return {
    calls,
    limit: async ({ key }) => {
      calls.push(key);
      return { success: allow };
    },
  };
}

/**
 * Minimal D1 stub. `handlers` is an array of { match, first } entries;
 * the first entry whose `match` substring appears in the SQL answers
 * `.first()`. Unmatched queries return null / empty — enough for the
 * pre-write portions of the routes under test.
 */
function stubDb(handlers) {
  return {
    prepare(sql) {
      return {
        bind() {
          const h = handlers.find((h) => sql.includes(h.match));
          return {
            first: async () => (h ? h.first() : null),
            run: async () => ({ success: true }),
            all: async () => ({ results: [] }),
          };
        },
      };
    },
  };
}

const REGISTRAR_A = { id: 'reg-a', role: 'registrar' };

// ---- 1. middleware helper contract ----

test('checkOperatorRateLimit: no binding configured → null (no-op)', async () => {
  assert.equal(await checkOperatorRateLimit({}, 'op-1'), null);
});

test('checkOperatorRateLimit: falsy operator id → null, binding untouched', async () => {
  const binding = fakeBinding({ allow: false });
  assert.equal(await checkOperatorRateLimit({ RL_OPERATOR: binding }, null), null);
  assert.equal(await checkOperatorRateLimit({ RL_OPERATOR: binding }, undefined), null);
  assert.equal(binding.calls.length, 0);
});

test('checkOperatorRateLimit: denying binding → 429 shape, op:<id> key, Retry-After', async () => {
  const binding = fakeBinding({ allow: false });
  const denial = await checkOperatorRateLimit({ RL_OPERATOR: binding }, 'op-1');
  assert.equal(denial.status, 429);
  assert.equal(denial.body.error.code, 'rate_limit_exceeded');
  assert.equal(denial.headers['Retry-After'], '60');
  assert.deepEqual(binding.calls, ['op:op-1']);
});

test('checkOperatorRateLimit: allowing binding → null', async () => {
  const binding = fakeBinding({ allow: true });
  assert.equal(await checkOperatorRateLimit({ RL_OPERATOR: binding }, 'op-1'), null);
  assert.deepEqual(binding.calls, ['op:op-1']);
});

test('checkOperatorRateLimit: binding throws → null (fail-open, never blocks on limiter failure)', async () => {
  const env = { RL_OPERATOR: { limit: async () => { throw new Error('boom'); } } };
  assert.equal(await checkOperatorRateLimit(env, 'op-1'), null);
});

test('checkRateLimit: tolerates a missing request object (in-route callers)', async () => {
  const binding = fakeBinding({ allow: false });
  const denial = await checkRateLimit({ RL_OPERATOR: binding }, RATE_LIMIT_TIERS.OPERATOR, 'op:op-1', null, null);
  assert.equal(denial.status, 429);
});

// ---- 2 + 3. handleRegister ----

function registerEnv({ operatorRow, binding }) {
  return {
    RL_OPERATOR: binding,
    DB: stubDb([{ match: 'FROM operators WHERE domain', first: () => operatorRow }]),
  };
}

const ACTIVE_OP_A = {
  id: 'op-1', registrar_id: 'reg-a', status: 'active',
  verification_tier: 'email', domain: null, email: 'a@example.com',
};

test('handleRegister: exhausted operator bucket → 429 with Retry-After', async () => {
  const binding = fakeBinding({ allow: false });
  const result = await handleRegister(
    { publicKey: 'pk-new', operator: { email: 'a@example.com' } },
    REGISTRAR_A,
    registerEnv({ operatorRow: ACTIVE_OP_A, binding })
  );
  assert.equal(result.status, 429);
  assert.equal(result.body.error.code, 'rate_limit_exceeded');
  assert.equal(result.headers['Retry-After'], '60');
  assert.deepEqual(binding.calls, ['op:op-1']);
});

test('handleRegister: BOLA fires before the brake — cross-registrar caller sees 403, bucket untouched', async () => {
  const binding = fakeBinding({ allow: false });
  const result = await handleRegister(
    { publicKey: 'pk-new', operator: { email: 'a@example.com' } },
    { id: 'reg-b', role: 'registrar' },
    registerEnv({ operatorRow: ACTIVE_OP_A, binding })
  );
  assert.equal(result.status, 403);
  assert.equal(result.body.error.code, 'not_your_resource');
  assert.equal(binding.calls.length, 0);
});

// ---- 2. handleCreateDelegation ----

test('handleCreateDelegation: exhausted issuer-operator bucket → 429 (agent-form issuer)', async () => {
  const binding = fakeBinding({ allow: false });
  const env = {
    RL_OPERATOR: binding,
    DB: stubDb([
      { match: 'FROM agents WHERE axis_id', first: () => ({ registrar_id: 'reg-a', operator_id: 'op-1' }) },
    ]),
  };
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const result = await handleCreateDelegation(
    {
      issued_by: 'axis:acme:agent-one', issued_to: 'did:example:consumer',
      root_operator: 'axis:acme:operator', scope: ['content:comment'], expires,
    },
    REGISTRAR_A,
    env
  );
  assert.equal(result.status, 429);
  assert.equal(result.body.error.code, 'rate_limit_exceeded');
  assert.equal(result.headers['Retry-After'], '60');
  assert.deepEqual(binding.calls, ['op:op-1']);
});

// ---- 2. handleUpdateAgent ----

test('handleUpdateAgent: exhausted operator bucket → 429 before any write', async () => {
  const binding = fakeBinding({ allow: false });
  const env = {
    RL_OPERATOR: binding,
    DB: stubDb([
      { match: 'FROM agents WHERE id = ? OR axis_id', first: () => ({ id: 'a1', registrar_id: 'reg-a', operator_id: 'op-1' }) },
    ]),
  };
  const result = await handleUpdateAgent('a1', { display_name: 'Renamed' }, REGISTRAR_A, env);
  assert.equal(result.status, 429);
  assert.deepEqual(binding.calls, ['op:op-1']);
});

// ---- 4. kill-switch exclusion ----

test('handleRevokeDelegation: revocation succeeds without ever consulting the operator bucket', async () => {
  const binding = fakeBinding({ allow: false }); // would deny if consulted
  const env = {
    RL_OPERATOR: binding,
    DB: stubDb([
      { match: 'FROM delegations WHERE id', first: () => ({ id: 'd1', registrar_id: 'reg-a', status: 'active' }) },
    ]),
  };
  const result = await handleRevokeDelegation('d1', {}, REGISTRAR_A, env);
  assert.equal(result.status, 200);
  assert.equal(result.body.status, 'revoked');
  assert.equal(binding.calls.length, 0);
});
