/**
 * Health-endpoint tests.
 *
 * The liveness surface must NOT depend on auth, rate limiting, or D1 — it is
 * the "is the worker running at all" signal. These tests invoke the Worker's
 * default fetch handler with an EMPTY env (no bindings, no DB) and assert it
 * still answers 200. If a future change makes /health touch env/D1, the empty
 * env would throw and these tests fail loud.
 *
 * Run: node --test test/*.test.js
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const ctx = { waitUntil() {}, passThroughOnException() {} };

for (const path of ["/health", "/v1/health"]) {
  test(`GET ${path} returns 200 with no env/DB dependency`, async () => {
    const res = await worker.fetch(new Request(`https://registry.axisprime.ai${path}`), {}, ctx);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, "ok");
    assert.equal(body.service, "axis-registry");
    assert.equal(body.axis_version, "0.3");
    assert.match(body.time, /^\d{4}-\d{2}-\d{2}T/);
    // Liveness must never be cached.
    assert.equal(res.headers.get("cache-control"), "no-store");
  });
}

test("POST /health is not a liveness match (falls through to routing)", async () => {
  // Only GET is the liveness verb; a POST should not short-circuit as 200 ok.
  const res = await worker.fetch(new Request("https://registry.axisprime.ai/health", { method: "POST" }), {}, ctx);
  assert.notEqual(res.status, 200);
});
