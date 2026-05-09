/**
 * Unit tests for axis-registry helper functions.
 *
 * Pure-logic tests only — no D1, no Workers runtime. For end-to-end
 * coverage of routes against a live registry, use the axis-conformance
 * suite (https://github.com/MachinesOfDesire/axis-conformance) or its
 * `npm run check` shortcut against this registry's `wrangler dev` URL.
 *
 * Run: node --test test/*.test.js
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { hashApiKey, isAdmin, isSuperAdmin, requireAdmin, requireSuperAdmin, notYourResource } from "../src/middleware/auth.js";

// ── hashApiKey ─────────────────────────────────────────────────────────────

test("hashApiKey produces 64-char lowercase hex", async () => {
  const h = await hashApiKey("test-key-value");
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
});

test("hashApiKey is deterministic for the same input", async () => {
  const a = await hashApiKey("hello");
  const b = await hashApiKey("hello");
  assert.equal(a, b);
});

test("hashApiKey produces different hashes for different inputs", async () => {
  const a = await hashApiKey("alpha");
  const b = await hashApiKey("beta");
  assert.notEqual(a, b);
});

test("hashApiKey is sensitive to trailing whitespace (CRLF bug class)", async () => {
  // This catches the "PowerShell pipe added \r\n to my secret" bug class —
  // if the hash were trim-tolerant, an env var with stray whitespace would
  // silently authenticate. We want it to fail loud instead.
  const clean = await hashApiKey("secret");
  const trailingNewline = await hashApiKey("secret\n");
  const trailingCRLF = await hashApiKey("secret\r\n");
  const leadingSpace = await hashApiKey(" secret");
  assert.notEqual(clean, trailingNewline);
  assert.notEqual(clean, trailingCRLF);
  assert.notEqual(clean, leadingSpace);
});

// ── role helpers ───────────────────────────────────────────────────────────

test("isAdmin: false for null/undefined registrar", () => {
  assert.equal(isAdmin(null), false);
  assert.equal(isAdmin(undefined), false);
});

test("isAdmin: true for role=admin", () => {
  assert.equal(isAdmin({ role: "admin" }), true);
});

test("isAdmin: true for role=super_admin", () => {
  assert.equal(isAdmin({ role: "super_admin" }), true);
});

test("isAdmin: false for role=registrar", () => {
  assert.equal(isAdmin({ role: "registrar" }), false);
});

test("isAdmin: false for unknown role string", () => {
  assert.equal(isAdmin({ role: "wizard" }), false);
});

test("isSuperAdmin: only true for role=super_admin", () => {
  assert.equal(isSuperAdmin(null), false);
  assert.equal(isSuperAdmin({ role: "registrar" }), false);
  assert.equal(isSuperAdmin({ role: "admin" }), false);
  assert.equal(isSuperAdmin({ role: "super_admin" }), true);
});

// ── requireAdmin / requireSuperAdmin gate responses ────────────────────────

test("requireAdmin: null registrar returns 401", () => {
  const denial = requireAdmin(null);
  assert.equal(denial.status, 401);
  assert.equal(denial.body.error.code, "unauthorized");
});

test("requireAdmin: registrar role returns 403", () => {
  const denial = requireAdmin({ role: "registrar" });
  assert.equal(denial.status, 403);
  assert.equal(denial.body.error.code, "forbidden");
});

test("requireAdmin: admin role returns null (allowed)", () => {
  assert.equal(requireAdmin({ role: "admin" }), null);
});

test("requireAdmin: super_admin role returns null (allowed)", () => {
  assert.equal(requireAdmin({ role: "super_admin" }), null);
});

test("requireSuperAdmin: admin role returns 403 (admin is not super_admin)", () => {
  const denial = requireSuperAdmin({ role: "admin" });
  assert.equal(denial.status, 403);
  assert.match(denial.body.error.message, /super_admin/);
});

test("requireSuperAdmin: super_admin role returns null (allowed)", () => {
  assert.equal(requireSuperAdmin({ role: "super_admin" }), null);
});

test("requireSuperAdmin: null registrar returns 401, not 403", () => {
  // Per the auth.js comment: 401 for unauthenticated, 403 for
  // authenticated-but-insufficient-role. Conformance tools key off this.
  const denial = requireSuperAdmin(null);
  assert.equal(denial.status, 401);
});

// ── notYourResource ────────────────────────────────────────────────────────

test("notYourResource: returns 403 with not_your_resource code", () => {
  const r = notYourResource();
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, "not_your_resource");
});

test("notYourResource: respects custom message", () => {
  const r = notYourResource("Operator owned by Registrar Bob");
  assert.match(r.body.error.message, /Operator owned by Registrar Bob/);
});
