/**
 * Tests for src/utils/crypto.js — pure functions, no D1/Workers bindings needed.
 *
 * Run with: node --test test/crypto.test.js
 *
 * This is the FIRST test file in the registry. Per the 2026-05-08 security
 * review, the highest-leverage missing tests are the BOLA matrix and the
 * AIT verification matrix; those need Wrangler dev or Miniflare. Until that
 * harness exists, this file covers the easy-to-isolate pure functions and
 * locks in their wire-format behavior.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  deriveAgentId,
  verifyEd25519Signature,
  generateToken,
  generateCredentialId,
  bytesToBase58,
  base64urlToBytes,
  base58ToBytes,
  bytesToHex,
  bytesToBase64url,
} from "../src/utils/crypto.js";

// ── deriveAgentId ──────────────────────────────────────────────────────────

test("deriveAgentId is deterministic for the same key", async () => {
  // Generate a real Ed25519 keypair and export raw public bytes
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pubB64 = bytesToBase64url(raw);
  const a = await deriveAgentId(pubB64);
  const b = await deriveAgentId(pubB64);
  assert.equal(a, b);
  assert.match(a, /^[1-9A-HJ-NP-Za-km-z]+$/);
});

test("deriveAgentId differs across keys", async () => {
  const kp1 = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const kp2 = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const r1 = new Uint8Array(await crypto.subtle.exportKey("raw", kp1.publicKey));
  const r2 = new Uint8Array(await crypto.subtle.exportKey("raw", kp2.publicKey));
  assert.notEqual(await deriveAgentId(bytesToBase64url(r1)), await deriveAgentId(bytesToBase64url(r2)));
});

// ── verifyEd25519Signature ─────────────────────────────────────────────────

test("verifyEd25519Signature accepts a valid signature", async () => {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const message = "hello AXIS";
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", kp.privateKey, new TextEncoder().encode(message)),
  );
  const ok = await verifyEd25519Signature(bytesToBase64url(raw), message, bytesToBase64url(sig));
  assert.equal(ok, true);
});

test("verifyEd25519Signature rejects a tampered message", async () => {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", kp.privateKey, new TextEncoder().encode("original")),
  );
  const ok = await verifyEd25519Signature(
    bytesToBase64url(raw),
    "tampered",
    bytesToBase64url(sig),
  );
  assert.equal(ok, false);
});

test("verifyEd25519Signature rejects a wrong-key signature", async () => {
  const kp1 = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const kp2 = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw2 = new Uint8Array(await crypto.subtle.exportKey("raw", kp2.publicKey));
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", kp1.privateKey, new TextEncoder().encode("msg")),
  );
  const ok = await verifyEd25519Signature(bytesToBase64url(raw2), "msg", bytesToBase64url(sig));
  assert.equal(ok, false);
});

test("verifyEd25519Signature returns false on malformed input (no throw)", async () => {
  // The function catches errors and returns false — confirm.
  const ok = await verifyEd25519Signature("not-a-valid-key", "msg", "not-a-sig");
  assert.equal(ok, false);
});

// ── generateToken / generateCredentialId ───────────────────────────────────

test("generateToken returns hex of requested length*2", () => {
  const t = generateToken(8);
  assert.equal(t.length, 16);
  assert.match(t, /^[0-9a-f]+$/);
});

test("generateToken default length is 32 → 64 hex chars", () => {
  const t = generateToken();
  assert.equal(t.length, 64);
});

test("generateToken collisions are vanishingly rare (sample 100)", () => {
  const set = new Set();
  for (let i = 0; i < 100; i++) set.add(generateToken());
  assert.equal(set.size, 100);
});

test("generateCredentialId formats `prefix:namespace:hex`", () => {
  const id = generateCredentialId("dlg", "offworld");
  assert.match(id, /^dlg:offworld:[0-9a-f]{16}$/);
});

// ── base58 / base64url roundtrips ─────────────────────────────────────────

test("bytesToBase58 → base58ToBytes roundtrip", () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5, 0, 0, 0, 255, 128, 64]);
  const b58 = bytesToBase58(bytes);
  const out = base58ToBytes(b58);
  assert.deepEqual(Array.from(out), Array.from(bytes));
});

test("bytesToBase58 preserves leading zero bytes as leading 1s", () => {
  const bytes = new Uint8Array([0, 0, 1, 2, 3]);
  const b58 = bytesToBase58(bytes);
  assert.ok(b58.startsWith("11"));
});

test("base58ToBytes throws on invalid character", () => {
  assert.throws(() => base58ToBytes("0OIl"), /Invalid base58 character/);
});

test("base64urlToBytes handles standard base64url", () => {
  // 'AAAA' decodes to [0, 0, 0]
  const bytes = base64urlToBytes("AAAA");
  assert.deepEqual(Array.from(bytes), [0, 0, 0]);
});

test("base64urlToBytes handles unpadded base64url", () => {
  // 'AA' = one byte, no padding
  const bytes = base64urlToBytes("AA");
  assert.deepEqual(Array.from(bytes), [0]);
});

test("base64urlToBytes handles base58btc multibase prefix 'z'", () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  const b58 = bytesToBase58(bytes);
  const decoded = base64urlToBytes("z" + b58);
  assert.deepEqual(Array.from(decoded), Array.from(bytes));
});

test("base64urlToBytes does NOT treat z-prefixed base64url as base58 when '_' is present", () => {
  // The base64url branch must be taken for any z-prefix string containing
  // base64-specific characters. Use a 4-char (no padding needed) input
  // with a '_' to force the base64url path.
  // 'z_AB' as base64url = atob('z/AB' + '=' padding to 4) = decodes cleanly.
  const decoded = base64urlToBytes("z_AB");
  assert.ok(decoded.length > 0);
  // No assertion on exact content — just that it didn't throw "Invalid base58".
});

// ── bytesToHex ─────────────────────────────────────────────────────────────

test("bytesToHex pads single-digit values", () => {
  assert.equal(bytesToHex(new Uint8Array([0, 1, 15, 255])), "00010fff");
});

// ── Hardening guard: no negative-key length to verifyEd25519Signature ─────

test("verifyEd25519Signature rejects empty key gracefully", async () => {
  const ok = await verifyEd25519Signature("", "msg", "AAAA");
  assert.equal(ok, false);
});

test("verifyEd25519Signature rejects short-key gracefully", async () => {
  // 8-byte key — Ed25519 requires 32. Web Crypto importKey throws; fn catches.
  const shortKey = bytesToBase64url(new Uint8Array(8));
  const ok = await verifyEd25519Signature(shortKey, "msg", "AAAA");
  assert.equal(ok, false);
});
