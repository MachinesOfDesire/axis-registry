import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeAud, recordVerifyEvent } from '../src/utils/telemetry.js';

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fakeAit({ aud = 'comments.mysite.com' } = {}) {
  return `${b64url({ typ: 'AIT', alg: 'EdDSA' })}.${b64url({ aud, iss: 'axis:op:agent' })}.sig`;
}

// Mock D1: captures INSERTs and SELECTs; returns a tier from SELECT when configured.
function mockDB({ tier = null } = {}) {
  const captured = { inserts: [], selects: [] };
  const db = {
    captured,
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async first() { captured.selects.push({ sql, args }); return tier === null ? null : { verification_tier: tier }; },
            async run() { captured.inserts.push({ sql, args }); return {}; },
          };
        },
      };
    },
  };
  return db;
}

test('decodeAud reads the aud claim, null on junk', () => {
  assert.equal(decodeAud(fakeAit({ aud: 'x.example' })), 'x.example');
  assert.equal(decodeAud('not-a-token'), null);
  assert.equal(decodeAud('a.b'), null);
});

test('valid verify -> one row: aud, agent, operator, tier, valid=1, code=null', async () => {
  const db = mockDB({ tier: 'domain' });
  const result = { status: 200, body: { valid: true, agent_id: 'axis:op:agent', operator_id: 'axis:acme:operator' } };
  await recordVerifyEvent({ DB: db }, fakeAit({ aud: 'comments.mysite.com' }), result);

  // operator slug 'acme' was looked up for the tier
  assert.equal(db.captured.selects.length, 1);
  assert.deepEqual(db.captured.selects[0].args, ['acme']);

  assert.equal(db.captured.inserts.length, 1);
  const a = db.captured.inserts[0].args; // [ts, aud, agent_id, operator_id, operator_tier, valid, code]
  assert.equal(typeof a[0], 'number');
  assert.equal(a[1], 'comments.mysite.com');
  assert.equal(a[2], 'axis:op:agent');
  assert.equal(a[3], 'axis:acme:operator');
  assert.equal(a[4], 'domain');
  assert.equal(a[5], 1);
  assert.equal(a[6], null);
});

test('invalid verify -> valid=0, code set, no operator lookup', async () => {
  const db = mockDB();
  const result = { status: 200, body: { valid: false, code: 'token_expired', agent_id: 'axis:op:agent' } };
  await recordVerifyEvent({ DB: db }, fakeAit(), result);

  assert.equal(db.captured.selects.length, 0); // no operator_id => no tier lookup
  const a = db.captured.inserts[0].args;
  assert.equal(a[3], null);   // operator_id
  assert.equal(a[4], null);   // operator_tier
  assert.equal(a[5], 0);      // valid
  assert.equal(a[6], 'token_expired');
});

test('never throws when DB is missing or insert fails', async () => {
  await recordVerifyEvent({}, fakeAit(), { body: { valid: true } }); // no env.DB
  const boom = { prepare() { return { bind() { return { async first() { return null; }, async run() { throw new Error('d1 down'); } }; } }; } };
  await recordVerifyEvent({ DB: boom }, fakeAit(), { body: { valid: true, agent_id: 'a' } });
  assert.ok(true); // reached here = swallowed
});
