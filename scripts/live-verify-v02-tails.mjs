// Live verification of PR #22 (v0.2 tails) against registry.axisprime.ai:
//  - /verify resolves the AIT `dlg` chain and returns effective scope (P0-2 half-2)
//  - signed-DC size cap returns a clean 400 document_too_large
// Reuses src/utils/jcs.js so signed bytes match the registry's verification.
//
// Run: AXIS_REGISTRAR_KEY=... node scripts/live-verify-v02-tails.mjs <operator-domain>
import { jcsCanonicalize } from '../src/utils/jcs.js';

const BASE = process.env.AXIS_REGISTRY_URL || 'https://registry.axisprime.ai';
const KEY = process.env.AXIS_REGISTRAR_KEY;
const OP_DOMAIN = process.argv[2];
if (!KEY || !OP_DOMAIN) { console.error('need AXIS_REGISTRAR_KEY + operator domain arg'); process.exit(1); }

const b64u = (b) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const TE = new TextEncoder();
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  PASS', m); } else { fail++; console.log('  FAIL', m); } };

async function genKey() {
  const k = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey));
  return { priv: k.privateKey, pubB64: b64u(raw) };
}
const signJcs = async (priv, obj) => b64u(new Uint8Array(await crypto.subtle.sign('Ed25519', priv, TE.encode(jcsCanonicalize(obj)))));
const post = (path, body) => fetch(BASE + path, { method: 'POST', headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
async function mintAIT(priv, kid, claims) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'EdDSA', typ: 'AIT', kid };
  const payload = { iss: kid, sub: kid, iat: now, exp: now + 600, ...claims };
  const si = `${b64u(TE.encode(JSON.stringify(header)))}.${b64u(TE.encode(JSON.stringify(payload)))}`;
  return `${si}.${b64u(new Uint8Array(await crypto.subtle.sign('Ed25519', priv, TE.encode(si))))}`;
}

(async () => {
  const op = OP_DOMAIN.split('.').slice(0, -1).join('-');
  const reg = async (name) => {
    const k = await genKey();
    const body = { operator: { domain: OP_DOMAIN }, publicKey: k.pubB64, metadata: { name: `${name}-${Date.now()}` } };
    const r = await post('/register', { ...body, proof: { proofType: 'jcs-eddsa-2026', proofValue: await signJcs(k.priv, body) } });
    const j = await r.json();
    if (r.status !== 201) throw new Error(`register ${name} failed: ${r.status} ${JSON.stringify(j)}`);
    return { ...k, axisId: j.axis_id };
  };

  console.log('Setup: register issuer + delegate');
  const issuer = await reg('tails-issuer');
  const delegate = await reg('tails-delegate');

  console.log('P0-2: /verify resolves dlg chain -> effective scope');
  const dc = {
    axis_version: '0.2', type: 'DelegationCredential', id: `dc:${op}:tails-${Date.now()}`,
    issued_by: issuer.axisId, issued_to: delegate.axisId, root_operator: op,
    scope: ['article:draft'], created: new Date().toISOString(),
    expires: new Date(Date.now() + 7 * 86400000).toISOString(), revocable: true,
  };
  const signedDc = { ...dc, proof: { type: 'Ed25519Signature2020', proofType: 'jcs-eddsa-2026', verificationMethod: `${issuer.axisId}#key-1`, proofPurpose: 'assertionMethod', proofValue: await signJcs(issuer.priv, dc) } };
  const rd = await post('/delegations', signedDc);
  const jd = await rd.json();
  ok(rd.status === 201, `create signed delegation -> ${rd.status} ${jd.id || JSON.stringify(jd)}`);

  const ait = await mintAIT(delegate.priv, delegate.axisId, { aud: OP_DOMAIN, dlg: dc.id });
  const rv = await fetch(`${BASE}/verify?token=${encodeURIComponent(ait)}`);
  const jv = await rv.json();
  ok(jv.valid === true, `verify valid -> ${jv.valid}`);
  ok(jv.delegation_resolved === true && jv.delegation_valid === true, `delegation_resolved+valid -> ${jv.delegation_resolved}/${jv.delegation_valid}`);
  ok(jv.delegation_bound_to_agent === true, `bound_to_agent -> ${jv.delegation_bound_to_agent}`);
  ok(Array.isArray(jv.effective_scope) && jv.effective_scope.length === 1 && jv.effective_scope[0] === 'article:draft', `effective_scope -> ${JSON.stringify(jv.effective_scope)}`);

  console.log('Size cap: oversized signed delegation -> 400 document_too_large');
  const big = { ...dc, id: `dc:${op}:tails-big-${Date.now()}`, note: 'x'.repeat(9000) };
  const bigSigned = { ...big, proof: { type: 'Ed25519Signature2020', proofType: 'jcs-eddsa-2026', verificationMethod: `${issuer.axisId}#key-1`, proofPurpose: 'assertionMethod', proofValue: await signJcs(issuer.priv, big) } };
  const rb = await post('/delegations', bigSigned);
  const jb = await rb.json();
  ok(rb.status === 400 && jb.error?.code === 'document_too_large', `oversized -> ${rb.status} ${jb.error?.code}`);

  // cleanup: revoke the valid delegation
  await fetch(`${BASE}/delegations/${encodeURIComponent(jd.id)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' }, body: '{"reason":"live-verify tails cleanup"}' }).catch(() => {});

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERROR', e?.message ?? e); process.exit(1); });
