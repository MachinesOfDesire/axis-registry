// Live verification of the v0.2 verification core against registry.axisprime.ai.
// Exercises the NEW paths the deploy introduced: JCS registration proof (P0-3),
// unknown-proofType rejection, signed delegation + chain proof verification
// (P0-1). Reuses the registry's own JCS canonicalizer so the signed bytes match.
//
// Run: AXIS_REGISTRAR_KEY=... node scripts/live-verify-v02.mjs <operator-domain>
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

(async () => {
  // --- P0-3: JCS registration proof ---
  console.log('P0-3 JCS registration proof');
  const a1 = await genKey();
  const body1 = { operator: { domain: OP_DOMAIN }, publicKey: a1.pubB64, metadata: { name: `liveverify-issuer-${Date.now()}` } };
  const r1 = await post('/register', { ...body1, proof: { proofType: 'jcs-eddsa-2026', proofValue: await signJcs(a1.priv, body1) } });
  const j1 = await r1.json();
  ok(r1.status === 201, `register issuer with JCS proof -> ${r1.status} ${j1.axis_id || JSON.stringify(j1)}`);
  const issuer = j1.axis_id;

  const a2 = await genKey();
  const body2 = { operator: { domain: OP_DOMAIN }, publicKey: a2.pubB64, metadata: { name: `liveverify-delegate-${Date.now()}` } };
  const r2 = await post('/register', { ...body2, proof: { proofType: 'jcs-eddsa-2026', proofValue: await signJcs(a2.priv, body2) } });
  const j2 = await r2.json();
  ok(r2.status === 201, `register delegate with JCS proof -> ${r2.status} ${j2.axis_id || JSON.stringify(j2)}`);
  const delegate = j2.axis_id;

  // --- P0-3: unknown proofType rejected ---
  const a3 = await genKey();
  const body3 = { operator: { domain: OP_DOMAIN }, publicKey: a3.pubB64, metadata: { name: `liveverify-bad-${Date.now()}` } };
  const r3 = await post('/register', { ...body3, proof: { proofType: 'bls12381-2020', proofValue: await signJcs(a3.priv, body3) } });
  const j3 = await r3.json();
  ok(r3.status === 400 && j3.error?.code === 'unsupported_proof_type', `unknown proofType -> ${r3.status} ${j3.error?.code}`);

  if (!issuer || !delegate) { console.log('cannot continue without both agents'); process.exit(fail ? 1 : 0); }

  // --- P0-1: signed delegation + chain proof ---
  console.log('P0-1 signed delegation + chain proof');
  const op = OP_DOMAIN.split('.').slice(0, -1).join('-');
  const dc = {
    axis_version: '0.2', type: 'DelegationCredential',
    id: `dc:${op}:liveverify-${Date.now()}`,
    issued_by: issuer, issued_to: delegate, root_operator: op,
    scope: ['article:draft'], created: new Date().toISOString(),
    expires: new Date(Date.now() + 7 * 86400000).toISOString(), revocable: true,
  };
  const signedDc = { ...dc, proof: { type: 'Ed25519Signature2020', proofType: 'jcs-eddsa-2026', verificationMethod: `${issuer}#key-1`, proofPurpose: 'assertionMethod', proofValue: await signJcs(a1.priv, dc) } };
  const rd = await post('/delegations', signedDc);
  const jd = await rd.json();
  ok(rd.status === 201, `create signed delegation -> ${rd.status} ${jd.id || JSON.stringify(jd)}`);

  const rc = await fetch(`${BASE}/delegations/${encodeURIComponent(delegate)}/chain`);
  const jc = await rc.json();
  const link = (jc.chain || []).find((c) => c.delegation === dc.id) || jc.chain?.[0];
  ok(rc.status === 200 && link?.signatureValid === true, `chain reports signatureValid=true -> ${JSON.stringify(link)?.slice(0, 160)}`);

  // --- P0-1: tampered signed delegation rejected ---
  const dc2 = { ...dc, id: `dc:${op}:liveverify-tamper-${Date.now()}` };
  const sig2 = await signJcs(a1.priv, dc2);
  const tampered = { ...dc2, scope: ['article:draft', 'article:publish'], proof: { type: 'Ed25519Signature2020', proofType: 'jcs-eddsa-2026', verificationMethod: `${issuer}#key-1`, proofPurpose: 'assertionMethod', proofValue: sig2 } };
  const rt = await post('/delegations', tampered);
  const jt = await rt.json();
  ok(rt.status === 400 && jt.error?.code === 'invalid_proof', `tampered signed delegation -> ${rt.status} ${jt.error?.code}`);

  // cleanup: revoke the valid delegation so we don't leave an active grant
  await fetch(`${BASE}/delegations/${encodeURIComponent(jd.id)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' }, body: '{"reason":"live-verify cleanup"}' }).catch(() => {});

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERROR', e?.message ?? e); process.exit(1); });
