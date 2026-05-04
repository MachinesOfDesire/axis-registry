# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** Email `security@kipplelabs.com` with the details.

Include, to the extent you can:

- A description of the vulnerability
- Steps to reproduce
- An assessment of the impact
- Any mitigations you've considered

We acknowledge receipt within 2 business days. We aim to provide an initial assessment within 5 business days and a remediation plan (with an estimated timeline) within 10 business days.

For critical issues we will coordinate a disclosure timeline with you. We'll credit reporters who request it in the public advisory.

## What counts

Anything that allows:

- Authentication bypass
- Cross-tenant data access beyond what Registry Conformance §2 permits (the BOLA class of bugs)
- Privilege escalation between `registrar`, `admin`, and `super_admin` roles
- Forgery of valid AITs, delegations, or registration records
- Tampering with audit log records in a way the `/admin/audit` endpoint cannot detect
- Denial of service that cannot be mitigated by ordinary infrastructure scaling

Configuration problems in a *specific deployment* (weak keys, accidentally public wrangler.toml committed to a fork's repo) are not vulnerabilities in this project. Report those to the operator of the affected registry.

## Out of scope

- Attacks requiring already-compromised valid API keys (those are operator-side problems)
- Reports from automated scanners without evidence of an actual vulnerability
- Social engineering of Kipple Labs staff
- Physical security of any hosting infrastructure

## Supported versions

The latest `main` branch is supported. We do not currently maintain versioned release branches for the registry. Fixes land on main and deploy via CI.

## Our own posture

We run the reference registry at `registry.axisprime.ai` on Cloudflare Workers. Our production secrets (registrar API keys, WorkOS client secret, Stripe webhook secret) are stored as Wrangler secrets, never in source control. API keys in the `registrars` table are SHA-256 hashed; the plaintext key exists only in the key holder's secret store.

We audit our own authorization model periodically. The current model is documented in [Registry Conformance v0.1 §2](./docs/conformance.md). If you find a bypass, that's exactly the kind of report we want.
