# Contributing to the AXIS Registry

Thanks for considering a contribution. This is the reference implementation of the AXIS protocol (v0.1). Changes here affect the federation's reference behavior, so we keep the contribution bar intentional.

## Before you write code

Open an issue first for anything beyond a small bug fix or typo. Useful issue content:

- What protocol requirement are you addressing? Cite the spec or conformance document section.
- What are the alternatives you considered?
- If this adds a new endpoint or changes an existing one, include the request/response shape.

For security-sensitive issues see [SECURITY.md](./SECURITY.md). Do not open a public issue for vulnerabilities.

## Scope of this repo

The registry repo is the server. It should NOT contain:

- Protocol specification text (belongs in [axis-protocol](https://github.com/MachinesOfDesire/axis-protocol))
- Client SDK code (belongs in [axis-protocol-sdk](https://github.com/MachinesOfDesire/axis-protocol-sdk))
- Gateway or consumer-application code

If your change affects the wire format, the spec must change first, then this repo.

## Code style

- ES modules, Node 20+ as the language floor (matches Cloudflare Workers)
- Two-space indentation, double quotes for strings
- Keep handlers small. Route handlers belong in `src/routes/`, shared utilities in `src/utils/`, cross-cutting concerns in `src/middleware/`.
- Prefer parameterized D1 queries. Never concatenate user input into SQL.
- Comments explain *why*, not *what*. If the code is not self-explanatory, the code is the problem.

## Authorization is load-bearing

Every new mutating endpoint MUST enforce ownership scoping per [Registry Conformance §2](./docs/conformance.md). Specifically:

- Look up the resource.
- Reject with HTTP 403 `not_your_resource` if `resource.registrar_id !== authenticated.registrar.id`.
- `admin` role does NOT bypass this on normal endpoints. Cross-tenant mutation requires a dedicated `/admin/force-*` break-glass endpoint, which MUST write an audit row before acting, MUST require a non-empty `reason`, and MUST abort if the audit write fails.

PRs that weaken or bypass this pattern will not be accepted.

## Tests

Add or update tests alongside code changes. Tests live next to the code they cover. Run them with:

```bash
npm test
```

A change that adds or modifies a route without adding at least one test is unlikely to merge.

## Migrations

Schema changes go in `migrations/NNNN_short_name.sql`. Numbers are sequential and never reused. Migrations must be idempotent (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE` guarded where the backend supports it).

Never edit a migration that has been committed and applied to any production database.

## Pull requests

- One logical change per PR
- Reference the issue it addresses: `Fixes #123`
- Commit messages: subject line under 72 chars, imperative mood, a paragraph body explaining why
- CI must pass before review

By submitting a PR you certify that you wrote the contribution (or have the right to submit it) and that it is licensed under Apache 2.0, consistent with this repository's license. There is no separate CLA.

## Review

Maintainer review is performed by Kipple Labs. Expect feedback within a week during normal operations. Larger changes may take longer. If a PR stalls, ping in the associated issue.

## License

By contributing you agree your contribution is licensed under Apache 2.0.
