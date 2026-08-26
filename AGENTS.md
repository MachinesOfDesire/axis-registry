# axis-registry

Cloudflare Workers + D1 implementation of the canonical AXIS Protocol registry API.

## Working conventions

Work in a git worktree, never in the primary clone. The primary clone stays checked out on `main` and is the integration point only. Do not edit or commit in it.

    git worktree add ~/dev/axis-registry-wt/<slug> -b <type>/<desc> origin/main
    # work, commit, open the PR from the worktree
    gh pr merge <n> --squash --delete-branch
    git worktree remove ~/dev/axis-registry-wt/<slug>

Delete the branch as soon as its PR merges. A merged-but-undeleted branch is what the next session stacks onto.

Branch names are `<type>/<desc>`, where type is one of: feat, fix, chore, docs, refactor, test, style, perf. No session slugs in branch names. Ownership is visible in the worktree path via `git worktree list`.

## Shipping

Commit early, push the branch immediately, verify against the running system, then merge and deploy. Pushing a branch is near-consequence-free. Merge and deploy are what need verification.

Never deploy a commit that isn't pushed. Deploy from `main` and record the deployed SHA.

A task is done when the working tree is clean, the branch is pushed, and if deployed, the deployed SHA matches origin/main.

## Security-sensitive work

Custodied-key signing, auth and token verification, secrets handling, tenant isolation. Do not block merge on review. Mark the site with a `SECURITY-REVIEW-PENDING` comment stating what is unreviewed and why, so `grep -r SECURITY-REVIEW-PENDING` finds everything owed a look later. Normal deploy-approval rules still apply.

## Public repository

This repository is public. Commit messages, PR descriptions, README, and all committed documentation stay generic. No internal slugs, no Notion links, no approval-chain detail, no attorney review references. Internal context stays out of this repo entirely.
