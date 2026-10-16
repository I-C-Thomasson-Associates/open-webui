---
name: open-webui-fork-upgrade
description: Safely merge an upstream Open WebUI release into the ICT/Salas O’Brien fork, preserve documented customizations, validate an isolated candidate, and prepare an approval-gated jp_dev promotion. Use when upgrading/syncing this fork to an upstream tag.
---

# Open WebUI fork upgrade

Compact workflow for merging an upstream release into the fork. Permissions come from the user's request and the runtime's policy, not from this skill. If a tool or policy denies a step, stop and report it; never bypass or change agent policy or extension permissions.

Read `references/validation.md` before the validation phase.

## 0. Scope and authorization

- Target version: use the version the user requested. If none, ask one focused question. Never auto-pick "latest".
- Source branch: `jp_dev`. Candidate branch: `integrate-v<version>`. If the candidate name already exists (local or remote), never delete or blindly reuse it. Inspect it and ask for a new name or direction.
- Never touch upstream `main` or production. This governs the normal OWUI upgrade: no edits to the fork's upstream-mirror branches. A sibling runtime `main` fast-forward is a separate, explicitly authorized maintenance exception (see 3a), not a contradiction.
- A clear user request to implement the upgrade authorizes scoped local edits and ordinary targeted local checks in a clean, isolated, synthetic runtime. Do not ask again for each Git read, build, test, or worker.
- Candidate branch creation and merge are covered when the user explicitly approved an integration plan that includes them; no per-command approval is needed. Include the planned commands in the plan, e.g. `git switch -c integrate-v<version> jp_dev` and `git merge --no-commit --no-ff <verified-upstream-tag>`. If tools deny them, report it.
- Separate authorization is required for: publication (commit, fast-forward, push; ONE approval may cover the whole sequence), dependency installation/downloads/environment creation, deployment, live credentials/data, and risky external side effects. Do not claim every Git or network action needs its own approval, and do not treat earlier approvals as blanket permission.
- Approvals from a prior upgrade are not standing permissions; only authorizations for the CURRENT upgrade apply, within the phases approved.
- Read applicable `AGENTS.md` files if they exist, plus `.opencode/memory/project.md` and the relevant fork doc overview (`open-webui-fork-changes.md`), scoped to this task, before work. Missing guidance in a past task is not a reason to skip it in future ones.
- Preserve unrelated user changes. Never stash, clean, reset, abort, or overwrite automatically. If the tree was dirty at start, protect those changes; ask only if they overlap the work or you cannot proceed safely. A dirty tree alone is not a reason to ask.

## 1. Baseline

Record, with actual commands, not remembered values:
- `git status`, current branch, `jp_dev` SHA (the original fork base).
- The upstream remote: find it from `git remote -v` (often tracks upstream `main`; `origin` is the fork). Verify the requested tag exists there, and record the tag object SHA and the commit it peels to, checked against the expected upstream repository. A hash alone is not a cryptographic authenticity claim, especially for an unsigned tag; verify the signature as extra provenance where available. Fetching is covered when within the approved scope.
- The prior upstream version/merge base and the log range between it and the target. If release notes or security items are uncertain, research narrowly. Pin the exact tag SHA, the original fork base SHA, the prior upstream SHA, and later the chosen merge HEAD.

## 2. Merge

- Use a merge, not a rebase. Never restore core files wholesale from either side.
- Resolve conflicts by preserving upstream security fixes and behavior first, then re-applying fork customizations.
- Prefer extension points first: `backend/open_webui/ext`, `src/lib/ext`. Reuse existing helpers. Add narrow hooks only where needed, and update their contracts, consumers, fixtures and exports.
- Check `git diff --name-only --diff-filter=U` and conflict markers before concluding. Do not commit without authorization.

## 3. Reconciliation matrix

Build a table covering every numbered item in `open-webui-fork-changes.md` (count dynamically, don't hardcode the number). Columns: ID, feature, affected paths, risk, disposition (kept / adapted / dropped upstream-covered / needs-decision), test evidence (passed / failed / not run).

Ask the user about material behavior choices. For example, the hide-unavailable-models + tags behavior is only a prior example, not a permanent preference, and must not override a security choice for the fork.

### 3a. Cross-repo compatibility gate (mandatory)

During reconciliation, BEFORE calling the candidate ready or proposing promotion, and even when all OWUI tests pass, check the sibling orchestrator/runtime repos the terminal feature calls. Prefer relative siblings `../open-webui-terminals` (orchestrator) and `../open-terminal-internal` (runtime); the user named `C:/Users/johnf/source/repos/open-webui-terminals` and `C:/Users/johnf/source/repos/open-terminal-internal`. Confirm each directory exists and actually plays that role (read its README/entrypoints). Hardcode no SHA or version; choose the current ones per upgrade.

- Once per repo, record HEAD, branch and `git status`; read its `AGENTS.md`/guidance and protect existing changes (including untracked, user-owned or prior-agent files).
- Runtime roles: in `../open-terminal-internal`, `main` mirrors the official `https://github.com/open-webui/open-terminal` source (verify which remote is the fork `origin` vs upstream) and `dev` is the custom integration/deploy branch. Mirror sync needs its own explicit authorization, fast-forward only: no force, no rebase, and never replace `dev` wholesale. Compare upstream `main` against `dev` and its original base HEAD. Updated local `main` ≠ pushed remote `main` ≠ integrated `dev`.
- Re-read scoped baseline (branch, HEAD, working tree) when the user may have changed state since an earlier phase; update evidence rather than repeating full research. Audit the correct branch and actual working tree, and pin the source used.
- Branch target gate: the runtime repo's explicit target is `dev`. Verify its HEAD and branch status; do not checkout over a dirty tree or auto-switch/ignore the checked-out branch. If it is on the wrong branch, request approval/authorization for a checkout before auditing, or read the `dev` tip via `git show`/`git rev-parse dev` and distinguish that source from the checked-out state in the report. For the orchestrator, inspect the user-requested branch; do not assume `main` or `dev` automatically. Treat findings and SHAs as per-audit evidence, never permanent facts, since heads change.
- Siblings are read-only by default. Edits there need an explicit user request naming them; the OWUI upgrade approval is not a blanket authorization. No commit, push or publish of siblings from this skill.
- Trace the current OWUI caller side (this fork's terminal ext code, routers, middleware) and compare it with the sibling implementation: API shapes; HTTP and WebSocket auth (bearer, first-message auth, `X-User-Id`, `X-Session-Id`, `X-Terminal-Context-Id`/policy headers); policy paths `/p/{policy}`; discovery with bearer only and no user header (`__system__` runtime, cold-provision timeout vs `AIOHTTP_CLIENT_TIMEOUT_TOOL_SERVER_DATA`); execute/polling process schemas (passive polling must not recreate or keep alive a runtime); files (raw upload stream, bounds, atomic write, matching limits across the three repos); cwd/home and AGENTS handling; `/skills` list and read resources with bounded manifests (compare against the actual release's paths; no hardcoded or fallback paths); search/match fallback; gateway header consumption (expected, separate optional feature).
- Route collisions: a static route such as `/skills/new` or `/skills/read` can shadow dynamic `/skills/{name}`, and a required query parameter can break legacy valid reads (including generated FastMCP tool URLs). Require regression tests for: no-query legacy read; query naming different actual skills; invalid, missing and empty names. Preserve the contract: auth fails closed, lookups stay safe (`safe_read`, bounds, resource ownership), OpenAPI operation IDs/aliases hidden as appropriate. Consider an optional-query fallback only where it preserves that contract; do not make all routes optional. Don't claim a patch state in generic text.
- Deployment workflows: compare the actual deployed image/source pin, not version-number parity. Do not inspect cloud credentials or live deployments, and make no authenticated calls without approval.
- Compare the prior fork base to the chosen upstream tag to separate NEW upstream regressions from already-broken fork source/runtime skew.
- Matrix columns: caller/path/schema/headers, OWUI delta, target repo, implementation evidence, status (compatible / required-for-feature / optional / preexisting / unknown), tested / not run, residual failure mode.
- Tests: run focused existing mock/unit tests in each repo. No Docker, Kubernetes, Redis, PTY, real commands or live ports. Fake-HTTP tests or fixture additions only if the user requests them, with named owners and authorization.
- On a gap: report the smallest required packet per repo and ask for a scoped local fix (never deploy). Claim no compatibility until each gap is explicitly accepted or deferred. A gap in an optional feature does not automatically block the whole upgrade, but blocks production promotion unless accepted.
- Track cross-repo commits, source tree and candidate versions in temporary docs or the new matrix. Do not commit or publish other repos. Upgrade approval never covers sibling publication.
- This is a source audit, not a live-image pass. Report when a rebuild is needed (when required, even if the repo already contains changes; do not assume the image has them).
- Any prior audit is only an example; never treat its facts as permanent instructions.

## 3b. Tag hygiene (sibling/fork releases)

- An official release tag may legitimately be older than upstream `main`. Never retag to HEAD just because the version matches.
- Before any release-tag conflict decision, compare the tag object and peeled commit across local, fork `origin` and upstream (`git show-ref`, `git ls-remote <remote> <tag>`; conditionally approved read/fetch; no credentials in URLs). Separate annotation-only differences (same commit) from a meaningful change.
- Never automate force/delete/move of official tags; there is no "always replace" rule. Mirror fetches may use an explicit branch with `--no-tags` to avoid following tags; this is not universal and does not replace ref-move or upstream-provenance records.
- Correcting a tag needs FRESH explicit approval naming the exact remote, tag and intended upstream target. Preflight the expected current remote object SHA, push only that exact tag ref with `--force-with-lease=refs/tags/<tag>:<expected-object-SHA>` (no generic `--force`, no branches, no all-tags), then verify the remote object. This skill is advisory and grants no force publication.
- Fork releases use a distinct suffix, e.g. `-ict.<n>`.

## 4. Work ledger

One outcome per builder packet; packet count follows actual independent risk, not a fixed 1–3. Each has: ID, owner/files (production and test ownership explicit), dependencies, acceptance checks, status. Run at most 4 workers, with disjoint file ownership and no overlap in checks. The parent may inspect and trace code directly; workers may also read. No universal architecture gate. Use independent review for medium/high-risk packets, with up to 2 repair cycles. Use one build/validator at a time; no concurrent runs sharing outputs.

## 5. Validate

Follow `references/validation.md`. Do not reuse old typecheck failure counts as predicted facts. Use valid recorded baseline evidence when available; run a safe baseline check only when needed. Compare candidate results and report unrun checks.

## 6. Stop and report before publication

Report: candidate HEAD, tree SHA, build SHA/output, Git SHAs pinned in step 1, the matrix (including the cross-repo gate: sibling HEAD/branch/status, statuses, gaps, rebuild needs), tests actually run, failures, and what remains. Do not claim all features were verified live.

Distinguish a full upstream merge (merged SHA is an ancestor, tree tested) from selected cherry-picked/ported patches or a source audit. Create no candidate branch unless authorized, and don't promise one when the patch lives on `dev`. Branches and HEAD can move outside the agent: re-check narrow state before publishing, and don't assume a clean tree means the agent committed or pushed. Per repo track base/current HEAD, selected upstream SHA, branch, tested working-tree diff, uncommitted state, mock/full test results (counts, skips, collection errors), optional-missing (not version-only) items, a deferred list with explicit ready criteria, and user-accepted limits versus completion. Mirror/`main` updated plus partial patches ≠ fully integrated `dev`; claim no whole-upstream parity until the remaining delta is reconciled. Documentation snapshots and uncommitted state are not promoted source evidence. Avoid new persistent report files, scripts and deps; keep reports concise.

## 7. Documentation

Preserve historical “Verified Branch Status” snapshots; never rewrite historical verification as current. Record pending/local validation before publication; add promoted facts only after they happen, and never embed a commit’s own SHA in that commit.

## 8. Publication (needs publication authorization; one approval may cover steps 1–6)

1. `git fetch origin jp_dev`; compare local and remote against the step-1 baseline. If diverged, STOP.
2. Stage ONLY the intended merge, including new tests and docs; reconcile index entries already from upstream or many files. Never `git add .`.
3. Create ONE candidate commit.
4. Switch to `jp_dev` and fast-forward only.
5. Push only `origin jp_dev`. Leave prod unchanged.
6. Verify the remote SHA, the intended clean status, and that unrelated changes are preserved. Never force BRANCH pushes; never assume all changes are gone. Tag correction is a separate gate (3b) and is not covered by this section or any blanket approval.
