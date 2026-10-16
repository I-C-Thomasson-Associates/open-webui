# Validation reference

Ordinary targeted local checks in the isolated synthetic runtime are covered by the upgrade request. Dependency installation/downloads/environment creation, deployment, live credentials/data and risky external side effects need separate approval; approvals from earlier upgrades do not apply.

## Static checks
- Unmerged files: `git diff --name-only --diff-filter=U` is empty; no conflict markers.
- `git diff --check`.
- Targeted backend and frontend tests for touched areas, then the full frontend build.
- Typecheck: the baseline can be huge. Reuse an existing valid recorded baseline, or run it once with a safe index/source that avoids checkout clobbering; repeat only when needed. Don't automatically recreate branches or worktrees. Compare with the candidate; don't reuse remembered counts.
- Security audit: the pip audit command may not be installed; do not install it or use credentials automatically. Network-based audits need approval. Report available results only.
- No new dependencies or testing runtime are required to validate this skill: do static reads, check relative links and frontmatter, and count items dynamically.

## Environments
- Backend: WSL Ubuntu, Conda env `open-webui`, historically Python 3.11. Verify the executable (e.g. `/home/john/miniconda3/envs/open-webui/bin/python`); don't assume the active one. From Git Bash on Windows use `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu --exec <path> ...`.
- Node: check the requested package `engines.node`. A previous Node 22 portable copy under Temp may be gone; verify, and use its absolute executable path. If PATH defaults to Node 24 and that fails the engine range, don't install without approval; report.
- `npm ci --ignore-scripts` may need cached downloads or auth, and may change packages; do not auto-change manifests or lockfiles.
- The Vite outDir/flags may be ignored by the adapter; builds may write ignored repo `build/`. Report it and preserve existing owned outputs; do not claim Vite output is universally ignored. Don't alter manifests during validation.

## Backend isolation (every process, before import)
Set: `PYTHON_DOTENV_DISABLED=1`, `ENABLE_CONFIG_ENV_HYDRATION=false`, empty `VAULT_HOST`, unique Temp `DATA_DIR` and `STATIC_DIR`, synthetic secret key, SQLite `DATABASE_URL`, `OFFLINE_MODE=true`; disable providers, Redis and OTEL. Config clears the default STATIC_DIR (destructive to tracked files), so never import with the default. Migrate the synthetic DB. No provider credentials, Vault, Redis, live or production DB.

## Browser checks
Use synthetic DB accounts for relevant features: repro, signup/login/onboarding, audio, dev/admin, mobile keyboard. Mocked/offline provider interactions are ordinary local validation; actual provider calls require explicit approval and scoped credentials. If a conditional welcome dialog was already dismissed, that is a harness failure, not a pass. Separate harness failures from app failures; capture console errors and app 5xx.

## Processes
Clean up only processes and ports you started. No system firewall changes without approval. Loopback tests are fine. WSL port forwarding can be intermittent: use an owned temporary loopback relay and clean it up. Don't bypass interpreter restrictions. Keep logs in Temp; no `rm -rf` without approval.

## Cross-repo compatibility (terminals)
Passing OWUI tests do not show the terminal orchestrator and runtime are compatible. Run this after OWUI reconciliation and before ready/promotion. Locate siblings via `../open-webui-terminals` and `../open-terminal-internal`, check each directory's role, and record HEAD, branch and `git status` once per repo. Read their guidance and protect existing changes. Stay read-only unless the user explicitly authorizes sibling edits.

Build a matrix with these columns: caller/path/schema/headers, OWUI delta, target repo, implementation evidence, status (compatible / required-for-feature / optional / preexisting / unknown), tested or not run, residual failure mode. Cover the areas listed in SKILL.md 3a. Compare the prior fork base to the chosen tag so that new upstream regressions are distinguished from existing source/runtime skew.

Run only focused existing mock/unit tests in each repo; do not use Docker, Kubernetes, Redis, PTY, real commands or live ports. Do not inspect cloud credentials or live deployments. Workflows are checked for the actual deployed image/source pin, not version parity. This is a source audit: say when an image rebuild is needed and never assume a live image contains source changes. Report gaps as the smallest per-repo packets. Do not claim compatibility until each gap is accepted or deferred. Do not commit or publish sibling repos.

## Runtime repo preflight (open-terminal)
For each selected Python package, before tests:
- `importlib.metadata.version('open-terminal')` metadata is mandatory; check without app init. Optional: the FastMCP module and supported version. If absent, report a collection failure, NOT a pass. Don't fake production metadata or stub the real integration to bypass.
- The WSL Conda `open-webui` env is the OWUI preference; the runtime may not be installed there, and a Windows venv does not imply it works on Linux. Installing an editable package into the EXISTING Conda env is not allowed without approval. If the user declined a disposable setup, capture it for that turn only (not a permanent refusal); ask one focused question if needed, otherwise leave blocked pending user decision.
- Linux descriptor/relative NOFOLLOW tests skip on Windows: report as not validated.
- A stub MCP verifier proves logic and wiring, not the real HTTP/stdio SDK API; an optional callable TokenVerifier is not real validation.
- Isolate: temp `HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `OPEN_TERMINAL_LOG_DIR`; force a synthetic `OPEN_TERMINAL_API_KEY` and REMOVE `OPEN_TERMINAL_API_KEY_FILE` (unset, not empty; they are mutually exclusive). Read no ambient credential/config files; conftest is not safe until preflight passes. Disable multiuser, notebook info and system prompt before import. No real exec/PTY/cloud services. Pytest fixtures must restore global env and must not pass by using the ambient `main.API_KEY`.

## Static check of skill files
`git diff --check` does not cover untracked files. For owned untracked skill files check statically: frontmatter `name` matches `^[a-z0-9-]+$` and ≤64 chars, `description` ≤1024, referenced files exist, no trailing whitespace or conflict markers, no invalid placeholder commands, across the full body. Make no autoload/runtime claims.

## Report
For each check: command, result, passed/failed/not run, and limits. Never claim features live-verified if they were not. Include the cross-repo matrix and per-repo checks run or not run.
