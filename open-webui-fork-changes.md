# Welcome to the ICT OpenWebUI Fork

# `jp_dev`, `prod`, and Upstream Differences

## Overview

The `jp_dev` and `prod` branches are based on Open WebUI with custom modifications for ICT / Salas O'Brien deployment.

### Upstream 0.12.0 integration — local validation

**Local validation only; the historical Verified Branch Status below is unchanged.** This section describes the merge recorded in the commit that contains this document. Promotion to `jp_dev` is planned and authorized (fast-forward push only, no force) but is not claimed as pushed. `prod` is not promoted; deployment is not verified.

- Branch `integrate-v0.12.0`. Merge base/start HEAD `af306dbdd703c94a77197ba6118b584676dd7bde`; upstream `v0.12.0` `f8ae8a6c328946dc62cd0712961a0632574581bf`; package version `0.12.0`. Before this commit, fresh-fetched `origin/jp_dev` equaled local `jp_dev` at `af306dbdd` with no divergence. The merge commit's own SHA is deliberately not recorded here.
- Candidate details below are preserved as provenance of the pre-commit state: the index had zero unmerged entries and resolved files had zero conflict markers.
- **Settled user decision (admin Models):** KEEP the fork's hide-unavailable-models behavior together with the fork's tag filtering (`src/lib/components/admin/Settings/Models.svelte`).
- **Preservation audit:** all 27 items in this document were audited statically; targeted tests covered selected items only. Not all 27 were tested live or end to end.
- **Repairs in the merge:**
  - Terminal saved auth is applied across model, header, path, WebSocket and skill reads; duplicate IDs, freshness and inherited permissions are handled; a 10 s WebSocket watcher is present.
  - Responses: trusted isolated consumer with per-model attribution; native structured output versus public normalized output; content blocks, attachments and final persisted links.
  - CallPanel with sub-agents and the shared Select integration are retained.
  - Capture: cancellation, late resources, and recoverable transcript retry/download.
  - Workflow: `jp_dev` builds with `BUILD_CHANNEL` `dev`.
  - Test fixtures: async and upstream closure behavior reconciled.
  - OnBoarding: narrow video listener lifecycle fix (video/show cleanup on hide/destroy) with regression coverage (4 tests), made after an actual browser bug; the Get started step now passes.
- **Latest local checks:**
  - Backend: 281 tests passed earlier on Windows `.venv` Python 3.11.9; also run in WSL Conda env `open-webui` (Python 3.11.14): boot reached health ready (HTTP 200) and the API reported version `0.12.0`. The 7 authorized dependency pins were updated with no other package changes; preexisting protobuf conflicts are unchanged.
  - Frontend: 133 tests across 7 files passed (including OnBoarding, 4 tests); full build passed on Node 22 with an 8 GB heap.
  - Real-browser (Chrome 155, Cypress 13.17) run is **partial**: signup Get started, login and chat landing PASS, with no app 5xx, uncaught exceptions or console errors. The 4 remaining tests FAILED because the welcome-overlay harness used the wrong conditional. Settings, mobile, keyboard and provider features are therefore NOT VERIFIED; there is no full browser pass.
  - Browser run used a temporary raw loopback relay (Windows to WSL) for port forwarding; it was removed, no processes were left running, and no firewall/system configuration changed.
  - Full typecheck: `svelte-check` FAILED with 6096 errors and 189 warnings across 321 files; no clean typecheck claim.
  - Dependency audit: 54 findings (2 low, 24 moderate, 26 high, 2 critical); no fix applied.
  - Static validation did not cover all 27 items live. Scoped `git diff --check` is clean.
- **Validation artifact caveat:** importing `backend/open_webui/config.py` clears the default `STATIC_DIR` before copying frontend assets. An earlier validator accidentally deleted tracked `backend/open_webui/static/BRANDING.md`, `README.md`, and `favicon-dark.png`; they were restored byte-for-byte from index blobs. Future validators must isolate `STATIC_DIR` before backend configuration imports.
- **Not run:** PostgreSQL, Redis, provider calls, live services or deployment. Local isolated SQLite tests are not live-database validation.
- **Preexisting static limitations, deliberately not fixed as unrelated to this upgrade:** baseline review R4 showed these existed at `af306dbdd`: modal save failure recovery; Select inside Modal focus trap (browser behavior not verified); dotenv-only `VAULT_HOST` initialized too early (KeyVault dotenv ordering).

---

### Verified Branch Status

**Historical snapshot, not current status.** Verified against the repository on August 26, 2026:

- `jp_dev` upstream-integration commit: `1f5656d6babe13227d41a6f188775927c966a93e` (`merge upstream v0.11.1 into jp_dev`)
- `jp_dev` Open WebUI version: `0.11.1`
- Upstream comparison point: `origin/main` at `d3e8bf3405e848cfba377814d0aa7ba7290e414d`, tagged `v0.11.1`
- `prod`: `9057cd039`
- `prod` Open WebUI version: `0.9.6`

> **Important:** `prod` is currently behind `jp_dev` and was not evaluated, changed, or promoted during this upstream sync. Features documented below are verified against `jp_dev` unless otherwise noted. Do not assume that a feature is deployed to `prod` until the corresponding `jp_dev` changes have been promoted.

Open WebUI frequently changes internal APIs, database models, memory handling, tool execution, permissions, and frontend settings components. Fork features should be revalidated after every merge-based upstream sync.

---

## Custom Modifications

### 1. Tool Server Connection Error Handling

**Status:** Active fork behavior.

**What Changed:**

- Tool server verification surfaces connection failures instead of silently discarding them.
- Likely browser content-blocker or shield failures are distinguished from generic connection failures.
- Tool server setup and Integrations display more specific error notifications.
- API helpers preserve timeout, backend detail, and raw connection errors where available.

**Files Modified:**

- `src/lib/components/AddToolServerModal.svelte`
- `src/lib/components/chat/Settings/Integrations.svelte`
- `src/lib/i18n/locales/en-US/translation.json`
- `src/lib/apis/index.ts`

> `src/routes/(app)/+layout.svelte` is not part of the current content-blocker-specific implementation and has been removed from this file list.

---

### 2. Azure Key Vault Secret Infrastructure and Microsoft OAuth

**Status:** Partially active; previous documentation overstated direct Microsoft OAuth integration.

**What Changed:**

- Added Azure Key Vault secret retrieval with environment-variable fallback.
- Secret names using underscores are translated to Key Vault names using hyphens.
- Added cached and uncached secret retrieval helpers.
- Added optional startup environment hydration from Key Vault.

**Microsoft OAuth Caveat:**

Microsoft OAuth configuration in `backend/open_webui/config.py` currently reads:

- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`
- `MICROSOFT_CLIENT_TENANT_ID`

using `os.getenv()`.

These values can still be supplied through environment variables or populated indirectly by the Key Vault environment hydrator, but `config.py` does **not** currently call `get_secret()` directly for Microsoft OAuth credentials.

**Files Modified:**

- `backend/open_webui/secrets.py`
- `backend/open_webui/ext/config_env_hydrator.py`
- `backend/open_webui/config.py`

---

### 3. `WEBUI_SECRET_KEY` Management

**Status:** Active fork behavior.

**What Changed:**

- Application bootstrap retrieves `WEBUI_SECRET_KEY` through `get_secret()`.
- Azure Key Vault is checked first when `VAULT_HOST` is configured.
- Environment-variable fallback remains available.
- Runtime configuration continues to consume the resulting environment value.
- Legacy secret/file handling remains compatible with the application bootstrap process.

**Files Modified:**

- `backend/open_webui/__init__.py`
- `backend/open_webui/secrets.py`
- `backend/open_webui/env.py`

---

### 4. Structured Content Blocks in Chat Responses

**Status:** Active fork behavior.

**What Changed:**

- Tool execution context uses `__content_blocks__`.
- The previous `__active_tool_results__` name is no longer present in the current source.
- Tool calls and tool results can be preserved as structured `function_call` and `function_call_output` content.
- Structured tool output is rendered instead of being discarded during middleware processing.

**Files Modified:**

- `backend/open_webui/utils/middleware.py`
- `src/lib/components/chat/Messages/structuredOutput.ts`
- `src/lib/components/chat/Messages/StructuredOutputRenderer.svelte`
- `src/lib/components/chat/Messages/ContentRenderer.svelte`
- `src/lib/components/chat/Messages/ResponseMessage.svelte`
- `src/lib/components/common/ToolCallDisplay.svelte`

---

### 5. File Upload Error Message Improvements

**Status:** Verified present on `jp_dev`.

**What Changed:**

- File extension validation reports the rejected extension.
- The response lists the currently allowed extensions.
- Backend `HTTPException` details are preserved instead of being replaced by a generic upload error.
- The frontend API propagates backend `detail` or error messages to the UI.
- `MessageInput.svelte` displays the resulting error in a toast.

**Before:**

> Error uploading file

**After:**

> File type '.pdf' is not allowed. Allowed types: txt, docx, md

**Files Modified:**

- `backend/open_webui/routers/files.py`
- `src/lib/apis/files/index.ts`
- `src/lib/components/chat/MessageInput.svelte`

---

### 6. Memory Import/Export with Batch Operations

**Status:** Active fork behavior; updated for Open WebUI 0.11.0.

**What Changed:**

- Added memory export and import controls to Personalization settings.
- Export now preserves current memory fields.
- Import accepts both the current object format and legacy JSON arrays.
- Imports are split into operation batches to avoid oversized vector database operations.
- Imported memories preserve metadata and timestamps where supplied.
- Loading and importing states provide user feedback.

**Current Export Format:**

```json
{
  "version": 2,
  "exported_at": "2026-08-07T19:00:00.000Z",
  "memories": [
    {
      "content": "User prefers dark mode",
      "type": "user",
      "path": null,
      "meta": {},
      "created_at": 1786138800,
      "updated_at": 1786138800
    }
  ]
}
```

**Backward Compatibility:**

Import continues to accept legacy arrays:

```json
[
  "User prefers dark mode",
  "User's favorite language is Python"
]
```

It can also accept arrays of memory objects.

**Current API Behavior:**

- The UI imports through operation batches sent to `POST /memories/update`.
- Import operations use `source: "import"`.
- `POST /memories/batch/add` remains available for simpler arrays of memory strings.

**Files Modified:**

- `src/lib/components/chat/Settings/Personalization.svelte`
- `src/lib/ext/memory-import-export.ts`
- `src/lib/ext/memory-ops-api.ts`
- `src/lib/apis/memories/index.ts`
- `backend/open_webui/routers/memories.py`
- `backend/open_webui/models/memories.py`

---

### 7. Open Terminal File Persistence and Transfer Tools

**Status:** Active fork behavior.

**What Changed:**

- Added terminal-to-OpenWebUI file persistence.
- Added OpenWebUI-to-terminal reverse file transfer.
- Terminal-generated files can be saved in Open WebUI and attached to chat.
- Existing Open WebUI files can be copied into a terminal session.

`persist_terminal_file_to_platform()` returns:

- `file_id`
- `download_url`, such as `/api/v1/files/{file_id}/content`
- `download_markdown`, such as `[Download simple.txt](/api/v1/files/{file_id}/content)`

Reverse transfer accepts:

- `file_id`
- `path`

A destination ending in `/` is treated as a directory target.

**Files Modified:**

- `backend/open_webui/ext/terminal_persist_tool.py`
- `backend/open_webui/ext/__init__.py`
- `backend/open_webui/utils/tools.py`
- `backend/open_webui/utils/terminals.py`
- `backend/open_webui/routers/terminals.py`
- `src/lib/apis/terminal/index.ts`
- `src/lib/components/chat/XTerminal.svelte`

> The implementation is in `terminal_persist_tool.py`; `ext/__init__.py` only identifies the extension package.

---

### 8. Capture Audio Feature

**Status:** Active fork behavior.

**What Changed:**

- Added a Capture Audio option to chat and recording menus.
- Records shared/display audio and microphone audio as separate streams.
- Transcribes audio in chunks in the background.
- Allows capture to continue with a single source if permission for the other source is unavailable.
- Merges and deduplicates transcript segments.
- Supports Azure AI Speech diarization where configured.

**Backend Endpoint:**

```text
POST /api/v1/audio/capture/transcriptions
```

**Files Modified:**

- `backend/open_webui/ext/audio_capture_router.py`
- `backend/open_webui/ext/audio_transcription.py`
- `src/lib/apis/audio/index.ts`
- `src/lib/components/chat/MessageInput.svelte`
- `src/lib/components/chat/MessageInput/InputMenu.svelte`
- `src/lib/components/chat/MessageInput/RecordMenu.svelte`
- `src/lib/components/chat/MessageInput/MeetingAudioCapture.svelte`
- `src/lib/ext/meeting-audio-transcript.ts`

**Commits:**

- [`55ed65b`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/55ed65bb76cd96462c06dfc2cc12377e7a095517) — feat: add Capture Audio to chat options
- `780fd942d` — feat: separate audio streams and combine transcriptions
- `a10810c18` — refactor capture audio and transcription formatting
- `04e784052` — fix: deduplicate generated transcripts

---

### 9. `DATABASE_URL` and Key Vault Hydration

**Status:** Active with an important correction.

**What Changed:**

- `DATABASE_URL` is read from the environment.
- The environment can optionally be hydrated from Azure Key Vault before runtime configuration is loaded.

**Important Current Behavior:**

The current source does **not** automatically append:

```text
/openwebui?sslmode=require
```

The complete database name, SSL mode, and query parameters must be included in the secret or environment value.

**Files Modified:**

- `backend/open_webui/env.py`
- `backend/open_webui/secrets.py`
- `backend/open_webui/ext/config_env_hydrator.py`

**Historical Commit:**

- [`e40ae2a`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/e40ae2af7bd51b8a6718ad120b811fc5bcfe9cb6) — historical database URL adjustment

> The URL-appending behavior introduced by this historical commit is not present in the current `jp_dev` source.

---

### 10. OAuth Callback Proxy for Tool Servers

**Status:** Active fork behavior on Open WebUI 0.11.1, with a corrected URL policy.

**What Changed:**

- Added `auth_callback_proxy` configuration to tool servers.
- Added extension-owned backend middleware at `backend/open_webui/ext/auth_callback_proxy_middleware.py` that matches configured callback hosts and paths.
- Added centralized callback configuration validation.
- Filters sensitive request headers, including authorization, cookies, and API-key headers.
- Filters sensitive response headers such as `Set-Cookie`.
- Applies request body limits and forwards appropriate host/protocol metadata.
- Filters the complete standard and `Connection`-nominated hop-by-hop header sets in both directions.
- Registers the callback middleware before upstream `AppHTTPMiddleware`, leaving `AppHTTPMiddleware` as the outermost middleware envelope.

**Operational Caveat:**

- Configuration validation rejects callback paths `/health`, `/ready`, `/health/db`, and any path ending in `/watch`.
- A non-empty `shared` query parameter on a callback `GET` remains an operational caveat because upstream redirect handling can intercept it.

**Current URL Policy:**

The current validator accepts both:

- `http://`
- `https://`

An older commit enforced HTTPS-only targets, but current source no longer enforces that restriction. Deployments requiring HTTPS-only callback targets must enforce that policy operationally or restore code-level enforcement.

**Files Modified:**

- `src/lib/components/AddToolServerModal.svelte`
- `backend/open_webui/ext/auth_callback_proxy_middleware.py`
- `backend/open_webui/main.py`
- `backend/open_webui/routers/configs.py`
- `backend/open_webui/utils/auth_callback_proxy_security.py`
- `backend/open_webui/ext/test_auth_callback_proxy_middleware.py`

**Upstream Integration Point:**

- `backend/open_webui/utils/asgi_middleware.py` owns the consolidated `AppHTTPMiddleware` envelope; it is not the callback-proxy implementation.

**Commits:**

- [`1c21e8209`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/1c21e820965af920a81a44e2a197314527574f7f) — add callback proxy middleware and UI
- [`a39bd0819`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/a39bd08190ecc4fee12e541c5f12247d8c3ba008) — validation and security hardening
- [`aac1c4257`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/aac1c4257d9834a9b87f78999ad529b832285117) — historical HTTPS enforcement

---

### 11. Terminal Tool Gateway

**Status:** Active fork behavior.

**What Changed:**

- Terminal sessions can call configured tool servers through Open WebUI.
- Terminal sessions receive seeded gateway URL/token headers.
- OpenAPI specifications are used for endpoint discovery.
- Requests are restricted by configured path and HTTP method allowlists.
- Paths are sanitized before forwarding.
- User grants are checked before tool server access is allowed.
- Browser/session authorization, cookies, API keys, forwarded-user headers, and similar credentials are not copied from terminal-originated requests.
- Only trusted server-side authentication/custom headers are used.

**Route Prefix:**

```text
/api/v1/ext/terminal-tool-gateway
```

**Files Modified:**

- `backend/open_webui/ext/terminal_tool_gateway.py`
- `backend/open_webui/routers/terminals.py`
- `backend/open_webui/utils/tools.py`
- `backend/open_webui/main.py`
- `src/lib/components/AddToolServerModal.svelte`

**Commits:**

- `e521d7ae3` — add terminal tool gateway integration
- `c50bead57` — add terminal gateway configuration UI
- `f767071bb` — add request validation and endpoint listing

---

### 12. Salas O'Brien Analytics Endpoint

**Status:** Active fork behavior.

**What Changed:**

- Added an admin-only analytics endpoint for Power BI chargeback reporting.
- Reads assistant-message usage rows from `chat_message`.
- Attributes usage to users and business units.
- Resolves per-message cost from provider usage, LiteLLM metadata, or Foundry rates.
- Supports opaque keyset pagination.

**Endpoint:**

```text
GET /api/v1/salasobrien/analytics
```

Requires `get_admin_user`.

**Query Parameters:**

- `start` — required epoch seconds, inclusive
- `end` — required epoch seconds, exclusive
- `group` — optional business unit/group filter
- `cursor` — optional opaque cursor from the previous response
- `limit` — default 10,000; minimum 1; maximum 100,000

The requested window must not exceed 366 days.

**Response Fields:**

- `timestamp`
- `chat_id`
- `chat_title`
- `user_id`
- `user_email`
- `user_name`
- `business_unit`
- `model`
- `model_name`
- `backend`
- `prompt_tokens`
- `completion_tokens`
- `total_tokens`
- `cost_usd`
- `next_cursor`

`next_cursor` is `null` on the final page.

**Business Unit Attribution:**

- Business units are derived from group membership.
- If a user belongs to multiple groups, the first group alphabetically is selected and a warning is logged.

**Cost Resolution Order:**

1. Inline `usage.cost`
2. LiteLLM rate lookup by deployment ID
3. LiteLLM rate lookup by model name
4. Azure Foundry rate table

Inline `usage.cost` is not restricted specifically to OpenRouter; any provider usage block containing this value can use that path.

**Foundry Rate Secret:**

The application requests:

```text
FOUNDRY_MODEL_RATES
```

`secrets.py` converts this to the Key Vault secret name:

```text
FOUNDRY-MODEL-RATES
```

Rates are loaded uncached for each analytics request.

**Foundry Rate Table Example:**

```json
{
  "gpt-5.5": {
    "input": 5.0,
    "cached_input": 0.5,
    "output": 30.0
  },
  "gpt-5.4": {
    "input": 2.5,
    "cached_input": 0.25,
    "output": 15.0,
    "input_long": 5.0,
    "cached_input_long": 0.5,
    "output_long": 22.5,
    "tier_threshold": 272000
  }
}
```

Additional behavior:

- Supports cached-token discounts.
- Supports long-context/tiered pricing.
- Custom agents can be priced through their base model.
- Messages with zero prompt and completion tokens receive `null` cost.

**Files Modified:**

- `backend/open_webui/routers/salasobrien.py`
- `backend/open_webui/utils/salasobrien_cost.py`
- `backend/open_webui/main.py`
- `src/lib/apis/analytics/index.ts`

**Verified Commits:**

- `837dd4a42` — update Salas O'Brien route for LiteLLM configuration
- `6b738f885` — fix analytics route

The router is currently registered once in `main.py`.

---

### 13. Usage Tab and Usage Limits

**Status:** Active fork behavior.

**What Changed:**

- Added a user-facing Usage tab.
- Added current-user usage and usage-limit APIs.
- Added monthly Redis-backed usage counters.
- Added tier configuration through secrets.
- Provides tier, percentage, reset time, and exemption information.

**Endpoints:**

```text
GET /api/v1/users/usage
GET /api/v1/usage/limit
```

**Files Modified:**

- `backend/open_webui/routers/usage.py`
- `backend/open_webui/utils/usage_limits.py`
- `backend/open_webui/main.py`
- `src/lib/apis/usage/index.ts`
- `src/lib/components/chat/Settings/Usage.svelte`
- `src/lib/components/chat/SettingsModal.svelte`

**Verified Commit:**

- `ab75b8fc0` — fix Usage tab UI

---

### 14. Tool Result Attachment Handling

**Status:** Active fork behavior.

**What Changed:**

- Tool responses can return attachment-style files.
- Detects `Content-Disposition: attachment`.
- Accepts validated base64 data URI payloads.
- Enforces attachment size handling.
- Stores attachments as Open WebUI files.
- Adds uploaded files to chat metadata.
- Text-like attachments can produce a text source event.
- Frontend chat rendering displays returned image/file attachments.

**Files Modified:**

- `backend/open_webui/ext/tool_result_files.py`
- `backend/open_webui/utils/middleware.py`
- `backend/open_webui/utils/tools.py`
- `src/lib/components/chat/Chat.svelte`
- `src/lib/components/chat/Messages/ResponseMessage.svelte`
- `src/lib/components/common/ToolCallDisplay.svelte`

**Commits:**

- `7b3933ef9` — base64 attachment handling
- `c2b71b204` — text content decoding
- `68135c336` — file metadata improvements

---

### 15. Image Edit Normalization

**Status:** Active fork behavior.

**What Changed:**

- Normalizes image edit input before forwarding it to OpenAI-compatible APIs.
- Decodes data URL image input.
- Applies EXIF orientation.
- Converts images to RGB or RGBA as appropriate.
- Encodes normalized input as PNG multipart data.
- Supports single and multiple image-edit inputs.

**Configuration:**

```text
ENABLE_OPENAI_IMAGE_EDIT_NORMALIZATION
```

**Files Modified:**

- `backend/open_webui/ext/image_edit_normalization.py`
- `backend/open_webui/routers/images.py`
- `backend/open_webui/config.py`

**Verified Commit:**

- `65319ee48` — add image edit PNG normalization

---

### 16. Azure OpenAI / Foundry Request Compatibility

**Status:** Partly historical; much of the current Azure behavior now matches upstream.

**Current Behavior:**

- Supports Azure `/openai/v1` endpoint formatting.
- Supports deployment-style Azure URLs.
- Sanitizes model/deployment names before constructing deployment paths.
- Handles Azure API-version query behavior.
- Supports chat, Responses, and embeddings request branches.
- Captures `x-litellm-model-id` where available for attribution/cost resolution.

The broad Azure URL and API-version behavior is no longer entirely a fork-only difference from upstream Open WebUI 0.11.0.

**Files Modified:**

- `backend/open_webui/routers/openai.py`

**Relevant Verified Commits:**

- `99f3c554c` — support Azure `/openai/v1` endpoint format
- `a2a9a3a42` — prevent path traversal through Azure deployment model names

---

### 17. Workspace and User Permission Extensions

**Status:** Present, but largely upstream parity in Open WebUI 0.11.0.

Current permission models include controls for:

- Workspace models
- Knowledge
- Prompts
- Tools
- Skills
- Import/export operations
- Sharing/public sharing
- User/group access grants
- Channels

The principal permission schema and frontend defaults now match `origin/main` at 0.11.0, so this should be treated as a historical fork customization and a rebase-verification area rather than an entirely current branch difference.

**Current Files:**

- `backend/open_webui/config.py`
- `backend/open_webui/routers/users.py`
- `backend/open_webui/routers/skills.py`
- `src/lib/constants/permissions.ts`
- `src/lib/components/admin/Users/Groups/Permissions.svelte`
- `src/routes/(app)/workspace/+layout.svelte`

---

### 18. Skills and PostgreSQL Compatibility Fixes

**Status:** Partially active; some behavior has since changed upstream.

**Current Behavior:**

- `Skill.name` has a database uniqueness constraint.
- The router explicitly checks duplicate skill IDs.
- Permission checks distinguish ordinary skill creation from skill import.
- Skill export requires the corresponding export permission.
- `function_name_filter_list` accepts both:
  - a list
  - a comma-delimited string
- Filtering behavior is compatible with PostgreSQL and SQLite paths.

The previous explicit router-level duplicate-name check is no longer clearly present; duplicate names are currently protected primarily by the database uniqueness constraint.

**Files Modified:**

- `backend/open_webui/routers/skills.py`
- `backend/open_webui/models/skills.py`
- `backend/open_webui/utils/tools.py`
- `backend/open_webui/utils/middleware.py`

**Verified Commits:**

- `47e127ac0` — duplicate skill name and PostgreSQL retrieval work
- `7b180daa3` — PostgreSQL/SQLite filter handling
- `3857c105f` — list/string filter handling

---

### 19. Database Dialect and Access-Grant Compatibility

**Status:** Historical customization; current model files match upstream 0.11.0.

Current source contains dialect-specific behavior where required, including:

- SQLite JSON extraction
- PostgreSQL JSON path extraction
- Dialect-specific chat search and token usage queries

However, access control has increasingly moved from serialized permission JSON to relational access grants. `access_grants.py` explicitly replaces older JSON-column filtering with relational joins.

The following files currently have no fork diff from `origin/main`:

- `backend/open_webui/models/chats.py`
- `backend/open_webui/models/chat_messages.py`
- `backend/open_webui/models/skills.py`
- `backend/open_webui/models/access_grants.py`

This section should therefore be treated as an upstream-parity/rebase verification item, not an active `jp_dev` difference.

---

### 20. Package and Dependency Changes

**Status:** Corrected for the current 0.11.0 source.

**Current Python Dependencies:**

`backend/requirements.txt` includes:

- `azure-identity==1.25.3`
- `azure-storage-blob==12.29.0`
- `azure-keyvault-secrets==4.9.0`
- `pymongo==4.17.0`

`pyproject.toml` includes:

- `azure-identity==1.25.3`
- `azure-storage-blob==12.29.0`
- `pymongo==4.17.0`

**Current Fork Difference:**

`azure-keyvault-secrets` is the meaningful current fork-only dependency in `backend/requirements.txt`.

The other listed Azure and PyMongo dependencies are also present upstream in Open WebUI 0.11.0.

**No Longer Declared:**

The current source does not declare either of the following as installed dependencies:

- `litellm`
- `mem0ai`

The application still handles LiteLLM-compatible metadata and rate information, but does not currently declare the LiteLLM Python package.

`package.json` and `package-lock.json` are JavaScript dependency manifests and do not contain these Python packages.

**Historical Commits:**

- `6f5024f33` — historically added `mem0ai`
- `eaed3ffc2` — historically added `litellm`
- `2683f3f0a` — PyMongo pin
- `36bad7328` — regenerated `package-lock.json`

> The first two packages were historically added but are no longer present in the current dependency declarations.

---

### 21. Docker Build Workflow Changes

**Status:** Active fork behavior.

**Current Workflow:**

```text
.github/workflows/docker.yaml
```

There is no current `.github/workflows/docker-build.yaml`.

**What Changed:**

- Supports manual `workflow_dispatch`.
- Supports selectable image variants:
  - main
  - CUDA
  - CUDA 12.6
  - Ollama
  - slim
- Pushes are configured for `jp_dev` and version tags.
- Non-manual runs build main and slim variants by default.
- Uses centralized variant eligibility logic.
- Applies eligibility to build, merge, and publishing behavior.
- Uses workflow concurrency cancellation by Git ref.
- Publishes to GitHub Container Registry.

**Verified Commits:**

- `5c559a5bb` — workflow update
- `e50a8e9be` — rename/merge workflow adjustment
- `38d43dc0f` — streamline eligibility checks
- `5cd246936` — fix conditional job execution

---

### 22. Responses API Streaming Normalization

**Status:** Active on `jp_dev`; not yet present on the current `prod` branch.

**What Changed:**

Open WebUI can configure an OpenAI-compatible connection with:

```text
api_type = responses
```

Before this fix, streaming requests through:

```text
POST /api/v1/chat/completions
```

could return raw OpenAI Responses API events such as:

```text
response.created
response.output_text.delta
response.completed
```

instead of the Chat Completions streaming contract expected by clients:

```text
chat.completion.chunk
```

This also affected:

```text
POST /api/v1/messages
```

because the Anthropic stream converter expects Chat Completions `choices[].delta` events. Raw Responses events were ignored, resulting in an Anthropic stream with lifecycle events but no content blocks.

**Fix:**

- Added Responses-SSE to Chat-Completions-SSE normalization.
- Upstream v0.11.1 removed the shared `stream_wrapper` `content_handler` parameter while the fork's Responses streaming call still required it. Restored the optional keyword hook while retaining the v0.11.1 positional calling contract, so Responses normalization remains active.
- Applied only to connections configured with `api_type == "responses"`.
- Standard Chat Completions providers continue using the existing stream handler.
- Preserves stable completion ID, model, and timestamp.
- Emits the assistant role exactly once.
- Converts text deltas to `delta.content`.
- Converts reasoning deltas to `delta.reasoning_content`.
- Converts function-call metadata and argument deltas to indexed `delta.tool_calls`.
- Normalizes usage:
  - `input_tokens` → `prompt_tokens`
  - `output_tokens` → `completion_tokens`
- Maps incomplete responses:
  - `max_output_tokens` → `finish_reason: "length"`
  - `content_filter` → `finish_reason: "content_filter"`
- Handles completed, incomplete, failed, upstream `[DONE]`, and EOF termination without duplicate terminal output.
- Emits exactly one final `[DONE]`.
- Allows the existing Anthropic converter to produce normal `content_block_start`, `content_block_delta`, and `content_block_stop` events.

**Files Modified:**

- `backend/open_webui/routers/openai.py`
- `backend/open_webui/utils/session_pool.py`
- `test/test_responses_stream_conversion.py`

**Commit:**

- [`87f270a73`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/87f270a733bd49389cf74c018786a8b55cffcc39) — fix: normalize Responses API streaming output

**Validation Note:**

Focused regression tests were added for:

- fragmented and CRLF SSE
- text and reasoning
- empty completions
- normalized usage
- incomplete responses
- multiple interleaved tool calls
- duplicate terminal suppression
- Anthropic content-block conversion
- the `session_pool.stream_wrapper` compatibility boundary: keyword `content_handler`, handler precedence over `passthrough`, positional passthrough compatibility, and early-close response cleanup

Focused validation ran all 12 Responses streaming tests successfully, with 27 focused aggregate tests passing. The covered behavior includes fragmented and CRLF SSE, text and reasoning deltas, empty completions, usage normalization, incomplete responses, interleaved tool calls, duplicate-terminal suppression, Anthropic content-block conversion, and `session_pool.stream_wrapper` compatibility.

---

### 23. Streaming Terminal File Uploads

The terminal client can upload files through a bounded streaming endpoint, avoiding the need to buffer an entire file in memory before it is sent to Open WebUI.

- **Endpoint:** `POST /api/v1/terminals/{server_id}/files/upload-stream`. The router also accepts the chat-scoped form `POST /api/v1/terminals/{server_id}/chats/{chat_id}/files/upload-stream`. (An earlier version of this section wrongly documented `/api/v1/files/upload-stream`; no such native route exists.)
- **Transport:** the body is a raw byte stream, not multipart form data. The terminal extension proxy (`ext/terminal_upload_proxy.py`) forwards the raw bytes to the terminal server; `curl -F` is not valid for it.
- **Controls:**
  - `OPEN_WEBUI_TERMINAL_UPLOAD_MAX_BYTES` limits the accepted upload size (default 4 GiB).
  - `OPEN_WEBUI_TERMINAL_UPLOAD_TIMEOUT_SECONDS` limits the total upload time (default 3600 s).
- **Behavior:** Requests that exceed either limit are rejected. This writes into the terminal workspace; it is distinct from the normal platform file upload (`POST /api/v1/files/`), which stores files in Open WebUI and runs file processing. The normal platform `/files/` route is confirmed in `src/lib/apis/files/index.ts` (`POST`).

```bash
curl -X POST "http://localhost:8080/api/v1/terminals/<server_id>/files/upload-stream?directory=<dir>&filename=<name>" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @/path/to/file
```

- **Commit:** [`8879a39a9`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/8879a39a9)

---

### 24. Administrator Memory-Index Rebuild

**Status:** Active fork behavior.

Administrators can rebuild the vector-memory collections for all users without deleting the SQL-backed memory records.

- **Endpoint:** `POST /api/v1/memories/reset/all`
- **Authorization:** Administrator access is required.
- **Behavior:** The operation rebuilds each user's memory vector collection from the persisted SQL memory rows. It does not delete persisted memories.

```bash
curl -X POST "http://localhost:8080/api/v1/memories/reset/all" \
  -H "Authorization: Bearer <admin-token>"
```

- **Commit:** [`57b86fb77`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/57b86fb77)
- **Focused validation:** 9 tests passed.

**Files Modified:**

- `backend/open_webui/ext/memory_admin_router.py`
- `backend/open_webui/main.py` (narrow registration)
- `backend/open_webui/ext/test_memory_admin_router.py`

---

### 25. Terminal Context Authorization

**Status:** Active fork behavior; required to safely integrate upstream 0.11.1 chat-scoped terminal contexts.

**What Changed:**

- Saved-chat terminal context selection is limited to the chat owner or an administrator for HTTP `X-Session-Id` and WebSocket authentication-message `chat_id` inputs.
- Shared-chat access and folder read access are insufficient to select a saved chat as a terminal context.
- Administrators are permitted only when `ENABLE_ADMIN_CHAT_ACCESS` applies or the chat is an internal-chat exception.
- Unauthorized saved-chat context IDs fail closed: HTTP returns `403`; WebSocket authentication closes with `4003`.
- Default and automation contexts remain unchanged.

This authorization boundary complements the terminal gateway controls in item 11 without changing its request-forwarding behavior.

**Files Modified:**

- `backend/open_webui/ext/terminal_context_authorization.py`
- `backend/open_webui/routers/terminals.py`
- `backend/open_webui/ext/test_terminal_context_authorization.py`

---

### 26. Native Sub-Agent Conversation Viewer

**Status:** Committed in the local checkout against Open WebUI 0.11.4; deployment and live-browser behavior are not verified.

**Commits:**

- [`1e381f7d6`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/1e381f7d6ff4fc7720d37e3daba5c9001b592d19) — feat: enhance sub-agent viewer with live catalog updates and keyboard navigation
- [`e580903ff`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/e580903ff18ccdb1a76a7a15c19b2613495d47d6) — feat: Implement Sub-Agent Catalog with new API and UI enhancements
- [`5c8fd0e83`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/5c8fd0e83dc926363a4a369262b61fb232e698c0) — feat: sub-agent viewer functionality and testing

**What Changed:**

- The **Sub-agents** tab is a permanent tab in the existing `ChatControls` panel (the resized desktop sidebar, or the mobile `Drawer`) whenever the mounted active chat matches the signed-in user and parent, including a new chat with no sub-agents yet (it then shows an empty state). Hydration never opens the sidebar. Clicking a persisted child-chat row from the companion Sub Agent tool opens the tab and selects that child. The tab replaces the earlier modal/multi-pane grid (up to eight panes), which is obsolete.
- The tab shows ONE compact, read-only conversation at a time. The child selector is the house `common/Select` dropdown (with a screen-reader label) rather than a native `<select>`; it switches between catalogued children, and each selection has **Open full chat** and Refresh controls. The viewer is read-only (`readOnly`).
- A row click both opens the tab and selects that child. Merging a `subagent:chats` catalog alone never opens the sidebar or changes the selection of an already-selected child. Opening clears the special artifacts, embeds, and call-overlay panels and shows controls.
- Uses the existing `Messages` renderer with read-only/compact-preview settings rather than nested full application iframes. The viewer does not mutate the global active-chat store (it only reads it) or expose generation/editing controls.
- Catalog state is a module-level store scoped to the active parent chat and signed-in user. It is reset on parent navigation, user change, and logout, and stale response callbacks from an earlier scope are rejected even when returning to the same parent. It survives activity-embed cleanup.
- **Historical availability (catalog hydration).** For a saved parent with a canonical UUID, the catalog is hydrated once per scope from the new native authenticated extension API (`GET /api/v1/ext/subagent-chats/{parent_id}`, below), so children remain available after a page reload or later session. The viewer shows loading, empty, and error states; the error state offers a **Retry catalog** action. The request is aborted, and its result discarded as stale, on parent change, user change, or teardown. A hydrated result never bumps `openRevision`, so it cannot open the sidebar. The server response is authoritative: children deleted since the last refresh drop out of the catalog, and the current selection is preserved only while it remains in the refreshed catalog (otherwise it falls back to the first returned child). Only live registrations received while that request was in flight are merged over the response, so a spawn racing the request is not lost. Hydrated historical results are unlimited (all returned children are merged); live `subagent:chats` snapshots keep their existing 64-chat batch bound unchanged.
- While the tab is visible, the selected running child refreshes through the authenticated chat API at most once per second, with no overlapping requests; a selection change queues behind an in-flight request. The existing API overlays active response-stream content. Socket events and reconnects request refreshes; terminal children stop routine polling after one final reconciliation. Hiding the tab or closing the panel stops tracking without stopping delegation.
- Preserves scrollback and follows new output only when the reader is already near the bottom. Late responses for an unmounted, hidden, or superseded selection are ignored.
- The terminal-activation auto-switch to Files now fires once per newly activated terminal rather than on every update, so it no longer steals a user-chosen tab (including Sub-agents).

**Live Catalog Socket Event and Reconciling Refresh (frontend):**

- The companion tool emits a parent-chat socket event, independent of the dashboard iframe, `{type: "subagent:catalog", data: {chats: [{chatId, title}]}}` (canonical child ID and display title), once per child after the child chat is persisted and before the foreground/background handler starts. The tool supplies no routing or authentication data. This is a separate path from the dashboard iframe `subagent:chats` snapshot bridge, which is unchanged; the dashboard worker/iframe is not involved, so the catalog survives activity-embed cleanup.
- The consumer lives in `trackSubAgentScope` in `subAgentViewer.ts` (extension-owned, mounted by the existing `ChatControls` tracker; no new upstream hook). It subscribes to the existing `socket` store `events` channel and accepts an event only while the mounted scope owner is current and the event `chat_id` equals the active parent chat, signed in. The payload is validated as a bounded (at most 64) catalog or a single chat with canonical UUIDs and bounded titles; invalid payloads are ignored.
- A matching event merges the child into the catalog for the active parent, preserving any current selection (the first selection defaults to the first child). It does not bump `openRevision`, so it never opens the sidebar and needs no page reload; a new background child appears in the tab as it is spawned.
- Reconnect or socket replacement: the consumer re-registers `events`/`connect` listeners on the new socket and, after a `connect` or a replaced socket, requests one reconciling refresh through the catalog API (`refreshSubAgentCatalog(true)`) to recover spawns missed while disconnected. At most one such refresh is queued behind an in-flight request (no overlapping requests). A refresh over an already-ready catalog is quiet: no loading spinner and no error flash.
- Live registrations (socket events and bridge snapshots) seen during an in-flight refresh override that response, so the authoritative-server rule above cannot drop a child that was just spawned. Scope change, user change, or teardown aborts the request and clears the queued refresh and live-registration set; socket listeners are removed on cleanup.
**Live-Child Stream Tracking (backend):**

- `chat_completion` (`backend/open_webui/main.py`) now has a single `create_task(redis, process, id=chat_id, task_id=metadata['task_id'])` registration site for every fan-out model. Internal (`request.state.internal`) calls then `await` the returned task internally and collect its result; external calls append the task ID and detach as before. The metadata task UUID is therefore registered under the child chat, so response-stream snapshots are exposed through the authenticated chat API while the child runs. The internal `results` and external `task_ids: []` response shapes are unchanged.
- `backend/open_webui/tasks.py` `create_task` gates the coroutine body behind a registration event (unchanged by this update): it starts only after the Redis registration (`redis_save_task`) succeeds, so the body cannot run before the task is saved. If registration fails or is cancelled, the task is cancelled, the never-started coroutine is closed (no "never awaited" warning), local state is cleaned, and the original exception propagates. There is no "started" flag: the done callback unconditionally closes the coroutine, which is a no-op once it has finished and also covers a task cancelled before its first step.
- `cleanup_task` now removes the local `tasks`, `response_streams`, and `item_tasks` entries first, then performs Redis cleanup inside a `try/except`; Redis errors are logged with `log.exception` rather than raised, so local state is always released. This prevents a failed registration from leaving a coordinator waiting on a caller decision (deadlock) or the built-in foreground reservation from being released twice.

**Sub-Agent Catalog Endpoint (backend, new):**

- `GET /api/v1/ext/subagent-chats/{parent_id}` (`backend/open_webui/ext/subagent_chats_router.py`, `get_verified_user`) returns summaries only: `[{chatId, title}]` ordered oldest first. No transcript, message, or model data is read; titles are trimmed and capped at 200 UTF-16 code units (matching the frontend's JS `title.length` check) without splitting a character, so non-BMP emoji titles cannot make the frontend reject the whole catalog (default `New Chat`).
- The parent ID must be a canonical UUID and the parent chat must be owned by the requesting user; otherwise (missing, foreign, malformed, or shared) the response is a uniform 404. Child rows must also belong to the user and have strict `meta.internal === true`, `meta.type === 'subagent'`, `meta.source === 'ai_team_delegate'`, and `meta.parent_chat_id` equal to the parent; returned IDs are canonical UUIDs.
- Native built-in sub-agent chats lack `meta.source` and are intentionally NOT shown, and legacy chats lacking the marker are excluded.
- The `internal` filter is a strict JSON-boolean-true test, not a text-to-boolean cast (which would also accept values such as the strings `"true"`/`"yes"`/`1`): SQLite uses `json_type(meta, '$.internal') = 'true'`; PostgreSQL requires `json_typeof(meta -> 'internal') = 'boolean'` and the text value `true` (the column is `json`, not `jsonb`). Numeric and string values (for example `"true"`, `1`) are not matched. The `source`, `type`, and owner predicates and the response shape are unchanged. An unsupported dialect raises `NotImplementedError` rather than silently using a lenient cast.
- Performance/dialect note: the JSON `meta` filter runs over the requesting user's own chats using the existing per-user indexed base query; no migrations or new indices were added. A large per-user history scan is a known potential cost; it was not measured or optimized here. SQL generation was compile-checked for PostgreSQL but not run against a live PostgreSQL database.

**Tool-to-Frontend Contract and Access Checks:**

- Requires the companion `sobe-ai-tools/Tools/Sub Agent` tool v1.2.1 (its dev/prod manifests align), which emits the parent `subagent:catalog` socket event described above in addition to the unchanged iframe bridge. An older tool still works through the iframe bridge and historical hydration but gives no live catalog without reload. Deploy by rebuilding the Open WebUI frontend and backend together; the sidebar tab and socket consumer need the frontend, live-child snapshots and the strict catalog filter need the backend change.
- Dashboard snapshots send `{type: 'subagent:chats', chats: [{chatId, title}]}`. The host acknowledges accepted catalogs with `{type: 'subagent:viewer-ready'}`; a plain row click then sends `{type: 'subagent:open-chat', chatId, title}`.
- `FullHeightIframe.svelte` exposes a generic `onEmbedMessage(data, source)` callback, invoked only after the message's `source` exactly equals its iframe `contentWindow`. It contains no feature acknowledgement or sub-agent strings. `createSubAgentBridge` (in `subAgentViewer.ts`) validates the payload and parent-chat/user/read-only scope, then sends the `subagent:viewer-ready` readiness message to the supplied `source` via `source.postMessage`. The bridge message schema is unchanged. The viewer validates canonical UUIDs, bounded titles/catalogs, and fetched chat identity before rendering.
- Fetched chats must belong to the signed-in user and have `meta.internal === true`, `meta.type === 'subagent'`, `meta.source === 'ai_team_delegate'`, and `meta.parent_chat_id` matching the invoking parent chat.
- Credentials remain at the native authenticated chat API boundary; tokens and transcripts are not transferred through iframe messages.
- No iframe **Allow Same Origin** setting is required. Without the companion frontend, rows retain normal `/c/<uuid>` new-tab links; modified clicks retain native link behavior.

**Files Modified / Added:**

- `src/lib/components/common/FullHeightIframe.svelte` — narrow upstream edit: generic `onEmbedMessage(data, source)` hook called after exact source equality; the feature-specific readiness acknowledgement was removed from this file.
- `src/lib/components/chat/Messages/ResponseMessage.svelte` — narrow upstream edit: builds the scoped bridge handler with `createSubAgentBridge` and passes it as `onEmbedMessage`; no longer mounts the viewer.
- `src/lib/components/chat/ChatControls.svelte` — narrow upstream edit: the tab is now permanent for the mounted active chat/user/parent (no longer requires a non-empty catalog); the tab button is now the extension-owned `SubAgentTabButton` at both the desktop sidebar and mobile `Drawer` sites, plus the necessary local lifecycle/scope tracking, tab/open handling (precedence over artifacts/embeds/call overlay), and terminal-tab activation fix. These must stay in this file because they depend on its local tab state and `showControls` lifecycle.
- `src/lib/ext/SubAgentTabButton.svelte` (new, extension-owned) — the Sub-agents tab button, replacing the duplicated tab markup in both `ChatControls` layouts.
- `src/lib/components/chat/SubAgentChatViewer.svelte` — single compact read-only conversation, house `common/Select` child selector, loading/empty/error-retry states, and refresh lifecycle (existing feature viewer; kept in place, not moved).
- `src/lib/components/chat/subAgentViewer.ts` — scoped catalog store, one-time historical hydration (abort/stale handling), authoritative-server refresh with in-flight live-registration precedence, the `subagent:catalog` socket consumer with reconnect/socket-replacement reconciling refresh, `createSubAgentBridge`, payload validation, catalog merging (historical results unlimited; live snapshots keep their 64-chat batch bound), and child-chat provenance checks (existing feature helper; kept in place, not moved).
- `src/lib/ext/subagent-chats-api.ts` (new, extension-owned) - authenticated `GET` client for the catalog endpoint, with `AbortSignal` support.
- `backend/open_webui/ext/subagent_chats_router.py` (new, extension-owned) - the owner-only catalog router, including the strict per-dialect JSON-boolean `internal` filter.
- `backend/open_webui/ext/test_subagent_chats_router.py` (new) - SQLite-backed router tests (including non-boolean `internal` values) plus a dialect SQL-compile check.
- `src/lib/components/chat/SubAgentChatViewer.test.ts` and `src/lib/components/chat/subAgentViewer.test.ts` — controller, sidebar, scope/stale-callback, bridge, provenance, catalog, and compile checks (the compile check now includes `SubAgentTabButton.svelte`).
- `backend/open_webui/main.py` — router registration (the import plus one `include_router` line at `/api/v1/ext/subagent-chats`) and the single task registration site; internal fan-out awaits the registered child task, external fan-out detaches and returns `task_ids`.
- `backend/open_webui/tasks.py` — registration-gated `create_task` (unconditional coroutine close in the done callback) and `cleanup_task` that releases local state before Redis cleanup and logs Redis errors.

Upstream-file edits are limited to what cannot live in a new file: the iframe hook, the `ResponseMessage` bridge hookup, the `ChatControls` invocations and local tab/lifecycle state, and the backend registration/cleanup fixes. Feature logic stays in the new or existing feature-owned files, and no speculative wrappers were added.
- `backend/open_webui/utils/subagents.py` — the built-in delegate's narrow registration handler restores foreground/background capacity exactly once on registration failure or cancellation; cancellation is re-raised, while ordinary exceptions still return `Error: ...`. Successful body cleanup is unchanged.
- `test/test_internal_response_stream_tracking.py` (new) — task registration, cancellation, cleanup, and reservation regression tests.

**Validation:**

- Frontend: 77 focused Vitest tests passed: 33 catalog-helper (`subAgentViewer.test.ts`), 15 `SubAgentChatViewer.test.ts`, and 29 `select-keyboard.test.ts` (27 handler-double tests plus 2 client/SSR compilation tests of `Select.svelte`).
- Backend: 39 tests passed before the final keyboard-only repair, which touched no backend code: 9 SQLite-backed `backend/open_webui/ext/test_subagent_chats_router.py`, 21 `test/test_internal_response_stream_tracking.py`, and 9 memory-admin. The PostgreSQL filter was checked by SQL compilation only, not against a live database. Combined command: `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/Scripts/python.exe -m pytest -q -p pytest_asyncio.plugin -p no:cacheprovider -o asyncio_default_fixture_loop_scope=function backend/open_webui/ext/test_subagent_chats_router.py test/test_internal_response_stream_tracking.py backend/open_webui/ext/test_memory_admin_router.py`. Plugin autoload is disabled because installed OpenTelemetry emits a deprecation during import; known dependency deprecation warnings are not suppressed and this is not a warning-clean claim. The fake-Redis fixture omits Redis's type-only import rather than suppressing warnings.
- Companion tool: 55 tests passed, Wizard validation reported 0 issues, and the source, README, and dev/prod manifests align at version 1.2.1.
- `git diff --check` and `git diff --cached --check` were clean.
- Reviewed: the strict JSON-boolean `internal` filter and the catalog refresh/live-registration repairs. The final trigger/focus-out ordering fix for the shared Select is covered by a handler-double regression test, not verified in a live browser.
- Not performed: no live browser, server, Redis, PostgreSQL, deployment, or multi-worker run; no full frontend build (skipped because it needs network access for Pyodide); checkout-wide `svelte-check` skipped because of roughly 7,000 existing type errors. This is not a clean full-check or browser-validation claim.

**Upstream Sync Checks:**

Revalidate the `subagent_chats_router` registration in `main.py` (exactly once), its `meta` JSON filters on the supported database dialects, the permanent tab condition in `ChatControls`, iframe source-scoping and the generic `onEmbedMessage(data, source)` hook, the `ResponseMessage` bridge hookup, and the `ChatControls` `SubAgentTabButton` invocations; `Messages` read-only/compact-preview behavior; the `ChatControls` Sub-agents tab (desktop sidebar and mobile `Drawer`), including open precedence over artifacts/embeds/call overlay and the terminal-tab activation behavior; scope reset on parent/user/logout; the child metadata contract; chat API stream overlays and socket event shapes; and, in `main.py`/`tasks.py`, internal-task registration under the child chat, registration-gated start, cancel/failure coroutine closing, and local cleanup despite Redis errors, after upstream merges.

---

### 27. Shared Select Keyboard Accessibility

**Status:** Committed in the local checkout against Open WebUI 0.11.4; deployment and live-browser behavior are not verified. Actual browser behavior is untested.

**Commits:**

- [`1e381f7d6`](https://github.com/I-C-Thomasson-Associates/open-webui/commit/1e381f7d6ff4fc7720d37e3daba5c9001b592d19) — feat: enhance sub-agent viewer with live catalog updates and keyboard navigation

**What Changed:**

- The shared `common/Select.svelte` dropdown is now keyboard-operable everywhere it is used (for example the Sub-agents child selector in item 26). Behavior is implemented in the new extension-owned `src/lib/ext/select-keyboard.ts`; `Select.svelte` has only narrow integration hooks. No `Drawer.svelte` edit and no per-caller edits were needed.
- **Opening and initial focus.** Opening focuses the selected option, else the first option, for the default menu. For slotted (custom) content, which is exposed as a `dialog`, initial focus goes to the first enabled search/text control, falling back to the selected or first option, then the content container.
- **Navigation.** ArrowDown/ArrowUp (wrapping), Home, and End move among enabled options; Enter and Space activate through the native button behavior. ArrowUp/ArrowDown on the trigger opens the menu; typing, caret movement, and activation inside a custom search input are left to that input.
- **Tab.** In the default menu, Tab returns focus to the trigger and closes so that the browser then tabs onward from the trigger rather than from the portal at the end of `body`. In custom dialog content, Tab moves internally between its controls.
- **Focus-out.** The trigger and custom dialog content form one local focus boundary. Moving focus onto the trigger keeps the dropdown open until its click toggles closed, even if mouseup occurs after the focus-out timer. Keyboard focus leaving both trigger and content closes without restoring focus; internal search/button traversal remains native.
- **Escape.** Escape is consumed (`preventDefault` and `stopPropagation`) by the open trigger or content before it can reach an ancestor `Drawer`, closes only the select, and restores focus to the trigger. The window-level Escape handler was removed.
- **ARIA.** The trigger gains `aria-haspopup`, `aria-controls`, and an id; the content gets `role` (`menu` or `dialog`), id, and `aria-labelledby`; default items are `menuitemradio` with `aria-checked`. Item buttons use `tabindex=-1`.
- Outside clicks close without refocusing the trigger; focus is restored to the trigger on keyboard or selection close. Selection behavior and the public props/callbacks are otherwise unchanged.

**Files Modified / Added:**

- `src/lib/ext/select-keyboard.ts` (new, extension-owned) — the focus, navigation, Tab, focus-out, and Escape helpers.
- `src/lib/components/common/Select.svelte` — narrow upstream edit: imports the helpers, generates an id, replaces `toggleOpen`/window Escape handling with `open`-driven focus and close handling, and adds the ARIA attributes and keydown/focusout bindings. This must stay in this file because it depends on its local `open` state and portal.
- `src/lib/ext/select-keyboard.test.ts` (new) — 27 handler-double tests of the helper behavior, plus 2 client/SSR compilation tests of `Select.svelte` (29 tests total). Includes delayed trigger-click ordering and keyboard traversal from content through the trigger to an outside control.

**Validation:**

- 29 `select-keyboard.test.ts` tests passed (27 handler-double tests plus 2 client/SSR compilation tests of `Select.svelte`, zero compiler warnings), as part of the 77 frontend tests in item 26. Targeted TypeScript `--noEmit`, scoped Prettier, and `git diff --check` / `git diff --cached --check` were clean. The final trigger/focus-out ordering fix is covered by a regression test using handler doubles. There is no installed mounted-DOM harness in this checkout, so the component was never mounted and no real browser exercised focus, Tab order, or `Drawer` interaction. **Actual native browser behavior is untested; do not treat this as a browser test.**
- No live deployment, full frontend check, or build was performed. Checkout-wide `svelte-check` remains unusable because of existing type errors.

**Upstream Sync Checks:**

After upstream merges, revalidate that `Select.svelte` still delegates to `select-keyboard.ts` with the same `open`/portal lifecycle, that the upstream `Drawer` still has no competing Escape handling that runs before the select's capture handler, and that upstream has not added its own keyboard handling to `Select.svelte`.

---

## Deployment Notes

### Required Configuration

- Set `VAULT_HOST` to enable Azure Key Vault integration.
- The workload identity, managed identity, or other `DefaultAzureCredential` source must have permission to read Key Vault secrets.
- Environment variables remain the fallback when Key Vault is unavailable.
- Key Vault secret names use hyphens where environment variable names use underscores.
- Supply a complete `DATABASE_URL`, including database name and SSL parameters.
- Configure Redis when usage-limit tracking is enabled.
- Configure the terminal server for terminal file transfer and gateway support.
- Configure Azure AI Speech when capture-audio transcription or diarization depends on Azure.
- Configure `FOUNDRY-MODEL-RATES` in Key Vault when Foundry models require analytics pricing.
- Configure the usage-limit tier secret expected by `usage_limits.py`.

### Security Notes

- Microsoft OAuth currently reads environment variables in `config.py`; Key Vault support is indirect through environment hydration.
- OAuth callback proxy targets currently allow HTTP and HTTPS. Enforce HTTPS operationally if required.
- Terminal gateway requests intentionally do not forward browser/session credentials.
- Treat callback proxy and terminal gateway allowlists as security-sensitive configuration.

### Historical Upstream-Sync Focused Validation

This validation belongs to the earlier upstream sync and is not the latest validation. The latest Sub-Agent/Select validation is recorded in items 26 and 27. The backend-focused validation completed with **27 passed** in 10.91 seconds, with **5 pytest-reported dependency/deprecation warnings** plus one final interpreter-shutdown SWIG deprecation warning:

- `test/test_responses_stream_conversion.py`
- `backend/open_webui/ext/test_memory_admin_router.py`
- `backend/open_webui/ext/test_terminal_context_authorization.py`
- `backend/open_webui/ext/test_auth_callback_proxy_middleware.py`

For that earlier sync, frontend tests were not run because its final changes were backend-focused and the frontend conflict resolution was additive only.

### Rebase Checklist

After merging a newer upstream version, verify:

- The package version and upstream base are updated in this page.
- The `prod` branch has actually received the intended `jp_dev` changes.
- Memory export preserves the current memory schema.
- Legacy memory import remains backward compatible.
- Capture Audio routes and frontend API signatures still match.
- The audio capture router is registered exactly once.
- Terminal gateway and terminal transfer routes remain registered.
- Terminal context authorization remains enforced at both HTTP and WebSocket ingress for saved-chat contexts.
- OAuth callback proxy middleware is registered exactly once, before `AppHTTPMiddleware`, and filters standard and `Connection`-nominated hop-by-hop headers in both directions.
- The callback-proxy implementation remains extension-owned at `backend/open_webui/ext/auth_callback_proxy_middleware.py`.
- Salas O'Brien analytics and Usage routers are registered exactly once.
- Tool result attachment handling remains wired into tool-result processing.
- Structured `__content_blocks__` handling remains compatible with current middleware.
- Native sub-agent viewer iframe source validation, read-only rendering, parent/owner checks, stream overlays, companion tool bridge, the `subagent:catalog` socket consumer, and the strict `internal` JSON-boolean filter remain compatible (item 26).
- The shared `common/Select.svelte` keyboard integration and `ext/select-keyboard.ts` still behave as described in item 27, and no other upstream component needs its own keyboard handling.
- Responses-backed streaming is normalized before reaching Chat Completions and Anthropic clients.
- Key Vault integration still retrieves secrets requiring direct secret-manager access.
- Microsoft OAuth environment hydration occurs before OAuth configuration is evaluated.
- The complete `DATABASE_URL` is supplied without relying on automatic URL suffixing.
- Current dependency manifests still include `azure-keyvault-secrets`.
- Docker workflow triggers and image variants remain appropriate for the deployment branch.
