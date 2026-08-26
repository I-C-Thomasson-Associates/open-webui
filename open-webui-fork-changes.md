# Welcome to the ICT OpenWebUI Fork

# `jp_dev`, `prod`, and Upstream Differences

## Overview

The `jp_dev` and `prod` branches are based on Open WebUI with custom modifications for ICT / Salas O'Brien deployment.

### Verified Branch Status

Verified against the repository on August 26, 2026:

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

The final focused validation ran all 9 Responses streaming tests successfully. The covered behavior includes fragmented and CRLF SSE, text and reasoning deltas, empty completions, usage normalization, incomplete responses, interleaved tool calls, duplicate-terminal suppression, and Anthropic content-block conversion.

---

### 23. Streaming Terminal File Uploads

The terminal client can upload files through a bounded streaming endpoint, avoiding the need to buffer an entire file in memory before it is sent to Open WebUI.

- **Endpoint:** `POST /api/v1/files/upload-stream`
- **Controls:**
  - `OPEN_WEBUI_TERMINAL_UPLOAD_MAX_BYTES` limits the accepted upload size.
  - `OPEN_WEBUI_TERMINAL_UPLOAD_TIMEOUT_SECONDS` limits the time allowed for an upload.
- **Behavior:** Requests that exceed either limit are rejected; successful uploads follow the normal file-processing path.

```bash
curl -X POST "http://localhost:8080/api/v1/files/upload-stream" \
  -H "Authorization: Bearer <token>" \
  -F "file=@/path/to/file"
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

### Final Focused Validation

The final backend-focused validation completed with **24 passed** and **5 dependency/deprecation warnings** in 11.29 seconds:

- `test/test_responses_stream_conversion.py`
- `backend/open_webui/ext/test_memory_admin_router.py`
- `backend/open_webui/ext/test_terminal_context_authorization.py`
- `backend/open_webui/ext/test_auth_callback_proxy_middleware.py`

Frontend tests were not run because the final changes were backend-focused and the frontend conflict resolution was additive only.

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
- Responses-backed streaming is normalized before reaching Chat Completions and Anthropic clients.
- Key Vault integration still retrieves secrets requiring direct secret-manager access.
- Microsoft OAuth environment hydration occurs before OAuth configuration is evaluated.
- The complete `DATABASE_URL` is supplied without relying on automatic URL suffixing.
- Current dependency manifests still include `azure-keyvault-secrets`.
- Docker workflow triggers and image variants remain appropriate for the deployment branch.
