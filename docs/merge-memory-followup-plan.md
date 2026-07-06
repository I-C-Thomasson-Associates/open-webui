# Memory Import/Export Follow-up Plan

This note captures the planned post-merge memory feature work so we can finish conflict resolution first.

## Goals

- Keep upstream Open WebUI 0.10.2 memory model and endpoints as the default behavior.
- Preserve and improve fork import/export features.
- Support both legacy and new memory file formats during import.

## Upstream Baseline To Keep

- Memory schema fields: `content`, `type`, `path`, `meta`, `created_at`, `updated_at`.
- Operation endpoint: `POST /api/v1/memories/update`.
- Existing single-memory flows (`add`, `update`, `delete`) and current `MemoryModal` UX.

## Planned API Changes

1. Add/confirm frontend wrapper for `/memories/update` with operation batches.
2. Remove frontend dependency on legacy `/memories/batch/add`.
3. Keep compatibility helpers that map import payloads into operation batches.

## Planned Import Changes

1. Detect input format:
   - Legacy: array of strings.
   - Structured: array/object entries with `content`, optional `type`, `path`, `meta`.
2. Normalize to canonical records.
3. Validate records:
   - non-empty `content`
   - valid `type` (`user` or `context`)
   - sanitized `path`
4. Convert to `add` operations and submit in chunks.
5. Show import result counts: imported, skipped, failed.

## Planned Export Changes

1. Default to a versioned structured format (v2) preserving `type`, `path`, and optional `meta`.
2. Optionally provide legacy export format for compatibility with old backups.
3. Keep file naming and UX simple (`memories-export-YYYY-MM-DD.json`).

## UX and Safety

- Keep current progress and error feedback during import.
- Avoid partial silent failures; summarize exactly what happened.
- Keep clear-all and per-memory delete behavior unchanged.

## Execution Order (After Merge Conflicts Are Done)

1. `src/lib/apis/memories/index.ts`
2. `src/lib/components/chat/Settings/Personalization/ManageModal.svelte`
3. Optional backend cleanup for legacy batch route if no callers remain
4. Targeted sanity checks for import/export and memory CRUD
