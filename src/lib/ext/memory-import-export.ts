import {
	type MemoryOperation,
	type MemoryOperationResult,
	updateMemories
} from '$lib/ext/memory-ops-api';

type MemoryType = 'user' | 'context';

type CanonicalImportRecord = {
	content: string;
	type: MemoryType;
	path: string;
	meta?: Record<string, unknown>;
};

type V2ImportPayload = {
	version: 2;
	exported_at?: string;
	memories: unknown[];
};

type StructuredMemory = {
	content?: unknown;
	type?: unknown;
	path?: unknown;
	meta?: unknown;
	created_at?: unknown;
	updated_at?: unknown;
};

export type ExportableMemory = {
	content: string;
	type?: string;
	path?: string | null;
	meta?: Record<string, unknown> | null;
	created_at?: number;
	updated_at?: number;
};

export type MemoryImportResult = {
	input_total: number;
	input_skipped: number;
	created: number;
	skipped: number;
	failed: number;
};

const chunkArray = <T>(items: T[], chunkSize: number): T[][] => {
	if (chunkSize <= 0) {
		return [items];
	}

	const chunks: T[][] = [];
	for (let i = 0; i < items.length; i += chunkSize) {
		chunks.push(items.slice(i, i + chunkSize));
	}

	return chunks;
};

const normalizeType = (value: unknown): MemoryType => {
	if (typeof value === 'string' && value.toLowerCase() === 'user') {
		return 'user';
	}

	return 'context';
};

const normalizePath = (value: unknown): string => {
	if (typeof value !== 'string') {
		return '';
	}

	return value.trim();
};

const normalizeMeta = (value: unknown): Record<string, unknown> | undefined => {
	if (value && typeof value === 'object' && !Array.isArray(value)) {
		return value as Record<string, unknown>;
	}

	return undefined;
};

const toImportSourceEntries = (payload: unknown): unknown[] => {
	if (Array.isArray(payload)) {
		return payload;
	}

	if (payload && typeof payload === 'object') {
		const maybeV2 = payload as Partial<V2ImportPayload>;
		if (Array.isArray(maybeV2.memories)) {
			return maybeV2.memories;
		}
	}

	throw new Error('Invalid file format. Expected a memory array or v2 export object.');
};

export const normalizeImportPayload = (payload: unknown) => {
	const entries = toImportSourceEntries(payload);
	const records: CanonicalImportRecord[] = [];
	let skipped = 0;

	for (const entry of entries) {
		if (typeof entry === 'string') {
			const content = entry.trim();
			if (!content) {
				skipped += 1;
				continue;
			}

			records.push({
				content,
				type: 'context',
				path: ''
			});
			continue;
		}

		if (entry && typeof entry === 'object') {
			const structured = entry as StructuredMemory;
			const content = typeof structured.content === 'string' ? structured.content.trim() : '';

			if (!content) {
				skipped += 1;
				continue;
			}

			records.push({
				content,
				type: normalizeType(structured.type),
				path: normalizePath(structured.path),
				meta: normalizeMeta(structured.meta)
			});
			continue;
		}

		skipped += 1;
	}

	return {
		records,
		inputTotal: entries.length,
		inputSkipped: skipped
	};
};

export const buildAddOperations = (records: CanonicalImportRecord[]): MemoryOperation[] => {
	return records.map((record) => ({
		action: 'add',
		content: record.content,
		type: record.type,
		path: record.path
	}));
};

const summarizeOperationResults = (results: MemoryOperationResult[]) => {
	let created = 0;
	let skipped = 0;
	let failed = 0;

	for (const result of results) {
		if (result.status === 'created') {
			created += 1;
		} else if (result.status === 'skipped') {
			skipped += 1;
		} else if (result.status !== 'updated' && result.status !== 'deleted') {
			failed += 1;
		}
	}

	return { created, skipped, failed };
};

export const importMemoriesFromPayload = async ({
	token,
	payload,
	chunkSize = 100
}: {
	token: string;
	payload: unknown;
	chunkSize?: number;
}): Promise<MemoryImportResult> => {
	const normalized = normalizeImportPayload(payload);
	const operations = buildAddOperations(normalized.records);

	if (operations.length === 0) {
		return {
			input_total: normalized.inputTotal,
			input_skipped: normalized.inputSkipped,
			created: 0,
			skipped: 0,
			failed: 0
		};
	}

	const chunks = chunkArray(operations, chunkSize);
	let created = 0;
	let skipped = 0;
	let failed = 0;

	for (const chunk of chunks) {
		try {
			const results = await updateMemories(token, chunk, 'tool');
			const summary = summarizeOperationResults(results);
			created += summary.created;
			skipped += summary.skipped;
			failed += summary.failed;
		} catch (error) {
			console.error(error);
			failed += chunk.length;
		}
	}

	return {
		input_total: normalized.inputTotal,
		input_skipped: normalized.inputSkipped,
		created,
		skipped,
		failed
	};
};

export const buildMemoryExportPayloadV2 = (memories: ExportableMemory[]) => {
	return {
		version: 2,
		exported_at: new Date().toISOString(),
		memories: memories.map((memory) => ({
			content: memory.content,
			type: normalizeType(memory.type),
			path: normalizePath(memory.path),
			meta: normalizeMeta(memory.meta),
			created_at: memory.created_at,
			updated_at: memory.updated_at
		}))
	};
};
