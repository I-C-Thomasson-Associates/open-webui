import { WEBUI_API_BASE_URL } from '$lib/constants';

export type MemoryOperation = {
	action: 'add' | 'replace' | 'remove' | 'move';
	id?: string;
	content?: string;
	type?: 'user' | 'context';
	path?: string;
};

export type MemoryOperationResult = {
	action: string;
	status: 'created' | 'updated' | 'deleted' | 'skipped' | string;
	reason?: string;
	id?: string;
	memory?: Record<string, unknown>;
};

export const updateMemories = async (
	token: string,
	operations: MemoryOperation[],
	source: 'tool' | 'background_review' = 'tool'
) => {
	let error = null;

	const res = await fetch(`${WEBUI_API_BASE_URL}/memories/update`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			authorization: `Bearer ${token}`
		},
		body: JSON.stringify({
			operations,
			source
		})
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			error = err?.detail ?? 'Failed to update memories';
			console.error(err);
			return null;
		});

	if (error) {
		throw error;
	}

	return (res ?? []) as MemoryOperationResult[];
};
