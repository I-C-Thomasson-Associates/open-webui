import { get, writable } from 'svelte/store';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
	createSubAgentBridge,
	isOwnedSubAgentChat,
	mergeSubAgentChats,
	parseSubAgentChat,
	refreshSubAgentCatalog,
	selectSubAgentChat,
	subAgentViewer,
	trackSubAgentScope
} from './subAgentViewer';
const id = '12345678-1234-1234-1234-123456789abc';
let stop: (() => void) | undefined;
afterEach(() => {
	stop?.();
	stop = undefined;
	vi.unstubAllGlobals();
});

describe('saved sub-agent catalog discovery', () => {
	const parentId = '32345678-1234-1234-1234-123456789abc';
	const child = { chatId: id, title: 'Saved task' };
	const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
	let fetchCatalog: ReturnType<typeof vi.fn>;
	beforeEach(() => {
		vi.stubGlobal('window', {});
		vi.stubGlobal('localStorage', { token: 'private-token' });
		fetchCatalog = vi.fn().mockResolvedValue({ ok: true, json: async () => [child] });
		vi.stubGlobal('fetch', fetchCatalog);
	});
	function savedScope() {
		const parent = writable(parentId);
		const user = writable<{ id: string } | null>({ id: 'owner' });
		stop = trackSubAgentScope(parent, user);
		return { parent, user };
	}
	it('discovers a saved chat once per scope and again after remount without opening the panel', async () => {
		const { parent, user } = savedScope();
		expect(get(subAgentViewer).discovery).toBe('loading');
		await settle();
		expect(fetchCatalog).toHaveBeenCalledWith('/api/v1/ext/subagent-chats/' + parentId, {
			method: 'GET',
			headers: { Accept: 'application/json', authorization: 'Bearer private-token' },
			signal: expect.any(AbortSignal)
		});
		expect(get(subAgentViewer)).toMatchObject({
			catalog: [child],
			selectedId: id,
			discovery: 'ready',
			openRevision: 0
		});
		parent.set(parentId);
		user.set({ id: 'owner' });
		expect(fetchCatalog).toHaveBeenCalledOnce();
		stop?.();
		savedScope();
		await settle();
		expect(fetchCatalog).toHaveBeenCalledTimes(2);
		expect(get(subAgentViewer).catalog).toEqual([child]);
	});
	it('retrieves every historical entry over 64 while still rejecting oversized live input', async () => {
		const catalog = Array.from({ length: 100 }, (_, index) => ({
			chatId: `${index.toString(16).padStart(8, '0')}-1234-1234-1234-123456789abc`,
			title: `Task ${index}`
		}));
		fetchCatalog.mockResolvedValue({ ok: true, json: async () => catalog });
		savedScope();
		await settle();
		expect(get(subAgentViewer).catalog).toEqual(catalog);
		selectSubAgentChat(catalog[99].chatId);
		expect(get(subAgentViewer).selectedId).toBe(catalog[99].chatId);
		const handler = createSubAgentBridge(
			parentId,
			'owner',
			false,
			get(subAgentViewer).scopeRevision
		);
		expect(handler({ type: 'subagent:chats', chats: catalog }, source() as unknown as Window)).toBe(
			false
		);
		expect(handler({ type: 'subagent:chats', chats: [child] }, source() as unknown as Window)).toBe(
			true
		);
		expect(get(subAgentViewer).catalog).toHaveLength(101);
	});
	it('late hydration preserves live additions, latest titles and explicit selection', async () => {
		let resolve!: (value: unknown) => void;
		fetchCatalog.mockReturnValue(
			new Promise((done) => {
				resolve = done;
			})
		);
		savedScope();
		const live = { chatId: '42345678-1234-1234-1234-123456789abc', title: 'Live task' };
		const handler = createSubAgentBridge(
			parentId,
			'owner',
			false,
			get(subAgentViewer).scopeRevision
		);
		handler(
			{ type: 'subagent:chats', chats: [live, { ...child, title: 'Latest title' }] },
			source() as unknown as Window
		);
		selectSubAgentChat(live.chatId);
		resolve({ ok: true, json: async () => [child] });
		await settle();
		expect(get(subAgentViewer)).toMatchObject({
			catalog: [{ ...child, title: 'Latest title' }, live],
			selectedId: live.chatId,
			openRevision: 0,
			discovery: 'ready'
		});
	});
	it.each(['parent', 'user', 'logout', 'destroy', 'replace'])(
		'aborts and ignores stale discovery after %s',
		async (change) => {
			let resolve!: (value: unknown) => void;
			fetchCatalog.mockReturnValue(new Promise(() => {}));
			fetchCatalog.mockReturnValueOnce(
				new Promise((done) => {
					resolve = done;
				})
			);
			const { parent, user } = savedScope();
			const signal = fetchCatalog.mock.calls[0][1].signal;
			if (change === 'parent') {
				parent.set('other');
				parent.set(parentId);
			}
			if (change === 'user') user.set({ id: 'other' });
			if (change === 'logout') user.set(null);
			if (change === 'destroy') stop?.();
			if (change === 'replace')
				stop = trackSubAgentScope(writable('other'), writable({ id: 'owner' }));
			expect(signal.aborted).toBe(true);
			resolve({ ok: true, json: async () => [child] });
			await settle();
			expect(get(subAgentViewer).catalog).toEqual([]);
			if (change === 'replace') {
				parent.set(parentId);
				expect(get(subAgentViewer).parentId).toBe('other');
			}
		}
	);
	it.each(['http', 'network', 'shape', 'entry', 'json'])(
		'reports %s failure separately and retries to a known empty catalog',
		async (failure) => {
			const response = { ok: true, json: async () => [] as unknown };
			if (failure === 'http') response.ok = false;
			if (failure === 'shape') response.json = async () => ({ chats: [] });
			if (failure === 'entry')
				response.json = async () => [child, { chatId: '../bad', title: 'Bad' }];
			if (failure === 'json')
				response.json = async () => {
					throw new Error('invalid JSON');
				};
			if (failure === 'network') fetchCatalog.mockRejectedValue(new Error('offline'));
			else fetchCatalog.mockResolvedValue(response);
			const { user } = savedScope();
			await settle();
			expect(get(subAgentViewer)).toMatchObject({
				discovery: 'error',
				catalog: [],
				selectedId: ''
			});
			user.set({ id: 'owner' });
			expect(fetchCatalog).toHaveBeenCalledOnce();
			fetchCatalog.mockResolvedValue({ ok: true, json: async () => [] });
			await refreshSubAgentCatalog();
			expect(get(subAgentViewer)).toMatchObject({
				discovery: 'ready',
				catalog: [],
				openRevision: 0
			});
		}
	);
	it('does not fetch for unsaved/non-UUID parents, missing user/token or SSR', async () => {
		for (const parent of ['', 'temporary:session', 'local:session', 'channel:id', '../bad']) {
			stop = trackSubAgentScope(writable(parent), writable({ id: 'owner' }));
			expect(get(subAgentViewer).discovery).toBe('idle');
		}
		stop = trackSubAgentScope(writable(parentId), writable(null));
		vi.stubGlobal('window', undefined);
		savedScope();
		await settle();
		expect(fetchCatalog).not.toHaveBeenCalled();
		vi.stubGlobal('window', {});
		vi.stubGlobal('localStorage', { token: '' });
		await refreshSubAgentCatalog();
		expect(fetchCatalog).not.toHaveBeenCalled();
		expect(get(subAgentViewer).discovery).toBe('error');
	});
	it('a stale rejection cannot clear a new scope request or permit overlapping retries', async () => {
		let reject!: (error: Error) => void;
		let resolve!: (value: unknown) => void;
		fetchCatalog.mockReturnValueOnce(
			new Promise((_, fail) => {
				reject = fail;
			})
		);
		fetchCatalog.mockReturnValueOnce(
			new Promise((done) => {
				resolve = done;
			})
		);
		const { parent } = savedScope();
		parent.set('other');
		parent.set(parentId);
		reject(new Error('aborted'));
		await settle();
		expect(get(subAgentViewer).discovery).toBe('loading');
		await refreshSubAgentCatalog();
		expect(fetchCatalog).toHaveBeenCalledTimes(2);
		resolve({ ok: true, json: async () => [child] });
		await settle();
		expect(get(subAgentViewer)).toMatchObject({ discovery: 'ready', catalog: [child] });
	});
});
const source = () => ({ postMessage: vi.fn() });
function scope() {
	const parent = writable('parent');
	const user = writable<{ id: string } | null>({ id: 'owner' });
	stop = trackSubAgentScope(parent, user);
	const bridge = () => {
		const handler = createSubAgentBridge(
			'parent',
			'owner',
			false,
			get(subAgentViewer).scopeRevision
		);
		return (value: unknown, from = source() as unknown as Window) => handler(value, from);
	};
	return { parent, user, bridge };
}
describe('sub-agent viewer boundaries', () => {
	it('rejects URL injection and oversized labels', () => {
		expect(parseSubAgentChat({ chatId: '../other', title: 'Task' })).toBeNull();
		expect(parseSubAgentChat({ chatId: id, title: 'x'.repeat(201) })).toBeNull();
		expect(parseSubAgentChat({ chatId: id, title: ' Task ' })).toEqual({
			chatId: id,
			title: 'Task'
		});
	});
	it('requires owner, child identity, internal provenance and originating parent', () => {
		const chat = {
			id,
			user_id: 'user',
			meta: {
				internal: true,
				type: 'subagent',
				source: 'ai_team_delegate',
				parent_chat_id: 'parent'
			}
		};
		expect(isOwnedSubAgentChat(chat, id, 'user', 'parent')).toBe(true);
		for (const changed of [
			{ ...chat, user_id: 'other' },
			{ ...chat, id: 'other' },
			...['internal', 'type', 'source', 'parent_chat_id'].map((key) => ({
				...chat,
				meta: { ...chat.meta, [key]: 'other' }
			}))
		])
			expect(isOwnedSubAgentChat(changed, id, 'user', 'parent')).toBe(false);
	});
	it('merges snapshots without removing or duplicating known children', () => {
		const chat = { chatId: id, title: 'Task' };
		expect(mergeSubAgentChats([chat], [])).toEqual([chat]);
		expect(mergeSubAgentChats([chat], [chat])).toEqual([chat]);
	});
	it('catalogs do not open the sidebar; explicit opens select and increment a request revision', () => {
		const { bridge } = scope();
		const handler = bridge();
		const chat = { chatId: id, title: 'Task' };
		expect(handler({ type: 'subagent:chats', chats: [chat] })).toBe(true);
		expect(get(subAgentViewer)).toMatchObject({ selectedId: id, openRevision: 0, catalog: [chat] });
		expect(handler({ type: 'subagent:open-chat', ...chat })).toBe(true);
		expect(handler({ type: 'subagent:open-chat', ...chat })).toBe(true);
		expect(get(subAgentViewer).openRevision).toBe(2);
		selectSubAgentChat('unknown');
		expect(get(subAgentViewer).selectedId).toBe(id);
	});
	it('resets on parent/user/logout and rejects stale callbacks even when returning to the parent', () => {
		const { parent, user, bridge } = scope();
		const handler = bridge();
		const event = { type: 'subagent:open-chat', chatId: id, title: 'Task' };
		expect(handler(event)).toBe(true);
		parent.set('other');
		expect(get(subAgentViewer).catalog).toEqual([]);
		expect(handler(event)).toBe(false);
		parent.set('parent');
		expect(handler(event)).toBe(false);
		expect(bridge()(event)).toBe(true);
		user.set({ id: 'other' });
		expect(get(subAgentViewer)).toMatchObject({ catalog: [], selectedId: '', openRevision: 0 });
		user.set(null);
		expect(bridge()(event)).toBe(false);
	});
	it('rejects read-only, wrong scope, malformed batches and events without a scope owner', () => {
		const { bridge } = scope();
		const revision = get(subAgentViewer).scopeRevision;
		const event = { type: 'subagent:chats', chats: [{ chatId: id, title: 'Task' }] };
		for (const handler of [
			createSubAgentBridge('parent', 'owner', true, revision),
			createSubAgentBridge('other', 'owner', false, revision),
			createSubAgentBridge('parent', 'other', false, revision)
		])
			expect(handler(event, source() as unknown as Window)).toBe(false);
		expect(
			bridge()({ ...event, chats: [...event.chats, { chatId: '../bad', title: 'Task' }] })
		).toBe(false);
		expect(get(subAgentViewer).catalog).toEqual([]);
		const handler = bridge();
		stop?.();
		expect(handler(event)).toBe(false);
	});
	it('acks the exact source only after a validated, in-scope catalog', () => {
		const { bridge } = scope();
		const handler = bridge();
		const good = source(),
			other = source();
		const catalog = { type: 'subagent:chats', chats: [{ chatId: id, title: 'Task' }] };
		expect(handler(catalog, good as unknown as Window)).toBe(true);
		expect(good.postMessage).toHaveBeenCalledOnce();
		expect(good.postMessage).toHaveBeenCalledWith({ type: 'subagent:viewer-ready' }, '*');
		expect(other.postMessage).not.toHaveBeenCalled();
		for (const bad of [
			{ ...catalog, chats: [{ chatId: '../bad', title: 'Task' }] },
			{ type: 'subagent:open-chat', chatId: id, title: 'Task' }
		])
			handler(bad, good as unknown as Window);
		createSubAgentBridge('parent', 'owner', true, 0)(catalog, good as unknown as Window);
		expect(good.postMessage).toHaveBeenCalledOnce();
	});
	it('an obsolete controls owner cannot reset the new owner on teardown', () => {
		const first = trackSubAgentScope(writable('old'), writable({ id: 'owner' }));
		const { bridge } = scope();
		bridge()({ type: 'subagent:chats', chats: [{ chatId: id, title: 'Task' }] });
		first();
		expect(get(subAgentViewer).catalog).toHaveLength(1);
	});
});
