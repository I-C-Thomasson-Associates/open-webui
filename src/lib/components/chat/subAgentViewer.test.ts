import { get, writable } from 'svelte/store';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	createSubAgentBridge,
	isOwnedSubAgentChat,
	mergeSubAgentChats,
	parseSubAgentChat,
	selectSubAgentChat,
	subAgentViewer,
	trackSubAgentScope
} from './subAgentViewer';
const id = '12345678-1234-1234-1234-123456789abc';
let stop: (() => void) | undefined;
afterEach(() => {
	stop?.();
	stop = undefined;
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
