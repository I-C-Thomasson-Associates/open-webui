import { get, writable, type Readable } from 'svelte/store';
import { getSubAgentChats } from '$lib/ext/subagent-chats-api';

export type SubAgentChat = { chatId: string; title: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const emptyScope = (parentId = '', userId = '', scopeRevision = 0) => ({
	parentId,
	userId,
	scopeRevision,
	catalog: [] as SubAgentChat[],
	discovery: 'idle' as 'idle' | 'loading' | 'ready' | 'error',
	selectedId: '',
	openRevision: 0
});
export const subAgentViewer = writable(emptyScope());
let scopeOwner: symbol | null = null;
let stopScope: (() => void) | null = null;
let catalogRequest: AbortController | null = null;

export async function refreshSubAgentCatalog() {
	const scope = get(subAgentViewer);
	const owner = scopeOwner;
	if (
		typeof window === 'undefined' ||
		!owner ||
		!scope.userId ||
		!uuid.test(scope.parentId) ||
		catalogRequest
	)
		return;
	const request = new AbortController();
	catalogRequest = request;
	const current = () => {
		const state = get(subAgentViewer);
		return (
			!request.signal.aborted &&
			catalogRequest === request &&
			scopeOwner === owner &&
			state.scopeRevision === scope.scopeRevision &&
			state.parentId === scope.parentId &&
			state.userId === scope.userId
		);
	};
	subAgentViewer.update((state) => ({ ...state, discovery: 'loading' }));
	try {
		const result = await getSubAgentChats(localStorage.token, scope.parentId, request.signal);
		if (!current()) return;
		if (!Array.isArray(result)) throw new Error('Unavailable');
		const parsed = result.map(parseSubAgentChat);
		if (parsed.some((chat) => !chat)) throw new Error('Unavailable');
		subAgentViewer.update((state) => {
			// Live snapshots may arrive while discovery is pending; keep their latest titles and selection.
			const catalog = mergeSubAgentChats(parsed as SubAgentChat[], state.catalog);
			return {
				...state,
				catalog,
				selectedId: state.selectedId || catalog[0]?.chatId || '',
				discovery: 'ready'
			};
		});
	} catch {
		if (current()) subAgentViewer.update((state) => ({ ...state, discovery: 'error' }));
	} finally {
		if (catalogRequest === request) catalogRequest = null;
	}
}

// Only the mounted chat controls owns scope; response teardown must not clear sibling catalogs.
export function trackSubAgentScope(
	activeChat: Readable<string>,
	activeUser: Readable<{ id: string } | null | undefined>
) {
	stopScope?.();
	const owner = Symbol();
	scopeOwner = owner;
	const sync = () => {
		if (scopeOwner !== owner) return;
		const parentId = get(activeChat) ?? '';
		const userId = get(activeUser)?.id ?? '';
		const state = get(subAgentViewer);
		if (state.parentId !== parentId || state.userId !== userId) {
			catalogRequest?.abort();
			catalogRequest = null;
			subAgentViewer.set(emptyScope(parentId, userId, state.scopeRevision + 1));
		}
		if (get(subAgentViewer).discovery === 'idle') void refreshSubAgentCatalog();
	};
	const offChat = activeChat.subscribe(sync);
	const offUser = activeUser.subscribe(sync);
	const cleanup = () => {
		offChat();
		offUser();
		if (scopeOwner === owner) {
			catalogRequest?.abort();
			catalogRequest = null;
			scopeOwner = null;
			stopScope = null;
			subAgentViewer.update((state) => emptyScope('', '', state.scopeRevision + 1));
		}
	};
	stopScope = cleanup;
	return cleanup;
}

export function createSubAgentBridge(
	parentId: string,
	userId: string,
	readOnly: boolean,
	scopeRevision: number
) {
	return (value: unknown, source: Window): boolean => {
		const state = get(subAgentViewer);
		if (
			readOnly ||
			!scopeOwner ||
			!parentId ||
			!userId ||
			state.parentId !== parentId ||
			state.userId !== userId ||
			state.scopeRevision !== scopeRevision ||
			!value ||
			typeof value !== 'object'
		)
			return false;
		const data = value as Record<string, unknown>;
		let chats: SubAgentChat[];
		if (data.type === 'subagent:chats' && Array.isArray(data.chats) && data.chats.length <= 64) {
			const parsed = data.chats.map(parseSubAgentChat);
			if (parsed.some((chat) => !chat)) return false;
			chats = parsed as SubAgentChat[];
		} else if (data.type === 'subagent:open-chat') {
			const chat = parseSubAgentChat(data);
			if (!chat) return false;
			chats = [chat];
		} else return false;
		const catalog = mergeSubAgentChats(state.catalog, chats);
		if (data.type === 'subagent:open-chat' && !catalog.some((chat) => chat.chatId === data.chatId))
			return false;
		subAgentViewer.set({
			...state,
			catalog,
			selectedId:
				data.type === 'subagent:open-chat'
					? chats[0].chatId
					: state.selectedId || catalog[0]?.chatId || '',
			openRevision: state.openRevision + (data.type === 'subagent:open-chat' ? 1 : 0)
		});
		// Ack only validated catalogs, and only to the iframe that sent them.
		if (data.type === 'subagent:chats') source.postMessage({ type: 'subagent:viewer-ready' }, '*');
		return true;
	};
}

export function selectSubAgentChat(id: string) {
	subAgentViewer.update((state) =>
		state.catalog.some((chat) => chat.chatId === id) ? { ...state, selectedId: id } : state
	);
}

export function parseSubAgentChat(value: unknown): SubAgentChat | null {
	if (!value || typeof value !== 'object') return null;
	const { chatId, title } = value as Record<string, unknown>;
	if (
		typeof chatId !== 'string' ||
		!uuid.test(chatId) ||
		typeof title !== 'string' ||
		title.length > 200
	)
		return null;
	return { chatId, title: title.trim() || 'Sub-agent' };
}

export function isOwnedSubAgentChat(
	chat: any,
	id: string,
	userId: string,
	parentId: string
): boolean {
	return (
		!!userId &&
		!!parentId &&
		chat?.id === id &&
		chat?.user_id === userId &&
		chat?.meta?.internal === true &&
		chat.meta.type === 'subagent' &&
		chat.meta.source === 'ai_team_delegate' &&
		chat.meta.parent_chat_id === parentId
	);
}

export function mergeSubAgentChats(
	existing: SubAgentChat[],
	incoming: SubAgentChat[]
): SubAgentChat[] {
	const chats = new Map(existing.map((chat) => [chat.chatId, chat]));
	for (const chat of incoming) chats.set(chat.chatId, chat);
	return [...chats.values()];
}
